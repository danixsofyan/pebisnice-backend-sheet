package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/xuri/excelize/v2"
)

// ════════════════════════════════════════════════════════════════
// CONFIG
// ════════════════════════════════════════════════════════════════

func secretKey() string {
	k := os.Getenv("SECRET_KEY")
	if k == "" {
		return "pebisnice_dev_key"
	}
	return k
}

// Token dari Lynk.id dashboard → Webhook Settings → Token
func lynkWebhookToken() string {
	return os.Getenv("LYNK_WEBHOOK_TOKEN")
}

// ════════════════════════════════════════════════════════════════
// AUTHORIZED EMAILS STORE
// Primary: Supabase PostgreSQL (permanen, survive restart)
// Cache:   in-memory map (load saat startup, update saat webhook)
// ════════════════════════════════════════════════════════════════

type PurchaseRecord struct {
	Email       string    `json:"email"`
	RefID       string    `json:"refId"`
	ProductName string    `json:"productName"`
	PurchasedAt time.Time `json:"purchasedAt"`
}

var (
	db           *sql.DB
	emailStoreMu sync.RWMutex
	emailCache   = map[string]*PurchaseRecord{} // in-memory cache
)

// DATABASE_URL format: postgres://user:password@host:5432/dbname?sslmode=require
func dbURL() string {
	return os.Getenv("DATABASE_URL")
}

// Inisialisasi koneksi Supabase PostgreSQL
func initDB() error {
	dsn := dbURL()
	if dsn == "" {
		log.Println("[DB] DATABASE_URL tidak diset — mode tanpa database")
		return nil
	}
	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("gagal buka koneksi DB: %w", err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Buat tabel jika belum ada
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS purchases (
			id          SERIAL PRIMARY KEY,
			email       TEXT NOT NULL UNIQUE,
			ref_id      TEXT,
			product     TEXT,
			bought_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS purchases_email_idx ON purchases(email);

		CREATE TABLE IF NOT EXISTS activations (
			spreadsheet_id  TEXT PRIMARY KEY,
			email           TEXT NOT NULL,
			token           TEXT NOT NULL,
			activated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS activations_email_idx ON activations(email);
		CREATE INDEX IF NOT EXISTS activations_token_idx ON activations(token);
	`)
	if err != nil {
		return fmt.Errorf("gagal buat tabel: %w", err)
	}
	// Verifikasi koneksi benar-benar aktif
	if err := db.Ping(); err != nil {
		db = nil
		return fmt.Errorf("ping DB gagal: %w", err)
	}
	log.Println("[DB] Terkoneksi ke Supabase PostgreSQL ✅")
	return nil
}

// Load semua email dari DB ke in-memory cache (dipanggil sekali saat startup)
func loadEmailsFromDB() {
	if db == nil {
		return
	}
	rows, err := db.Query(`SELECT email, ref_id, product, bought_at FROM purchases`)
	if err != nil {
		log.Printf("[DB] Gagal load emails: %v", err)
		return
	}
	defer rows.Close()

	emailStoreMu.Lock()
	defer emailStoreMu.Unlock()
	loaded := 0
	for rows.Next() {
		var r PurchaseRecord
		if err := rows.Scan(&r.Email, &r.RefID, &r.ProductName, &r.PurchasedAt); err != nil {
			continue
		}
		emailCache[r.Email] = &r
		loaded++
	}
	log.Printf("[DB] Loaded %d emails dari Supabase ke cache", loaded)
}

// Tambah/update email dari webhook → simpan ke DB + update cache
func authorizeEmail(email, refID, productName string) {
	email = strings.ToLower(strings.TrimSpace(email))
	record := &PurchaseRecord{
		Email:       email,
		RefID:       refID,
		ProductName: productName,
		PurchasedAt: time.Now(),
	}

	// Update in-memory cache dulu (non-blocking)
	emailStoreMu.Lock()
	emailCache[email] = record
	emailStoreMu.Unlock()

	// Simpan ke Supabase — sync agar error terlihat di log
	go func() {
		if db == nil {
			log.Printf("[DB] ⚠️  db=nil saat upsert %s — DATABASE_URL mungkin belum terset saat startup", email)
			// Coba init ulang DB jika belum terhubung
			if err := initDB(); err != nil {
				log.Printf("[DB] Retry initDB gagal: %v", err)
				return
			}
			if db == nil {
				log.Printf("[DB] Retry initDB selesai tapi db masih nil — skip upsert")
				return
			}
			log.Printf("[DB] Retry initDB berhasil — lanjut upsert")
		}
		_, err := db.Exec(`
			INSERT INTO purchases (email, ref_id, product, bought_at, updated_at)
			VALUES ($1, $2, $3, NOW(), NOW())
			ON CONFLICT (email) DO UPDATE SET
				ref_id     = EXCLUDED.ref_id,
				product    = EXCLUDED.product,
				updated_at = NOW()
		`, email, refID, productName)
		if err != nil {
			log.Printf("[DB] Gagal upsert email %s: %v", email, err)
		} else {
			log.Printf("[DB] Tersimpan: email=%s refId=%s", email, refID)
		}
	}()

	log.Printf("[AUTHORIZE] email=%s refId=%s", email, refID)
}

// Cek apakah email sudah beli (dari cache — cepat, tanpa query DB)
// Jika tidak ada di cache, cek langsung ke DB (fallback untuk cache miss)
func isEmailAuthorized(email string) *PurchaseRecord {
	email = strings.ToLower(strings.TrimSpace(email))

	// Cek cache dulu
	emailStoreMu.RLock()
	r, ok := emailCache[email]
	emailStoreMu.RUnlock()
	if ok {
		return r
	}

	// Cache miss → query langsung ke DB (buyer yang beli sebelum server restart)
	if db == nil {
		return nil
	}
	var record PurchaseRecord
	err := db.QueryRow(`
		SELECT email, ref_id, product, bought_at
		FROM purchases WHERE email = $1
	`, email).Scan(&record.Email, &record.RefID, &record.ProductName, &record.PurchasedAt)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("[DB] Query error untuk %s: %v", email, err)
		}
		return nil
	}

	// Masukkan ke cache untuk request berikutnya
	emailStoreMu.Lock()
	emailCache[email] = &record
	emailStoreMu.Unlock()

	return &record
}

// ════════════════════════════════════════════════════════════════
// TOKEN MANAGEMENT — random UUID di Supabase
//
// Token = random hex 64 karakter, dibuat saat /activate
// Disimpan di DB tabel activations(spreadsheet_id, email, token)
// Tidak bisa di-forge — harus ada record di DB
//
// Anti-bypass: pirate tidak bisa hardcode spreadsheetId+email
// karena token-nya random dan hanya ada di DB kita
// ════════════════════════════════════════════════════════════════

func generateToken(spreadsheetId string) string {
	// Random token — tidak deterministik, tidak bisa di-forge
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// validateToken: cek token di DB activations
// return (valid bool, email string)
func validateToken(spreadsheetId, token string) (bool, string) {
	if db == nil || spreadsheetId == "" || token == "" {
		return false, ""
	}
	var email string
	err := db.QueryRow(
		`SELECT email FROM activations WHERE spreadsheet_id=$1 AND token=$2`,
		spreadsheetId, token,
	).Scan(&email)
	if err != nil {
		return false, ""
	}
	return true, email
}

// saveActivation: simpan token ke DB activations
// Jika spreadsheetId sudah ada, update token (re-aktivasi)
func saveActivation(spreadsheetId, email, token string) error {
	if db == nil {
		return fmt.Errorf("database tidak tersedia")
	}
	_, err := db.Exec(`
		INSERT INTO activations (spreadsheet_id, email, token, activated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (spreadsheet_id) DO UPDATE SET
			token = EXCLUDED.token,
			email = EXCLUDED.email,
			activated_at = NOW()
	`, spreadsheetId, email, token)
	return err
}

// ════════════════════════════════════════════════════════════════
// BLOCKLIST — SpreadsheetId
// Set env BLOCKED_IDS="id1,id2" di Leapcell → cabut akses instan
// ════════════════════════════════════════════════════════════════

func isBlocked(spreadsheetId string) bool {
	raw := os.Getenv("BLOCKED_IDS")
	if raw == "" {
		return false
	}
	for _, id := range strings.Split(raw, ",") {
		if strings.TrimSpace(id) == spreadsheetId {
			return true
		}
	}
	return false
}

// ════════════════════════════════════════════════════════════════
// FIELD ALIASES — Shopee export columns
// ════════════════════════════════════════════════════════════════

var orderFieldAliases = map[string][]string{
	"noPesanan":    {"No. Pesanan", "Order ID", "No Pesanan"},
	"waktuDibuat":  {"Waktu Pesanan Dibuat", "Tanggal Pesanan Dibuat", "Order Date"},
	"waktuSelesai": {"Waktu Pesanan Selesai", "Tanggal Pesanan Selesai", "Order Completion Time"},
	"status":       {"Status Pesanan", "Order Status", "Status"},
	"skuInduk":     {"SKU Induk", "Parent SKU", "SKU Utama"},
	"namaProduk":   {"Nama Produk", "Product Name", "Nama Barang"},
	"skuRef":       {"Nomor Referensi SKU", "SKU Reference Number", "Seller SKU"},
	"variasi":      {"Nama Variasi", "Variation Name", "Variasi"},
	"qty":          {"Jumlah", "Quantity", "Qty", "Jumlah Produk di Pesan"},
	"totalHarga":   {"Total Harga Produk", "Subtotal Produk", "Total Product Price"},
	"totalBayar":   {"Total Pembayaran", "Total Payment", "Grand Total", "Buyer Paid"},
}

var incomeLabelAliases = map[string][]string{
	"totalPendapatan":  {"1. Total Pendapatan"},
	"hargaAsli":        {"Harga Asli Produk"},
	"totalDiskon":      {"Total Diskon Produk"},
	"pengembalianDana": {"Jumlah Pengembalian Dana ke Pembeli"},
	"totalPengeluaran": {"2. Total Pengeluaran"},
	"biayaKomisi":      {"Biaya Komisi AMS"},
	"biayaAdmin":       {"Biaya Administrasi"},
	"biayaLayanan":     {"Biaya Layanan", "Biaya Layanan (termasuk PPN 11%)"},
	"biayaProses":      {"Biaya Proses Pesanan", "Biaya Proses"},
	"totalDilepas":     {"3. Total yang Dilepas"},
}

var criticalFields = []string{"noPesanan", "namaProduk", "qty", "totalHarga", "totalBayar"}

// ════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════

type OrderItem struct {
	NoPesanan    string  `json:"noPesanan"`
	WaktuDibuat  string  `json:"waktuDibuat"`
	WaktuSelesai string  `json:"waktuSelesai"`
	Status       string  `json:"status"`
	SkuInduk     string  `json:"skuInduk"`
	NamaProduk   string  `json:"namaProduk"`
	SkuRef       string  `json:"skuRef"`
	SkuForHpp    string  `json:"skuForHpp"`
	Variasi      string  `json:"variasi"`
	Qty          float64 `json:"qty"`
	TotalHarga   float64 `json:"totalHarga"`
	TotalBayar   float64 `json:"totalBayar"`
}

type IncomeData struct {
	TotalPendapatan  *float64 `json:"totalPendapatan"`
	HargaAsli        *float64 `json:"hargaAsli"`
	TotalDiskon      *float64 `json:"totalDiskon"`
	PengembalianDana *float64 `json:"pengembalianDana"`
	TotalPengeluaran *float64 `json:"totalPengeluaran"`
	BiayaKomisi      *float64 `json:"biayaKomisi"`
	BiayaAdmin       *float64 `json:"biayaAdmin"`
	BiayaLayanan     *float64 `json:"biayaLayanan"`
	BiayaProses      *float64 `json:"biayaProses"`
	TotalDilepas     *float64 `json:"totalDilepas"`
}

// Lynk.id webhook payload
type LynkWebhookPayload struct {
	Event string `json:"event"`
	Data  struct {
		MessageAction string `json:"message_action"`
		MessageID     string `json:"message_id"`
		MessageData   struct {
			RefID    string `json:"refId"`
			Customer struct {
				Email string `json:"email"`
				Name  string `json:"name"`
			} `json:"customer"`
			Items []struct {
				Title string `json:"title"`
				Price int    `json:"price"`
				Qty   int    `json:"qty"`
			} `json:"items"`
			Totals struct {
				GrandTotal int `json:"grandTotal"`
			} `json:"totals"`
		} `json:"message_data"`
	} `json:"data"`
}

type ActivateRequest struct {
	Key           string `json:"key"`
	SpreadsheetId string `json:"spreadsheetId"`
	Email         string `json:"email"` // Gmail buyer dari Session.getActiveUser()
}

type ParseRequest struct {
	Key           string `json:"key"`
	Token         string `json:"token"`
	SpreadsheetId string `json:"spreadsheetId"`
	Type          string `json:"type"`
	FileBase64    string `json:"fileBase64"`
	FileName      string `json:"fileName"`
}

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════

func strip(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "'")
	return strings.TrimSpace(s)
}

func toNum(s string) (float64, bool) {
	s = strings.ReplaceAll(strip(s), ",", "")
	n, err := strconv.ParseFloat(s, 64)
	return n, err == nil
}

func ptr(v float64) *float64 { return &v }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func decodeToTempFile(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("base64 decode gagal: %w", err)
	}
	f, err := os.CreateTemp("", "pb-*.xlsx")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.Write(raw)
	return f.Name(), err
}

func openXlsx(b64 string) (*excelize.File, string, error) {
	path, err := decodeToTempFile(b64)
	if err != nil {
		return nil, "", err
	}
	f, err := excelize.OpenFile(path)
	if err != nil {
		os.Remove(path)
		return nil, "", fmt.Errorf("tidak bisa buka xlsx: %w", err)
	}
	return f, path, nil
}

func getAllRows(f *excelize.File) ([][]string, error) {
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("file tidak punya sheet")
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, err
	}
	for i, row := range rows {
		for j, c := range row {
			rows[i][j] = strip(c)
		}
	}
	return rows, nil
}

func findHeaderRow(rows [][]string) (int, error) {
	primary := map[string]bool{}
	for _, aliases := range orderFieldAliases {
		primary[aliases[0]] = true
	}
	for i, row := range rows {
		if i >= 10 {
			break
		}
		hits := 0
		for _, c := range row {
			if primary[c] {
				hits++
			}
		}
		if hits >= 3 {
			return i, nil
		}
	}
	return -1, fmt.Errorf("header tidak ditemukan — pastikan file adalah export Order Shopee")
}

func buildColIdx(headers []string) map[string]int {
	idx := map[string]int{}
	for field, aliases := range orderFieldAliases {
		idx[field] = -1
		for _, alias := range aliases {
			for i, h := range headers {
				if h == alias {
					idx[field] = i
					goto next
				}
			}
		}
	next:
	}
	return idx
}

func getCell(row []string, idx map[string]int, field string) string {
	i, ok := idx[field]
	if !ok || i < 0 || i >= len(row) {
		return ""
	}
	return row[i]
}

func detectRibuan(rows [][]string, headerIdx, col int) bool {
	if col < 0 {
		return true
	}
	var samples []float64
	for _, row := range rows[headerIdx+1:] {
		if len(samples) >= 20 {
			break
		}
		if col < len(row) {
			if n, ok := toNum(row[col]); ok && n > 0 {
				samples = append(samples, n)
			}
		}
	}
	if len(samples) == 0 {
		return true
	}
	sort.Float64s(samples)
	return samples[len(samples)/2] < 1000
}

// ════════════════════════════════════════════════════════════════
// PARSE ORDER
// ════════════════════════════════════════════════════════════════

func parseOrder(b64 string) ([]OrderItem, int, string, error) {
	f, path, err := openXlsx(b64)
	if err != nil {
		return nil, 0, "", err
	}
	defer f.Close()
	defer os.Remove(path)

	rows, err := getAllRows(f)
	if err != nil {
		return nil, 0, "", err
	}

	hIdx, err := findHeaderRow(rows)
	if err != nil {
		return nil, 0, "", err
	}

	headers := rows[hIdx]
	colIdx := buildColIdx(headers)

	var missing []string
	for _, field := range criticalFields {
		if i, ok := colIdx[field]; !ok || i < 0 {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		return nil, 0, "", fmt.Errorf("kolom tidak ditemukan: %s", strings.Join(missing, ", "))
	}

	mult := 1.0
	if detectRibuan(rows, hIdx, colIdx["totalHarga"]) {
		mult = 1000.0
	}

	completed := map[string]bool{"Selesai": true, "Completed": true, "SELESAI": true}
	var orders []OrderItem
	nonSelesai := 0
	uniqueMap := map[string]bool{}

	for _, row := range rows[hIdx+1:] {
		noPesanan := getCell(row, colIdx, "noPesanan")
		if noPesanan == "" {
			continue
		}
		uniqueMap[noPesanan] = true

		status := getCell(row, colIdx, "status")
		if status != "" && !completed[status] {
			nonSelesai++
		}

		qty, _ := toNum(getCell(row, colIdx, "qty"))
		totalHarga, _ := toNum(getCell(row, colIdx, "totalHarga"))
		totalBayar, _ := toNum(getCell(row, colIdx, "totalBayar"))
		skuRef := getCell(row, colIdx, "skuRef")
		skuInduk := getCell(row, colIdx, "skuInduk")
		namaProd := getCell(row, colIdx, "namaProduk")

		skuForHpp := skuRef
		if skuForHpp == "" {
			skuForHpp = skuInduk
		}
		if skuForHpp == "" {
			skuForHpp = namaProd
		}

		orders = append(orders, OrderItem{
			NoPesanan:    noPesanan,
			WaktuDibuat:  getCell(row, colIdx, "waktuDibuat"),
			WaktuSelesai: getCell(row, colIdx, "waktuSelesai"),
			Status:       status,
			SkuInduk:     skuInduk,
			NamaProduk:   namaProd,
			SkuRef:       skuRef,
			SkuForHpp:    skuForHpp,
			Variasi:      getCell(row, colIdx, "variasi"),
			Qty:          qty,
			TotalHarga:   math.Round(totalHarga*mult*100) / 100,
			TotalBayar:   math.Round(totalBayar*mult*100) / 100,
		})
	}

	if len(orders) == 0 {
		return nil, 0, "", fmt.Errorf("tidak ada data order")
	}

	warn := ""
	if nonSelesai > 0 {
		warn = fmt.Sprintf("%d order bukan Selesai ikut terimport", nonSelesai)
	}
	return orders, len(uniqueMap), warn, nil
}

// ════════════════════════════════════════════════════════════════
// PARSE INCOME
// ════════════════════════════════════════════════════════════════

func parseIncome(b64 string) (*IncomeData, string, string, string, error) {
	f, path, err := openXlsx(b64)
	if err != nil {
		return nil, "", "", "", err
	}
	defer f.Close()
	defer os.Remove(path)

	rows, err := getAllRows(f)
	if err != nil {
		return nil, "", "", "", err
	}

	numMap := map[string]float64{}
	strMap := map[string]string{}

	for _, row := range rows {
		rightNum := math.NaN()
		for ci := len(row) - 1; ci >= 0; ci-- {
			if n, ok := toNum(row[ci]); ok {
				rightNum = n
				break
			}
		}
		for ci, cell := range row {
			label := strip(cell)
			if len(label) < 2 {
				continue
			}
			if !math.IsNaN(rightNum) {
				numMap[label] = rightNum
			}
			if ci+1 < len(row) {
				next := strip(row[ci+1])
				if next != "" {
					if _, isNum := toNum(next); !isNum {
						strMap[label] = next
					}
				}
			}
		}
	}

	lookupNum := func(primary string) *float64 {
		for _, alias := range incomeLabelAliases[primary] {
			if v, ok := numMap[alias]; ok {
				return ptr(v)
			}
		}
		return nil
	}

	inc := &IncomeData{
		TotalPendapatan:  lookupNum("totalPendapatan"),
		HargaAsli:        lookupNum("hargaAsli"),
		TotalDiskon:      lookupNum("totalDiskon"),
		PengembalianDana: lookupNum("pengembalianDana"),
		TotalPengeluaran: lookupNum("totalPengeluaran"),
		BiayaKomisi:      lookupNum("biayaKomisi"),
		BiayaAdmin:       lookupNum("biayaAdmin"),
		BiayaLayanan:     lookupNum("biayaLayanan"),
		BiayaProses:      lookupNum("biayaProses"),
		TotalDilepas:     lookupNum("totalDilepas"),
	}

	if inc.TotalDilepas == nil && inc.TotalPendapatan == nil {
		return nil, "", "", "", fmt.Errorf(
			"data penghasilan tidak ditemukan — pastikan file adalah Laporan Penghasilan Shopee")
	}

	return inc,
		strMap["Dari"],
		strMap["ke"],
		strMap["Username (Penjual)"],
		nil
}

// ════════════════════════════════════════════════════════════════
// CORS MIDDLEWARE
// ════════════════════════════════════════════════════════════════

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// ════════════════════════════════════════════════════════════════
// HANDLER: /health
// ════════════════════════════════════════════════════════════════

func handleHealth(w http.ResponseWriter, r *http.Request) {
	emailStoreMu.RLock()
	count := len(emailCache)
	emailStoreMu.RUnlock()
	dbStatus := "no database"
	if db != nil {
		if err := db.Ping(); err == nil {
			dbStatus = "connected"
		} else {
			dbStatus = "error: " + err.Error()
		}
	}
	writeJSON(w, 200, map[string]any{
		"status":       "ok",
		"service":      "pebisnice-backend",
		"cachedEmails": count,
		"database":     dbStatus,
	})
}

// ════════════════════════════════════════════════════════════════
// HANDLER: /webhook  (Lynk.id payment webhook)
// ════════════════════════════════════════════════════════════════
// Setup di Lynk.id dashboard:
//   Webhook URL : https://sheet-api.pebisnice.my.id/webhook
//   Event       : payment.received
//   Token       : isi bebas → set ke env var LYNK_WEBHOOK_TOKEN di Leapcell

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"success": false, "error": "method not allowed"})
		return
	}

	// Baca body sekaligus — butuh untuk signature + parsing
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "error": "gagal baca body"})
		return
	}

	// Parse payload
	var payload LynkWebhookPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "error": "invalid JSON"})
		return
	}

	// ── Validasi Signature Lynk.id ────────────────────────────
	// Formula: SHA256(grandTotal + refId + message_id + merchantKey)
	// Dikirim via header: X-Lynk-Signature
	// Catatan: Test URL dari Lynk.id dashboard tidak mengirim signature
	//          (hanya ping koneksi) → jika header kosong, anggap test ping
	merchantKey := lynkWebhookToken()
	receivedSig := r.Header.Get("X-Lynk-Signature")

	if receivedSig == "" {
		// Test ping dari Lynk.id dashboard — tidak ada signature
		log.Printf("[WEBHOOK] Test ping diterima (no signature) ✅")
		writeJSON(w, 200, map[string]any{"success": true, "note": "test ping ok"})
		return
	}

	if merchantKey != "" {
		refID     := payload.Data.MessageData.RefID
		messageID := payload.Data.MessageID
		amount    := strconv.Itoa(payload.Data.MessageData.Totals.GrandTotal)

		sigInput := amount + refID + messageID + merchantKey
		h        := sha256.New()
		h.Write([]byte(sigInput))
		expectedSig := hex.EncodeToString(h.Sum(nil))

		log.Printf("[WEBHOOK] sig_input=%q", sigInput)
		log.Printf("[WEBHOOK] expected=%s received=%s", expectedSig, receivedSig)

		if receivedSig != expectedSig {
			log.Printf("[WEBHOOK] ❌ Signature mismatch")
			writeJSON(w, 401, map[string]any{"success": false, "error": "invalid signature"})
			return
		}
		log.Printf("[WEBHOOK] ✅ Signature valid")
	}

	// Hanya proses event payment.received dengan status SUCCESS
	if payload.Event != "payment.received" {
		writeJSON(w, 200, map[string]any{"success": true, "note": "event ignored"})
		return
	}
	if payload.Data.MessageAction != "SUCCESS" {
		writeJSON(w, 200, map[string]any{"success": true, "note": "non-success payment ignored"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(payload.Data.MessageData.Customer.Email))
	if email == "" {
		writeJSON(w, 400, map[string]any{"success": false, "error": "customer email kosong"})
		return
	}

	refID := payload.Data.MessageData.RefID
	productName := ""
	if len(payload.Data.MessageData.Items) > 0 {
		productName = payload.Data.MessageData.Items[0].Title
	}

	authorizeEmail(email, refID, productName)

	log.Printf("[WEBHOOK] ✅ Pembayaran diterima — email=%s refId=%s produk=%q",
		email, refID, productName)

	writeJSON(w, 200, map[string]any{
		"success": true,
		"message": fmt.Sprintf("Email %s berhasil diotorisasi", email),
	})
}

// ════════════════════════════════════════════════════════════════
// HANDLER: /activate
// Dipanggil dari initSheets() di Google Apps Script
// Menerima email Google user + spreadsheetId
// ════════════════════════════════════════════════════════════════

func handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"success": false, "error": "method not allowed"})
		return
	}

	var req ActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "error": "invalid JSON"})
		return
	}

	// Validasi secret key (tidak dilihat buyer — ada di ClientCode.gs)
	if req.Key != secretKey() {
		writeJSON(w, 401, map[string]any{"success": false, "error": "Unauthorized"})
		return
	}

	if req.SpreadsheetId == "" || req.Email == "" {
		writeJSON(w, 400, map[string]any{"success": false, "error": "spreadsheetId dan email wajib diisi"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Cek blocklist
	if isBlocked(req.SpreadsheetId) {
		writeJSON(w, 403, map[string]any{
			"success": false,
			"error":   "Akses diblokir. Hubungi support di lynk.id/pebisnice",
		})
		return
	}

	// Cek apakah email sudah beli di Lynk.id
	record := isEmailAuthorized(email)
	if record == nil {
		log.Printf("[ACTIVATE] DENIED — email=%s spreadsheetId=%s", email, req.SpreadsheetId)
		writeJSON(w, 403, map[string]any{
			"success": false,
			"error": fmt.Sprintf(
				"Email %s belum terdaftar sebagai pembeli Pebisnice.\n\n"+
					"Pastikan kamu:\n"+
					"1. Sudah membeli di lynk.id/pebisnice\n"+
					"2. Membuka Google Sheets dengan email yang sama saat membeli\n\n"+
					"Jika sudah beli tapi masih error, hubungi @pebisnice di Instagram.",
				email,
			),
		})
		return
	}

	// Generate random token dan simpan ke DB
	token := generateToken(req.SpreadsheetId)
	if err := saveActivation(req.SpreadsheetId, email, token); err != nil {
		log.Printf("[ACTIVATE] Gagal simpan token: %v", err)
		writeJSON(w, 500, map[string]any{
			"success": false,
			"error":   "Gagal menyimpan aktivasi. Coba lagi.",
		})
		return
	}

	log.Printf("[ACTIVATE] ✅ email=%s spreadsheetId=%s", email, req.SpreadsheetId)

	writeJSON(w, 200, map[string]any{
		"success": true,
		"token":   token,
		"message": fmt.Sprintf("Aktivasi berhasil! Selamat datang di Pebisnice 🎉"),
		"buyer": map[string]any{
			"email":       record.Email,
			"productName": record.ProductName,
			"purchasedAt": record.PurchasedAt.Format("02 Jan 2006"),
		},
	})
}

// ════════════════════════════════════════════════════════════════
// HANDLER: /parse
// ════════════════════════════════════════════════════════════════

func handleParse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"success": false, "error": "method not allowed"})
		return
	}

	var req ParseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "error": "invalid JSON"})
		return
	}

	if req.Key != secretKey() {
		writeJSON(w, 401, map[string]any{"success": false, "error": "Unauthorized"})
		return
	}

	// Validasi token HMAC (stateless — tidak butuh database)
	if req.Token == "" || req.SpreadsheetId == "" {
		writeJSON(w, 401, map[string]any{
			"success": false,
			"error":   "Template belum diaktivasi. Jalankan menu ⚙️ Inisialisasi Sheet.",
		})
		return
	}

	valid, tokenEmail := validateToken(req.SpreadsheetId, req.Token)
	if !valid {
		log.Printf("[PARSE] INVALID TOKEN — spreadsheetId=%s", req.SpreadsheetId)
		writeJSON(w, 401, map[string]any{
			"success": false,
			"error":   "Lisensi tidak valid. Jalankan ulang ⚙️ Inisialisasi Sheet atau beli template asli di lynk.id/pebisnice",
		})
		return
	}
	log.Printf("[PARSE] ✅ token valid — email=%s spreadsheetId=%s", tokenEmail, req.SpreadsheetId)

	if isBlocked(req.SpreadsheetId) {
		writeJSON(w, 403, map[string]any{
			"success": false,
			"error":   "Akses diblokir. Hubungi support di lynk.id/pebisnice",
		})
		return
	}

	if req.FileBase64 == "" {
		writeJSON(w, 400, map[string]any{"success": false, "error": "fileBase64 is required"})
		return
	}

	switch req.Type {
	case "order":
		orders, uniqueOrders, warn, err := parseOrder(req.FileBase64)
		if err != nil {
			log.Printf("[ERROR] parseOrder: %v", err)
			writeJSON(w, 200, map[string]any{"success": false, "error": err.Error()})
			return
		}
		resp := map[string]any{
			"success":      true,
			"orders":       orders,
			"totalRows":    len(orders),
			"uniqueOrders": uniqueOrders,
		}
		if warn != "" {
			resp["warning"] = warn
		}
		writeJSON(w, 200, resp)

	case "income":
		inc, dari, ke, username, err := parseIncome(req.FileBase64)
		if err != nil {
			log.Printf("[ERROR] parseIncome: %v", err)
			writeJSON(w, 200, map[string]any{"success": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{
			"success":  true,
			"income":   inc,
			"dari":     dari,
			"ke":       ke,
			"username": username,
		})

	default:
		writeJSON(w, 400, map[string]any{"success": false, "error": "type harus 'order' atau 'income'"})
	}
}

// ════════════════════════════════════════════════════════════════
// HANDLER: /admin/authorize
// Tambah email manual — untuk test atau refund/re-issue
// Dilindungi SECRET_KEY — tidak bisa diakses buyer
// ════════════════════════════════════════════════════════════════

func handleAdminAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"success": false, "error": "method not allowed"})
		return
	}

	var req struct {
		Key     string `json:"key"`
		Email   string `json:"email"`
		RefID   string `json:"refId"`
		Product string `json:"product"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "error": "invalid JSON"})
		return
	}

	if req.Key != secretKey() {
		writeJSON(w, 401, map[string]any{"success": false, "error": "Unauthorized"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		writeJSON(w, 400, map[string]any{"success": false, "error": "email tidak valid"})
		return
	}

	refID   := req.RefID
	product := req.Product
	if refID == ""   { refID = "manual-add" }
	if product == "" { product = "Pebisnice Template" }

	authorizeEmail(email, refID, product)
	log.Printf("[ADMIN] Email ditambahkan manual: %s", email)

	writeJSON(w, 200, map[string]any{
		"success": true,
		"message": fmt.Sprintf("Email %s berhasil ditambahkan", email),
		"email":   email,
	})
}

// ════════════════════════════════════════════════════════════════
// MAIN
// ════════════════════════════════════════════════════════════════

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Log env check untuk debug
	log.Printf("[CONFIG] DATABASE_URL set: %v", os.Getenv("DATABASE_URL") != "")
	log.Printf("[CONFIG] SECRET_KEY set: %v", os.Getenv("SECRET_KEY") != "")
	log.Printf("[CONFIG] LYNK_WEBHOOK_TOKEN set: %v", os.Getenv("LYNK_WEBHOOK_TOKEN") != "")

	// Init Supabase PostgreSQL
	if err := initDB(); err != nil {
		log.Printf("[DB] Warning: %v — berjalan tanpa database", err)
	} else {
		loadEmailsFromDB()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health",            corsMiddleware(handleHealth))
	mux.HandleFunc("/webhook",           corsMiddleware(handleWebhook))
	mux.HandleFunc("/activate",          corsMiddleware(handleActivate))
	mux.HandleFunc("/parse",             corsMiddleware(handleParse))
	mux.HandleFunc("/admin/authorize",   corsMiddleware(handleAdminAuthorize))
	mux.HandleFunc("/",                  corsMiddleware(handleHealth))

	log.Printf("🚀 Pebisnice Backend v7 — port %s", port)
	log.Printf("   /webhook   — Lynk.id payment event")
	log.Printf("   /activate  — registrasi token (verifikasi email Lynk.id vs Google)")
	log.Printf("   /parse     — proses file xlsx")

	if lynkWebhookToken() == "" {
		log.Println("⚠️  LYNK_WEBHOOK_TOKEN tidak diset — webhook tidak terverifikasi")
	}

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server gagal: %v", err)
	}
}

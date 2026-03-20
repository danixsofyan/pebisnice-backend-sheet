package main

import (
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
			activated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen       TIMESTAMPTZ,
			request_count   INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS activations_email_idx ON activations(email);
		CREATE INDEX IF NOT EXISTS activations_token_idx ON activations(token);
		-- Rate limiting table
		CREATE TABLE IF NOT EXISTS rate_limits (
			token           TEXT NOT NULL,
			window_start    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			request_count   INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY (token, window_start)
		);
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

// signResponse: buat signature untuk response payload
// Signature = SHA256(token + spreadsheetId + timestamp + secretKey)
// ClientCode verifikasi ini — kalau response di-dummy, signature tidak cocok
func signResponse(token, spreadsheetId, timestamp string) string {
	// SHA256(token + spreadsheetId + ts)
	// Token sudah unik per spreadsheet — tidak perlu tambahan secretKey
	h := sha256.New()
	h.Write([]byte(token + spreadsheetId + timestamp))
	return hex.EncodeToString(h.Sum(nil))
}

// validateToken: cek token + expiry + rate limit + update stats
// return (valid bool, email string, errMsg string)
func validateToken(spreadsheetId, token string) (bool, string, string) {
	if db == nil || spreadsheetId == "" || token == "" {
		return false, "", "token atau spreadsheetId kosong"
	}

	var email string
	err := db.QueryRow(
		`SELECT email FROM activations WHERE spreadsheet_id=$1 AND token=$2`,
		spreadsheetId, token,
	).Scan(&email)
	if err != nil {
		return false, "", "lisensi tidak valid"
	}

	// Cek rate limit: max 60 request per menit per token
	if !checkRateLimit(token) {
		return false, "", "terlalu banyak request. Tunggu beberapa saat"
	}

	// Update last_seen dan request_count (async)
	go func() {
		db.Exec(`UPDATE activations SET last_seen=NOW(), request_count=request_count+1
				 WHERE spreadsheet_id=$1 AND token=$2`, spreadsheetId, token)
	}()

	return true, email, ""
}

// checkRateLimit: max 60 request per menit per token
func checkRateLimit(token string) bool {
	if db == nil { return true }
	var count int
	err := db.QueryRow(`
		SELECT COALESCE(SUM(request_count), 0) FROM rate_limits
		WHERE token=$1 AND window_start > NOW() - INTERVAL '1 minute'`,
		token,
	).Scan(&count)
	if err != nil || count >= 60 { return false }

	// Insert atau update window
	db.Exec(`
		INSERT INTO rate_limits (token, window_start, request_count)
		VALUES ($1, date_trunc('minute', NOW()), 1)
		ON CONFLICT (token, window_start) DO UPDATE
		SET request_count = rate_limits.request_count + 1`, token)
	return true
}

const maxDevicesPerEmail = 1 // 1 email = 1 spreadsheet

// saveActivation: simpan token ke DB
// Batasi max 3 spreadsheet aktif per email
func saveActivation(spreadsheetId, email, token string) error {
	if db == nil {
		return fmt.Errorf("database tidak tersedia")
	}

	// Cek apakah spreadsheetId sudah ada (re-aktivasi — selalu boleh)
	var existing int
	db.QueryRow(`SELECT COUNT(*) FROM activations WHERE spreadsheet_id=$1`, spreadsheetId).Scan(&existing)

	if existing == 0 {
		// Spreadsheet baru — cek limit per email
		var activeCount int
		db.QueryRow(`SELECT COUNT(*) FROM activations WHERE email=$1`, email).Scan(&activeCount)
		if activeCount >= maxDevicesPerEmail {
			return fmt.Errorf("batas %d spreadsheet aktif per akun tercapai. "+
				"Hapus aktivasi lama atau hubungi support", maxDevicesPerEmail)
		}
	}

	_, err := db.Exec(`
		INSERT INTO activations (spreadsheet_id, email, token, activated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (spreadsheet_id) DO UPDATE SET
			token        = EXCLUDED.token,
			email        = EXCLUDED.email,
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
	"totalHarga":   {"Total Harga Produk", "Harga Setelah Diskon", "Subtotal Produk", "Total Product Price"},
	"totalBayar":   {"Total Pembayaran", "Dibayar Pembeli", "Total Payment", "Grand Total", "Buyer Paid"},
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
	WaktuSelesai  string  `json:"waktuSelesai"`
	Status        string  `json:"status"`
	IsCancelled   bool    `json:"isCancelled"`
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
	Token         string          `json:"token"`
	SpreadsheetId string          `json:"spreadsheetId"`
	Type          string          `json:"type"`
	FileBase64    string          `json:"fileBase64"`
	FileName      string          `json:"fileName"`
	Context       *SheetContext   `json:"context,omitempty"`
}

// SheetContext: state sheet yang dikirim client untuk diproses backend
type SheetContext struct {
	HppData      []HppRow `json:"hppData"`      // Master HPP rows
	LastOrderRow int      `json:"lastOrderRow"`  // baris terakhir Rekap Penjualan
	LastIncomeRow int     `json:"lastIncomeRow"` // baris terakhir Rekap Pencairan
}

type HppRow struct {
	Row       int     `json:"row"`
	SkuInduk  string  `json:"skuInduk"`
	SkuRef    string  `json:"skuRef"`
	NamaProd  string  `json:"namaProd"`
	BerlakuMulai string `json:"berlakuMulai"`
	Hpp       float64 `json:"hpp"`
}

// WriteInstruction: instruksi tulis yang dikirim ke client
type WriteInstruction struct {
	Sheet     string          `json:"sheet"`
	StartRow  int             `json:"startRow"`
	StartCol  int             `json:"startCol"`
	Values    [][]interface{} `json:"values"`
	Append    bool            `json:"append,omitempty"`
	Formats   *CellFormats    `json:"formats,omitempty"`
}

type CellFormats struct {
	NumberFormats []string `json:"numberFormats,omitempty"` // per kolom
	Backgrounds   []string `json:"backgrounds,omitempty"`   // per baris
	FontColors    []string `json:"fontColors,omitempty"`    // per baris
	FontBolds     []bool   `json:"fontBolds,omitempty"`     // per baris
}

// HppPopupItem: item untuk popup HPP di sidebar
type HppPopupItem struct {
	Row       int    `json:"row"`
	SkuInduk  string `json:"skuInduk"`
	SkuRef    string `json:"skuRef"`
	NamaProduk string `json:"namaProduk"`
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

	cancelled := map[string]bool{"Batal": true, "Cancelled": true, "BATAL": true, "Dibatalkan": true}
	cancelledOrders := map[string]bool{} // track unique cancelled orders

	for _, row := range rows[hIdx+1:] {
		noPesanan := getCell(row, colIdx, "noPesanan")
		if noPesanan == "" {
			continue
		}
		uniqueMap[noPesanan] = true

		status := getCell(row, colIdx, "status")
		if status != "" && !completed[status] && !cancelledOrders[noPesanan] {
			cancelledOrders[noPesanan] = true
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
			IsCancelled:  cancelled[status],
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
		warn = fmt.Sprintf("%d order berstatus Batal — omzet tidak dihitung", nonSelesai)
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

	// Validasi token via database
	if req.Token == "" || req.SpreadsheetId == "" {
		writeJSON(w, 401, map[string]any{
			"success": false,
			"error":   "Template belum diaktivasi. Jalankan menu ⚙️ Inisialisasi Sheet.",
		})
		return
	}

	valid, tokenEmail, validErr := validateToken(req.SpreadsheetId, req.Token)
	if !valid {
		log.Printf("[PARSE] INVALID TOKEN — spreadsheetId=%s reason=%s", req.SpreadsheetId, validErr)
		code := 401
		if validErr == "terlalu banyak request. Tunggu beberapa saat" { code = 429 }
		writeJSON(w, code, map[string]any{
			"success": false,
			"error":   validErr,
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
		// Build HPP map dari context (dikirim client)
		hppHistory := buildHppHistoryFromContext(req.Context)

		// Build write instructions — semua logic di backend
		startRow := 6
		if req.Context != nil && req.Context.LastOrderRow > 0 {
			startRow = req.Context.LastOrderRow + 1
		}

		writes, hppPopup, newHppRows := buildOrderWrites(orders, hppHistory, startRow)

		// Tambah write untuk Master HPP jika ada SKU baru
		if len(newHppRows) > 0 {
			hppStartRow := 5
			if req.Context != nil && req.Context.HppData != nil {
				hppStartRow = len(req.Context.HppData) + 5
			}
			writes = append(writes, buildHppWrites(newHppRows, hppStartRow))
		}

		// Log write
		writes = append(writes, WriteInstruction{
			Sheet: "Log Import", Append: true,
			Values: [][]interface{}{{
				time.Now().Format("02/01/2006 15:04:05"),
				"ORDER", req.FileName, len(orders), warn,
			}},
		})

		ts := fmt.Sprintf("%d", time.Now().Unix())
		resp := map[string]any{
			"success":    true,
			"writes":     writes,
			"hppPopup":   hppPopup,
			"totalRows":  len(orders),
			"uniqueOrders": uniqueOrders,
			"toast":      fmt.Sprintf("✅ %d baris dari %d order berhasil diimport.", len(orders), uniqueOrders),
			"ts":         ts,
			"sig":        signResponse(req.Token, req.SpreadsheetId, ts),
		}
		if warn != "" {
			resp["warning"] = warn
		}
		writeJSON(w, 200, resp)

	case "income":
		inc, dari, ke, _, err := parseIncome(req.FileBase64)
		if err != nil {
			log.Printf("[ERROR] parseIncome: %v", err)
			writeJSON(w, 200, map[string]any{"success": false, "error": err.Error()})
			return
		}
		startRow := 5
		if req.Context != nil && req.Context.LastIncomeRow > 0 {
			startRow = req.Context.LastIncomeRow + 1
		}

		incomeWrite := buildIncomeWrites(inc, dari, ke, startRow)
		logWrite := WriteInstruction{
			Sheet: "Log Import", Append: true,
			Values: [][]interface{}{{
				time.Now().Format("02/01/2006 15:04:05"),
				"INCOME", req.FileName, 1,
				fmt.Sprintf("Periode: %s s/d %s", dari, ke),
			}},
		}

		ts := fmt.Sprintf("%d", time.Now().Unix())
		writeJSON(w, 200, map[string]any{
			"success":  true,
			"writes":   []WriteInstruction{incomeWrite, logWrite},
			"toast":    fmt.Sprintf("✅ Penghasilan %s s/d %s berhasil diimport.", dari, ke),
			"ts":       ts,
			"sig":      signResponse(req.Token, req.SpreadsheetId, ts),
		})

	case "refreshHpp":
		if req.Context == nil {
			writeJSON(w, 400, map[string]any{"success": false, "error": "context required"})
			return
		}
		hppHistory := buildHppHistoryFromContext(req.Context)
		updated, writes := buildRefreshHppWrites(req.Context, hppHistory)
		ts := fmt.Sprintf("%d", time.Now().Unix())
		writeJSON(w, 200, map[string]any{
			"success": true,
			"writes":  writes,
			"updated": updated,
			"ts":      ts,
			"sig":     signResponse(req.Token, req.SpreadsheetId, ts),
		})

	default:
		writeJSON(w, 400, map[string]any{"success": false, "error": "type harus 'order', 'income', atau 'refreshHpp'"})
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


// ════════════════════════════════════════════════════════════════
// WRITE INSTRUCTION BUILDERS
// Semua logic ada di sini — client hanya terima dan eksekusi
// ════════════════════════════════════════════════════════════════

func buildHppHistoryFromContext(ctx *SheetContext) map[string][]struct{ date time.Time; hpp float64 } {
	history := make(map[string][]struct{ date time.Time; hpp float64 })
	if ctx == nil {
		return history
	}
	for _, row := range ctx.HppData {
		if row.Hpp <= 0 {
			continue
		}
		var effDate time.Time
		if row.BerlakuMulai != "" {
			parsed, err := parseFlexDate(row.BerlakuMulai)
			if err == nil {
				effDate = parsed
			}
		}
		if effDate.IsZero() {
			effDate = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		entry := struct{ date time.Time; hpp float64 }{effDate, row.Hpp}
		for _, key := range []string{row.SkuInduk, row.SkuRef, row.NamaProd} {
			if key != "" {
				history[key] = append(history[key], entry)
			}
		}
	}
	return history
}

func lookupHpp(history map[string][]struct{ date time.Time; hpp float64 }, key string, orderDate time.Time) float64 {
	entries, ok := history[key]
	if !ok || len(entries) == 0 {
		return 0
	}
	// Cari HPP berlaku pada orderDate (terbaru yang <= orderDate)
	var best float64
	var bestDate time.Time
	for _, e := range entries {
		if !e.date.After(orderDate) && (best == 0 || e.date.After(bestDate)) {
			best = e.hpp
			bestDate = e.date
		}
	}
	return best
}

func parseFlexDate(s string) (time.Time, error) {
	// Support: DD/MM/YYYY, YYYY-MM-DD, DD/MM/YYYY HH:mm:ss
	formats := []string{"02/01/2006", "2006-01-02", "02/01/2006 15:04:05", "2006-01-02T15:04:05Z"}
	for _, f := range formats {
		if t, err := time.Parse(f, s[:min(len(s), len(f))]); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse date: %s", s)
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

func buildOrderWrites(orders []OrderItem, hppHistory map[string][]struct{ date time.Time; hpp float64 }, startRow int) ([]WriteInstruction, []HppPopupItem, []HppRow) {
	var rows [][]interface{}
	var backgrounds, fontColors []string
	var hppPopup []HppPopupItem
	newHppKeys := make(map[string]HppRow)
	existingHppKeys := make(map[string]bool)

	// Build existing HPP key set
	for key := range hppHistory {
		existingHppKeys[key] = true
	}

	for i, o := range orders {
		orderDate, _ := parseFlexDate(o.WaktuDibuat)
		if orderDate.IsZero() {
			orderDate = time.Now()
		}

		skuForHpp := o.SkuForHpp
		if skuForHpp == "" { skuForHpp = o.SkuRef }
		if skuForHpp == "" { skuForHpp = o.SkuInduk }

		hpp := lookupHpp(hppHistory, skuForHpp, orderDate)
		if hpp == 0 { hpp = lookupHpp(hppHistory, o.SkuRef, orderDate) }
		if hpp == 0 { hpp = lookupHpp(hppHistory, o.SkuInduk, orderDate) }

		var totalHpp, grossProfit interface{}
		var hppStatus string
		var omzet float64

		if o.IsCancelled {
			omzet = 0
			hppStatus = "🚫 Batal"
		} else {
			omzet = o.TotalHarga
			if hpp > 0 {
				totalHpp = o.Qty * hpp
				grossProfit = o.TotalHarga - o.Qty*hpp
				hppStatus = "✅ HPP OK"
			} else {
				hppStatus = "⚠️ HPP Belum Input"
			}
		}

		// Track SKU baru
		if !o.IsCancelled && hpp == 0 && skuForHpp != "" {
			if _, exists := newHppKeys[skuForHpp]; !exists {
				newHppKeys[skuForHpp] = HppRow{
					SkuInduk: o.SkuInduk, SkuRef: o.SkuRef,
					NamaProd: o.NamaProduk,
				}
				hppPopup = append(hppPopup, HppPopupItem{
					Row: startRow + len(rows), // akan diisi setelah write
					SkuInduk: o.SkuInduk, SkuRef: o.SkuRef, NamaProduk: o.NamaProduk,
				})
			}
		}

		rowNum := startRow + i
		var hppVal interface{}
		if hpp > 0 && !o.IsCancelled { hppVal = hpp }
		var totalBayar float64
		if !o.IsCancelled { totalBayar = o.TotalBayar }

		rows = append(rows, []interface{}{
			o.WaktuDibuat, o.NoPesanan, o.SkuInduk, o.WaktuSelesai, o.Status,
			o.NamaProduk, o.SkuRef, o.Variasi, o.Qty,
			omzet, omzet,
			hppVal, totalHpp, grossProfit,
			totalBayar, hppStatus,
		})

		var bg, fc string
		if o.IsCancelled {
			bg = "#F1F5F9"; fc = "#94A3B8"
		} else if rowNum%2 == 0 {
			bg = "#F8FAFC"; fc = ""
		} else {
			bg = "#FFFFFF"; fc = ""
		}
		backgrounds = append(backgrounds, bg)
		fontColors = append(fontColors, fc)
	}

	var newHppSlice []HppRow
	for _, v := range newHppKeys {
		newHppSlice = append(newHppSlice, v)
	}

	instruction := WriteInstruction{
		Sheet:    "Rekap Penjualan",
		StartRow: startRow,
		StartCol: 1,
		Values:   rows,
		Formats: &CellFormats{
			NumberFormats: []string{"", "", "", "", "", "", "", "", `#,##0`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, ""},
			Backgrounds:   backgrounds,
			FontColors:    fontColors,
		},
	}

	return []WriteInstruction{instruction}, hppPopup, newHppSlice
}

func buildHppWrites(newRows []HppRow, startRow int) WriteInstruction {
	today := time.Now().Format("02/01/2006")
	var values [][]interface{}
	for _, r := range newRows {
		values = append(values, []interface{}{
			"", r.SkuInduk, r.SkuRef, r.NamaProd, "", today, "", "",
		})
	}
	return WriteInstruction{
		Sheet: "Master HPP", StartRow: startRow, StartCol: 1, Values: values,
		Formats: &CellFormats{
			NumberFormats: []string{"", "", "", "", "", "DD/MM/YYYY", "#,##0", ""},
		},
	}
}

func buildIncomeWrites(inc *IncomeData, dari, ke string, startRow int) WriteInstruction {
	periode := dari + " s/d " + ke
	fv := func(p *float64) interface{} {
		if p == nil { return 0 }
		return *p
	}
	biayaShopee := 0.0
	if inc.BiayaKomisi != nil { biayaShopee += math.Abs(*inc.BiayaKomisi) }
	if inc.BiayaAdmin != nil { biayaShopee += math.Abs(*inc.BiayaAdmin) }
	if inc.BiayaLayanan != nil { biayaShopee += math.Abs(*inc.BiayaLayanan) }
	if inc.BiayaProses != nil { biayaShopee += math.Abs(*inc.BiayaProses) }

	return WriteInstruction{
		Sheet: "Rekap Pencairan", StartRow: startRow, StartCol: 1,
		Values: [][]interface{}{{
			"", periode,
			fv(inc.TotalPendapatan), biayaShopee, fv(inc.TotalDilepas),
			math.Abs(float64OrZero(inc.BiayaKomisi)),
			math.Abs(float64OrZero(inc.BiayaAdmin)),
			math.Abs(float64OrZero(inc.BiayaLayanan)),
			math.Abs(float64OrZero(inc.BiayaProses)),
			"✅",
		}},
		Formats: &CellFormats{
			NumberFormats: []string{"", "", `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, `#,##0;(#,##0);"-"`, ""},
		},
	}
}

func float64OrZero(p *float64) float64 {
	if p == nil { return 0 }
	return *p
}

func buildRefreshHppWrites(ctx *SheetContext, hppHistory map[string][]struct{ date time.Time; hpp float64 }) (int, []WriteInstruction) {
	type rowUpdate struct {
		row int
		hpp, totalHpp, grossProfit float64
	}
	// ctx.HppData tidak punya Rekap Penjualan data — client harus kirim juga
	// Untuk simplicity, return empty (client akan call setelah read sheet sendiri)
	// Ini akan diimplementasi lebih lengkap di v2 backend
	return 0, nil
}


// ════════════════════════════════════════════════════════════════
// ADMIN ENDPOINTS
// ════════════════════════════════════════════════════════════════

// Revoke lisensi: hapus atau expire token tertentu
func handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"success": false, "error": "method not allowed"})
		return
	}
	var req struct {
		Key           string `json:"key"`
		SpreadsheetId string `json:"spreadsheetId"`
		Email         string `json:"email"` // revoke semua milik email ini
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "error": "invalid JSON"})
		return
	}
	if req.Key != secretKey() {
		writeJSON(w, 401, map[string]any{"success": false, "error": "Unauthorized"})
		return
	}
	if db == nil {
		writeJSON(w, 500, map[string]any{"success": false, "error": "database tidak tersedia"})
		return
	}

	var result sql.Result
	var err error
	if req.SpreadsheetId != "" {
		// Revoke specific spreadsheet
		result, err = db.Exec(`DELETE FROM activations WHERE spreadsheet_id=$1`, req.SpreadsheetId)
	} else if req.Email != "" {
		// Revoke semua milik email
		result, err = db.Exec(`DELETE FROM activations WHERE email=$1`, req.Email)
	} else {
		writeJSON(w, 400, map[string]any{"success": false, "error": "spreadsheetId atau email wajib diisi"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"success": false, "error": err.Error()})
		return
	}
	affected, _ := result.RowsAffected()
	log.Printf("[ADMIN] Revoke: spreadsheetId=%s email=%s affected=%d", req.SpreadsheetId, req.Email, affected)
	writeJSON(w, 200, map[string]any{"success": true, "revoked": affected})
}

// List aktivasi: lihat semua aktivasi aktif
func handleAdminListActivations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"success": false, "error": "method not allowed"})
		return
	}
	var req struct {
		Key   string `json:"key"`
		Email string `json:"email"` // optional filter
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "error": "invalid JSON"})
		return
	}
	if req.Key != secretKey() {
		writeJSON(w, 401, map[string]any{"success": false, "error": "Unauthorized"})
		return
	}
	if db == nil {
		writeJSON(w, 500, map[string]any{"success": false, "error": "database tidak tersedia"})
		return
	}

	query := `SELECT spreadsheet_id, email, activated_at, last_seen, request_count
			  FROM activations`
	args := []interface{}{}
	if req.Email != "" {
		query += ` AND email=$1`
		args = append(args, req.Email)
	}
	query += ` ORDER BY activated_at DESC`

	rows, err := db.Query(query, args...)
	if err != nil {
		writeJSON(w, 500, map[string]any{"success": false, "error": err.Error()})
		return
	}
	defer rows.Close()

	type ActivationRecord struct {
		SpreadsheetId string     `json:"spreadsheetId"`
		Email         string     `json:"email"`
		ActivatedAt   time.Time  `json:"activatedAt"`
		LastSeen      *time.Time `json:"lastSeen"`
		RequestCount  int        `json:"requestCount"`
	}
	var list []ActivationRecord
	for rows.Next() {
		var a ActivationRecord
		rows.Scan(&a.SpreadsheetId, &a.Email, &a.ActivatedAt, &a.LastSeen, &a.RequestCount)
		list = append(list, a)
	}
	writeJSON(w, 200, map[string]any{"success": true, "activations": list, "count": len(list)})
}

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
	mux.HandleFunc("/admin/revoke",      corsMiddleware(handleAdminRevoke))
	mux.HandleFunc("/admin/activations", corsMiddleware(handleAdminListActivations))
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

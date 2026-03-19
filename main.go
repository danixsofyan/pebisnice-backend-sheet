package main

import (
	"crypto/hmac"
	"crypto/sha256"
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

// File JSON untuk persist authorized emails (survive Leapcell restart)
const authorizedEmailsFile = "/tmp/pb_authorized_emails.json"

// ════════════════════════════════════════════════════════════════
// AUTHORIZED EMAILS STORE
// In-memory + file persistence
// ════════════════════════════════════════════════════════════════

type PurchaseRecord struct {
	Email       string    `json:"email"`
	RefID       string    `json:"refId"`
	ProductName string    `json:"productName"`
	PurchasedAt time.Time `json:"purchasedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

var (
	emailStoreMu    sync.RWMutex
	authorizedEmails = map[string]*PurchaseRecord{} // key: email lowercase
)

// Load dari file saat startup (restore setelah restart)
func loadAuthorizedEmails() {
	data, err := os.ReadFile(authorizedEmailsFile)
	if err != nil {
		return // file belum ada, normal
	}
	emailStoreMu.Lock()
	defer emailStoreMu.Unlock()
	var records []*PurchaseRecord
	if err := json.Unmarshal(data, &records); err != nil {
		log.Printf("[STORE] Gagal load authorized emails: %v", err)
		return
	}
	now := time.Now()
	loaded := 0
	for _, r := range records {
		if r.ExpiresAt.After(now) {
			authorizedEmails[r.Email] = r
			loaded++
		}
	}
	log.Printf("[STORE] Loaded %d authorized emails from disk", loaded)
}

// Simpan ke file (dipanggil setiap kali ada perubahan)
func persistAuthorizedEmails() {
	emailStoreMu.RLock()
	records := make([]*PurchaseRecord, 0, len(authorizedEmails))
	for _, r := range authorizedEmails {
		records = append(records, r)
	}
	emailStoreMu.RUnlock()

	data, err := json.Marshal(records)
	if err != nil {
		log.Printf("[STORE] Gagal marshal emails: %v", err)
		return
	}
	if err := os.WriteFile(authorizedEmailsFile, data, 0600); err != nil {
		log.Printf("[STORE] Gagal write file: %v", err)
	}
}

// Tambah email baru dari webhook
func authorizeEmail(email, refID, productName string) {
	email = strings.ToLower(strings.TrimSpace(email))
	emailStoreMu.Lock()
	authorizedEmails[email] = &PurchaseRecord{
		Email:       email,
		RefID:       refID,
		ProductName: productName,
		PurchasedAt: time.Now(),
		ExpiresAt:   time.Now().Add(90 * 24 * time.Hour), // 90 hari
	}
	emailStoreMu.Unlock()
	log.Printf("[AUTHORIZE] email=%s refId=%s", email, refID)
	go persistAuthorizedEmails()
}

// Cek apakah email sudah beli
func isEmailAuthorized(email string) *PurchaseRecord {
	email = strings.ToLower(strings.TrimSpace(email))
	emailStoreMu.RLock()
	defer emailStoreMu.RUnlock()
	r, ok := authorizedEmails[email]
	if !ok || r.ExpiresAt.Before(time.Now()) {
		return nil
	}
	return r
}

// ════════════════════════════════════════════════════════════════
// HMAC TOKEN — stateless per spreadsheetId
// ════════════════════════════════════════════════════════════════

func generateToken(spreadsheetId string) string {
	mac := hmac.New(sha256.New, []byte(secretKey()))
	mac.Write([]byte(spreadsheetId))
	return hex.EncodeToString(mac.Sum(nil))
}

func validateToken(spreadsheetId, token string) bool {
	expected := generateToken(spreadsheetId)
	return hmac.Equal([]byte(token), []byte(expected))
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
	count := len(authorizedEmails)
	emailStoreMu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"status":           "ok",
		"service":          "pebisnice-backend",
		"authorizedEmails": count,
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
	merchantKey := lynkWebhookToken()
	if merchantKey != "" {
		receivedSig := r.Header.Get("X-Lynk-Signature")
		refID       := payload.Data.MessageData.RefID
		messageID   := payload.Data.MessageID
		amount      := strconv.Itoa(payload.Data.MessageData.Totals.GrandTotal)

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

	// Email valid → generate token HMAC(spreadsheetId)
	token := generateToken(req.SpreadsheetId)
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

	if !validateToken(req.SpreadsheetId, req.Token) {
		log.Printf("[PARSE] INVALID TOKEN — spreadsheetId=%s", req.SpreadsheetId)
		writeJSON(w, 401, map[string]any{
			"success": false,
			"error":   "Lisensi tidak valid. Jalankan ulang ⚙️ Inisialisasi Sheet atau beli template asli di lynk.id/pebisnice",
		})
		return
	}

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
// MAIN
// ════════════════════════════════════════════════════════════════

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Restore authorized emails dari disk (survive restart)
	loadAuthorizedEmails()

	mux := http.NewServeMux()
	mux.HandleFunc("/health",   corsMiddleware(handleHealth))
	mux.HandleFunc("/webhook",  corsMiddleware(handleWebhook))
	mux.HandleFunc("/activate", corsMiddleware(handleActivate))
	mux.HandleFunc("/parse",    corsMiddleware(handleParse))
	mux.HandleFunc("/",         corsMiddleware(handleHealth))

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

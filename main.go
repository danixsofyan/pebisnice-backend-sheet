package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

// ── Config ────────────────────────────────────────────────────
func secretKey() string {
	k := os.Getenv("SECRET_KEY")
	if k == "" {
		k = "pebisnice_dev_key"
	}
	return k
}

// ── Field Aliases ─────────────────────────────────────────────
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

// ── Types ─────────────────────────────────────────────────────
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

type RequestBody struct {
	Key        string `json:"key"`
	Type       string `json:"type"`
	FileBase64 string `json:"fileBase64"`
	FileName   string `json:"fileName"`
}

// ── Helpers ───────────────────────────────────────────────────
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

// ── Parse Order ───────────────────────────────────────────────
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

	// Validate critical
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
		skuRef   := getCell(row, colIdx, "skuRef")
		skuInduk := getCell(row, colIdx, "skuInduk")
		namaProd := getCell(row, colIdx, "namaProduk")

		skuForHpp := skuRef
		if skuForHpp == "" { skuForHpp = skuInduk }
		if skuForHpp == "" { skuForHpp = namaProd }

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

// ── Parse Income ──────────────────────────────────────────────
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

	// Rightmost numeric value per row → label map
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

// ── Handlers ──────────────────────────────────────────────────
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

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok", "service": "pebisnice-backend"})
}

func handleParse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"success": false, "error": "method not allowed"})
		return
	}

	var req RequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "error": "invalid JSON"})
		return
	}

	if req.Key != secretKey() {
		writeJSON(w, 401, map[string]any{"success": false, "error": "Unauthorized"})
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

// ── Main ──────────────────────────────────────────────────────
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", corsMiddleware(handleHealth))
	mux.HandleFunc("/parse",  corsMiddleware(handleParse))
	mux.HandleFunc("/",       corsMiddleware(handleHealth))

	log.Printf("🚀 Pebisnice Backend — port %s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server gagal: %v", err)
	}
}

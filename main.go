package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
)

// ── Config ────────────────────────────────────────────────────────────────────
// SECRET_KEY diambil dari environment variable — lebih aman dari hardcode
func getSecretKey() string {
	key := os.Getenv("SECRET_KEY")
	if key == "" {
		key = "pebisnice_default_key_ganti_ini" // fallback dev only
	}
	return key
}

// ── Field Aliases ─────────────────────────────────────────────────────────────
// Setiap field punya beberapa kemungkinan nama kolom di export Shopee
var orderFieldAliases = map[string][]string{
	"noPesanan":    {"No. Pesanan", "Order ID", "No Pesanan", "Nomor Pesanan"},
	"waktuDibuat":  {"Waktu Pesanan Dibuat", "Tanggal Pesanan Dibuat", "Order Date", "Waktu Pembuatan Pesanan"},
	"waktuSelesai": {"Waktu Pesanan Selesai", "Tanggal Pesanan Selesai", "Order Completion Time"},
	"status":       {"Status Pesanan", "Order Status", "Status"},
	"skuInduk":     {"SKU Induk", "Parent SKU", "SKU Utama", "Master SKU"},
	"namaProduk":   {"Nama Produk", "Product Name", "Nama Barang", "Deskripsi Produk"},
	"skuRef":       {"Nomor Referensi SKU", "SKU Reference Number", "Referensi SKU", "No. SKU", "Seller SKU"},
	"variasi":      {"Nama Variasi", "Variation Name", "Variasi", "Nama Varian"},
	"qty":          {"Jumlah", "Quantity", "Qty", "Jumlah Produk di Pesan", "Jumlah Produk"},
	"totalHarga":   {"Total Harga Produk", "Subtotal Produk", "Total Product Price", "Total Harga"},
	"totalBayar":   {"Total Pembayaran", "Total Payment", "Grand Total", "Buyer Paid"},
}

var criticalOrderFields = []string{"noPesanan", "namaProduk", "qty", "totalHarga", "totalBayar"}

var incomeLabelAliases = map[string][]string{
	"totalPendapatan":  {"1. Total Pendapatan"},
	"hargaAsli":        {"Harga Asli Produk"},
	"totalDiskon":      {"Total Diskon Produk"},
	"pengembalianDana": {"Jumlah Pengembalian Dana ke Pembeli"},
	"totalPengeluaran": {"2. Total Pengeluaran"},
	"biayaKomisi":      {"Biaya Komisi AMS"},
	"biayaAdmin":       {"Biaya Administrasi"},
	"biayaLayanan":     {"Biaya Layanan", "Biaya Layanan (termasuk PPN 11%)", "Biaya Layanan (incl. PPN 11%)"},
	"biayaProses":      {"Biaya Proses Pesanan", "Biaya Proses"},
	"totalDilepas":     {"3. Total yang Dilepas"},
}

// ── Data Types ────────────────────────────────────────────────────────────────
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

// ── Helpers ───────────────────────────────────────────────────────────────────

// strip: bersihkan apostrophe awal dan whitespace (Shopee kadang prefix dengan ')
func strip(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "'")
	return strings.TrimSpace(s)
}

// toNum: parse angka dari string, handles apostrophe prefix
func toNum(s string) (float64, bool) {
	s = strip(s)
	s = strings.ReplaceAll(s, ",", "")
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// cellStr: ambil nilai sel sebagai string bersih
func cellStr(f *excelize.File, sheet, cell string) string {
	v, _ := f.GetCellValue(sheet, cell)
	return strip(v)
}

// decodeBase64ToFile: tulis base64 ke temp file, return path
func decodeBase64ToFile(data string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("base64 decode gagal: %w", err)
	}
	tmp, err := os.CreateTemp("", "pebisnice-*.xlsx")
	if err != nil {
		return "", fmt.Errorf("tidak bisa buat temp file: %w", err)
	}
	defer tmp.Close()
	if _, err := tmp.Write(raw); err != nil {
		return "", fmt.Errorf("tidak bisa tulis temp file: %w", err)
	}
	return tmp.Name(), nil
}

// openXlsx: decode base64 dan buka sebagai excelize
func openXlsx(base64Data string) (*excelize.File, string, error) {
	path, err := decodeBase64ToFile(base64Data)
	if err != nil {
		return nil, "", err
	}
	f, err := excelize.OpenFile(path)
	if err != nil {
		os.Remove(path)
		return nil, "", fmt.Errorf("tidak bisa buka file xlsx: %w", err)
	}
	return f, path, nil
}

// getAllRows: ambil semua baris dari sheet pertama
func getAllRows(f *excelize.File) ([][]string, error) {
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("file tidak punya sheet")
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, fmt.Errorf("tidak bisa baca rows: %w", err)
	}
	// Strip apostrophe dari semua sel
	for i, row := range rows {
		for j, cell := range row {
			rows[i][j] = strip(cell)
		}
	}
	return rows, nil
}

// findHeaderRow: cari baris header dengan mencocokkan nama field primer
func findHeaderRow(rows [][]string) (int, error) {
	primaryNames := make(map[string]bool)
	for _, aliases := range orderFieldAliases {
		primaryNames[aliases[0]] = true
	}

	for i, row := range rows {
		if i >= 10 {
			break
		}
		hits := 0
		for _, cell := range row {
			if primaryNames[cell] {
				hits++
			}
		}
		if hits >= 3 {
			return i, nil
		}
	}
	return -1, fmt.Errorf("baris header tidak ditemukan. Pastikan file adalah export Order Shopee")
}

// buildColIndex: buat map fieldKey → index kolom menggunakan alias matching
func buildColIndex(headers []string) map[string]int {
	colIdx := make(map[string]int)
	for field, aliases := range orderFieldAliases {
		colIdx[field] = -1
		for _, alias := range aliases {
			for i, h := range headers {
				if h == alias {
					colIdx[field] = i
					goto nextField
				}
			}
		}
	nextField:
	}
	return colIdx
}

// getCell: ambil nilai dari row berdasarkan field key
func getCell(row []string, colIdx map[string]int, field string) string {
	idx, ok := colIdx[field]
	if !ok || idx < 0 || idx >= len(row) {
		return ""
	}
	return strip(row[idx])
}

// detectRibuan: deteksi apakah nilai dalam ribuan Rupiah (×1000)
// Shopee export harga dalam ribuan: 35 = Rp 35.000
func detectRibuan(rows [][]string, headerIdx int, totalHargaCol int) bool {
	if totalHargaCol < 0 {
		return true // default assume ribuan
	}
	var samples []float64
	for i := headerIdx + 1; i < len(rows) && len(samples) < 20; i++ {
		if totalHargaCol >= len(rows[i]) {
			continue
		}
		n, ok := toNum(rows[i][totalHargaCol])
		if ok && n > 0 {
			samples = append(samples, n)
		}
	}
	if len(samples) == 0 {
		return true
	}
	sort.Float64s(samples)
	median := samples[len(samples)/2]
	return median < 1000 // jika median < 1000 → kemungkinan besar ribuan
}

// ── Parse Order ───────────────────────────────────────────────────────────────
func parseOrder(base64Data string) ([]OrderItem, int, string, error) {
	f, path, err := openXlsx(base64Data)
	if err != nil {
		return nil, 0, "", err
	}
	defer f.Close()
	defer os.Remove(path)

	rows, err := getAllRows(f)
	if err != nil {
		return nil, 0, "", err
	}

	headerIdx, err := findHeaderRow(rows)
	if err != nil {
		return nil, 0, "", err
	}

	headers := rows[headerIdx]
	colIdx := buildColIndex(headers)

	// Validasi critical columns
	var missingCols []string
	for _, field := range criticalOrderFields {
		if idx, ok := colIdx[field]; !ok || idx < 0 {
			missingCols = append(missingCols, field)
		}
	}
	if len(missingCols) > 0 {
		return nil, 0, "", fmt.Errorf("kolom penting tidak ditemukan: %s", strings.Join(missingCols, ", "))
	}

	multiplyK := detectRibuan(rows, headerIdx, colIdx["totalHarga"])
	multiplier := 1.0
	if multiplyK {
		multiplier = 1000.0
	}

	statusCompleted := map[string]bool{
		"Selesai": true, "Completed": true, "Complete": true,
		"SELESAI": true, "selesai": true,
	}

	var orders []OrderItem
	nonSelesai := 0

	for _, row := range rows[headerIdx+1:] {
		noPesanan := getCell(row, colIdx, "noPesanan")
		if noPesanan == "" {
			continue
		}

		status := getCell(row, colIdx, "status")
		if status != "" && !statusCompleted[status] {
			nonSelesai++
		}

		qty, _ := toNum(getCell(row, colIdx, "qty"))
		totalHarga, _ := toNum(getCell(row, colIdx, "totalHarga"))
		totalBayar, _ := toNum(getCell(row, colIdx, "totalBayar"))

		skuRef   := getCell(row, colIdx, "skuRef")
		skuInduk := getCell(row, colIdx, "skuInduk")
		namaProd := getCell(row, colIdx, "namaProduk")

		// Fallback chain untuk HPP lookup
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
			TotalHarga:   math.Round(totalHarga*multiplier*100) / 100,
			TotalBayar:   math.Round(totalBayar*multiplier*100) / 100,
		})
	}

	if len(orders) == 0 {
		return nil, 0, "", fmt.Errorf("tidak ada data order ditemukan")
	}

	// Hitung unique orders
	uniqueMap := make(map[string]bool)
	for _, o := range orders {
		uniqueMap[o.NoPesanan] = true
	}

	warning := ""
	if nonSelesai > 0 {
		warning = fmt.Sprintf("%d order dengan status bukan Selesai ikut terimport.", nonSelesai)
	}

	return orders, len(uniqueMap), warning, nil
}

// ── Parse Income ──────────────────────────────────────────────────────────────
func parseIncome(base64Data string) (*IncomeData, string, string, string, error) {
	f, path, err := openXlsx(base64Data)
	if err != nil {
		return nil, "", "", "", err
	}
	defer f.Close()
	defer os.Remove(path)

	rows, err := getAllRows(f)
	if err != nil {
		return nil, "", "", "", err
	}

	// Build label map: setiap label di row → rightmost numeric value di row yang sama
	// Ini handle format 4-kolom (2025) dan 2-kolom (2026) sekaligus
	labelNumMap := make(map[string]float64)
	labelStrMap := make(map[string]string)

	for _, row := range rows {
		// Cari nilai numerik paling kanan di row ini
		rightmostNum := math.NaN()
		for ci := len(row) - 1; ci >= 0; ci-- {
			if n, ok := toNum(row[ci]); ok {
				rightmostNum = n
				break
			}
		}

		// Map setiap label text di row ini ke nilai numerik tersebut
		for ci, cell := range row {
			label := strip(cell)
			if label == "" || len(label) < 2 {
				continue
			}
			if !math.IsNaN(rightmostNum) {
				labelNumMap[label] = rightmostNum
			}
			// Juga map ke nilai string berikutnya (untuk Dari, ke, Username)
			if ci+1 < len(row) {
				nextVal := strip(row[ci+1])
				if nextVal != "" {
					if _, isNum := toNum(nextVal); !isNum {
						labelStrMap[label] = nextVal
					}
				}
			}
		}
	}

	// Lookup dengan alias
	lookupNum := func(primaryLabel string) *float64 {
		aliases := incomeLabelAliases[primaryLabel]
		for _, alias := range aliases {
			if v, ok := labelNumMap[alias]; ok {
				result := v
				return &result
			}
		}
		return nil
	}

	income := &IncomeData{
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

	if income.TotalDilepas == nil && income.TotalPendapatan == nil {
		return nil, "", "", "", fmt.Errorf(
			"data penghasilan tidak ditemukan. Pastikan file adalah Laporan Penghasilan Shopee")
	}

	dari     := labelStrMap["Dari"]
	ke       := labelStrMap["ke"]
	username := labelStrMap["Username (Penjual)"]

	return income, dari, ke, username, nil
}

// ── Middleware ────────────────────────────────────────────────────────────────
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body RequestBody
		// Peek at body to get key
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid request body"})
			c.Abort()
			return
		}
		if body.Key != getSecretKey() {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Unauthorized"})
			c.Abort()
			return
		}
		// Store parsed body so handler can use it
		c.Set("body", body)
		c.Next()
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────
func handleParse(c *gin.Context) {
	body, _ := c.Get("body")
	req := body.(RequestBody)

	if req.FileBase64 == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "fileBase64 is required"})
		return
	}

	switch req.Type {
	case "order":
		orders, uniqueOrders, warning, err := parseOrder(req.FileBase64)
		if err != nil {
			log.Printf("[ERROR] parseOrder: %v", err)
			c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
			return
		}
		resp := gin.H{
			"success":      true,
			"orders":       orders,
			"totalRows":    len(orders),
			"uniqueOrders": uniqueOrders,
		}
		if warning != "" {
			resp["warning"] = warning
		}
		c.JSON(http.StatusOK, resp)

	case "income":
		income, dari, ke, username, err := parseIncome(req.FileBase64)
		if err != nil {
			log.Printf("[ERROR] parseIncome: %v", err)
			c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"income":   income,
			"dari":     dari,
			"ke":       ke,
			"username": username,
		})

	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "type harus 'order' atau 'income'"})
	}
}

func handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "pebisnice-backend"})
}

// ── Main ──────────────────────────────────────────────────────────────────────
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Production mode jika PORT di-set (Leapcell selalu set PORT)
	if os.Getenv("PORT") != "" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// CORS — izinkan request dari Google Apps Script
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	r.GET("/health", handleHealth)
	r.POST("/parse", authMiddleware(), handleParse)

	// Redirect root ke health untuk mudah cek status
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/health")
	})

	log.Printf("🚀 Pebisnice Backend running on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server gagal start: %v", err)
	}
}

// ── File reader helper untuk excelize ─────────────────────────────────────────
// excelize butuh io.ReadSeeker, helper ini convert file path
func openFileAsReader(path string) (io.ReadSeekCloser, error) {
	return os.Open(path)
}

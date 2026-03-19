-- ============================================================
-- Pebisnice — Supabase Schema
-- Jalankan di: Supabase Dashboard → SQL Editor
-- ============================================================

-- Tabel utama: data pembelian dari Lynk.id
CREATE TABLE IF NOT EXISTS purchases (
    id          SERIAL PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,       -- email buyer (lowercase)
    ref_id      TEXT,                       -- refId dari Lynk.id (bukti transaksi)
    product     TEXT,                       -- nama produk yang dibeli
    bought_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index untuk lookup cepat by email
CREATE INDEX IF NOT EXISTS purchases_email_idx ON purchases(email);

-- ============================================================
-- OPTIONAL: View untuk monitoring di Supabase dashboard
-- ============================================================
CREATE OR REPLACE VIEW purchases_summary AS
SELECT
    COUNT(*)                                          AS total_buyers,
    COUNT(*) FILTER (WHERE bought_at > NOW() - INTERVAL '7 days')  AS buyers_last_7d,
    COUNT(*) FILTER (WHERE bought_at > NOW() - INTERVAL '30 days') AS buyers_last_30d,
    MIN(bought_at)                                    AS first_purchase,
    MAX(bought_at)                                    AS latest_purchase
FROM purchases;

-- ============================================================
-- OPTIONAL: Tambah email manual (untuk test atau buyer lama)
-- Ganti 'email@gmail.com' dengan email yang ingin didaftarkan
-- ============================================================
-- INSERT INTO purchases (email, ref_id, product)
-- VALUES ('email@gmail.com', 'manual-add', 'Pebisnice Template')
-- ON CONFLICT (email) DO NOTHING;

-- ============================================================
-- Cek data yang sudah masuk
-- ============================================================
-- SELECT * FROM purchases ORDER BY bought_at DESC LIMIT 20;
-- SELECT * FROM purchases_summary;

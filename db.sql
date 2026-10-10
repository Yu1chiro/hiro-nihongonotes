-- Nihongo Notes - Schema untuk Neon DB (PostgreSQL)
-- Jalankan di Neon SQL Editor

CREATE TABLE IF NOT EXISTS notes (
  id          BIGSERIAL PRIMARY KEY,
  pattern     VARCHAR(255) NOT NULL,                       -- Pola kalimat yang dipelajari hari ini
  note_date   DATE NOT NULL DEFAULT ((now() AT TIME ZONE 'Asia/Makassar')::date),
  description TEXT NOT NULL,                               -- HTML dari Quill
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS links (
  id          BIGSERIAL PRIMARY KEY,
  name        VARCHAR(255) NOT NULL,                       -- Name link
  url         TEXT NOT NULL,                               -- Link (http/https)
  link_date   DATE NOT NULL DEFAULT ((now() AT TIME ZONE 'Asia/Makassar')::date),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notes_date ON notes (note_date DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_links_date ON links (link_date DESC, id DESC);
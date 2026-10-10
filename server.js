require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const { DATABASE_URL, PIN, JWT_SECRET } = process.env;
const PORT = process.env.PORT || 3000;
if (!DATABASE_URL || !PIN || !JWT_SECRET) {
  console.error('ENV belum lengkap: DATABASE_URL, PIN, JWT_SECRET wajib diisi di .env');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// Header ringan (tanpa helmet, tidak memblokir CDN)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});

/* ---------- AUTH (PIN + JWT cookie httpOnly) ---------- */
const COOKIE = 'nn_token';
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const attempts = new Map();
const WINDOW = 15 * 60 * 1000;
const MAX_TRY = 5;

function loginLimiter(req, res, next) {
  const now = Date.now();
  let a = attempts.get(req.ip) || { n: 0, t: now };
  if (now - a.t > WINDOW) a = { n: 0, t: now };
  attempts.set(req.ip, a);
  if (a.n >= MAX_TRY) return res.status(429).json({ message: 'Terlalu banyak percobaan. Coba lagi 15 menit lagi.' });
  req.attempt = a;
  next();
}

function auth(req, res, next) {
  try {
    req.user = jwt.verify(req.cookies[COOKIE], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Silakan masukkan PIN.' });
  }
}

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const pin = String((req.body && req.body.pin) || '');
  if (!crypto.timingSafeEqual(sha(pin), sha(PIN))) {
    req.attempt.n++;
    return res.status(401).json({ message: 'PIN salah.' });
  }
  attempts.delete(req.ip);
  const token = jwt.sign({ sub: 'owner' }, JWT_SECRET, { expiresIn: '12h' });
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 12 * 60 * 60 * 1000,
  });
  res.json({ ok: true });
});
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE);
  res.json({ ok: true });
});
app.get('/api/auth/me', auth, (req, res) => res.json({ ok: true }));

/* ---------- VALIDASI ---------- */
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const isDate = (s) => DATE_RE.test(s) && !isNaN(new Date(s + 'T00:00:00Z'));
const stripDangerous = (h) =>
  String(h)
    .replace(/<\s*(script|iframe|object|embed)[\s\S]*?<\/\s*\1\s*>/gi, '')
    .replace(/<\s*(script|iframe|object|embed)[^>]*>/gi, '')
    .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/javascript:/gi, '');

const resources = {
  notes: {
    table: 'notes',
    dateCol: 'note_date',
    fields: ['pattern', 'note_date', 'description'],
    select: `id, pattern, to_char(note_date,'YYYY-MM-DD') AS note_date, description, created_at, updated_at`,
    clean(b = {}) {
      const pattern = String(b.pattern || '').trim();
      const description = stripDangerous(b.description || '');
      if (!pattern || pattern.length > 255) return { error: 'Pola kalimat wajib diisi (maks 255 karakter).' };
      if (!isDate(b.note_date)) return { error: 'Tanggal tidak valid.' };
      if (!description.replace(/<[^>]*>/g, '').trim() && !/<img/i.test(description)) return { error: 'Deskripsi wajib diisi.' };
      if (description.length > 500000) return { error: 'Deskripsi terlalu panjang.' };
      return { values: [pattern, b.note_date, description] };
    },
  },
  links: {
    table: 'links',
    dateCol: 'link_date',
    fields: ['name', 'url', 'link_date'],
    select: `id, name, url, to_char(link_date,'YYYY-MM-DD') AS link_date, created_at, updated_at`,
    clean(b = {}) {
      const name = String(b.name || '').trim();
      const url = String(b.url || '').trim();
      if (!name || name.length > 255) return { error: 'Nama link wajib diisi (maks 255 karakter).' };
      try {
        const u = new URL(url);
        if (!['http:', 'https:'].includes(u.protocol)) throw 0;
      } catch {
        return { error: 'Link harus berupa URL http/https yang valid.' };
      }
      if (!isDate(b.link_date)) return { error: 'Tanggal tidak valid.' };
      return { values: [name, url, b.link_date] };
    },
  },
};

const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const validId = (req, res, next) => {
  if (!/^\d{1,18}$/.test(req.params.id)) return res.status(400).json({ message: 'ID tidak valid.' });
  next();
};

/* ---------- API CRUD ---------- */
for (const [name, r] of Object.entries(resources)) {
  const base = `/api/${name}`;

  app.get(base, auth, wrap(async (req, res) => {
    const { rows } = await pool.query(`SELECT ${r.select} FROM ${r.table} ORDER BY ${r.dateCol} DESC, id DESC`);
    res.json(rows);
  }));

  app.get(`${base}/:id`, auth, validId, wrap(async (req, res) => {
    const { rows } = await pool.query(`SELECT ${r.select} FROM ${r.table} WHERE id=$1`, [req.params.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json(rows[0]);
  }));

  app.post(base, auth, wrap(async (req, res) => {
    const c = r.clean(req.body);
    if (c.error) return res.status(400).json({ message: c.error });
    const ph = c.values.map((_, i) => `$${i + 1}`).join(',');
    const { rows } = await pool.query(
      `INSERT INTO ${r.table} (${r.fields.join(',')}) VALUES (${ph}) RETURNING ${r.select}`, c.values);
    res.status(201).json(rows[0]);
  }));

  app.put(`${base}/:id`, auth, validId, wrap(async (req, res) => {
    const c = r.clean(req.body);
    if (c.error) return res.status(400).json({ message: c.error });
    const set = r.fields.map((f, i) => `${f}=$${i + 1}`).join(',');
    const { rows } = await pool.query(
      `UPDATE ${r.table} SET ${set}, updated_at=now() WHERE id=$${c.values.length + 1} RETURNING ${r.select}`,
      [...c.values, req.params.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json(rows[0]);
  }));

  app.delete(`${base}/:id`, auth, validId, wrap(async (req, res) => {
    const { rowCount } = await pool.query(`DELETE FROM ${r.table} WHERE id=$1`, [req.params.id]);
    if (!rowCount) return res.status(404).json({ message: 'Data tidak ditemukan.' });
    res.json({ ok: true });
  }));
}

app.use('/api', (req, res) => res.status(404).json({ message: 'Endpoint tidak ditemukan.' }));

/* ---------- ROUTE VIEW ---------- */
const view = (file) => (req, res) => res.sendFile(path.join(__dirname, 'public', file));
app.get(['/', '/index.html'], view('index.html'));
app.get(['/list-notes', '/list-notes.html'], view('list-notes.html'));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Terjadi kesalahan pada server.' });
});

app.listen(PORT, () => console.log(`Nihongo Notes berjalan di http://localhost:${PORT}`));
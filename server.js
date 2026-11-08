require('dotenv').config();
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { rateLimit } = require('express-rate-limit');

const app = express();
const port = Number(process.env.PORT || 3000);
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('Set SESSION_SECRET to a random secret of at least 32 characters.');
}
if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD_HASH) {
  throw new Error('Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH. See README.md.');
}

const db = new sqlite3.Database(path.join(dataDir, 'app.sqlite'));
const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (error) { if (error) reject(error); else resolve(this); });
});
const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (error, row) => { if (error) reject(error); else resolve(row); });
});
const all = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (error, rows) => { if (error) reject(error); else resolve(rows); });
});

async function initializeDatabase() {
  await run(`CREATE TABLE IF NOT EXISTS call_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1), enabled INTEGER NOT NULL DEFAULT 0,
    destination TEXT NOT NULL DEFAULT '', condition TEXT NOT NULL DEFAULT 'always', updated_at TEXT NOT NULL
  )`);
  await run(`INSERT OR IGNORE INTO call_settings (id, enabled, destination, condition, updated_at)
    VALUES (1, 0, '', 'always', ?)` , [new Date().toISOString()]);
  await run(`CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, created_at TEXT NOT NULL
  )`);
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"]
} } }));
app.use(express.json({ limit: '10kb' }));
app.use(session({
  name: 'mr_anon_admin',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir, table: 'sessions', concurrentDB: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(__dirname, { index: 'index.html', dotfiles: 'deny', maxAge: '1h' }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many sign-in attempts. Try again later.' } });
function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function requireAuth(req, res, next) {
  if (!req.session.admin) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function requireCsrf(req, res, next) {
  const supplied = req.get('X-CSRF-Token') || '';
  if (!req.session.csrfToken || !safeEqual(supplied, req.session.csrfToken)) {
    return res.status(403).json({ error: 'Security token expired. Refresh and try again.' });
  }
  next();
}
async function record(action) {
  await run('INSERT INTO audit_events (action, created_at) VALUES (?, ?)', [action, new Date().toISOString()]);
  await run('DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT 50)');
}

app.get('/api/csrf', (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.set('Cache-Control', 'no-store').json({ csrfToken: req.session.csrfToken });
});
app.get('/api/me', (req, res) => res.json({ authenticated: Boolean(req.session.admin) }));
app.post('/api/login', loginLimiter, requireCsrf, async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string' || username.length > 80 || password.length > 200) {
      return res.status(400).json({ error: 'Enter your username and password.' });
    }
    const [usernameMatches, passwordMatches] = await Promise.all([
      Promise.resolve(safeEqual(username, process.env.ADMIN_USERNAME)),
      bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH)
    ]);
    if (!usernameMatches || !passwordMatches) return res.status(401).json({ error: 'Incorrect username or password.' });
    req.session.regenerate((error) => {
      if (error) return next(error);
      req.session.admin = true;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.save(async (saveError) => {
        if (saveError) return next(saveError);
        try { await record('Administrator signed in'); } catch (e) { console.error('Audit write failed:', e.message); }
        res.json({ ok: true });
      });
    });
  } catch (error) { next(error); }
});
app.post('/api/logout', requireAuth, requireCsrf, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie('mr_anon_admin', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
    res.json({ ok: true });
  });
});
app.get('/api/settings', requireAuth, async (req, res, next) => {
  try {
    const row = await get('SELECT enabled, destination, condition, updated_at FROM call_settings WHERE id = 1');
    res.set('Cache-Control', 'no-store').json({ call: { enabled: Boolean(row.enabled), destination: row.destination, condition: row.condition, updatedAt: row.updated_at }, providerConnected: false });
  } catch (error) { next(error); }
});
app.put('/api/settings/call', requireAuth, requireCsrf, async (req, res, next) => {
  try {
    const { enabled, destination, condition } = req.body || {};
    const allowedConditions = new Set(['always', 'busy', 'unanswered', 'unreachable']);
    if (typeof enabled !== 'boolean' || typeof destination !== 'string' || destination.length > 30 || !allowedConditions.has(condition)) {
      return res.status(400).json({ error: 'Invalid call preference.' });
    }
    const normalized = destination.replace(/[\s()-]/g, '');
    if (enabled && !/^\+[1-9]\d{7,14}$/.test(normalized)) {
      return res.status(400).json({ error: 'Enter a valid international destination number.' });
    }
    const updatedAt = new Date().toISOString();
    await run('UPDATE call_settings SET enabled = ?, destination = ?, condition = ?, updated_at = ? WHERE id = 1', [enabled ? 1 : 0, normalized, condition, updatedAt]);
    await record(enabled ? 'Call forwarding preference enabled (not applied to carrier)' : 'Call forwarding preference disabled (not applied to carrier)');
    res.json({ ok: true, call: { enabled, destination: normalized, condition, updatedAt }, providerConnected: false });
  } catch (error) { next(error); }
});
app.get('/api/audit', requireAuth, async (req, res, next) => {
  try {
    const events = await all('SELECT action, created_at AS createdAt FROM audit_events ORDER BY id DESC LIMIT 20');
    res.set('Cache-Control', 'no-store').json({ events });
  } catch (error) { next(error); }
});

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: 'Server error. Check server logs.' });
});

initializeDatabase().then(() => {
  app.listen(port, () => console.log(`Admin panel listening on http://localhost:${port}`));
}).catch((error) => {
  console.error('Could not initialize database:', error);
  process.exit(1);
});

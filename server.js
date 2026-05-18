/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                    Work Pro - Pi Network Freelance Marketplace            ║
 * ║                        Complete Backend Server                            ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 *  Tech Stack: Express.js, SQLite3, node-fetch, cors
 *  Auth: Pi Network accessToken verification via api.minepi.com/v2/me
 */
console.log('[Server] v203 boot starting...');

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const fetch = require('node-fetch');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const PI_API_KEY = process.env.PI_API_KEY;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || process.env.WORKPRO_API_ACCESS;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';
const NODE_ENV = process.env.NODE_ENV || 'production';
const IS_SANDBOX = process.env.PI_SANDBOX === 'true' || !PI_API_KEY;

// ─── Rate Limiting ──────────────────────────────────────────────
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 100;
const PAYMENT_RATE_LIMIT_MAX = 30; // increased for sandbox testing

// Cleanup old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitMap.entries()) {
    if (now > v.resetTime) rateLimitMap.delete(k);
  }
}, 5 * 60 * 1000);

function rateLimit(req, res, next) {
  // Use x-forwarded-for for Render proxy, fallback to connection remoteAddress
  const forwarded = req.headers['x-forwarded-for'];
  const key = (forwarded ? forwarded.split(',')[0].trim() : null) || req.connection?.remoteAddress || req.ip || 'unknown';
  const now = Date.now();
  const isPaymentEndpoint = req.path && (req.path.includes('/payments') || req.path.includes('/connects'));
  const limit = isPaymentEndpoint ? PAYMENT_RATE_LIMIT_MAX : RATE_LIMIT_MAX;

  const entry = rateLimitMap.get(key) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
  if (now > entry.resetTime) {
    entry.count = 0;
    entry.resetTime = now + RATE_LIMIT_WINDOW;
  }
  entry.count++;
  rateLimitMap.set(key, entry);

  if (entry.count > limit) {
    return res.status(429).json({ error: 'Too many requests, please try again later' });
  }
  next();
}

// ─── Body Parsers ───────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ─── CORS ───────────────────────────────────────────────────────
const corsOrigins = NODE_ENV === 'production'
  ? [FRONTEND_URL, 'https://cherry19899.github.io']
  : [FRONTEND_URL, 'https://cherry19899.github.io', 'http://localhost:5173', 'http://localhost:3000'];

app.use(cors({
  origin: corsOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-pi-token'],
}));
app.use(rateLimit);

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ─── Static Assets (CORS-enabled for GitHub Pages) ─────────────
app.use('/assets', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Cache-Control', 'public, max-age=60');
  next();
}, express.static(path.join(__dirname, 'assets')));

// ─── SQLite Database ────────────────────────────────────────────
const dbPath = process.env.DB_PATH || '/var/data/workpro.db';
const dbDir = path.dirname(dbPath);

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath);
// NOTE: db.serialize() REMOVED — it serializes ALL operations causing massive
// bottlenecks under concurrent load. WAL mode + busy_timeout handles concurrency.
db.run('PRAGMA busy_timeout = 15000'); // 15s wait before returning BUSY
db.run('PRAGMA journal_mode = WAL'); // Write-Ahead Logging for better concurrency

// ─── ALL CREATE TABLE STATEMENTS (from schema.sql) ──────────────
const SCHEMA_SQL = `
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 10000;

-- 1. USERS
CREATE TABLE IF NOT EXISTS users (
  id                TEXT PRIMARY KEY,
  username          TEXT NOT NULL,
  role              TEXT DEFAULT 'freelancer',
  balance_connects  INTEGER DEFAULT 0,
  balance_pi        REAL DEFAULT 0,
  rating            REAL DEFAULT 0,
  total_jobs_posted INTEGER DEFAULT 0,
  total_jobs_completed INTEGER DEFAULT 0,
  bio               TEXT,
  skills            TEXT,
  kyc_verified      INTEGER DEFAULT 0,
  availability      TEXT DEFAULT 'available',
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- v88: Add avatar column if not exists
-- This is handled conditionally in code below

-- 2. JOBS
CREATE TABLE IF NOT EXISTS jobs (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  title             TEXT NOT NULL,
  description       TEXT,
  category          TEXT DEFAULT 'other',
  budget            REAL DEFAULT 0,
  connects_spent    INTEGER DEFAULT 0,
  skills            TEXT,
  images            TEXT,
  deadline          TEXT,
  status            TEXT DEFAULT 'open',
  posted_by         TEXT NOT NULL,
  posted_by_name    TEXT,
  applications      INTEGER DEFAULT 0,
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (posted_by) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. APPLICATIONS
CREATE TABLE IF NOT EXISTS applications (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id            INTEGER NOT NULL,
  user_id           TEXT NOT NULL,
  username          TEXT,
  message           TEXT,
  bid_amount        REAL,
  status            TEXT DEFAULT 'pending',
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4. CHAT_ROOMS
CREATE TABLE IF NOT EXISTS chat_rooms (
  id                TEXT PRIMARY KEY,
  job_id            INTEGER,
  user1_id          TEXT NOT NULL,
  user2_id          TEXT NOT NULL,
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE SET NULL,
  FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 5. CHAT_MESSAGES
CREATE TABLE IF NOT EXISTS chat_messages (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id           TEXT NOT NULL,
  sender_id         TEXT NOT NULL,
  sender_name       TEXT,
  message           TEXT NOT NULL,
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 6. ESCROWS
CREATE TABLE IF NOT EXISTS escrows (
  id                TEXT PRIMARY KEY,
  job_id            INTEGER NOT NULL,
  client_id         TEXT NOT NULL,
  freelancer_id     TEXT,
  amount            REAL NOT NULL,
  status            TEXT DEFAULT 'pending',
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  funded_at         DATETIME,
  released_at       DATETIME,
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (freelancer_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 7. ESCROW_MESSAGES
CREATE TABLE IF NOT EXISTS escrow_messages (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  escrow_id         TEXT NOT NULL,
  sender_id         TEXT NOT NULL,
  sender_name       TEXT,
  message           TEXT NOT NULL,
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (escrow_id) REFERENCES escrows(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 8. REVIEWS
CREATE TABLE IF NOT EXISTS reviews (
  id                TEXT PRIMARY KEY,
  reviewer_id       TEXT NOT NULL,
  reviewer_name     TEXT,
  target_id         TEXT NOT NULL,
  target_name       TEXT,
  job_id            TEXT,
  job_title         TEXT,
  rating            INTEGER NOT NULL,
  text              TEXT,
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (target_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 9. PAYMENTS
CREATE TABLE IF NOT EXISTS payments (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL,
  username          TEXT,
  amount            REAL NOT NULL,
  memo              TEXT,
  status            TEXT DEFAULT 'pending',
  txid              TEXT,
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at      DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 10. CONNECTS_PURCHASES
CREATE TABLE IF NOT EXISTS connects_purchases (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id           TEXT NOT NULL,
  amount            INTEGER NOT NULL,
  pi_amount         REAL NOT NULL,
  payment_id        TEXT,
  status            TEXT DEFAULT 'pending',
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (payment_id) REFERENCES payments(id) ON DELETE SET NULL
);

-- 11. OFFERS
CREATE TABLE IF NOT EXISTS offers (
  id                TEXT PRIMARY KEY,
  client_id         TEXT NOT NULL,
  client_name       TEXT,
  freelancer_id     TEXT NOT NULL,
  freelancer_name   TEXT,
  job_id            TEXT,
  job_title         TEXT,
  amount            REAL DEFAULT 0,
  message           TEXT,
  status            TEXT DEFAULT 'pending',
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (freelancer_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 12. NOTIFICATIONS
-- Notifications table (v88: add if not exists)
CREATE TABLE IF NOT EXISTS notifications (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL,
  type              TEXT NOT NULL,
  title             TEXT NOT NULL,
  message           TEXT NOT NULL,
  related_id        TEXT,
  related_type      TEXT,
  is_read           INTEGER DEFAULT 0,
  created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at DESC);

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_txid ON payments(txid);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_jobs_posted_by ON jobs(posted_by);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_category ON jobs(category);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_applications_job ON applications(job_id);
CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_chat_rooms_job ON chat_rooms(job_id);
CREATE INDEX IF NOT EXISTS idx_chat_rooms_user1 ON chat_rooms(user1_id);
CREATE INDEX IF NOT EXISTS idx_chat_rooms_user2 ON chat_rooms(user2_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_room ON chat_messages(room_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_sender ON chat_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_created ON chat_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_escrows_job ON escrows(job_id);
CREATE INDEX IF NOT EXISTS idx_escrows_client ON escrows(client_id);
CREATE INDEX IF NOT EXISTS idx_escrows_freelancer ON escrows(freelancer_id);
CREATE INDEX IF NOT EXISTS idx_escrows_status ON escrows(status);
CREATE INDEX IF NOT EXISTS idx_escrow_messages_escrow ON escrow_messages(escrow_id);
CREATE INDEX IF NOT EXISTS idx_escrow_messages_sender ON escrow_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_reviews_reviewer ON reviews(reviewer_id);
CREATE INDEX IF NOT EXISTS idx_reviews_target ON reviews(target_id);
CREATE INDEX IF NOT EXISTS idx_reviews_target_name ON reviews(target_name);
CREATE INDEX IF NOT EXISTS idx_reviews_job ON reviews(job_id);
CREATE INDEX IF NOT EXISTS idx_reviews_rating ON reviews(rating);
CREATE INDEX IF NOT EXISTS idx_connects_user ON connects_purchases(user_id);
CREATE INDEX IF NOT EXISTS idx_connects_payment ON connects_purchases(payment_id);
CREATE INDEX IF NOT EXISTS idx_connects_status ON connects_purchases(status);
CREATE INDEX IF NOT EXISTS idx_offers_client ON offers(client_id);
CREATE INDEX IF NOT EXISTS idx_offers_freelancer ON offers(freelancer_id);
CREATE INDEX IF NOT EXISTS idx_offers_status ON offers(status);
`;

// ─── Initialize Database ────────────────────────────────────────
function initDatabase() {
  const statements = SCHEMA_SQL.split(';').filter(s => s.trim().length > 0);
  for (const stmt of statements) {
    try {
      db.run(stmt + ';', (err) => {
        if (err) console.warn('[DB Init] Warning:', err.message);
      });
    } catch (e) {
      console.warn('[DB Init] Warning:', e.message);
    }
  }
  console.log('[DB] Database initialized at:', dbPath);
}

initDatabase();

// ─── Add avatar column if missing ───────────────────────────────
db.all(`PRAGMA table_info(users)`, [], (err, columns) => {
  if (err) {
    console.warn('[DB Init] Could not check users table:', err.message);
    return;
  }
  const hasAvatar = columns && columns.some(col => col.name === 'avatar');
  if (!hasAvatar) {
    db.run(`ALTER TABLE users ADD COLUMN avatar TEXT;`, (err) => {
      if (err) console.warn('[DB Init] Could not add avatar:', err.message);
      else console.log('[DB Init] avatar column added');
    });
  } else {
    console.log('[DB Init] avatar column already exists');
  }
});

// ─── Auth Middleware ────────────────────────────────────────────

/**
 * Verify Pi access token by calling api.minepi.com/v2/me
 */
async function verifyAccessTokenWithPi(accessToken) {
  if (!accessToken) return { valid: false, error: 'No access token' };
  try {
    const response = await fetch('https://api.minepi.com/v2/me', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!response.ok) {
      return { valid: false, error: `Pi API error: ${response.status}` };
    }
    const userData = await response.json();
    return { valid: true, uid: userData.uid, username: userData.username };
  } catch (err) {
    console.error('[Pi API] /me verification error:', err.message);
    return { valid: false, error: err.message };
  }
}

/**
 * requireUser middleware: checks x-user-id header AND verifies x-pi-token
 */
async function requireUser(req, res, next) {
  const userId = req.headers['x-user-id'];
  const piToken = req.headers['x-pi-token'];

  if (!userId) {
    return res.status(401).json({ error: 'Authentication required. Missing x-user-id header.' });
  }

  // If pi token is provided, verify it matches the user
  if (piToken && PI_API_KEY) {
    const result = await verifyAccessTokenWithPi(piToken);
    if (!result.valid) {
      return res.status(401).json({ error: 'Invalid Pi access token', details: result.error });
    }
    if (result.uid !== userId) {
      return res.status(403).json({ error: 'Token user_id mismatch' });
    }
  }

  req.userId = userId;
  next();
}

/**
 * Admin auth middleware
 */
function requireAdmin(req, res, next) {
  // Allow cherry19899 owner access via x-user-id (Pi Browser auth)
  const userId = req.headers['x-user-id'];
  if (userId === 'cherry19899' || userId === 'admin') {
    return next();
  }

  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Admin authentication required. Use: Authorization: Bearer <token>' });
  }

  const validKeys = [];
  if (process.env.ADMIN_API_KEY) validKeys.push(process.env.ADMIN_API_KEY);
  if (process.env.WORKPRO_API_ACCESS && process.env.WORKPRO_API_ACCESS !== process.env.ADMIN_API_KEY) validKeys.push(process.env.WORKPRO_API_ACCESS);
  if (process.env.ADMIN_SECRET && process.env.ADMIN_SECRET !== process.env.ADMIN_API_KEY && process.env.ADMIN_SECRET !== process.env.WORKPRO_API_ACCESS) validKeys.push(process.env.ADMIN_SECRET);

  let match = false;
  const tokenBuf = Buffer.from(token, 'utf8');
  for (const key of validKeys) {
    const keyBuf = Buffer.from(key, 'utf8');
    if (tokenBuf.length === keyBuf.length) {
      if (crypto.timingSafeEqual(tokenBuf, keyBuf)) {
        match = true;
        break;
      }
    }
  }

  if (!match || validKeys.length === 0) {
    return res.status(403).json({ error: 'Invalid admin token' });
  }
  next();
}

// ─── Payment Helpers ────────────────────────────────────────────
async function fetchWithRetry(url, options, retries = 2, delay = 1000) {
  try {
    const response = await fetch(url, options);
    if (response.status === 429 && retries > 0) {
      await new Promise(r => setTimeout(r, delay));
      return fetchWithRetry(url, options, retries - 1, delay * 2);
    }
    return response;
  } catch (e) {
    if (retries > 0) {
      await new Promise(r => setTimeout(r, delay));
      return fetchWithRetry(url, options, retries - 1, delay * 2);
    }
    throw e;
  }
}

async function verifyPaymentWithPi(paymentId) {
  try {
    const encodedPaymentId = encodeURIComponent(paymentId);
    const response = await fetchWithRetry(`https://api.minepi.com/v2/payments/${encodedPaymentId}`, {
      method: 'GET',
      headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
    });
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    console.error('[Pi API] Verification error:', e.message);
    return null;
  }
}

function isValidTxid(txid) {
  return typeof txid === 'string' && txid.length >= 3 && txid.length <= 128;
}

// ─── Input Validation ───────────────────────────────────────────
function sanitizeString(str, maxLength = 500) {
  if (typeof str !== 'string') return null;
  const trimmed = str.trim();
  if (trimmed.length === 0) return null;
  return trimmed.slice(0, maxLength);
}

function sanitizeArray(arr, maxItems = 10) {
  if (!Array.isArray(arr)) return null;
  return arr.slice(0, maxItems).filter(x => typeof x === 'string').map(x => x.trim().slice(0, 200));
}

// ─── Notification Helper ────────────────────────────────────────
function createNotification(userId, type, title, message, relatedId, relatedType) {
  try {
    const id = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    console.log('[Notification] Creating for user:', userId, 'type:', type);
    db.run(
      `INSERT INTO notifications (id, user_id, type, title, message, related_id, related_type) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, userId, type, title, message, relatedId || null, relatedType || null],
      (err) => {
        if (err) console.error('[Notification] Insert error:', err.message);
        else console.log('[Notification] Created:', id, 'type:', type, 'user:', userId);
      }
    );
    return id;
  } catch (e) {
    console.error('[Notification] Exception:', e.message);
    return null;
  }
}

// ─── DB Helpers ─────────────────────────────────────────────────
function getUser(userId, callback) {
  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err) return callback(err, null);
    callback(null, row || null);
  });
}

function createUser(userId, username, callback) {
  db.run(
    `INSERT OR IGNORE INTO users (id, username, balance_connects) VALUES (?, ?, ?)`,
    [userId, username || 'User_' + userId.slice(0, 8), 0],
    (err) => {
      if (err) return callback(err, null);
      db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, row) => callback(err, row));
    }
  );
}

function updateUserBalance(userId, connectsDelta, piDelta, callback) {
  getUser(userId, (err, user) => {
    if (err) return callback(err);
    if (!user) {
      db.run(
        `INSERT INTO users (id, username, balance_connects, balance_pi) VALUES (?, ?, ?, ?)`,
        [userId, 'User_' + userId.slice(0, 8), connectsDelta, piDelta],
        (err) => {
          if (err) return callback(err);
          callback(null, { balance_connects: connectsDelta, balance_pi: piDelta });
        }
      );
      return;
    }
    const newConnects = (user.balance_connects || 0) + connectsDelta;
    const newPi = (user.balance_pi || 0) + piDelta;
    db.run(
      `UPDATE users SET balance_connects = ?, balance_pi = ? WHERE id = ?`,
      [newConnects, newPi, userId],
      (err) => {
        if (err) return callback(err);
        callback(null, { balance_connects: newConnects, balance_pi: newPi });
      }
    );
  });
}

function getJob(jobId, callback) {
  db.get(`SELECT j.*, (SELECT COUNT(*) FROM applications WHERE job_id = j.id) as applications_count FROM jobs j WHERE j.id = ?`, [jobId], (err, row) => {
    if (err) return callback(err, null);
    if (row) {
      if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
      row.apply_cost = Math.ceil((row.budget || 0) / 50) || 1;
    }
    callback(err, row);
  });
}

function getEscrow(escrowId, callback) {
  db.get(`SELECT * FROM escrows WHERE id = ?`, [escrowId], callback);
}

// ─── Startup Security Check ─────────────────────────────────────
if (!ADMIN_API_KEY) {
  console.warn('[Security] ADMIN_API_KEY is not set! Admin endpoints will return 403.');
}
if (!PI_API_KEY) {
  console.warn('[Security] PI_API_KEY is not set! Pi payment endpoints will return 500.');
}

// ════════════════════════════════════════════════════════════════
//  ENDPOINTS
// ════════════════════════════════════════════════════════════════

// ─── Frontend HTML (served from same domain to avoid CDN issues) ──
// Inline bundle + CSS — no external dependencies, no CORS, no CDN cache issues
const FRONTEND_HTML = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg?v=47" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />
    <meta name="theme-color" content="#10b981" />
    <meta name="description" content="Hire and work in Pi cryptocurrency. Find freelance jobs, pay and get paid in Pi." />
    <meta name="keywords" content="Pi Network, freelance, jobs, cryptocurrency, hire, work" />
    <meta property="og:title" content="Work Pro - Freelance on Pi" />
    <meta property="og:description" content="Hire and work in Pi cryptocurrency." />
    <link rel="manifest" href="/manifest.json?v=47" />
    <link rel="apple-touch-icon" href="/vite.svg?v=47" />
    <title>Work Pro — Pi Network Freelance Marketplace</title>
    <script>window.WORKPRO_VERSION='v209';</script>
<script>
// Fallback: show Sign In button if auto-auth takes too long
(function(){
  var t = setTimeout(function(){
    var btn = document.querySelector('button, [class*="sign"], [class*="auth"]');
    if (!btn || btn.textContent.indexOf('Connecting') !== -1 || btn.disabled) {
      // Force show sign in button
      var root = document.getElementById('root');
      if (root) {
        var fallback = document.createElement('button');
        fallback.textContent = 'π Sign in with Pi';
        fallback.style.cssText = 'background:#0d9488;color:#fff;border:none;padding:14px 28px;border-radius:8px;font-size:16px;margin:20px auto;display:block;cursor:pointer;';
        fallback.onclick = function() {
          if (window.Pi && window.Pi.authenticate) {
            window.Pi.authenticate(['username', 'payments'], function(p) {
              console.log('[Pi] incomplete:', p);
              return Promise.resolve();
            }).then(function(auth) {
              console.log('[Pi] auth success:', auth);
              window.location.reload();
            }).catch(function(err) {
              console.error('[Pi] auth error:', err);
              alert('Auth failed: ' + (err.message || err));
            });
          } else {
            alert('Pi SDK not loaded. Open in Pi Browser.');
          }
        };
        root.appendChild(fallback);
        console.log('[Fallback] Sign in button added');
      }
    }
  }, 3000);
  window._cancelFallback = function(){ clearTimeout(t); };
})();
</script>
    <script>
      // One-time cache clear for v47 upgrade (forces fresh bundle)
      (function() {
        try {
          var cleared = localStorage.getItem('workpro_v53_cleared');
          if (!cleared) {
            localStorage.setItem('workpro_v53_cleared', '1');
            if ('caches' in window) {
              caches.keys().then(function(names) {
                names.forEach(function(n) { caches.delete(n); });
              });
            }
            if ('serviceWorker' in navigator) {
              navigator.serviceWorker.getRegistrations().then(function(regs) {
                regs.forEach(function(r) { r.unregister(); });
              });
            }
            if ('serviceWorker' in navigator) {
              navigator.serviceWorker.getRegistrations().then(function(regs) {
                for (var reg of regs) reg.unregister();
              });
            }
            setTimeout(function() { window.location.reload(); }, 500);
          }
        } catch(e) {}
      })();
    </script>
    <script src="https://sdk.minepi.com/pi-sdk.js"></script>
    <script>
    // ---- PI SDK INIT (must run BEFORE bundle) ----
    (function() {
      function tryInit() {
        if (!window.Pi || typeof window.Pi.init !== 'function') {
          setTimeout(tryInit, 50);
          return;
        }
        if (window.Pi._initialized) return;
        try {
          // Pi.init is already called inside JS bundle - don't double init
          window.Pi._initialized = true;
          console.log('[Pi] SDK will be initialized by app bundle');
        } catch(e) {
          console.error('[Pi] init error:', e);
        }
      }
      tryInit();
    })();
    </script>
    <script>
    // ---- PI SDK AUTH PATCH (must run BEFORE bundle) ----
    (function() {
      function patchAuth() {
        if (!window.Pi || typeof window.Pi.authenticate !== 'function') {
          setTimeout(patchAuth, 50);
          return;
        }
        var origAuth = window.Pi.authenticate;
        window.Pi.authenticate = function(scopes, onIncompletePaymentFound) {
          // Force async onIncompletePaymentFound that returns Promise
          var wrapped = function(payment) {
            console.log('[Pi] onIncompletePaymentFound called', payment);
            if (payment && payment.identifier) {
              fetch('https://workpro-api.onrender.com/api/payments/' + payment.identifier + '/cancelled', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }
              }).catch(function(){});
            }
            return Promise.resolve();
          };
          var result = origAuth.call(window.Pi, scopes, wrapped);
          // Store userId globally for createPayment proxy
          if (result && typeof result.then === 'function') {
            result.then(function(authResult) {
              if (authResult && authResult.user) {
                var uid = authResult.user.uid || authResult.user.id;
                if (uid) {
                  window._workproUserId = uid;
                  // Save to localStorage for fetch interceptor
                  var userToStore = {
                    id: uid,
                    uid: uid,
                    username: authResult.user.username || authResult.user.name || 'User',
                    name: authResult.user.name || authResult.user.username || 'User',
                    accessToken: authResult.accessToken || '',
                    balance_connects: authResult.user.balance_connects || 0
                  };
                  localStorage.setItem('workpro_user', JSON.stringify(userToStore));
                  localStorage.setItem('workpro_user_id', uid);
                  window._workproUserId = uid;
                  console.log('[Pi] User stored:', uid, userToStore.username);
                  setupCreatePaymentPatch();
                }
              }
            }).catch(function(err) { console.warn('[Pi] Auth storage error:', err); });
          }
          return result;
        };
        console.log('[Pi] authenticate patched with Promise wrapper + userId storage');
      }
      patchAuth();

      // ---- 3b. XMLHttpRequest INTERCEPTOR (catches non-fetch requests) ----
  (function() {
    var origOpen = XMLHttpRequest.prototype.open;
    var origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
    var currentUrl = '';
    var hasUserId = false;

    XMLHttpRequest.prototype.open = function(method, url) {
      currentUrl = url;
      hasUserId = false;
      return origOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
      if (header.toLowerCase() === 'x-user-id') hasUserId = true;
      return origSetHeader.apply(this, arguments);
    };

    // Monkey-patch send to inject x-user-id before sending
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
      if (typeof currentUrl === 'string' && currentUrl.indexOf('/api/') !== -1 && !hasUserId) {
        try {
          var userStr = localStorage.getItem('workpro_user');
          if (userStr) {
            var user = JSON.parse(userStr);
            var uid = user.id || user.uid;
            if (uid) origSetHeader.call(this, 'x-user-id', uid);
          }
        } catch(e) {}
      }
      return origSend.apply(this, arguments);
    };
  })();

  // ---- 4. GLOBAL USER ID STORAGE ----
      window._workproUserId = null;

      // ---- 5. CREATE PAYMENT PROXY (injects x-user-id into callbacks) ----
      function setupCreatePaymentPatch() {
        if (window._createPaymentPatched) return;
        var uid = window._workproUserId;
        if (!uid) {
          try {
            var userStr = localStorage.getItem('workpro_user');
            if (userStr) { var u = JSON.parse(userStr); uid = u.id || u.uid; window._workproUserId = uid; }
          } catch(e) {}
        }
        if (!uid) { console.log('[Pi] patch: waiting for auth'); return; }
        if (!window.Pi || !window.Pi.createPayment) { console.log('[Pi] patch: Pi.createPayment not ready'); return; }

        function wrapCallback(cb) {
          if (typeof cb !== 'function') return cb;
          return function(data) {
            var origFetch2 = window.fetch;
            window.fetch = function(url, opts) {
              if (typeof url === 'string' && (url.indexOf('/api/') !== -1 || url.indexOf('workpro-api') !== -1)) {
                if (!opts) opts = {};
                if (!opts.headers) opts.headers = {};
                if (typeof opts.headers === 'object' && !(opts.headers instanceof Headers) && !Array.isArray(opts.headers)) {
                  opts.headers['x-user-id'] = uid;
                }
              }
              return origFetch2.call(this, url, opts);
            };
            var result;
            try { result = cb(data); } catch(e) { window.fetch = origFetch2; throw e; }
            if (result && typeof result.then === 'function') {
              result.then(function() { window.fetch = origFetch2; }).catch(function() { window.fetch = origFetch2; });
            } else { window.fetch = origFetch2; }
            return result;
          };
        }

        var origCreatePayment = window.Pi.createPayment;
        window.Pi.createPayment = function(paymentData, callbacks) {
          if (callbacks.onReadyForServerApproval) callbacks.onReadyForServerApproval = wrapCallback(callbacks.onReadyForServerApproval);
          if (callbacks.onReadyForServerCompletion) callbacks.onReadyForServerCompletion = wrapCallback(callbacks.onReadyForServerCompletion);
          if (callbacks.onCancel) callbacks.onCancel = wrapCallback(callbacks.onCancel);
          if (callbacks.onError) callbacks.onError = wrapCallback(callbacks.onError);
          return origCreatePayment.call(window.Pi, paymentData, callbacks);
        };
        window._createPaymentPatched = true;
        console.log('[Pi] createPayment patched for uid:', uid);
      } // ---- 6. NOTIFICATION BADGE POLLER ----
      (function pollNotifications() {
        try {
          var userStr = localStorage.getItem('workpro_user');
          if (!userStr) { setTimeout(pollNotifications, 5000); return; }
          var user = JSON.parse(userStr);
          var uid = user.id || user.uid;
          if (!uid) { setTimeout(pollNotifications, 5000); return; }

          fetch('https://workpro-api.onrender.com/api/notifications/unread-count', {
            headers: { 'x-user-id': uid }
          }).then(function(r) { return r.json(); }).then(function(data) {
            var count = data.unread_count || 0;
            window._unreadNotificationCount = count;
            // Try to update badge in DOM
            var badges = document.querySelectorAll('.notification-badge, .nav-badge, [data-badge]');
            badges.forEach(function(b) {
              b.textContent = count > 0 ? (count > 9 ? '9+' : String(count)) : '';
              b.style.display = count > 0 ? 'inline-block' : 'none';
            });
            console.log('[Notifications] Unread count:', count);
          }).catch(function(){});
        } catch(e) {}
        setTimeout(pollNotifications, 30000); // Poll every 30s
      })();
    })();
    </script>
    <script>
    (function(){
      var start=Date.now();
      fetch('https://workpro-api.onrender.com/assets/index-v95.js?v=209')
        .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.text();})
        .then(function(code){
          console.log('[Loader] JS fetched in '+(Date.now()-start)+'ms');
          try{
            var s=document.createElement('script');
            s.textContent=code+'\n;(function(){try{window.__jsLoaded=true;console.log("[Loader] JS executed");var l=document.getElementById("_loader");if(l){l.style.opacity="0";setTimeout(function(){l.style.display="none"},500)}}catch(e){}})();';
            document.body.appendChild(s);
          }catch(e){
            console.error('[Loader] exec error:',e.message);
            var el=document.getElementById('_error'),rl=document.getElementById('_reload');
            if(el){el.textContent='Error: '+e.message;el.style.display='block';}
            if(rl)rl.style.display='inline-block';
          }
        })
        .catch(function(e){
          console.error('[Loader] fetch error:',e.message);
          var el=document.getElementById('_error'),rl=document.getElementById('_reload');
          if(el){el.textContent='Load failed: '+e.message+'. <a href="javascript:location.reload()">Reload</a> or <a href="https://workpro-api.onrender.com/">Try alternative</a>';el.style.display='block';}
          if(rl)rl.style.display='inline-block';
        });
    })();
    </script>
<script>
(function(){var c=document.getElementById('__c'),cnt=0;
function lg(t,m){if(!c)return;cnt++;if(cnt>50)return;c.style.display='block';var d=document.createElement('div');d.style.color=t;d.textContent=m;c.appendChild(d);}
    <link rel="stylesheet" href="/assets/app-v196.css">
<!-- Console at bottom -->
  <script>
// ===== WORK PRO PATCH v53 =====
(function() {
  'use strict';

  // ---- 2. USER FORMAT FIX ----
  (function() {
    var origGet = localStorage.getItem;
    localStorage.getItem = function(key) {
      var val = origGet.call(localStorage, key);
      if (key === 'workpro_user' && val) {
        try {
          var user = JSON.parse(val);
          if (user.uid && !user.id) user.id = user.uid;
          if (user.name && !user.username) user.username = user.name;
          if (!user.id) user.id = 'guest_' + Date.now();
          if (!user.username) user.username = user.name || 'Guest';
          // ─── PROTECT connects from backend reset ─────────────────
          var sc = origGet.call(localStorage, 'workpro_connects');
          var storedC = parseInt(sc || '0', 10);
          var userC = user.balance_connects || user.connects || 0;
          if (storedC >= 0 && storedC !== userC) {
            console.log('[WorkPro] GET: restoring connects', storedC, 'over', userC);
            user.balance_connects = storedC;
            user.connects = storedC;
          }
          return JSON.stringify(user);
        } catch(e) {}
      }
      return val;
    };
    var origSet = localStorage.setItem;
    localStorage.setItem = function(key, val) {
      if (key === 'workpro_user' && val) {
        try {
          var user = JSON.parse(val);
          if (user.uid && !user.id) user.id = user.uid;
          if (user.id && !user.uid) user.uid = user.id;
          if (user.name && !user.username) user.username = user.name;
          if (user.username && !user.name) user.name = user.username;
          val = JSON.stringify(user);
        } catch(e) {}
      }
      return origSet.call(localStorage, key, val);
    };
  })();

  // ---- 3. FETCH INTERCEPTOR ----
  var origFetch = window.fetch;
  window.fetch = function(url, options) {
    if (typeof url !== 'string') return origFetch.call(this, url, options);

    // AUTH INJECT: add x-user-id and admin token to all API calls
    if (url.indexOf('/api/') !== -1) {
      if (!options) options = {};
      var args = [url, options];
      var headers = options.headers || {};
      if (typeof Headers !== 'undefined' && headers instanceof Headers) {
        var h = {};
        headers.forEach(function(v, k) { h[k] = v; });
        headers = h;
      } else if (Array.isArray(headers)) {
        var h2 = {};
        headers.forEach(function(item) { h2[item[0]] = item[1]; });
        headers = h2;
      }
      if (!headers['x-user-id'] && !headers['X-User-Id']) {
        try {
          var userStr = localStorage.getItem('workpro_user');
          if (userStr) {
            var user = JSON.parse(userStr);
            var uid = user.id || user.uid;
            if (uid) headers['x-user-id'] = uid;
          }
        } catch(e) {}
      }
      if (url.indexOf('/api/admin/') !== -1 && !headers['Authorization']) {
        var adminToken = localStorage.getItem('workpro_admin_token');
        if (adminToken) headers['Authorization'] = 'Bearer ' + adminToken;
      }
      options.headers = headers;
    }

    // Admin API format fix
    if (url.indexOf('/api/admin/') !== -1) {
      return origFetch.call(this, url, options).then(function(response) {
        var clone = response.clone();
        return clone.json().then(function(data) {
          var fixed = data;
          if (url.indexOf('/users') !== -1 && Array.isArray(data)) fixed = {users: data};
          if (url.indexOf('/jobs/all') !== -1 && Array.isArray(data)) fixed = {jobs: data};
          if (url.indexOf('/escrows') !== -1 && Array.isArray(data)) fixed = {escrows: data};
          if (url.indexOf('/earnings') !== -1 && data && !data.summary) {
            var payments = data.payments || [];
            var total = data.total || payments.length || 0;
            var earnings = payments.reduce(function(a, p) { return a + (p.amount || 0); }, 0);
            fixed = {
              summary: { total_earnings: earnings, total_transactions: total, average_transaction: total > 0 ? Math.round(earnings / total) : 0 },
              payments: payments
            };
          }
          return new Response(JSON.stringify(fixed), { status: response.status, statusText: response.statusText, headers: {'Content-Type': 'application/json'} });
        }).catch(function() { return response; });
      });
    }

    return origFetch.call(this, url, options).then(function(response) {
      // ─── For user data endpoint: return modified response ────────────
      if (url.indexOf('/api/users/') !== -1 && url.indexOf('/balance') === -1) {
        return response.json().then(function(data) {
          if (data && (data.balance_connects !== undefined || data.connects !== undefined)) {
            try {
              var sc = localStorage.getItem('workpro_connects');
              var storedC = parseInt(sc || '0', 10);
              var serverC = data.balance_connects || data.connects || 0;
              if (storedC > serverC && (storedC - serverC) > 2) {
                console.log('[WorkPro] MERGE response:', storedC, 'over', serverC);
                data.balance_connects = storedC;
                data.connects = storedC;
              }
            } catch(e) {}
          }
          return new Response(JSON.stringify(data), {
            status: response.status,
            statusText: response.statusText,
            headers: {'Content-Type': 'application/json'}
          });
        }).catch(function() { return response; });
      }

      var clone = response.clone();
      clone.json().then(function(data) {
        if (data && data.remaining_connects !== undefined) {
          try {
            var userStr = localStorage.getItem('workpro_user');
            if (userStr) {
              var user = JSON.parse(userStr);
              user.balance_connects = data.remaining_connects;
              user.connects = data.remaining_connects;
              localStorage.setItem('workpro_user', JSON.stringify(user));
              localStorage.setItem('workpro_connects', String(data.remaining_connects));
            }
          } catch(e) {}
          var el = document.getElementById('stat-connects');
          if (el) el.textContent = data.remaining_connects;
        }
        // ─── Handle connects purchase new_balance ──────────────────
        if (data && data.new_balance !== undefined) {
          try {
            var userStr = localStorage.getItem('workpro_user');
            if (userStr) {
              var user = JSON.parse(userStr);
              user.balance_connects = data.new_balance;
              user.connects = data.new_balance;
              localStorage.setItem('workpro_user', JSON.stringify(user));
              localStorage.setItem('workpro_connects', String(data.new_balance));
            }
          } catch(e) {}
          var el = document.getElementById('stat-connects');
          if (el) el.textContent = data.new_balance;
        }
      }).catch(function() {});
      return response;
    });
  };

  // ---- 3b. XMLHTTPREQUEST INTERCEPTOR (bundle uses XHR, not fetch) ----
  (function() {
    var OrigXHR = window.XMLHttpRequest;
    function InterceptedXHR() {
      var xhr = new OrigXHR();
      var _open = xhr.open;
      var _setHeader = xhr.setRequestHeader;
      var _url = '';
      var _headers = {};

      xhr.open = function(method, url) {
        _url = url;
        return _open.apply(xhr, arguments);
      };

      xhr.setRequestHeader = function(name, value) {
        _headers[name.toLowerCase()] = value;
        return _setHeader.apply(xhr, arguments);
      };

      // Intercept send to inject x-user-id for API calls
      var _send = xhr.send;
      xhr.send = function(body) {
        if (_url.indexOf('/api/') !== -1 && !_headers['x-user-id'] && !_headers['x-user-id']) {
          try {
            var userStr = localStorage.getItem('workpro_user');
            if (userStr) {
              var user = JSON.parse(userStr);
              var uid = user.id || user.uid;
              if (uid) _setHeader.call(xhr, 'x-user-id', uid);
            }
          } catch(e) {}
        }
        return _send.apply(xhr, arguments);
      };

      return xhr;
    }
    window.XMLHttpRequest = InterceptedXHR;
  })();

  // ---- 4. CONNECTS PROTECTION ----
  var STORAGE_KEY = 'workpro_user';
  var CONNECTS_KEY = 'workpro_connects';
  var BALANCE_KEY = 'workpro_balance';
  var SIG_KEY = 'workpro_user_sig';
  var SECRET = 'workpro_v42_' + location.hostname;

  function hash(str) {
    var h = 0;
    for (var i = 0; i < str.length; i++) { h = ((h << 5) - h) + str.charCodeAt(i); h |= 0; }
    return Math.abs(h).toString(36);
  }
  function sign(s) { return hash(s + SECRET); }

  var savedConnects = null, savedBalance = null;
  try {
    var sc = localStorage.getItem(CONNECTS_KEY);
    var sb = localStorage.getItem(BALANCE_KEY);
    if (sc) savedConnects = parseInt(sc, 10);
    if (sb) savedBalance = parseInt(sb, 0);
  } catch(e) {}

  var origSetItem = localStorage.setItem;
  localStorage.setItem = function(key, val) {
    if (key === STORAGE_KEY && val) {
      try {
        var user = JSON.parse(val);
        var sc = origGetItem.call(localStorage, CONNECTS_KEY);
        var storedC = parseInt(sc || '0', 10);
        var currentC = user.balance_connects || user.connects || 0;
        var currentB = user.balance_pi || 0;
        // If stored connects differ from what is being written, use stored value (truth)
        if (storedC >= 0 && storedC !== currentC) {
          console.log('[WorkPro] BLOCKED server reset, restoring:', storedC, 'vs', currentC);
          user.balance_connects = storedC;
          user.connects = storedC;
          currentC = storedC;
          val = JSON.stringify(user);
        }
        var finalC = user.balance_connects || user.connects || 0;
        var finalB = user.balance_pi || 0;
        origSetItem.call(localStorage, CONNECTS_KEY, String(finalC));
        origSetItem.call(localStorage, BALANCE_KEY, String(finalB));
        origSetItem.call(localStorage, SIG_KEY, sign(val));
      } catch(e) {}
    }
    return origSetItem.call(localStorage, key, val);
  };

  var origRemoveItem = localStorage.removeItem;
  localStorage.removeItem = function(key) {
    if (key === CONNECTS_KEY || key === BALANCE_KEY || key === SIG_KEY) {
      console.log('[WorkPro] BLOCKED remove:', key);
      return;
    }
    if (key === STORAGE_KEY) {
      var sc = origGetItem.call(localStorage, CONNECTS_KEY);
      if (sc) savedConnects = parseInt(sc, 10);
      console.log('[WorkPro] Logout, keeping connects:', savedConnects);
      try {
        var userStr = origGetItem.call(localStorage, key);
        if (userStr) {
          var user = JSON.parse(userStr);
          user.pi_token = null;
          origSetItem.call(localStorage, key, JSON.stringify(user));
          return;
        }
      } catch(e) {}
    }
    return origRemoveItem.call(localStorage, key);
  };

  var origGetItem = localStorage.getItem;
  localStorage.getItem = function(key) {
    var val = origGetItem.call(localStorage, key);
    if (key === STORAGE_KEY && val) {
      try {
        var user = JSON.parse(val);
        var sc = origGetItem.call(localStorage, CONNECTS_KEY);
        var storedC = parseInt(sc || '0', 10);
        var currentC = user.balance_connects || user.connects || 0;
        if (storedC > currentC && (storedC - currentC) > 5) {
          user.balance_connects = storedC;
          user.connects = storedC;
          val = JSON.stringify(user);
        }
        return val;
      } catch(e) {}
    }
    return val;
  };

  // ─── BLOCK localStorage.clear() from wiping connects ──────────
  var origClear = localStorage.clear;
  localStorage.clear = function() {
    var sc = origGetItem.call(localStorage, CONNECTS_KEY);
    var sb = origGetItem.call(localStorage, BALANCE_KEY);
    console.log('[WorkPro] BLOCKED clear, preserving connects:', sc);
    var keysToRemove = [];
    for (var i = 0; i < localStorage.length; i++) {
      var k = localStorage.key(i);
      if (k !== CONNECTS_KEY && k !== BALANCE_KEY && k !== SIG_KEY) {
        keysToRemove.push(k);
      }
    }
    for (var j = 0; j < keysToRemove.length; j++) {
      origRemoveItem.call(localStorage, keysToRemove[j]);
    }
    if (sc) origSetItem.call(localStorage, CONNECTS_KEY, sc);
    if (sb) origSetItem.call(localStorage, BALANCE_KEY, sb);
  };

  setInterval(function() {
    var userStr = localStorage.getItem(STORAGE_KEY);
    var sc = localStorage.getItem(CONNECTS_KEY);
    if (userStr && sc) {
      try {
        var user = JSON.parse(userStr);
        var stored = parseInt(sc, 10);
        var current = user.balance_connects || user.connects || 0;
        if (stored > current && (stored - current) > 5) {
          user.balance_connects = stored;
          user.connects = stored;
          localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
        }
      } catch(e) {}
    }
  }, 1000);

  // ---- 5. PHOTO COMPRESSION ----
  (function() {
    function compressImage(file, maxWidth, quality) {
      return new Promise(function(resolve, reject) {
        if (!file || !file.type || !file.type.startsWith('image/')) return resolve(file);
        var img = new Image();
        var url = URL.createObjectURL(file);
        img.onload = function() {
          URL.revokeObjectURL(url);
          var scale = Math.min(1, maxWidth / img.width);
          var w = Math.round(img.width * scale);
          var h = Math.round(img.height * scale);
          var canvas = document.createElement('canvas');
          canvas.width = w;
          canvas.height = h;
          canvas.getContext('2d').drawImage(img, 0, 0, w, h);
          canvas.toBlob(function(blob) {
            if (!blob) return reject('compress fail');
            var reader = new FileReader();
            reader.onloadend = function() { resolve(reader.result); };
            reader.readAsDataURL(blob);
          }, 'image/jpeg', quality);
        };
        img.onerror = function() { URL.revokeObjectURL(url); reject('load fail'); };
        img.src = url;
      });
    }

    window.__workproCompressImage = compressImage;

    // Intercept all file inputs: compress before React sees them
    document.addEventListener('change', function(e) {
      var input = e.target;
      if (input.type !== 'file' || !input.accept || input.accept.indexOf('image') === -1) return;
      if (!input.files || !input.files[0]) return;
      // Skip if already processed (prevents infinite loop on re-dispatch)
      if (input.__workpro_compressed) { input.__workpro_compressed = false; return; }
      var file = input.files[0];
      if (file.size < 500 * 1024) return; // skip small files
      e.preventDefault();
      e.stopPropagation();
      input.__workpro_processing = true;
      compressImage(file, 1200, 0.6).then(function(dataUrl) {
        var byteString = atob(dataUrl.split(',')[1]);
        var mime = dataUrl.split(',')[0].split(':')[1].split(';')[0];
        var ab = new ArrayBuffer(byteString.length);
        var ia = new Uint8Array(ab);
        for (var i = 0; i < byteString.length; i++) ia[i] = byteString.charCodeAt(i);
        var blob = new Blob([ab], {type: mime});
        var newFile = new File([blob], file.name.replace(/\.[^.]+$/, '.jpg'), {type: 'image/jpeg'});
        var dt = new DataTransfer();
        dt.items.add(newFile);
        input.files = dt.files;
        input.__workpro_compressed = true;
        input.__workpro_processing = false;
        // Re-dispatch change so React picks up compressed file
        input.dispatchEvent(new Event('change', {bubbles: true}));
      }).catch(function(err) {
        input.__workpro_processing = false;
        console.error('[WorkPro] compress error:', err);
      });
    }, true);
  })();

  console.log('[WorkPro] Patch v47 loaded (with photo compression)');
</script>
</head>
  <body>
    <!-- LOADER -->
    <div id="_loader" style="position:fixed;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;background:linear-gradient(135deg,#f0fdf4,#ecfdf5);z-index:99999;font-family:sans-serif;">
      <h1 style="color:#0d9488;font-size:36px;margin-bottom:8px;">Work Pro</h1>
      <p style="color:#666;font-size:14px;margin-bottom:20px;">Loading...</p>
      <div style="width:40px;height:40px;border:3px solid #ddd;border-top-color:#0d9488;border-radius:50%;animation:spin 1s linear infinite;"></div>
      <div id="_error" style="display:none;color:#dc2626;font-size:13px;text-align:center;margin-top:20px;max-width:280px;padding:0 20px;"></div>
      <button id="_reload" style="display:none;margin-top:12px;padding:10px 24px;background:#0d9488;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;" onclick="location.reload()">Reload</button>
      <a href="https://workpro-api.onrender.com/" style="color:#0d9488;font-size:12px;margin-top:8px;text-decoration:underline;">Alternative link</a>
    </div>
    <style>@keyframes spin{to{transform:rotate(360deg)}}</style>
    <script>
    (function(){
      var start=Date.now();
      var check=setInterval(function(){
        var root=document.getElementById('root');
        var hasReact=root&&root.children.length>0;
        var loader=document.getElementById('_loader');
        var elapsed=Date.now()-start;
        if(hasReact&&loader){loader.style.opacity='0';setTimeout(function(){loader.style.display='none';},500);clearInterval(check);}
        else if(elapsed>120000&&!hasReact){clearInterval(check);var e=document.getElementById('_error');var r=document.getElementById('_reload');if(e){e.textContent='Loading timed out (120s). JS loaded='+!!window.__jsLoaded+'. Check connection.';e.style.display='block';}if(r)r.style.display='inline-block';}
      },500);
    })();
    </script>
    <div id="root"></div>
    <!-- DEBUG CONSOLE -->
    <div id="__cw" style="position:fixed;bottom:0;left:0;right:0;z-index:99998;display:none;"><div id="__ct" style="background:#0d9488;color:#fff;font-size:10px;padding:2px 6px;cursor:pointer;font-family:monospace;text-align:center;" onclick="var c=document.getElementById('__c'),t=document.getElementById('__ct');if(c.style.display==='none'){c.style.display='block';t.textContent='▼ Console'}else{c.style.display='none';t.textContent='▲ Console'}">▼ Console</div><div id="__c" style="max-height:100px;overflow-y:auto;background:rgba(0,0,0,.85);color:#0f0;font-family:monospace;font-size:10px;line-height:1.4;padding:6px;display:block;border-top:2px solid #0f0;"></div></div>
    <script>
    (function(){var c=document.getElementById('__c'),cw=document.getElementById('__cw'),cnt=0;function lg(t,m){if(!c||!cw)return;cnt++;if(cnt>80)return;cw.style.display='block';c.style.display='block';var d=document.createElement('div');d.style.color=t;d.textContent=m;c.appendChild(d);}lg('#0f0','[WP] v209 start');var o=console.log,oe=console.error,ow=console.warn;console.log=function(){var a=Array.prototype.slice.call(arguments).join(' ');o.apply(console,arguments);lg('#0f0','[L] '+a);};console.error=function(){var a=Array.prototype.slice.call(arguments).join(' ');oe.apply(console,arguments);lg('#f00','[E] '+a);};console.warn=function(){var a=Array.prototype.slice.call(arguments).join(' ');if(a.indexOf('already initialized')>-1)return;ow.apply(console,arguments);lg('#ff0','[W] '+a);};window.onerror=function(m,u,l,co,err){lg('#f00','[ERR] '+m+' @'+l+':'+co);return true;};window.onunhandledrejection=function(e){var r=e.reason||e,msg=r&&r.message?r.message:String(r);lg('#f00','[REJ] '+msg);};})();
    </script>
    <!-- MENU PATCH: Show both client and freelancer menus regardless of role -->
    <script>
    (function(){
      console.log('[MenuPatch] Starting...');
      var menuItemsAdded = false;
      
      function patchMenu() {
        if (menuItemsAdded) return;
        // Find navigation container by common patterns
        var nav = document.querySelector('nav') || document.querySelector('[class*="nav"]') || document.querySelector('[class*="menu"]');
        if (!nav) return;
        
        // Check if menu has role-based filtering by looking for specific items
        var menuText = nav.textContent || '';
        var hasMyJobs = menuText.toLowerCase().includes('my jobs') || menuText.toLowerCase().includes('мои работы');
        var hasMyApplications = menuText.toLowerCase().includes('my applications') || menuText.toLowerCase().includes('мои отклики');
        
        if (hasMyJobs && hasMyApplications) {
          console.log('[MenuPatch] Menu already has both sections');
          menuItemsAdded = true;
          return;
        }
        
        // Find or create the menu list
        var menuList = nav.querySelector('ul') || nav.querySelector('div') || nav;
        if (!menuList) return;
        
        // Add missing menu items
        if (!hasMyJobs) {
          var myJobsItem = document.createElement('div');
          myJobsItem.innerHTML = '<a href="#/my-jobs" style="display:block;padding:8px 12px;color:#0d9488;text-decoration:none;border-bottom:1px solid #eee;">📋 Мои работы (заказчик)</a>';
          menuList.appendChild(myJobsItem);
          console.log('[MenuPatch] Added "Мои работы"');
        }
        
        // "My Applications" moved to Profile section — not in main menu
        

        
        menuItemsAdded = true;
        console.log('[MenuPatch] Menu patched successfully');
      }
      
      // Try to patch immediately and after React loads
      setTimeout(patchMenu, 2000);
      setTimeout(patchMenu, 5000);
      setTimeout(patchMenu, 10000);
      
      // Profile page patch — add freelancer links
      function patchProfile() {
        var profileSections = document.querySelectorAll('[class*="profile"]');
        profileSections.forEach(function(section) {
          var sectionText = section.textContent || '';
          if (sectionText.includes('Portfolio') && !section.querySelector('[data-patched]')) {
            var wrapper = document.createElement('div');
            wrapper.setAttribute('data-patched', 'true');
            wrapper.innerHTML = 
              '<div style="margin-top:8px;padding-top:8px;border-top:1px solid #e5e7eb;">' +
              '<a href="#/my-applications" style="display:flex;align-items:center;padding:8px 0;color:#0d9488;text-decoration:none;font-size:14px;">' +
              '<span style="margin-right:8px;">📤</span> Мои отклики (фрилансер)</a>' +
              '<a href="/privacy-policy.html" target="_blank" style="display:flex;align-items:center;padding:8px 0;color:#9ca3af;text-decoration:none;font-size:12px;">' +
              '<span style="margin-right:8px;">🔒</span> Privacy Policy</a></div>';
            section.appendChild(wrapper);
            console.log('[MenuPatch] Added freelancer links to Profile');
          }
        });
      }
      
      // Observe DOM changes
      if (window.MutationObserver) {
        var observer = new MutationObserver(function(mutations) {
          if (!menuItemsAdded) patchMenu();
          patchProfile();
        });
        observer.observe(document.body, { childList: true, subtree: true });
        console.log('[MenuPatch] DOM observer started');
      }
    })();
    </script>
    <!-- Privacy Policy Link (required for Pi Network listing) -->
<script>
  (function() {
    var ppLink = document.createElement('a');
    ppLink.href = '/privacy-policy.html';
    ppLink.id = 'privacy-policy-link';
    ppLink.style.cssText = 'position:fixed;bottom:10px;right:10px;color:#64748b;font-size:12px;z-index:9999;text-decoration:none;opacity:0.7;';
    ppLink.textContent = 'Privacy Policy';
    document.body.appendChild(ppLink);
  })();
  </script>
</body>
</html>


app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(FRONTEND_HTML);
});

app.get('/health', (req, res) => {
  const mem = process.memoryUsage();
  db.get(`SELECT 1 as ok`, [], (err) => {
    res.json({
      status: 'ok',
      uptime: process.uptime(),
      memory: { rss: mem.rss, heapUsed: mem.heapUsed },
      database: err ? 'error' : 'connected',
      version: '2.2.9 (v209-1779142856)',
      timestamp: new Date().toISOString(),
    });
  });
});

// ─── Auth: /api/me (Verify Token & Register User) ──────────────
app.post('/api/me', async (req, res) => {
  const { accessToken } = req.body;
  if (!accessToken) return res.status(400).json({ error: 'accessToken is required' });

  const result = await verifyAccessTokenWithPi(accessToken);
  if (!result.valid) {
    return res.status(401).json({ error: 'Invalid access token', details: result.error });
  }

  db.run(
    `INSERT OR REPLACE INTO users (id, username, balance_connects, balance_pi, updated_at) VALUES (?, ?, COALESCE((SELECT balance_connects FROM users WHERE id = ?), 0), COALESCE((SELECT balance_pi FROM users WHERE id = ?), 0), datetime('now'))`,
    [result.uid, result.username || 'User_' + result.uid.slice(0, 8), result.uid, result.uid],
    (err) => {
      if (err) console.warn('[DB] User update warning:', err.message);
    }
  );

  res.json({ success: true, user: { uid: result.uid, username: result.username } });
});

app.get('/api/me', async (req, res) => {
  const userId = req.headers['x-user-id'];
  const piToken = req.headers['x-pi-token'];
  if (!userId) return res.status(401).json({ error: 'Missing x-user-id header' });

  if (piToken && PI_API_KEY) {
    const result = await verifyAccessTokenWithPi(piToken);
    if (!result.valid) return res.status(401).json({ error: 'Invalid token', details: result.error });
    if (result.uid !== userId) return res.status(403).json({ error: 'User ID mismatch' });
  }

  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) {
      // Auto-create user with trial connects
      const newUser = {
        id: userId,
        username: 'User_' + userId.slice(-8),
        name: 'User_' + userId.slice(-8),
        role: 'freelancer',
        balance_connects: 3,  // Trial connects for new users
        balance_pi: 0,
        created_at: new Date().toISOString()
      };
      db.run(
        `INSERT INTO users (id, username, role, balance_connects, balance_pi) VALUES (?, ?, ?, ?, ?)`,
        [newUser.id, newUser.username, newUser.role, newUser.balance_connects, newUser.balance_pi],
        (err) => {
          if (err) return res.status(500).json({ error: 'Failed to create user' });
          res.json({ success: true, exists: false, user: { ...newUser, is_admin: false } });
        }
      );
      return;
    }
    const isAdmin = user.role === 'admin' || user.id === 'cherry19899' || (user.username && user.username.toLowerCase() === 'cherry19899') || user.username === 'admin';
    res.json({ success: true, exists: true, user: { ...user, is_admin: isAdmin } });
  });
});

// ════════════════════════════════════════════════════════════════
//  JOBS
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/jobs - List all jobs (paginated, filterable)
 * Query: ?category=&q=&page=&limit=
 */
app.get('/api/jobs', (req, res) => {
  const { category, q, page = 1, limit = 20, all, min_budget, max_budget, sort } = req.query;
  // If ?all=1 is passed, show all statuses (for admin/management)
  // Otherwise default to 'open' for public job feed
  let whereSql = (all === '1') ? `WHERE 1=1` : `WHERE status = 'open'`;
  let whereParams = [];
  let countParams = [];

  if (category && category !== 'all') {
    whereSql += ` AND category = ?`;
    whereParams.push(category);
    countParams.push(category);
  }
  if (q) {
    const safeSearch = q.replace(/[%_]/g, '\$&');
    whereSql += ` AND (title LIKE ? OR description LIKE ?)`;
    whereParams.push(`%${safeSearch}%`, `%${safeSearch}%`);
    countParams.push(`%${safeSearch}%`, `%${safeSearch}%`);
  }
  if (min_budget) {
    whereSql += ` AND budget >= ?`;
    whereParams.push(parseInt(min_budget));
    countParams.push(parseInt(min_budget));
  }
  if (max_budget) {
    whereSql += ` AND budget <= ?`;
    whereParams.push(parseInt(max_budget));
    countParams.push(parseInt(max_budget));
  }

  const pageInt = Math.max(1, parseInt(page) || 1);
  const limitInt = Math.min(100, Math.max(1, parseInt(limit) || 20));
  const offset = (pageInt - 1) * limitInt;

  // Sort order
  let orderBy = 'created_at DESC';
  if (sort === 'budget_asc') orderBy = 'budget ASC';
  else if (sort === 'budget_desc') orderBy = 'budget DESC';
  else if (sort === 'oldest') orderBy = 'created_at ASC';

  db.get(`SELECT COUNT(*) as total FROM jobs ${whereSql}`, countParams, (err, countRow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const total = countRow ? countRow.total : 0;
    const totalPages = Math.ceil(total / limitInt);

    const sql = `SELECT j.*, 
                   (SELECT COUNT(*) FROM applications WHERE job_id = j.id) as applications_count 
                 FROM jobs j 
                 ${whereSql} 
                 ORDER BY ${orderBy} 
                 LIMIT ? OFFSET ?`;
    const params = [...whereParams, limitInt, offset];

    db.all(sql, params, (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error', details: err.message });
      rows.forEach(row => {
        if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
        row.apply_cost = Math.ceil((row.budget || 0) / 50) || 1;
      });
      res.json({ jobs: rows, page: pageInt, limit: limitInt, total, total_pages: totalPages });
    });
  });
});

/**
 * GET /api/jobs/search?q= - Search jobs
 */
app.get('/api/jobs/search', (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Query parameter "q" is required' });
  const safeSearch = q.replace(/[%_]/g, '\$&');
  const searchTerm = `%${safeSearch}%`;

  db.all(
    `SELECT * FROM jobs WHERE status = 'open' AND (title LIKE ? OR description LIKE ? OR category LIKE ? OR skills LIKE ?) ORDER BY created_at DESC LIMIT 50`,
    [searchTerm, searchTerm, searchTerm, searchTerm],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      rows.forEach(row => {
        if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
        row.apply_cost = Math.ceil((row.budget || 0) / 50) || 1;
      });
      res.json({ jobs: rows, query: q });
    }
  );
});

/**
 * GET /api/jobs/me - Get my jobs (jobs I posted)
 */
app.get('/api/jobs/me', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = (page - 1) * limit;

  db.get(`SELECT COUNT(*) as total FROM jobs WHERE posted_by = ?`, [userId], (err, countRow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const total = countRow ? countRow.total : 0;

    db.all(`SELECT * FROM jobs WHERE posted_by = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`, 
      [userId, limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      rows.forEach(row => {
        if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
        row.apply_cost = Math.ceil((row.budget || 0) / 50) || 1;
      });
      res.json({ 
        jobs: rows, 
        total: total, 
        page: page, 
        limit: limit, 
        total_pages: Math.ceil(total / limit) 
      });
    });
  });
});

/**
 * GET /api/jobs/user/:username - Get jobs by username (frontend compatibility)
 */
app.get('/api/jobs/user/:username', async (req, res) => {
  const authUserId = req.headers['x-user-id'];
  if (!authUserId) return res.status(401).json({ error: 'Authentication required' });

  const username = req.params.username;

  // Find user by username (case-insensitive)
  db.get(`SELECT id FROM users WHERE username = ? COLLATE NOCASE`, [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(404).json({ error: 'User not found' });

    db.all(`SELECT * FROM jobs WHERE posted_by = ? ORDER BY created_at DESC`, [user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      rows.forEach(row => {
        if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
        row.apply_cost = Math.ceil((row.budget || 0) / 50) || 1;
      });
      res.json(rows || []);
    });
  });
});

/**
 * GET /api/jobs/:id - Get single job
 */
app.get('/api/jobs/:id', (req, res) => {
  getJob(req.params.id, (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'Job not found' });
    res.json(row);
  });
});

/**
 * POST /api/jobs/:id/apply - Apply to a job (deducts 1 connect)
 */
app.post('/api/jobs/:id/apply', async (req, res) => {
  const userId = req.headers['x-user-id'] || req.body?.user_id;
  const piToken = req.headers['x-pi-token'];
  const job_id = req.params.id;
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  if (piToken && PI_API_KEY) {
    const result = await verifyAccessTokenWithPi(piToken);
    if (!result.valid) return res.status(401).json({ error: 'Invalid token' });
    if (result.uid !== userId) return res.status(403).json({ error: 'User ID mismatch' });
  }

  const { message, username } = req.body;

  db.get(`SELECT * FROM jobs WHERE id = ? AND status = 'open'`, [job_id], (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found or not open' });
    if (job.posted_by === userId) return res.status(403).json({ error: 'Cannot apply to your own job' });

    // Check if already applied
    db.get(`SELECT * FROM applications WHERE job_id = ? AND user_id = ?`, [job_id, userId], (err, existing) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (existing) return res.status(409).json({ error: 'Already applied to this job' });

      // Ensure user exists (auto-create if missing)
      db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        const doApply = (u) => {
          if ((u.balance_connects || 0) < 1) {
            return res.status(400).json({ error: 'Not enough connects to apply', required: 1, current: u.balance_connects || 0 });
          }
          const safeMessage = sanitizeString(message, 2000) || '';
          const safeBid = job.budget || 0;
          const newConnects = (u.balance_connects || 0) - 1;
          const applicantName = username || u.username || 'User';
          
          db.run(`UPDATE users SET balance_connects = ? WHERE id = ?`, [newConnects, userId], (err) => {
            if (err) console.warn('[DB] Connect deduction warning:', err.message);
            db.run(
              `INSERT INTO applications (job_id, user_id, username, message, bid_amount, status) VALUES (?, ?, ?, ?, ?, 'pending')`,
              [job_id, userId, applicantName, safeMessage, safeBid],
              function(err) {
                if (err) return res.status(500).json({ error: 'Failed to create application' });
                db.run(`UPDATE jobs SET applications = applications + 1 WHERE id = ?`, [job_id]);
                createNotification(job.posted_by, 'application', 'New Application', `${applicantName} applied to "${job.title}"`, String(this.lastID), 'application');
                res.json({ success: true, id: this.lastID, job_id, user_id: userId, status: 'pending', message: safeMessage, bid_amount: safeBid, connects_deducted: 1, remaining_connects: newConnects, created_at: new Date().toISOString() });
              }
            );
          });
        };
        
        if (!user) {
          // Auto-create user with trial connects
          const newUser = { id: userId, username: 'User_' + userId.slice(-8), role: 'freelancer', balance_connects: 3, balance_pi: 0 };
          db.run(`INSERT INTO users (id, username, role, balance_connects, balance_pi) VALUES (?, ?, ?, ?, ?)`,
            [newUser.id, newUser.username, newUser.role, newUser.balance_connects, newUser.balance_pi],
            (err) => {
              if (err) return res.status(500).json({ error: 'Failed to create user' });
              doApply(newUser);
            }
          );
        } else {
          doApply(user);
        }
      });
    });
  });
});

/**
 * POST /api/jobs - Create job (deducts 1 connect)
 */
app.post('/api/jobs', async (req, res) => {
  const userId = req.headers['x-user-id'];
  const piToken = req.headers['x-pi-token'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  // Verify token
  if (piToken && PI_API_KEY) {
    const result = await verifyAccessTokenWithPi(piToken);
    if (!result.valid) return res.status(401).json({ error: 'Invalid token' });
    if (result.uid !== userId) return res.status(403).json({ error: 'User ID mismatch' });
  }

  const { title, description, category, budget, skills, images, deadline, posted_by, posted_by_name } = req.body;
  const safeTitle = sanitizeString(title, 120);
  const safeDescription = sanitizeString(description, 2000);
  const safeCategory = sanitizeString(category, 30) || 'other';
  const safeSkills = sanitizeString(skills, 200);
  const safeImages = sanitizeArray(images);
  const safeDeadline = sanitizeString(deadline, 30);
  const safePostedByName = sanitizeString(posted_by_name, 50) || 'User';

  if (!safeTitle) return res.status(400).json({ error: 'Title is required (1-120 chars)' });
  if (!safeDescription) return res.status(400).json({ error: 'Description is required (1-2000 chars)' });
  if (budget !== undefined && (typeof budget !== 'number' || budget < 0 || budget > 1000000)) {
    return res.status(400).json({ error: 'Budget must be 0-1,000,000' });
  }

  const posterId = posted_by || userId;
  if (posterId !== userId) return res.status(403).json({ error: 'Can only post as yourself' });

  // Deduct 1 connect
  getUser(userId, (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if ((user.balance_connects || 0) < 1) {
      return res.status(400).json({ error: 'Not enough connects to post a job', required: 1, current: user.balance_connects });
    }
    const newConnects = (user.balance_connects || 0) - 1;
    const imagesStr = safeImages ? JSON.stringify(safeImages) : null;

    db.run(
      `INSERT INTO jobs (title, description, category, budget, skills, images, deadline, posted_by, posted_by_name, connects_spent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [safeTitle, safeDescription, safeCategory, budget || 0, safeSkills || '', imagesStr, safeDeadline || null, posterId, safePostedByName, 1],
      function(err) {
        if (err) {
          console.error('[DB] Error creating job:', err);
          return res.status(500).json({ error: 'Failed to create job' });
        }
        const jobId = this.lastID;
        db.run(
          `UPDATE users SET balance_connects = ?, total_jobs_posted = total_jobs_posted + 1 WHERE id = ?`,
          [newConnects, userId],
          (err) => {
            if (err) console.warn('[DB] Balance update warning:', err.message);
            res.json({ id: jobId, title: safeTitle, description: safeDescription, category: safeCategory, budget: budget || 0, status: 'open', posted_by: posterId, posted_by_name: safePostedByName, connects_spent: 1, created_at: new Date().toISOString(), success: true, remaining_connects: newConnects });
          }
        );
      }
    );
  });
});

/**
 * POST /api/jobs/:id/images - Add images to job (base64)
 */
app.post('/api/jobs/:id/images', (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { images } = req.body;
  if (!images || !Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ error: 'images must be a non-empty array of base64 strings' });
  }
  if (images.some(img => typeof img !== 'string' || img.length > 500000)) {
    return res.status(400).json({ error: 'Each image must be a base64 string under 500KB' });
  }

  db.get(`SELECT posted_by, images FROM jobs WHERE id = ?`, [req.params.id], (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== userId) return res.status(403).json({ error: 'Only job owner can add images' });

    let existingImages = [];
    try { existingImages = JSON.parse(job.images || '[]'); } catch(e) {}
    const newImages = existingImages.concat(images).slice(0, 10);

    db.run(`UPDATE jobs SET images = ? WHERE id = ?`, [JSON.stringify(newImages), req.params.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update images' });
      res.json({ success: true, images_added: images.length, total_images: newImages.length });
    });
  });
});

/**
 * PUT /api/jobs/:id - Update job (owner only)
 */
app.put('/api/jobs/:id', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  const { title, description, category, budget, skills, images, deadline, status } = req.body;

  getJob(id, (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== userId) return res.status(403).json({ error: 'You can only edit your own jobs' });

    const safeTitle = title !== undefined ? sanitizeString(title, 120) : job.title;
    const safeDesc = description !== undefined ? sanitizeString(description, 2000) : job.description;
    const safeCategory = category !== undefined ? (sanitizeString(category, 30) || 'other') : job.category;
    const safeSkills = skills !== undefined ? sanitizeString(skills, 200) : job.skills;
    const safeImages = images !== undefined ? (sanitizeArray(images) ? JSON.stringify(sanitizeArray(images)) : null) : job.images;
    const safeDeadline = deadline !== undefined ? sanitizeString(deadline, 30) : job.deadline;
    const safeStatus = status !== undefined ? (['open','in_progress','completed','cancelled'].includes(status) ? status : job.status) : job.status;

    if (budget !== undefined && (typeof budget !== 'number' || budget < 0 || budget > 1000000)) {
      return res.status(400).json({ error: 'Budget must be 0-1,000,000' });
    }

    db.run(
      `UPDATE jobs SET title = ?, description = ?, category = ?, budget = ?, skills = ?, images = ?, deadline = ?, status = ? WHERE id = ?`,
      [safeTitle, safeDesc, safeCategory, budget !== undefined ? budget : job.budget, safeSkills, safeImages, safeDeadline, safeStatus, id],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to update job' });
        res.json({ success: true });
      }
    );
  });
});

/**
 * DELETE /api/jobs/:id - Delete job (owner only)
 */
app.delete('/api/jobs/:id', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  getJob(id, (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== userId) return res.status(403).json({ error: 'You can only delete your own jobs' });

    db.run(`DELETE FROM jobs WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete job' });
      res.json({ success: true });
    });
  });
});

// ════════════════════════════════════════════════════════════════
//  APPLICATIONS
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/applications?job_id= - List applications for a job
 */
app.get('/api/applications', (req, res) => {
  const { job_id } = req.query;
  if (!job_id) {
    return res.status(400).json({ error: 'job_id query parameter is required' });
  }
  db.all(
    `SELECT a.*, j.title as job_title FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.job_id = ? ORDER BY a.created_at DESC`,
    [job_id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows || []);
    }
  );
});

/**
 * POST /api/applications - Apply for a job (deducts 1 connect)
 */
/**
 * GET /api/jobs/:id/applications - Get applications for a specific job
 */
app.get('/api/jobs/:id/applications', (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;

  db.get(`SELECT posted_by FROM jobs WHERE id = ?`, [id], (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== userId) return res.status(403).json({ error: 'Only job owner can view applications' });

    db.all(
      `SELECT a.*, u.username, u.rating, u.availability FROM applications a LEFT JOIN users u ON a.user_id = u.id WHERE a.job_id = ? ORDER BY a.created_at DESC`,
      [id],
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
      }
    );
  });
});

app.post('/api/applications', async (req, res) => {
  const userId = req.headers['x-user-id'];
  const piToken = req.headers['x-pi-token'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  if (piToken && PI_API_KEY) {
    const result = await verifyAccessTokenWithPi(piToken);
    if (!result.valid) return res.status(401).json({ error: 'Invalid token' });
    if (result.uid !== userId) return res.status(403).json({ error: 'User ID mismatch' });
  }

  const { job_id, message, bid_amount, username } = req.body;
  if (!job_id) return res.status(400).json({ error: 'job_id is required' });

  db.get(`SELECT * FROM jobs WHERE id = ? AND status = 'open'`, [job_id], (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found or not open' });
    if (job.posted_by === userId) return res.status(403).json({ error: 'Cannot apply to your own job' });

    // Check if already applied
    db.get(`SELECT * FROM applications WHERE job_id = ? AND user_id = ?`, [job_id, userId], (err, existing) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (existing) return res.status(409).json({ error: 'Already applied to this job' });

      getUser(userId, (err, user) => {
        console.log(`[APPLY] getUser(${userId}): found=${!!user} balance=${user?.balance_connects}`);
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if ((user.balance_connects || 0) < 1) {
          console.log(`[APPLY] REJECT: ${userId} has ${user.balance_connects} connects`);
          return res.status(400).json({ error: 'Not enough connects to apply', required: 1, current: user.balance_connects || 0 });
        }

        const safeMessage = sanitizeString(message, 2000) || '';
        const safeBid = bid_amount || job.budget || 0;
        const newConnects = (user.balance_connects || 0) - 1;

        db.run(`UPDATE users SET balance_connects = ? WHERE id = ?`, [newConnects, userId], (err) => {
          if (err) console.warn('[DB] Connect deduction warning:', err.message);

          db.run(
            `INSERT INTO applications (job_id, user_id, username, message, bid_amount, status) VALUES (?, ?, ?, ?, ?, 'pending')`,
            [job_id, userId, username || user.username || 'User', safeMessage, safeBid],
            function(err) {
              if (err) return res.status(500).json({ error: 'Failed to create application' });

              // Increment application count on job
              db.run(`UPDATE jobs SET applications = applications + 1 WHERE id = ?`, [job_id]);

              // Notify job owner
              createNotification(job.posted_by, 'application', 'New Application', `${username || user.username || 'Someone'} applied to "${job.title}"`, String(this.lastID), 'application');

              res.json({
                success: true,
                id: this.lastID,
                job_id,
                user_id: userId,
                status: 'pending',
                message: safeMessage,
                bid_amount: safeBid,
                connects_deducted: 1,
                balance_connects: newConnects,
                created_at: new Date().toISOString()
              });
            }
          );
        });
      });
    });
  });
});

/**
 * POST /api/applications/:id/accept - Accept application + create chat room
 */
app.post('/api/applications/:id/accept', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  db.get(
    `SELECT a.*, j.posted_by as job_owner FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = ?`,
    [id],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row) return res.status(404).json({ error: 'Application not found' });
      if (row.job_owner !== userId) return res.status(403).json({ error: 'Only the job owner can accept applications' });
      if (row.status !== 'pending') return res.status(400).json({ error: 'Application already processed' });

      db.run(`UPDATE applications SET status = 'accepted' WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to accept' });

        db.run(`UPDATE jobs SET status = 'in_progress' WHERE id = ?`, [row.job_id], function(err) {
          if (err) console.warn('[DB] Job status update warning:', err.message);

          const roomId = 'job_' + row.job_id + '_' + row.job_owner + '_' + row.user_id + '_' + Date.now();
          const now = new Date().toISOString();
          // NOTE: production DB chat_rooms table may not have job_id column (older schema)
          // Use INSERT without job_id for compatibility
          db.run(
            `INSERT INTO chat_rooms (id, user1_id, user2_id, created_at) VALUES (?, ?, ?, ?)`,
            [roomId, row.job_owner, row.user_id, now],
            function(err) {
              if (err) {
                console.error('[DB] Chat room creation ERROR:', err.message);
                return res.json({ success: true, status: 'accepted', chat_room_id: null, job_status: 'in_progress', warning: 'Chat room creation failed: ' + err.message });
              }
              console.log('[DB] Chat room created:', roomId);

              // Notify freelancer
              createNotification(row.user_id, 'application_accepted', 'Application Accepted', `Your application was accepted! Chat room created.`, row.job_id, 'job');

              res.json({ success: true, status: 'accepted', chat_room_id: roomId, job_status: 'in_progress' });
            }
          );
        });
      });
    }
  );
});

/**
 * POST /api/applications/:id/reject - Reject application
 */
app.post('/api/applications/:id/reject', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  db.get(
    `SELECT a.*, j.posted_by as job_owner FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = ?`,
    [id],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row) return res.status(404).json({ error: 'Application not found' });
      if (row.job_owner !== userId) return res.status(403).json({ error: 'Only the job owner can reject applications' });
      if (row.status !== 'pending') return res.status(400).json({ error: 'Application already processed' });

      db.run(`UPDATE applications SET status = 'rejected' WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to reject' });
        createNotification(row.user_id, 'application_rejected', 'Application Rejected', `Your application for job #${row.job_id} was rejected.`, row.job_id, 'job');
        res.json({ success: true, status: 'rejected' });
      });
    }
  );
});

/**
 * POST /api/applications/:id/view - Mark application as viewed by client
 */
app.post('/api/applications/:id/view', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  db.get(
    `SELECT a.*, j.posted_by as job_owner FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = ?`,
    [id],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row) return res.status(404).json({ error: 'Application not found' });
      if (row.job_owner !== userId) return res.status(403).json({ error: 'Only the job owner can mark as viewed' });

      db.run(`UPDATE applications SET status = 'viewed' WHERE id = ? AND status = 'pending'`, [id], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to update' });
        res.json({ success: true, status: 'viewed' });
      });
    }
  );
});

// ════════════════════════════════════════════════════════════════
//  OFFERS — direct offers between client and freelancer
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/offers/:jobId - Get all offers for a job (as client)
 */
app.get('/api/offers/:jobId', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { jobId } = req.params;

  db.get(`SELECT * FROM jobs WHERE id = ?`, [jobId], (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    
    // Allow both job owner and offer recipients to view offers
    const isOwner = job.posted_by === userId;
    
    let sql, params;
    if (isOwner) {
      sql = `SELECT o.*, u.username as freelancer_name FROM offers o LEFT JOIN users u ON o.freelancer_id = u.id WHERE o.job_id = ? ORDER BY o.created_at DESC`;
      params = [jobId];
    } else {
      // Freelancer sees only their own offers for this job
      sql = `SELECT o.*, u.username as client_name FROM offers o LEFT JOIN users u ON o.client_id = u.id WHERE o.job_id = ? AND o.freelancer_id = ? ORDER BY o.created_at DESC`;
      params = [jobId, userId];
    }

    db.all(sql, params, (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows || []);
    });
  });
});

/**
 * POST /api/offers/:id/accept - Accept a direct offer
 */
app.post('/api/offers/:id/accept', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  db.get(`SELECT * FROM offers WHERE id = ?`, [id], (err, offer) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    if (offer.client_id !== userId) return res.status(403).json({ error: 'Only the offer recipient can accept' });
    if (offer.status !== 'pending') return res.status(400).json({ error: 'Offer already processed' });

    db.run(`UPDATE offers SET status = 'accepted' WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to accept' });
      createNotification(offer.freelancer_id, 'offer_accepted', 'Offer Accepted', `Your offer for job #${offer.job_id} was accepted!`, offer.job_id, 'job');
      res.json({ success: true, status: 'accepted' });
    });
  });
});

/**
 * POST /api/offers/:id/decline - Decline a direct offer
 */
app.post('/api/offers/:id/decline', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  db.get(`SELECT * FROM offers WHERE id = ?`, [id], (err, offer) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    if (offer.client_id !== userId) return res.status(403).json({ error: 'Only the offer recipient can decline' });
    if (offer.status !== 'pending') return res.status(400).json({ error: 'Offer already processed' });

    db.run(`UPDATE offers SET status = 'declined' WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to decline' });
      createNotification(offer.freelancer_id, 'offer_declined', 'Offer Declined', `Your offer for job #${offer.job_id} was declined.`, offer.job_id, 'job');
      res.json({ success: true, status: 'declined' });
    });
  });
});

/**
 * GET /api/applications/me - Get my applications (as freelancer)
 */
app.get('/api/applications/me', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100); // max 100
  const offset = (page - 1) * limit;

  try {
    db.get(`SELECT COUNT(*) as total FROM applications WHERE user_id = ?`, [userId], (err, countRow) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const total = countRow ? countRow.total : 0;

      db.all(
        `SELECT a.*, j.title as job_title, j.status as job_status, j.budget, j.posted_by_name, j.category
         FROM applications a
         JOIN jobs j ON a.job_id = j.id
         WHERE a.user_id = ?
         ORDER BY a.created_at DESC
         LIMIT ? OFFSET ?`,
        [userId, limit, offset],
        (err, rows) => {
          if (err) return res.status(500).json({ error: 'Database error' });
          res.json({
            applications: rows || [],
            total: total,
            page: page,
            limit: limit,
            total_pages: Math.ceil(total / limit)
          });
        }
      );
    });
  } catch (err) {
    console.error('[Applications/Me] Error:', err);
    res.status(500).json({ error: 'Failed to fetch applications' });
  }
});

/**
 * GET /api/applications/user/:userId - Get applications for a user (returns ARRAY for frontend compatibility)
 */
app.get('/api/applications/user/:userId', async (req, res) => {
  const authUserId = req.headers['x-user-id'];
  if (!authUserId) return res.status(401).json({ error: 'Authentication required' });
  // Use x-user-id from headers for security (frontend injects it via interceptor)
  // URL param is ignored — user can only view their own applications

  db.all(
    `SELECT a.*, j.title as job_title, j.status as job_status, j.budget, j.posted_by_name, j.category
     FROM applications a
     JOIN jobs j ON a.job_id = j.id
     WHERE a.user_id = ?
     ORDER BY a.created_at DESC`,
    [authUserId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      // Return ARRAY (not object) — frontend expects this
      res.json(rows || []);
    }
  );
});

// ════════════════════════════════════════════════════════════════
//  CHAT
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/chat/rooms - Get my chat rooms
 */
app.get('/api/chat/rooms', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  db.all(
    `SELECT r.*,
      CASE WHEN r.user1_id = ? THEN r.user2_id ELSE r.user1_id END as other_user_id
     FROM chat_rooms r WHERE r.user1_id = ? OR r.user2_id = ? ORDER BY r.created_at DESC`,
    [userId, userId, userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows || []);
    }
  );
});

/**
 * GET /api/chat/:roomId/messages - Get messages for a room
 * Query params:
 *   since — ISO timestamp to get only messages after this time (for real-time polling)
 *   limit — max messages (default 200, max 500)
 */
app.get('/api/chat/:roomId/messages', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { roomId } = req.params;
  const since = req.query.since; // ISO timestamp for real-time polling
  const limit = Math.min(parseInt(req.query.limit) || 200, 500);

  db.get(
    `SELECT * FROM chat_rooms WHERE id = ? AND (user1_id = ? OR user2_id = ?)`,
    [roomId, userId, userId],
    (err, room) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!room) return res.status(403).json({ error: 'Access denied to this chat room' });

      let sql = `SELECT * FROM chat_messages WHERE room_id = ?`;
      let params = [roomId];

      if (since) {
        sql += ` AND created_at > ?`;
        params.push(since);
      }

      sql += ` ORDER BY created_at ASC LIMIT ?`;
      params.push(limit);

      db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
      });
    }
  );
});

/**
 * POST /api/chat/:roomId/messages - Send a message
 */
app.post('/api/chat/:roomId/messages', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { roomId } = req.params;
  const { message, sender_name } = req.body;

  if (!message || !message.trim()) return res.status(400).json({ error: 'Message is required' });

  const safeMessage = sanitizeString(message, 1000);
  if (!safeMessage) return res.status(400).json({ error: 'Message is required (1-1000 characters)' });

  // Verify room access
  db.get(
    `SELECT * FROM chat_rooms WHERE id = ? AND (user1_id = ? OR user2_id = ?)`,
    [roomId, userId, userId],
    (err, room) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!room) return res.status(403).json({ error: 'Access denied to this chat room' });

      // Determine recipient
      const recipientId = room.user1_id === userId ? room.user2_id : room.user1_id;

      db.run(
        `INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES (?, ?, ?, ?)`,
        [roomId, userId, sanitizeString(sender_name, 50) || 'User', safeMessage],
        function(err) {
          if (err) return res.status(500).json({ error: 'Failed to send message' });

          // Notify recipient
          createNotification(recipientId, 'chat_message', 'New Message', `${sanitizeString(sender_name, 50) || 'Someone'}: ${safeMessage.slice(0, 50)}`, roomId, 'chat_room');

          res.json({
            success: true,
            id: this.lastID,
            room_id: roomId,
            sender_id: userId,
            message: safeMessage,
            created_at: new Date().toISOString()
          });
        }
      );
    }
  );
});

/**
 * POST /api/chat/start - Start a new chat with a user
 */
app.post('/api/chat/start', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { user_id, other_user_id } = req.body;
  if (!user_id || !other_user_id) return res.status(400).json({ error: 'Missing user_id or other_user_id' });
  if (userId !== user_id) return res.status(403).json({ error: 'Access denied' });
  if (user_id === other_user_id) return res.status(400).json({ error: 'Cannot start chat with yourself' });

  const u1 = user_id < other_user_id ? user_id : other_user_id;
  const u2 = user_id < other_user_id ? other_user_id : user_id;

  db.get(`SELECT * FROM chat_rooms WHERE user1_id = ? AND user2_id = ?`, [u1, u2], (err, room) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (room) return res.json({ room_id: room.id, existing: true });

    const roomId = 'room_' + Date.now();
    db.run(`INSERT INTO chat_rooms (id, user1_id, user2_id) VALUES (?, ?, ?)`, [roomId, u1, u2], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create chat room' });
      res.json({ room_id: roomId, existing: false });
    });
  });
});

/**
 * POST /api/chat/rooms - Create chat room (frontend compatibility)
 */
app.post('/api/chat/rooms', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { participant_id, other_user_id } = req.body;
  const targetId = participant_id || other_user_id;
  if (!targetId) return res.status(400).json({ error: 'Missing participant_id or other_user_id' });
  if (userId === targetId) return res.status(400).json({ error: 'Cannot start chat with yourself' });

  const u1 = userId < targetId ? userId : targetId;
  const u2 = userId < targetId ? targetId : userId;

  db.get(`SELECT * FROM chat_rooms WHERE user1_id = ? AND user2_id = ?`, [u1, u2], (err, room) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (room) return res.json({ id: room.id, room_id: room.id, existing: true, participants: [u1, u2] });

    const roomId = 'room_' + Date.now();
    db.run(`INSERT INTO chat_rooms (id, user1_id, user2_id) VALUES (?, ?, ?)`, [roomId, u1, u2], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create chat room' });
      res.json({ id: roomId, room_id: roomId, existing: false, participants: [u1, u2] });
    });
  });
});

// ════════════════════════════════════════════════════════════════
//  NOTIFICATIONS
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/notifications - Get user notifications
 */
app.get('/api/notifications', (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  db.all(
    `SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`,
    [userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ notifications: rows || [], count: (rows || []).length });
    }
  );
});

/**
 * GET /api/notifications/unread-count - Get unread count
 */
app.get('/api/notifications/unread-count', (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  db.get(
    `SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0`,
    [userId],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ unread_count: row ? row.count : 0 });
    }
  );
});

/**
 * PUT /api/notifications/:id/read - Mark as read
 */
app.put('/api/notifications/:id/read', (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  db.run(
    `UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?`,
    [req.params.id, userId],
    function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, read: this.changes > 0 });
    }
  );
});

/**
 * PUT /api/notifications/read-all - Mark all as read
 */
app.put('/api/notifications/read-all', (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  db.run(
    `UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0`,
    [userId],
    function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, marked_read: this.changes });
    }
  );
});

// ════════════════════════════════════════════════════════════════
//  ESCROW
// ════════════════════════════════════════════════════════════════

/**
 * POST /api/escrows - Create escrow
 */
app.post('/api/escrows', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  let { job_id, jobId, client_id, clientId, freelancer_id, freelancerId, amount } = req.body;
  // Support both snake_case and camelCase
  if (!job_id && jobId) job_id = jobId;
  if (!client_id && clientId) client_id = clientId;
  if (!freelancer_id && freelancerId) freelancer_id = freelancerId;
  if (!client_id) client_id = userId;
  if (!job_id || !freelancer_id || !amount) {
    return res.status(400).json({ error: 'Missing required fields: job_id, freelancer_id, amount' });
  }
  if (client_id !== userId) return res.status(403).json({ error: 'Can only create escrow as client' });

  getJob(job_id, (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== userId) return res.status(403).json({ error: 'Only the job owner can create escrow' });

    const id = 'esc_' + Date.now();
    db.run(
      `INSERT INTO escrows (id, job_id, client_id, freelancer_id, amount) VALUES (?, ?, ?, ?, ?)`,
      [id, job_id, client_id, freelancer_id, amount],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to create escrow' });
        db.run(`UPDATE jobs SET status = 'in_progress' WHERE id = ?`, [job_id], function(err) {
          if (err) console.warn('[DB] Job status update warning:', err.message);
          res.json({ id, success: true, status: 'pending' });
        });
      }
    );
  });
});

/**
 * GET /api/escrows/me - Get my escrows (convenience alias)
 * NOTE: Must be BEFORE /api/escrows/:id to avoid 'me' being treated as id
 */
app.get('/api/escrows/me', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100); // max 100
  const offset = (page - 1) * limit;

  db.get(`SELECT COUNT(*) as total FROM escrows WHERE client_id = ? OR freelancer_id = ?`, [userId, userId], (err, countRow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const total = countRow ? countRow.total : 0;

    db.all(
      `SELECT * FROM escrows WHERE client_id = ? OR freelancer_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [userId, userId, limit, offset],
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ escrows: rows || [], total, page, limit, total_pages: Math.ceil(total / limit) });
      }
    );
  });
});

/**
 * GET /api/escrows/:id - Get escrow
 */
app.get('/api/escrows/:id', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  db.get(`SELECT * FROM escrows WHERE id = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'Escrow not found' });
    if (row.client_id !== userId && row.freelancer_id !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }
    res.json(row);
  });
});

/**
 * POST /api/escrows/:id/fund - Fund escrow
 */
app.post('/api/escrows/:id/fund', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  getEscrow(id, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== userId && escrow.freelancer_id !== userId) return res.status(403).json({ error: 'Only client or freelancer can fund escrow' });
    if (escrow.status !== 'pending') return res.status(400).json({ error: `Escrow is ${escrow.status}, not pending` });

    db.run(
      `UPDATE escrows SET status = 'funded', funded_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [id],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to fund' });
        createNotification(escrow.freelancer_id, 'escrow_funded', 'Escrow Funded', `The escrow for job #${escrow.job_id} has been funded (${escrow.amount} Pi). Start working!`, escrow.id, 'escrow');
        res.json({ success: true, status: 'funded' });
      }
    );
  });
});

/**
 * POST /api/escrows/:id/release - Release payment to freelancer
 */
app.post('/api/escrows/:id/release', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  getEscrow(id, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== userId) return res.status(403).json({ error: 'Only the client can release escrow' });
    if (escrow.status !== 'funded') return res.status(400).json({ error: `Escrow is ${escrow.status}, must be funded` });

    db.run(`UPDATE escrows SET status = 'released', released_at = CURRENT_TIMESTAMP WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to release' });

      db.run(`UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + ? WHERE id = ?`, [escrow.amount, escrow.freelancer_id], function(err) {
        if (err) console.warn('[DB] Freelancer balance update warning:', err.message);

        db.run(`UPDATE jobs SET status = 'completed' WHERE id = ?`, [escrow.job_id], function(err) {
          if (err) console.warn('[DB] Job status update warning:', err.message);

          createNotification(escrow.freelancer_id, 'escrow_released', 'Payment Released', `Payment of ${escrow.amount} Pi released for job #${escrow.job_id}!`, escrow.id, 'escrow');

          db.get(`SELECT balance_pi FROM users WHERE id = ?`, [escrow.freelancer_id], (err, row) => {
            const newBalance = row ? row.balance_pi : null;
            res.json({ success: true, status: 'released', freelancer_new_balance: newBalance });
          });
        });
      });
    });
  });
});

/**
 * POST /api/escrows/:id/cancel - Cancel escrow (client only, pending only)
 */
app.post('/api/escrows/:id/cancel', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  getEscrow(id, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== userId) return res.status(403).json({ error: 'Only the client can cancel escrow' });
    if (escrow.status !== 'pending') return res.status(400).json({ error: `Escrow is ${escrow.status}, only pending can be cancelled` });

    db.run(`UPDATE escrows SET status = 'cancelled' WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to cancel escrow' });

      createNotification(escrow.freelancer_id, 'escrow_cancelled', 'Escrow Cancelled', `The escrow for job #${escrow.job_id} has been cancelled.`, escrow.id, 'escrow');

      db.run(`UPDATE jobs SET status = 'cancelled' WHERE id = ?`, [escrow.job_id], function(err) {
        if (err) console.warn('[DB] Job status update warning:', err.message);
        res.json({ success: true, status: 'cancelled' });
      });
    });
  });
});

/**
 * POST /api/escrows/:id/dispute - Dispute an escrow (client or freelancer)
 */
app.post('/api/escrows/:id/dispute', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { id } = req.params;
  getEscrow(id, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== userId && escrow.freelancer_id !== userId) {
      return res.status(403).json({ error: 'Only escrow parties can dispute' });
    }
    if (escrow.status !== 'funded') {
      return res.status(400).json({ error: `Escrow is ${escrow.status}, only funded can be disputed` });
    }

    const reason = sanitizeString(req.body.reason, 500);

    db.run(`UPDATE escrows SET status = 'disputed', disputed_at = CURRENT_TIMESTAMP WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to dispute' });

      const otherParty = (escrow.client_id === userId) ? escrow.freelancer_id : escrow.client_id;
      createNotification(otherParty, 'escrow_disputed', 'Escrow Disputed',
        `Escrow for job #${escrow.job_id} has been disputed${reason ? ': ' + reason : ''}.`, escrow.id, 'escrow');

      res.json({ success: true, status: 'disputed', reason });
    });
  });
});

/**
 * GET /api/escrows/user/:userId - List user's escrows
 */
app.get('/api/escrows/user/:userId', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  if (userId !== req.params.userId) return res.status(403).json({ error: 'Access denied' });

  db.all(
    `SELECT * FROM escrows WHERE client_id = ? OR freelancer_id = ? ORDER BY created_at DESC`,
    [userId, userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows || []);
    }
  );
});

// ════════════════════════════════════════════════════════════════
//  REVIEWS
// ════════════════════════════════════════════════════════════════

/**
 * POST /api/reviews - Create review
 */
app.post('/api/reviews', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { reviewer_id, reviewer_name, target_id, target_name, job_id, job_title, rating, text, escrow_id, escrowId } = req.body;
  
  // Support both snake_case and camelCase
  const escrowId_final = escrow_id || escrowId;
  
  // If no target_id provided, try to get it from escrow
  let final_target_id = target_id;
  
  function doLookupAndProceed() {
    if (!final_target_id && escrowId_final) {
      db.get(`SELECT freelancer_id FROM escrows WHERE id = ?`, [escrowId_final], (err, row) => {
        if (!err && row) final_target_id = row.freelancer_id;
        proceedWithReview();
      });
    } else {
      proceedWithReview();
    }
  }
  
  function proceedWithReview() {
    if (!final_target_id) return res.status(400).json({ error: 'target_id is required (or provide escrow_id)' });
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
    if (reviewer_id && reviewer_id !== userId) return res.status(403).json({ error: 'Can only review as yourself' });

  const safeText = sanitizeString(text, 1000) || '';
  const safeReviewerName = sanitizeString(reviewer_name, 50) || 'User';
  const safeTargetName = sanitizeString(target_name, 50) || 'User';
  const safeJobTitle = sanitizeString(job_title, 120) || '';
  const id = 'rev_' + Date.now();

  db.run(
    `INSERT INTO reviews (id, reviewer_id, reviewer_name, target_id, target_name, job_id, job_title, rating, text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, userId, safeReviewerName, final_target_id, safeTargetName, job_id || null, safeJobTitle, rating, safeText],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to submit review' });

      // Update target user's average rating
      db.all(`SELECT rating FROM reviews WHERE target_id = ?`, [target_id], (err, rows) => {
        if (!err && rows.length > 0) {
          const avg = (rows.reduce((sum, r) => sum + r.rating, 0) / rows.length).toFixed(2);
          db.run(`UPDATE users SET rating = ? WHERE id = ?`, [avg, target_id]);
        }
      });

      res.json({ success: true, id });
    }
  );
  }
  
  doLookupAndProceed();
});

/**
 * GET /api/reviews?user_id= - Get user reviews
 */
app.get('/api/reviews', (req, res) => {
  const { user_id } = req.query;
  if (!user_id) return res.status(400).json({ error: 'user_id query parameter is required' });

  db.all(`SELECT * FROM reviews WHERE target_id = ? ORDER BY created_at DESC`, [user_id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows || []);
  });
});

/**
 * GET /api/reviews/stats/:user_id - Get review stats
 */
app.get('/api/reviews/stats/:user_id', (req, res) => {
  db.all(`SELECT rating FROM reviews WHERE target_id = ?`, [req.params.user_id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const count = rows.length;
    const average_rating = count > 0 ? (rows.reduce((sum, r) => sum + r.rating, 0) / count).toFixed(1) : 0;
    res.json({ count, average_rating: parseFloat(average_rating) });
  });
});

// ════════════════════════════════════════════════════════════════
//  USERS
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/users/:id - User profile
 */
app.get('/api/users/:id', (req, res) => {
  db.get(`SELECT * FROM users WHERE id = ?`, [req.params.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

/**
 * PUT /api/users/:id - Update profile
 */
app.put('/api/users/:id', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  if (userId !== req.params.id) return res.status(403).json({ error: 'Can only update your own profile' });

  const { username, role, bio, skills, availability } = req.body;
  const updates = [];
  const values = [];

  if (username !== undefined) { updates.push('username = ?'); values.push(sanitizeString(username, 50)); }
  if (role !== undefined && ['freelancer', 'client', 'admin'].includes(role)) { updates.push('role = ?'); values.push(role); }
  if (bio !== undefined) { updates.push('bio = ?'); values.push(sanitizeString(bio, 2000)); }
  if (skills !== undefined) {
    let safeSkills = null;
    if (skills) {
      if (Array.isArray(skills)) {
        safeSkills = JSON.stringify(sanitizeArray(skills));
      } else if (typeof skills === 'string') {
        // Accept comma-separated string like "js,react,node"
        safeSkills = JSON.stringify(skills.split(',').map(s => s.trim()).filter(Boolean));
      }
    }
    updates.push('skills = ?'); values.push(safeSkills);
  }
  if (availability !== undefined && ['available', 'busy'].includes(availability)) { updates.push('availability = ?'); values.push(availability); }

  if (updates.length === 0) return res.status(400).json({ error: 'No valid fields to update' });

  values.push(req.params.id);
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values, function(err) {
    if (err) return res.status(500).json({ error: 'Failed to update profile' });
    db.get(`SELECT * FROM users WHERE id = ?`, [req.params.id], (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, user });
    });
  });
});

/**
 * PUT /api/users/:id/avatar - Update user avatar (base64)
 */
app.put('/api/users/:id/avatar', (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  if (userId !== req.params.id) return res.status(403).json({ error: 'Can only update your own avatar' });

  const { avatar } = req.body;
  if (!avatar || typeof avatar !== 'string' || avatar.length > 500000) {
    return res.status(400).json({ error: 'Invalid avatar. Must be base64 string under 500KB' });
  }

  db.run(`UPDATE users SET avatar = ? WHERE id = ?`, [avatar, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to update avatar' });
    res.json({ success: true, avatar_updated: this.changes > 0 });
  });
});

/**
 * POST /api/users/:id/availability - Update availability (frontend compatibility)
 */
app.post('/api/users/:id/availability', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  if (userId !== req.params.id) return res.status(403).json({ error: 'Can only update your own profile' });

  const { availability } = req.body;
  if (!availability || !['available', 'busy'].includes(availability)) {
    return res.status(400).json({ error: 'Invalid availability. Use "available" or "busy"' });
  }

  db.run(`UPDATE users SET availability = ? WHERE id = ?`, [availability, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to update availability' });
    res.json({ success: true, availability });
  });
});

// ════════════════════════════════════════════════════════════════
//  CATEGORIES
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/categories - List categories
 */
app.get('/api/categories', (req, res) => {
  const categories = [
    { id: 'web-development', name: 'Web Development', icon: 'laptop-code' },
    { id: 'mobile-apps', name: 'Mobile Apps', icon: 'mobile-alt' },
    { id: 'design', name: 'Design & Creative', icon: 'paint-brush' },
    { id: 'writing', name: 'Writing & Translation', icon: 'pen' },
    { id: 'marketing', name: 'Marketing & Sales', icon: 'chart-line' },
    { id: 'data-science', name: 'Data Science', icon: 'database' },
    { id: 'video', name: 'Video & Animation', icon: 'video' },
    { id: 'music', name: 'Music & Audio', icon: 'music' },
    { id: 'consulting', name: 'Consulting', icon: 'briefcase' },
    { id: 'virtual-assistant', name: 'Virtual Assistant', icon: 'hands-helping' },
    { id: 'customer-service', name: 'Customer Service', icon: 'headset' },
    { id: 'accounting', name: 'Accounting & Finance', icon: 'calculator' },
    { id: 'legal', name: 'Legal Services', icon: 'gavel' },
    { id: 'engineering', name: 'Engineering', icon: 'cogs' },
    { id: 'other', name: 'Other', icon: 'thumbtack' }
  ];
  res.json(categories);
});

// ════════════════════════════════════════════════════════════════
//  PAYMENTS (Pi Network)
// ════════════════════════════════════════════════════════════════

/**
 * POST /api/payments/:paymentId/approve - Approve payment on Pi Network
 */
app.post('/api/payments/:paymentId/approve', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  const { paymentId } = req.params;
  console.log('[SERVER] Approve request received:', { paymentId, userId });

  // Check if this is a sandbox payment (exists in connects_purchases)
  const sandboxPurchase = await new Promise((resolve) => {
    db.get(`SELECT * FROM connects_purchases WHERE payment_id = ?`, [paymentId], (err, row) => {
      resolve(err ? null : row);
    });
  });

  if (sandboxPurchase) {
    // Sandbox mode: update local status without calling Pi API
    db.run(`UPDATE connects_purchases SET status = 'approved' WHERE payment_id = ?`, [paymentId], (err) => {
      if (err) console.error('[DB] Error updating sandbox purchase:', err);
    });
    db.run(
      `INSERT OR REPLACE INTO payments (id, user_id, username, amount, memo, status) VALUES (?, ?, ?, ?, ?, 'approved')`,
      [paymentId, sandboxPurchase.user_id, 'sandbox_user', sandboxPurchase.pi_amount || 0, 'Sandbox connects purchase'],
      (err) => { if (err) console.error('[DB] Error saving payment:', err); }
    );
    return res.json({ success: true, payment: { id: paymentId, status: 'approved', sandbox: true } });
  }

  if (!PI_API_KEY) return res.status(500).json({ error: 'PI_API_KEY not configured' });

  try {
    const encodedPaymentId = encodeURIComponent(paymentId);
    const response = await fetch(`https://api.minepi.com/v2/payments/${encodedPaymentId}/approve`, {
      method: 'POST',
      headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
    });
    const data = await response.json();

    if (!response.ok) {
      console.error('[Pi API] Approve failed:', data);
      return res.status(response.status).json({ error: data.error || 'Approval failed', details: data });
    }

    const uid = data.user_uid || req.headers['x-user-id'] || 'unknown';
    const username = data.metadata?.user?.username || 'unknown';
    const amount = data.amount || 0;
    const memo = data.memo || '';

    db.run(
      `INSERT OR REPLACE INTO payments (id, user_id, username, amount, memo, status) VALUES (?, ?, ?, ?, ?, 'approved')`,
      [paymentId, uid, username, amount, memo],
      (err) => { if (err) console.error('[DB] Error saving payment:', err); }
    );

    res.json({ success: true, payment: data });
  } catch (err) {
    console.error('[Server] Approve error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

/**
 * POST /api/payments/:paymentId/complete - Complete payment on Pi Network
 */
app.post('/api/payments/:paymentId/complete', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  const { paymentId } = req.params;
  let { txid } = req.body;
  console.log('[SERVER] Complete request received:', { paymentId, txid, userId });

  // Auto-fetch txid from Pi API if not provided by frontend
  if (!txid && PI_API_KEY) {
    try {
      const encodedPaymentId = encodeURIComponent(paymentId);
      const piRes = await fetch(`https://api.minepi.com/v2/payments/${encodedPaymentId}`, {
        headers: { 'Authorization': `Key ${PI_API_KEY}` }
      });
      if (piRes.ok) {
        const piData = await piRes.json();
        if (piData?.transaction?.txid) {
          txid = piData.transaction.txid;
          console.log('[SERVER] Auto-fetched txid from Pi API:', txid);
        }
      }
    } catch (e) { console.error('[SERVER] Auto-fetch txid failed:', e.message); }
  }

  if (!PI_API_KEY) return res.status(500).json({ error: 'PI_API_KEY not configured' });
  if (!txid) return res.status(400).json({ error: 'txid is required' });
  if (!isValidTxid(txid)) return res.status(400).json({ error: 'Invalid txid format' });

  try {
    const encodedPaymentId = encodeURIComponent(paymentId);
    const response = await fetch(`https://api.minepi.com/v2/payments/${encodedPaymentId}/complete`, {
      method: 'POST',
      headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ txid }),
    });
    const data = await response.json();

    if (!response.ok) {
      console.error('[Pi API] Complete failed:', data);
      if (response.status === 404) {
        return res.status(404).json({ error: 'Payment not found on Pi Network' });
      }
      return res.status(response.status).json({ error: data.error || 'Completion failed', details: data });
    }

    db.run(
      `UPDATE payments SET status = 'completed', txid = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [txid, paymentId],
      (err) => { if (err) console.error('[DB] Error updating payment:', err); }
    );

    res.json({ success: true, payment: data });
  } catch (err) {
    console.error('[Server] Complete error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

/**
 * POST /api/payments/:paymentId/cancelled - Cancel payment
 */
app.post('/api/payments/:paymentId/cancelled', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });
  const { paymentId } = req.params;

  if (PI_API_KEY) {
    try {
      const encodedPaymentId = encodeURIComponent(paymentId);
      const piRes = await fetch(`https://api.minepi.com/v2/payments/${encodedPaymentId}/cancel`, {
        method: 'POST',
        headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' }
      });
      if (piRes.ok || piRes.status === 404) {
        console.log('[Pi API] Payment cancelled on Pi Network:', paymentId, 'status:', piRes.status);
      } else {
        console.warn('[Pi API] Cancel warning:', piRes.status);
      }
    } catch (err) {
      console.warn('[Pi API] Cancel network error:', err.message);
    }
  }

  db.run(`UPDATE payments SET status = 'cancelled' WHERE id = ?`, [paymentId]);
  db.run(`UPDATE connects_purchases SET status = 'cancelled' WHERE payment_id = ?`, [paymentId]);

  res.json({ success: true, status: 'cancelled', message: 'Payment cancelled' });
});

/**
 * POST /api/payments/cancel-all-pending - Cancel all pending payments
 */
app.post('/api/payments/cancel-all-pending', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  try {
    const pendingPayments = await new Promise((resolve, reject) => {
      db.all(
        `SELECT payment_id FROM connects_purchases WHERE user_id = ? AND status = 'pending'`,
        [userId],
        (err, rows) => {
          if (err) return reject(err);
          resolve(rows || []);
        }
      );
    });

    const results = [];
    for (const row of pendingPayments) {
      const paymentId = row.payment_id;
      if (PI_API_KEY && paymentId) {
        try {
          const encodedPaymentId = encodeURIComponent(paymentId);
          const piRes = await fetch(`https://api.minepi.com/v2/payments/${encodedPaymentId}/cancel`, {
            method: 'POST',
            headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' }
          });
          results.push({ payment_id: paymentId, pi_status: piRes.status, local: 'cancelled' });
        } catch (e) {
          results.push({ payment_id: paymentId, pi_status: 'error', local: 'cancelled' });
        }
      }
      db.run(`UPDATE payments SET status = 'cancelled' WHERE id = ?`, [paymentId]);
      db.run(`UPDATE connects_purchases SET status = 'cancelled' WHERE payment_id = ?`, [paymentId]);
    }

    res.json({ success: true, message: `Cancelled ${pendingPayments.length} pending payments`, results });
  } catch (err) {
    console.error('[CancelAll] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/payments/:paymentId - Get payment status
 */
app.get('/api/payments/:paymentId', (req, res) => {
  const { paymentId } = req.params;
  db.get(`SELECT * FROM payments WHERE id = ?`, [paymentId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(row || { id: paymentId, status: 'not_found' });
  });
});

// ════════════════════════════════════════════════════════════════
//  CONNECTS PURCHASE
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/connects/balance - Get user's connects balance
 */
app.get('/api/connects/balance', (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  db.get(`SELECT balance_connects, balance_pi FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.json({ balance_connects: 0, balance_pi: 0 });
    res.json({ balance_connects: row.balance_connects || 0, balance_pi: row.balance_pi || 0 });
  });
});

/**
 * POST /api/connects/initiate - Start connects purchase
 */
app.post('/api/connects/initiate', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  if (!PI_API_KEY) return res.status(500).json({ error: 'PI_API_KEY not configured' });

  const { user_id, package_amount, pi_amount, payment_id } = req.body;
  if (!payment_id || !user_id || !package_amount || !pi_amount) {
    return res.status(400).json({ error: 'Missing required fields: user_id, package_amount, pi_amount, payment_id' });
  }
  if (user_id !== userId) return res.status(403).json({ error: 'user_id mismatch' });

  try {
    const result = await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO connects_purchases (user_id, amount, pi_amount, payment_id, status) VALUES (?, ?, ?, ?, 'pending')`,
        [user_id, package_amount, pi_amount, payment_id],
        function(err) {
          if (err) reject(err);
          else resolve({ purchase_id: this.lastID });
        }
      );
    });
    res.json({ success: true, purchase_id: result.purchase_id, payment_id, status: 'pending' });
  } catch (err) {
    console.error('[DB] Initiate error:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/connects/complete - Complete connects purchase
 */
app.post('/api/connects/complete', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { payment_id, txid, user_id, package_amount } = req.body;
  if (!PI_API_KEY || !txid) return res.status(400).json({ error: 'Missing txid or API key' });
  if (!isValidTxid(txid)) return res.status(400).json({ error: 'Invalid txid format' });
  if (user_id !== userId) return res.status(403).json({ error: 'user_id mismatch' });

  try {
    const encodedPaymentId = encodeURIComponent(payment_id);
    const piRes = await fetch(`https://api.minepi.com/v2/payments/${encodedPaymentId}/complete`, {
      method: 'POST',
      headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ txid }),
    });
    if (!piRes.ok) {
      const errData = await piRes.json().catch(() => ({}));
      if (piRes.status === 404) {
        return res.status(404).json({ error: 'Payment not found on Pi Network', details: errData });
      }
      return res.status(piRes.status).json({ error: 'Pi complete failed', details: errData });
    }

    updateUserBalance(user_id, package_amount, 0, (err, result) => {
      if (err) console.warn('[DB] Balance update warning:', err.message);
      const newBalance = result ? result.balance_connects : package_amount;
      db.run(`UPDATE connects_purchases SET status = 'completed' WHERE payment_id = ?`, [payment_id], (err) => {
        if (err) console.error('[DB] Purchase status update error:', err);
        res.json({ success: true, new_balance: newBalance });
      });
    });
  } catch (err) {
    console.error('[Server] Complete error:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/connects/buy - Frontend compatibility (proxies to /approve and /complete)
 * Body: { payment_id, txid, user_id, package_amount, action: 'approve'|'complete' }
 */
app.post('/api/connects/buy', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  const { payment_id, txid, user_id, package_amount, action } = req.body;
  if (user_id !== userId) return res.status(403).json({ error: 'user_id mismatch' });

  const isSandbox = IS_SANDBOX;

  if (action === 'approve' && payment_id) {
    // Sandbox mode: skip Pi API call
    if (isSandbox) {
      return res.json({ success: true, status: 'approved', sandbox: true });
    }
    // Proxy to /api/payments/:id/approve
    if (!PI_API_KEY) return res.status(500).json({ error: 'PI_API_KEY not configured' });
    try {
      const encodedPaymentId = encodeURIComponent(payment_id);
      const response = await fetch(`https://api.minepi.com/v2/payments/${encodedPaymentId}/approve`, {
        method: 'POST',
        headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
      });
      const data = await response.json();
      if (!response.ok) return res.status(response.status).json({ error: data.error || 'Approval failed' });
      return res.json({ success: true, status: 'approved' });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (action === 'complete' && payment_id && txid) {
    // Sandbox mode: skip Pi API call, directly update balance
    if (isSandbox) {
      updateUserBalance(user_id, package_amount || 0, 0, (err, result) => {
        if (err) console.warn('[DB] Balance update warning:', err.message);
        res.json({ success: true, new_balance: result ? result.balance_connects : (package_amount || 0), sandbox: true });
      });
      return;
    }
    // Proxy to /api/payments/:id/complete
    if (!PI_API_KEY || !isValidTxid(txid)) return res.status(400).json({ error: 'Missing API key or invalid txid' });
    try {
      const encodedPaymentId = encodeURIComponent(payment_id);
      const piRes = await fetch(`https://api.minepi.com/v2/payments/${encodedPaymentId}/complete`, {
        method: 'POST',
        headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ txid }),
      });
      const piData = await piRes.json().catch(() => ({}));
      if (!piRes.ok) {
        if (piRes.status === 404) return res.status(404).json({ error: 'Payment not found on Pi Network' });
        return res.status(piRes.status).json({ error: 'Pi complete failed', details: piData });
      }
      // Update balance
      updateUserBalance(user_id, package_amount || 0, 0, (err, result) => {
        if (err) console.warn('[DB] Balance update warning:', err.message);
        res.json({ success: true, new_balance: result ? result.balance_connects : (package_amount || 0) });
      });
      return;
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.status(400).json({ error: 'Invalid action. Use action: "approve" or "complete" with required fields' });
});

// ════════════════════════════════════════════════════════════════
//  ADMIN (Protected)
// ════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  db.get(`SELECT COUNT(*) as total_users FROM users`, [], (err, usersRow) => {
    db.get(`SELECT COUNT(*) as total_jobs FROM jobs`, [], (err, jobsRow) => {
      db.get(`SELECT COUNT(*) as total_applications FROM applications`, [], (err, appsRow) => {
        db.get(`SELECT SUM(amount) as total_escrows FROM escrows`, [], (err, escRow) => {
          res.json({
            total_users: usersRow?.total_users || 0,
            total_jobs: jobsRow?.total_jobs || 0,
            total_applications: appsRow?.total_applications || 0,
            total_escrows: escRow?.total_escrows || 0,
          });
        });
      });
    });
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM users ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/admin/jobs/all', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM jobs ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

/**
 * GET /api/admin/backup - Export database as JSON
 */
app.get('/api/admin/backup', requireAdmin, async (req, res) => {
  try {
    const tables = ['users', 'jobs', 'applications', 'chat_rooms', 'chat_messages', 'escrows', 'notifications', 'payments', 'reviews', 'categories'];
    const backup = {};

    for (const table of tables) {
      const rows = await new Promise((resolve, reject) => {
        db.all(`SELECT * FROM ${table}`, [], (err, rows) => {
          if (err) resolve([]);
          else resolve(rows || []);
        });
      });
      backup[table] = rows;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="workpro-backup-${timestamp}.json"`);
    res.json({
      exported_at: new Date().toISOString(),
      version: '2.2.2 (v146)',
      tables: backup
    });
  } catch (err) {
    console.error('[Admin] Backup error:', err);
    res.status(500).json({ error: 'Backup failed', message: err.message });
  }
});

/**
 * POST /api/admin/deploy - Trigger Render deploy hook
 */
app.post('/api/admin/deploy', requireAdmin, async (req, res) => {
  try {
    const deployHookUrl = process.env.RENDER_DEPLOY_HOOK;
    if (!deployHookUrl) return res.status(500).json({ error: 'RENDER_DEPLOY_HOOK not configured' });
    const response = await fetch(deployHookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    // Render may return plain text or JSON
    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }
    res.json({ success: true, status: response.status, deploy: data });
  } catch (err) {
    console.error('[Admin] Deploy error:', err);
    res.status(500).json({ error: 'Deploy failed', message: err.message });
  }
});

app.get('/api/admin/earnings', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM payments WHERE status = 'completed' ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    db.get(`SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'completed'`, [], (err, sumRow) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ payments: rows, total: sumRow?.total || 0 });
    });
  });
});

/**
 * GET /api/admin/escrows - List all escrows (admin)
 */
app.get('/api/admin/escrows', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM escrows ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    db.get(`SELECT COUNT(*) as total, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending_count, SUM(CASE WHEN status='funded' THEN 1 ELSE 0 END) as funded_count, SUM(CASE WHEN status='released' THEN 1 ELSE 0 END) as released_count, SUM(CASE WHEN status='disputed' THEN 1 ELSE 0 END) as disputed_count, SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END) as cancelled_count, COALESCE(SUM(amount), 0) as total_volume FROM escrows`, [], (err, statsRow) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ escrows: rows || [], stats: statsRow || {} });
    });
  });
});

// ════════════════════════════════════════════════════════════════
//  GRACEFUL SHUTDOWN
// ════════════════════════════════════════════════════════════════

function gracefulShutdown(signal) {
  console.log(`[WorkPro Backend] ${signal} received. Closing database and server...`);
  db.close((err) => {
    if (err) console.error('[DB] Error closing database:', err);
    else console.log('[DB] Database connection closed.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ════════════════════════════════════════════════════════════════
//  START SERVER
// ════════════════════════════════════════════════════════════════
//  DEBUG (temporary)
// ════════════════════════════════════════════════════════════════

/**
 * POST /api/debug/notif-test - Test notification insert
 */
app.post('/api/debug/notif-test', (req, res) => {
  const { userId } = req.body;
  const id = 'notif_' + Date.now();
  db.run(
    `INSERT INTO notifications (id, user_id, type, title, message) VALUES (?, ?, ?, ?, ?)`,
    [id, userId || 'test_user', 'test', 'Test Title', 'Test Message'],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id: id });
    }
  );
});

/**
 * GET /api/debug/db - Check database tables
 */
app.get('/api/debug/db', (req, res) => {
  db.all(`SELECT name FROM sqlite_master WHERE type='table'`, [], (err, tables) => {
    if (err) return res.status(500).json({ error: err.message });
    db.all(`SELECT COUNT(*) as count FROM notifications`, [], (err2, count) => {
      res.json({ tables: tables.map(t => t.name), notifications_count: err2 ? err2.message : count[0].count });
    });
  });
});

// ════════════════════════════════════════════════════════════════

const server = app.listen(PORT, () => {
  console.log(`[WorkPro Backend] Running on port ${PORT}`);
  console.log(`[WorkPro Backend] Environment: ${NODE_ENV}`);
  console.log(`[WorkPro Backend] Frontend allowed: ${corsOrigins.join(', ')}`);
  console.log(`[WorkPro Backend] Pi API Key: ${PI_API_KEY ? 'Configured' : 'MISSING!'}`);
  console.log(`[WorkPro Backend] Admin API Key: ${ADMIN_API_KEY ? 'Configured' : 'MISSING!'}`);
  console.log(`[WorkPro Backend] Database: ${dbPath}`);

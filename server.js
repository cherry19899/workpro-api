require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const PI_API_KEY = process.env.PI_API_KEY;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || process.env.WORKPRO_API_ACCESS;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';
const NODE_ENV = process.env.NODE_ENV || 'production';

// ─── Rate Limiting ────────────────────────────────────────────
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 100; // requests per window
const PAYMENT_RATE_LIMIT_MAX = 10; // stricter for payment endpoints

function rateLimit(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  const isPaymentEndpoint = req.path && (req.path.includes('/payments') || req.path.includes('/connects'));
  const limit = isPaymentEndpoint ? PAYMENT_RATE_LIMIT_MAX : RATE_LIMIT_MAX;

  // HIGH-006 FIX: Cap map size + cleanup old entries
  const MAX_MAP_SIZE = 10000;
  if (rateLimitMap.size >= MAX_MAP_SIZE && !rateLimitMap.has(key)) {
    const firstKey = rateLimitMap.keys().next().value;
    if (firstKey !== undefined) rateLimitMap.delete(firstKey);
  }
  // Cleanup old entries (memory leak fix)
  for (const [k, v] of rateLimitMap.entries()) {
    if (now > v.resetTime) rateLimitMap.delete(k);
  }

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

// ─── Admin Auth Middleware ────────────────────────────────────
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  // Admin via x-admin-secret (from Render env var)
  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret && process.env.ADMIN_SECRET && adminSecret === process.env.ADMIN_SECRET) {
    return next();
  }

  // Owner access (cherry19899 is the project owner)
  if (req.headers['x-user-id'] === 'cherry19899') {
    return next();
  }

  if (!token) {
    return res.status(401).json({ error: 'Admin authentication required. Use: Authorization: Bearer <token> or x-admin-secret' });
  }

  // Check against ALL configured admin keys (supports multiple env vars)
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

// ─── Body Parser Limits (for photo uploads) ───────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ─── User Auth Middleware ─────────────────────────────────────
function requireUser(req, res, next) {
  // CORS preflight: skip auth check (browser sends OPTIONS without custom headers)
  if (req.method === 'OPTIONS') return next();
  const userId = req.headers['x-user-id'];
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required. Missing x-user-id header.' });
  }
  req.userId = userId;
  next();
}

function requireBodyUserMatch(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  const userId = req.headers['x-user-id'];
  const bodyUserId = req.body.user_id || req.body.posted_by || req.body.client_id || req.body.reviewer_id;
  if (bodyUserId && bodyUserId !== userId) {
    return res.status(403).json({ error: 'You can only act on your own behalf.' });
  }
  next();
}

// ─── Payment Signature Verification ────────────────────────────
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
    const response = await fetchWithRetry(`https://api.minepi.com/v2/payments/${paymentId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Key ${PI_API_KEY}`,
        'Content-Type': 'application/json',
      },
    });
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    console.error('[Pi API] Verification error:', e.message);
    return null;
  }
}

// ─── TXID Validation ──────────────────────────────────────────
function isValidTxid(txid) {
  return typeof txid === 'string' && /^[a-fA-F0-9]{64}$/.test(txid);
}

// ─── CORS Configuration ───────────────────────────────────────
const corsOrigins = NODE_ENV === 'production'
  ? [FRONTEND_URL, 'https://cherry19899.github.io']
  : [FRONTEND_URL, 'https://cherry19899.github.io', 'http://localhost:5173', 'http://localhost:3000'];

app.use(cors({
  origin: corsOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-pi-token', 'x-admin-secret'],
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

// ─── SQLite Database ────────────────────────────────────────────
const dbPath = '/var/data/workpro.db';
const db = new sqlite3.Database(dbPath);

// Prevent SQLITE_BUSY errors under concurrent load
// WAL mode improves write performance and concurrency

db.serialize(() => {
  db.run(`PRAGMA busy_timeout = 10000`);
  db.run(`PRAGMA journal_mode = WAL`);
  db.run(`CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT,
    amount REAL NOT NULL,
    memo TEXT,
    status TEXT DEFAULT 'pending',
    txid TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT DEFAULT 'freelancer',
    balance_connects INTEGER DEFAULT 0,
    balance_pi REAL DEFAULT 0,
    kyc_verified INTEGER DEFAULT 0,
    availability TEXT DEFAULT 'available',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'other',
    budget REAL DEFAULT 0,
    skills TEXT,
    images TEXT,
    deadline TEXT,
    status TEXT DEFAULT 'open',
    posted_by TEXT NOT NULL,
    posted_by_name TEXT,
    applications INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT,
    message TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS escrows (
    id TEXT PRIMARY KEY,
    job_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    freelancer_id TEXT,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    funded_at DATETIME,
    released_at DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS escrow_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    escrow_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_name TEXT,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS connects_purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    pi_amount REAL NOT NULL,
    payment_id TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY,
    reviewer_id TEXT NOT NULL,
    reviewer_name TEXT,
    target_id TEXT NOT NULL,
    target_name TEXT,
    job_id TEXT,
    job_title TEXT,
    rating INTEGER NOT NULL,
    text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS offers (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_name TEXT,
    freelancer_id TEXT NOT NULL,
    freelancer_name TEXT,
    job_id TEXT,
    job_title TEXT,
    amount REAL DEFAULT 0,
    message TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS chat_rooms (
    id TEXT PRIMARY KEY,
    user1_id TEXT NOT NULL,
    user2_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_name TEXT,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ─── Indexes for performance ──────────────────────────────────
  db.run(`CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_jobs_posted_by ON jobs(posted_by)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_jobs_category ON jobs(category)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_applications_job ON applications(job_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_escrows_job ON escrows(job_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_escrows_client ON escrows(client_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_escrows_freelancer ON escrows(freelancer_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_reviews_target ON reviews(target_name)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_connects_payment ON connects_purchases(payment_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_connects_user ON connects_purchases(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_offers_freelancer ON offers(freelancer_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_escrow_messages_escrow ON escrow_messages(escrow_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_chat_rooms_user1 ON chat_rooms(user1_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_chat_rooms_user2 ON chat_rooms(user2_id)`);
  db.run(`CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    endpoint TEXT NOT NULL UNIQUE,
    auth TEXT,
    p256dh TEXT,
    created_at INTEGER
  )`);

  // ─── Indexes for performance ──────────────────────────────────
  db.run(`CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_jobs_posted_by ON jobs(posted_by)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_jobs_category ON jobs(category)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_applications_job ON applications(job_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_escrows_job ON escrows(job_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_escrows_client ON escrows(client_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_escrows_freelancer ON escrows(freelancer_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_reviews_target ON reviews(target_name)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_connects_payment ON connects_purchases(payment_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_connects_user ON connects_purchases(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_offers_freelancer ON offers(freelancer_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_escrow_messages_escrow ON escrow_messages(escrow_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_chat_rooms_user1 ON chat_rooms(user1_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_chat_rooms_user2 ON chat_rooms(user2_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_chat_messages_room ON chat_messages(room_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id)`);
});

// ─── Input Validation Helpers ───────────────────────────────────
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

// ─── Startup Security Check ────────────────────────────────────
if (!ADMIN_API_KEY) {
  console.warn('[Security] ADMIN_API_KEY is not set! Admin endpoints will return 403.');
}
if (!PI_API_KEY) {
  console.warn('[Security] PI_API_KEY is not set! Pi payment endpoints will return 500.');
}

// ─── Helpers ────────────────────────────────────────────────────
function getUser(userId, callback) {
  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err) return callback(err, null);
    callback(null, row || null);
  });
}

function createUser(userId, username, callback) {
  db.run(`INSERT INTO users (id, username, balance_connects) VALUES (?, ?, ?)`, [userId, username || 'User_' + userId.slice(0, 8), 0], (err) => {
    if (err) return callback(err, null);
    db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, row) => callback(err, row));
  });
}

function updateUserBalance(userId, connectsDelta, piDelta, callback) {
  db.run('BEGIN TRANSACTION', (err) => {
    if (err) return callback(err);
    getUser(userId, (err, user) => {
      if (err) {
        db.run('ROLLBACK');
        return callback(err);
      }
      if (!user) {
        // Auto-create user with default balance
        db.run(`INSERT INTO users (id, username, balance_connects, balance_pi) VALUES (?, ?, ?, ?)`,
          [userId, 'User_' + userId.slice(0, 8), connectsDelta, piDelta],
          (err) => {
            if (err) {
              db.run('ROLLBACK');
              return callback(err);
            }
            db.run('COMMIT', (err) => {
              if (err) {
                db.run('ROLLBACK');
                return callback(err);
              }
              callback(null, { balance_connects: connectsDelta, balance_pi: piDelta });
            });
          }
        );
        return;
      }
      const newConnects = (user.balance_connects || 0) + connectsDelta;
      const newPi = (user.balance_pi || 0) + piDelta;
      db.run(`UPDATE users SET balance_connects = ?, balance_pi = ? WHERE id = ?`, [newConnects, newPi, userId], (err) => {
        if (err) {
          db.run('ROLLBACK');
          return callback(err);
        }
        db.run('COMMIT', (err) => {
          if (err) {
            db.run('ROLLBACK');
            return callback(err);
          }
          callback(null, { balance_connects: newConnects, balance_pi: newPi });
        });
      });
    });
  });
}

function getJob(jobId, callback) {
  db.get(`SELECT * FROM jobs WHERE id = ?`, [jobId], (err, row) => {
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

// ─── Health Check ───────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Work Pro Backend Running', pi_api_configured: !!PI_API_KEY, admin_configured: !!ADMIN_API_KEY, env: NODE_ENV });
});

app.get('/health', (req, res) => {
  const mem = process.memoryUsage();
  db.get(`SELECT 1 as ok`, [], (err) => {
    res.json({
      status: 'ok',
      uptime: process.uptime(),
      memory: { rss: mem.rss, heapUsed: mem.heapUsed },
      database: err ? 'error' : 'connected',
      pi_api_configured: !!PI_API_KEY,
      admin_configured: !!ADMIN_API_KEY,
      version: require('./package.json').version,
      timestamp: new Date().toISOString(),
    });
  });
});

// ─── Approve Pi Payment ───────────────────────────────────────
app.post('/api/payments/:paymentId/approve', requireUser, async (req, res) => {
  const { paymentId } = req.params;

  if (!PI_API_KEY) {
    return res.status(500).json({ error: 'PI_API_KEY not configured' });
  }

  try {
    const response = await fetch(`https://api.minepi.com/v2/payments/${paymentId}/approve`, {
      method: 'POST',
      headers: {
        'Authorization': `Key ${PI_API_KEY}`,
        'Content-Type': 'application/json',
      },
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('[Pi API] Approve failed:', data);
      return res.status(response.status).json({ error: data.error || 'Approval failed', details: data });
    }

    // Save payment record (use Pi API data if available, else body)
    const uid = data.user_uid || req.body?.user?.uid || req.userId || 'unknown';
    const username = data.metadata?.user?.username || req.body?.user?.username || 'unknown';
    const amount = data.amount || req.body?.amount || 0;
    const memo = data.memo || req.body?.memo || '';

    db.run(
      `INSERT OR REPLACE INTO payments (id, user_id, username, amount, memo, status) VALUES (?, ?, ?, ?, ?, 'approved')`,
      [paymentId, uid, username, amount, memo],
      (err) => {
        if (err) console.error('[DB] Error saving payment:', err);
      }
    );

    console.log('[Pi API] Payment approved:', paymentId);
    res.json({ success: true, payment: data });
  } catch (err) {
    console.error('[Server] Approve error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

// ─── Complete Pi Payment ──────────────────────────────────────
app.post('/api/payments/:paymentId/complete', requireUser, async (req, res) => {
  const { paymentId } = req.params;
  const { txid } = req.body;

  if (!PI_API_KEY) {
    return res.status(500).json({ error: 'PI_API_KEY not configured' });
  }

  if (!txid) {
    return res.status(400).json({ error: 'txid is required' });
  }

  // Validate txid format (64-char hex)
  if (!isValidTxid(txid)) {
    return res.status(400).json({ error: 'Invalid txid format. Must be 64-character hex string.' });
  }

  try {
    const response = await fetch(`https://api.minepi.com/v2/payments/${paymentId}/complete`, {
      method: 'POST',
      headers: {
        'Authorization': `Key ${PI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ txid }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('[Pi API] Complete failed:', data);
      return res.status(response.status).json({ error: data.error || 'Completion failed', details: data });
    }

    // Update payment status
    db.run(
      `UPDATE payments SET status = 'completed', txid = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [txid, paymentId],
      (err) => {
        if (err) console.error('[DB] Error updating payment:', err);
      }
    );

    console.log('[Pi API] Payment completed:', paymentId, 'txid:', txid);
    res.json({ success: true, payment: data });
  } catch (err) {
    console.error('[Server] Complete error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

// ─── Cancelled Payment Webhook ──────────────────────────────────
app.post('/api/payments/:paymentId/cancelled', async (req, res) => {
  const { paymentId } = req.params;

  // Verify payment exists on Pi Network before cancelling
  const piPayment = await verifyPaymentWithPi(paymentId);
  if (!piPayment) {
    return res.status(400).json({ error: 'Payment not found on Pi Network' });
  }

  // Only allow cancelling payments that are still pending
  if (piPayment.status !== 'pending' && piPayment.status !== 'approved') {
    return res.status(400).json({ error: 'Payment cannot be cancelled in current state: ' + piPayment.status });
  }

  db.run(
    `UPDATE payments SET status = 'cancelled' WHERE id = ?`,
    [paymentId],
    (err) => {
      if (err) console.error('[DB] Error updating payment:', err);
    }
  );

  console.log('[Pi API] Payment cancelled:', paymentId);
  res.json({ success: true, message: 'Payment marked as cancelled' });
});

// ─── Check Payment Status on Pi Network ──────────────────────
app.get('/api/payments/:paymentId/status', async (req, res) => {
  const { paymentId } = req.params;
  if (!PI_API_KEY) return res.status(500).json({ error: 'PI_API_KEY not configured' });

  try {
    const piPayment = await verifyPaymentWithPi(paymentId);
    if (!piPayment) {
      return res.status(404).json({ error: 'Payment not found on Pi Network' });
    }
    res.json({
      payment_id: paymentId,
      pi_status: piPayment.status,
      amount: piPayment.amount,
      memo: piPayment.memo,
      metadata: piPayment.metadata,
      txid: piPayment.transaction?.txid || null,
    });
  } catch (err) {
    console.error('[Server] Status check error:', err);
    res.status(500).json({ error: 'Failed to check payment status', message: err.message });
  }
});

// ─── Handle Incomplete Payments (onIncompletePaymentFound) ───
app.post('/api/payments/incomplete', requireUser, async (req, res) => {
  const { payment_id, txid, user_id, package_amount } = req.body;
  if (!payment_id) {
    return res.status(400).json({ error: 'payment_id is required' });
  }
  if (!PI_API_KEY) return res.status(500).json({ error: 'PI_API_KEY not configured' });

  try {
    // Verify payment on Pi Network
    const piPayment = await verifyPaymentWithPi(payment_id);
    if (!piPayment) {
      return res.status(404).json({ error: 'Payment not found on Pi Network' });
    }

    // If it's already completed on Pi, complete it locally
    if (piPayment.status === 'completed' && txid) {
      if (!isValidTxid(txid)) {
        return res.status(400).json({ error: 'Invalid txid format' });
      }
      db.run(
        `INSERT OR REPLACE INTO payments (id, user_id, username, amount, memo, status, txid, completed_at) VALUES (?, ?, ?, ?, ?, 'completed', ?, CURRENT_TIMESTAMP)`,
        [payment_id, user_id || req.userId, req.body.username || 'unknown', req.body.amount || piPayment.amount, req.body.memo || piPayment.memo || '', txid],
        (err) => { if (err) console.error('[DB] Error saving completed payment:', err); }
      );
      // Also update connects purchase if applicable
      if (package_amount && user_id) {
        updateUserBalance(user_id, package_amount, 0, (err) => {
          if (err) console.error('[DB] Balance update error:', err);
        });
        db.run(`UPDATE connects_purchases SET status = 'completed' WHERE payment_id = ?`, [payment_id]);
      }
      return res.json({ success: true, status: 'completed', message: 'Payment was already completed on Pi Network' });
    }

    // If cancelled, mark as cancelled locally
    if (piPayment.status === 'cancelled') {
      db.run(`UPDATE payments SET status = 'cancelled' WHERE id = ?`, [payment_id]);
      db.run(`UPDATE connects_purchases SET status = 'cancelled' WHERE payment_id = ?`, [payment_id]);
      return res.json({ success: true, status: 'cancelled', message: 'Payment was cancelled on Pi Network' });
    }

    // Still pending or approved — just return current status
    res.json({ success: true, status: piPayment.status, message: 'Payment is still in progress' });
  } catch (err) {
    console.error('[Server] Incomplete payment error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

// ─── Get Payment Status ───────────────────────────────────────
app.get('/api/payments/:paymentId', requireUser, (req, res) => {
  const { paymentId } = req.params;
  db.get(`SELECT * FROM payments WHERE id = ?`, [paymentId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(row || { id: paymentId, status: 'not_found' });
  });
});

// ─── Search & Filter Jobs ────────────────────────────────────
app.get('/api/jobs/search', (req, res) => {
  const {
    q, keyword,
    category,
    min_budget, max_budget,
    status,
    posted_by,
    sort = 'newest',
    page = 1, limit = 10
  } = req.query;

  const searchKeyword = sanitizeString(q || keyword || '', 100);
  const safeCategory = sanitizeString(category || '', 50);
  const safeStatus = sanitizeString(status || '', 20);
  const safePostedBy = sanitizeString(posted_by || '', 100);
  const minBudget = parseInt(min_budget) || 0;
  const maxBudget = parseInt(max_budget) || 0;
  const pageNum = Math.max(1, parseInt(page) || 1);
  const pageSize = Math.min(50, Math.max(1, parseInt(limit) || 10));
  const offset = (pageNum - 1) * pageSize;

  const conditions = ['1=1'];
  const params = [];

  if (searchKeyword) {
    conditions.push('(title LIKE ? OR description LIKE ?)');
    const like = `%${searchKeyword}%`;
    params.push(like, like);
  }
  if (safeCategory) { conditions.push('category = ?'); params.push(safeCategory); }
  if (safeStatus) { conditions.push('status = ?'); params.push(safeStatus); }
  if (safePostedBy) { conditions.push('posted_by = ?'); params.push(safePostedBy); }
  if (minBudget > 0) { conditions.push('budget >= ?'); params.push(minBudget); }
  if (maxBudget > 0) { conditions.push('budget <= ?'); params.push(maxBudget); }

  const where = conditions.join(' AND ');
  let orderBy = 'created_at DESC';
  if (sort === 'oldest') orderBy = 'created_at ASC';
  else if (sort === 'budget_high') orderBy = 'budget DESC';
  else if (sort === 'budget_low') orderBy = 'budget ASC';

  db.get(`SELECT COUNT(*) as total FROM jobs WHERE ${where}`, params, (err, countRow) => {
    if (err) { console.error('[DB] Search count error:', err); return res.status(500).json({ error: 'Database error' }); }
    const total = countRow ? countRow.total : 0;
    const queryParams = [...params, pageSize, offset];
    db.all(`SELECT * FROM jobs WHERE ${where} ORDER BY ${orderBy} LIMIT ? OFFSET ?`, queryParams, (err, rows) => {
      if (err) { console.error('[DB] Search error:', err); return res.status(500).json({ error: 'Database error' }); }
      res.json({ jobs: rows || [], total, page: pageNum, page_size: pageSize, total_pages: Math.ceil(total / pageSize), filters: { keyword: searchKeyword, category: safeCategory, status: safeStatus, min_budget: minBudget, max_budget: maxBudget }, sort });
    });
  });
});

// ─── Connects Purchase (Legacy — backward compatible) ─────────
app.post('/api/connects/buy', requireUser, (req, res) => {
  const { user_id, username, package_amount, pi_amount, payment_id } = req.body;
  if (!user_id || !package_amount) {
    return res.status(400).json({ error: 'Missing user_id or package_amount' });
  }

  db.run('BEGIN TRANSACTION', (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    db.run(
      `INSERT INTO connects_purchases (user_id, amount, pi_amount, payment_id, status) VALUES (?, ?, ?, ?, 'pending')`,
      [user_id, package_amount, pi_amount, payment_id],
      function(err) {
        if (err) {
          db.run('ROLLBACK');
          console.error('[DB] Error saving connects purchase:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        const purchaseId = this.lastID;

        // Update user connects balance
        getUser(user_id, (err, row) => {
          if (err) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: 'Database error' });
          }
          if (row) {
            const newBalance = (row.balance_connects || 0) + package_amount;
            db.run(`UPDATE users SET balance_connects = ? WHERE id = ?`, [newBalance, user_id], (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: 'Database error' });
              }
              db.run('COMMIT', (err) => {
                if (err) {
                  db.run('ROLLBACK');
                  return res.status(500).json({ error: 'Failed to commit transaction' });
                }
                res.json({ success: true, purchase_id: purchaseId, added_connects: package_amount });
              });
            });
          } else {
            db.run(`INSERT INTO users (id, username, balance_connects) VALUES (?, ?, ?)`, [user_id, username || 'user', package_amount], (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: 'Database error' });
              }
              db.run('COMMIT', (err) => {
                if (err) {
                  db.run('ROLLBACK');
                  return res.status(500).json({ error: 'Failed to commit transaction' });
                }
                res.json({ success: true, purchase_id: purchaseId, added_connects: package_amount });
              });
            });
          }
        });
      }
    );
  });
});

// ─── Connects Purchase Initiate (Pi SDK flow) ────────────────
// This ONLY records the pending purchase. The frontend must call
// /api/payments/:paymentId/approve from onReadyForServerApproval callback.
app.post('/api/connects/initiate', requireUser, async (req, res) => {
  const { user_id, package_amount, pi_amount, payment_id } = req.body;
  if (!PI_API_KEY) return res.status(500).json({ error: 'PI_API_KEY not configured' });
  if (!payment_id || !user_id || !package_amount || !pi_amount) {
    return res.status(400).json({ error: 'Missing required fields: user_id, package_amount, pi_amount, payment_id' });
  }

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

// ─── Connects Purchase Complete (Pi SDK flow) ────────────────
app.post('/api/connects/complete', requireUser, async (req, res) => {
  const { payment_id, txid, user_id, package_amount } = req.body;

  // Sandbox mode: skip Pi API validation if PI_API_KEY not configured
  const sandboxMode = !PI_API_KEY;

  if (!payment_id) return res.status(400).json({ error: 'Missing payment_id' });
  if (!txid) return res.status(400).json({ error: 'Missing txid' });

  // In sandbox mode, accept any non-empty txid; in production validate hex format
  if (sandboxMode) {
    // Sandbox: any non-empty txid is fine
  } else if (!isValidTxid(txid)) {
    return res.status(400).json({ error: 'Invalid txid format' });
  }

  try {
    if (!sandboxMode) {
      // Production: validate with Pi API
      const piRes = await fetch(`https://api.minepi.com/v2/payments/${payment_id}/complete`, {
        method: 'POST',
        headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ txid }),
      });
      if (!piRes.ok) {
        const errData = await piRes.json().catch(() => ({}));
        console.error('[Pi API] Complete failed:', errData);
        return res.status(piRes.status).json({ error: 'Pi complete failed', details: errData });
      }
    } else {
      console.log('[Pi] Sandbox mode — complete bypass');
    }

    db.run('BEGIN TRANSACTION', (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      // CRIT-003 FIX: Inline balance update instead of calling updateUserBalance (avoids nested transaction)
      db.get(`SELECT balance_connects, balance_pi FROM users WHERE id = ?`, [user_id], (err, user) => {
        if (err) { db.run('ROLLBACK'); return res.status(500).json({ error: 'DB error' }); }
        const newConnects = (user ? user.balance_connects || 0 : 0) + package_amount;
        db.run(`INSERT INTO users (id, username, balance_connects, balance_pi) VALUES (?, COALESCE((SELECT username FROM users WHERE id = ?), ?), ?, 0) ON CONFLICT(id) DO UPDATE SET balance_connects = ?`,
          [user_id, user_id, 'User_' + user_id.slice(0,8), newConnects, newConnects], (err) => {
          if (err) { db.run('ROLLBACK'); return res.status(500).json({ error: 'DB error updating balance' }); }
          db.run(`UPDATE connects_purchases SET status = 'completed' WHERE payment_id = ?`, [payment_id], (err) => {
            if (err) { db.run('ROLLBACK'); return res.status(500).json({ error: 'DB error updating purchase' }); }
            db.run('COMMIT', (err) => {
              if (err) { db.run('ROLLBACK'); return res.status(500).json({ error: 'Failed to commit' }); }
              res.json({ success: true, new_balance: newConnects, sandbox: sandboxMode });
            });
          });
        });
      });
    });
  } catch (err) {
    console.error('[Server] Complete error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Get User Data ────────────────────────────────────────────
app.get('/api/users/:userId', requireUser, (req, res) => {
  const { userId } = req.params;
  // HIGH-004 FIX: Users can only view their own profile
  if (req.userId !== userId) {
    return res.status(403).json({ error: 'Access denied. Can only view your own profile.' });
  }
  getUser(userId, (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

// ─── Update User Balance ──────────────────────────────────────
// CRIT-002 FIX: Disabled direct balance manipulation.
// Balances should only change via verified payment flows (/api/connects/buy, /api/connects/initiate+complete, escrow).
app.post('/api/users/:userId/balance', requireUser, (req, res) => {
  return res.status(403).json({ error: 'Direct balance updates are disabled. Use /api/connects/buy or escrow flows.' });
});

// ─── Update User Availability ─────────────────────────────────
app.post('/api/users/:userId/availability', requireUser, (req, res) => {
  const { userId } = req.params;
  const { availability } = req.body;
  if (req.userId !== userId) return res.status(403).json({ error: 'Can only update your own availability' });
  if (!availability || !['available', 'busy'].includes(availability)) {
    return res.status(400).json({ error: 'Invalid availability value' });
  }

  getUser(userId, (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    db.run(`UPDATE users SET availability = ? WHERE id = ?`, [availability, userId], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, availability });
    });
  });
});

// ─── Push Notification Subscriptions ──────────────────────────
// Store push subscriptions for users (for new job alerts, messages)
app.post('/api/push/subscribe', requireUser, (req, res) => {
  const { subscription } = req.body;
  if (!subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'Invalid push subscription' });
  }
  db.run(`INSERT INTO push_subscriptions (user_id, endpoint, auth, p256dh, created_at) VALUES (?, ?, ?, ?, ?) 
    ON CONFLICT(endpoint) DO UPDATE SET user_id = ?, auth = ?, p256dh = ?, created_at = ?`,
    [req.userId, subscription.endpoint, subscription.keys?.auth || '', subscription.keys?.p256dh || '', Date.now(),
     req.userId, subscription.keys?.auth || '', subscription.keys?.p256dh || '', Date.now()],
    (err) => {
      if (err) { console.error('[DB] Push sub error:', err); return res.status(500).json({ error: 'Database error' }); }
      res.json({ success: true });
    }
  );
});

app.post('/api/push/unsubscribe', requireUser, (req, res) => {
  const { endpoint } = req.body;
  db.run(`DELETE FROM push_subscriptions WHERE endpoint = ? AND user_id = ?`, [endpoint, req.userId], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true });
  });
});

// ─── Job Expiration ───────────────────────────────────────────
// Auto-close jobs past their deadline
app.post('/api/jobs/expire', (req, res) => {
  // Can be called by cron job or manually by admin
  const adminSecret = req.headers['x-admin-secret'];
  const cronSecret = req.headers['x-cron-secret'];
  // CRIT: Must check header exists, env exists, AND values match
  // undefined === undefined would be true without !!() wrapper
  const isAdmin = !!(adminSecret && process.env.ADMIN_SECRET && adminSecret === process.env.ADMIN_SECRET);
  const isCron = !!(cronSecret && process.env.CRON_SECRET && cronSecret === process.env.CRON_SECRET);
  // Additional safety: require at least one auth header to be present
  if (!isAdmin && !isCron) return res.status(401).json({ error: 'Unauthorized. Use x-admin-secret or x-cron-secret.' });

  const now = new Date().toISOString();
  db.run(`UPDATE jobs SET status = 'expired' WHERE status = 'open' AND deadline IS NOT NULL AND deadline < ?`, [now], function(err) {
    if (err) { console.error('[DB] Expire error:', err); return res.status(500).json({ error: 'Database error' }); }
    res.json({ expired_count: this.changes, timestamp: now });
  });
});

// ─── Jobs ─────────────────────────────────────────────────────
app.get('/api/jobs', (req, res) => {
  const { category, search, page = 1, limit = 20 } = req.query;
  let whereSql = `WHERE status = 'open'`;
  let whereParams = [];
  let countParams = [];

  if (category && category !== 'all') {
    whereSql += ` AND category = ?`;
    whereParams.push(category);
    countParams.push(category);
  }
  if (search) {
    const safeSearch = search.replace(/[%_]/g, '\$&');
    whereSql += ` AND (title LIKE ? OR description LIKE ?)`;
    whereParams.push(`%${safeSearch}%`, `%${safeSearch}%`);
    countParams.push(`%${safeSearch}%`, `%${safeSearch}%`);
  }

  const pageInt = Math.max(1, parseInt(page) || 1);
  const limitInt = Math.min(100, Math.max(1, parseInt(limit) || 20));
  const offset = (pageInt - 1) * limitInt;

  // Get total count for real pagination
  db.get(`SELECT COUNT(*) as total FROM jobs ${whereSql}`, countParams, (err, countRow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const total = countRow ? countRow.total : 0;
    const totalPages = Math.ceil(total / limitInt);

    const sql = `SELECT * FROM jobs ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    const params = [...whereParams, limitInt, offset];

    db.all(sql, params, (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      rows.forEach(row => {
        if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
        row.apply_cost = Math.ceil((row.budget || 0) / 50) || 1;
      });
      res.json({ jobs: rows, page: pageInt, limit: limitInt, total, total_pages: totalPages });
    });
  });
});

app.get('/api/jobs/:id', (req, res) => {
  getJob(req.params.id, (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'Job not found' });
    res.json(row);
  });
});

app.get('/api/jobs/user/:username', (req, res) => {
  db.all(`SELECT * FROM jobs WHERE posted_by_name = ? ORDER BY created_at DESC`, [req.params.username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    rows.forEach(row => {
      if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
      row.apply_cost = Math.ceil((row.budget || 0) / 50) || 1;
    });
    res.json(rows);
  });
});

app.post('/api/jobs', requireUser, requireBodyUserMatch, (req, res) => {
  const { title, description, category, budget, skills, images, deadline, posted_by, posted_by_name } = req.body;
  const safeTitle = sanitizeString(title, 120);
  const safeDescription = sanitizeString(description, 2000);
  const safeCategory = sanitizeString(category, 30) || 'other';
  const safeSkills = sanitizeString(skills, 200);
  const safeImages = sanitizeArray(images);
  const safeDeadline = sanitizeString(deadline, 30);
  const safePostedByName = sanitizeString(posted_by_name, 50) || 'User';

  if (!safeTitle) {
    return res.status(400).json({ error: 'Title must be at least 3 characters and max 120' });
  }
  if (!safeDescription) {
    return res.status(400).json({ error: 'Description must be at least 10 characters and max 2000' });
  }
  if (budget !== undefined && (typeof budget !== 'number' || budget < 0 || budget > 1000000)) {
    return res.status(400).json({ error: 'Budget must be a non-negative number and max 1,000,000' });
  }
  if (images && !Array.isArray(images)) {
    return res.status(400).json({ error: 'Images must be an array' });
  }

  // Deduct 1 connect for posting
  getUser(req.userId, (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if ((user.balance_connects || 0) < 1) {
      return res.status(400).json({ error: 'Not enough connects to post a job', required: 1, current: user.balance_connects });
    }
    const imagesStr = safeImages ? JSON.stringify(safeImages) : null;
    const newConnects = (user.balance_connects || 0) - 1;

    db.run('BEGIN TRANSACTION', (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      db.run(
        `INSERT INTO jobs (title, description, category, budget, skills, images, deadline, posted_by, posted_by_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [safeTitle, safeDescription, safeCategory, budget || 0, safeSkills || '', imagesStr, safeDeadline || null, posted_by || req.userId, safePostedByName],
        function(err) {
          if (err) {
            db.run('ROLLBACK');
            console.error('[DB] Error creating job:', err);
            return res.status(500).json({ error: 'Failed to create job' });
          }
          const jobId = this.lastID;
          db.run(`UPDATE users SET balance_connects = ? WHERE id = ?`, [newConnects, req.userId], (err) => {
            if (err) {
              db.run('ROLLBACK');
              console.error('[DB] Error updating balance:', err);
              return res.status(500).json({ error: 'Failed to deduct connects' });
            }
            db.run('COMMIT', (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: 'Failed to commit transaction' });
              }
              res.json({ id: jobId, success: true, remaining_connects: newConnects });
            });
          });
        }
      );
    });
  });
});

app.put('/api/jobs/:id', requireUser, (req, res) => {
  const { id } = req.params;
  const { title, description, category, budget, skills, images, deadline, status } = req.body;

  getJob(id, (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'You can only edit your own jobs' });

    const safeTitle = title !== undefined ? sanitizeString(title, 120) : job.title;
    const safeDesc = description !== undefined ? sanitizeString(description, 2000) : job.description;
    const safeCategory = category !== undefined ? (sanitizeString(category, 30) || 'other') : job.category;
    const safeSkills = skills !== undefined ? sanitizeString(skills, 200) : job.skills;
    const safeImages = images !== undefined ? (sanitizeArray(images) ? JSON.stringify(sanitizeArray(images)) : null) : job.images;
    const safeDeadline = deadline !== undefined ? sanitizeString(deadline, 30) : job.deadline;
    const safeStatus = status !== undefined ? (['open','in_progress','completed','cancelled'].includes(status) ? status : job.status) : job.status;

    if (budget !== undefined && (typeof budget !== 'number' || budget < 0 || budget > 1000000)) {
      return res.status(400).json({ error: 'Budget must be between 0 and 1,000,000' });
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

app.delete('/api/jobs/:id', requireUser, (req, res) => {
  const { id } = req.params;
  getJob(id, (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'You can only delete your own jobs' });

    db.run(`DELETE FROM jobs WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete job' });
      res.json({ success: true });
    });
  });
});

// ─── Applications ────────────────────────────────────────────
app.post('/api/jobs/:jobId/apply', requireUser, requireBodyUserMatch, (req, res) => {
  const { jobId } = req.params;
  const { user_id, username, message } = req.body;

  getJob(jobId, (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by === req.userId) return res.status(403).json({ error: 'Cannot apply to your own job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });

    getUser(req.userId, (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const applyCost = Math.ceil(job.budget / 50) || 1;
      if ((user.balance_connects || 0) < applyCost) {
        return res.status(400).json({ error: 'Not enough connects', required: applyCost, current: user.balance_connects });
      }
      const newConnects = (user.balance_connects || 0) - applyCost;

      db.run('BEGIN TRANSACTION', (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        db.run(
          `INSERT INTO applications (job_id, user_id, username, message) VALUES (?, ?, ?, ?)`,
          [jobId, user_id, username, message],
          function(err) {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: 'Failed to apply' });
            }
            const appId = this.lastID;
            db.run(`UPDATE jobs SET applications = applications + 1 WHERE id = ?`, [jobId], (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: 'Failed to update job' });
              }
              db.run(`UPDATE users SET balance_connects = ? WHERE id = ?`, [newConnects, req.userId], (err) => {
                if (err) {
                  db.run('ROLLBACK');
                  return res.status(500).json({ error: 'Failed to deduct connects' });
                }
                db.run('COMMIT', (err) => {
                  if (err) {
                    db.run('ROLLBACK');
                    return res.status(500).json({ error: 'Failed to commit transaction' });
                  }
                  res.json({ success: true, id: appId, remaining_connects: newConnects });
                });
              });
            });
          }
        );
      });
    });
  });
});

app.get('/api/jobs/:jobId/applications', requireUser, (req, res) => {
  db.all(`SELECT * FROM applications WHERE job_id = ? ORDER BY created_at DESC`, [req.params.jobId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/applications/user/:userId', requireUser, (req, res) => {
  if (req.userId !== req.params.userId) return res.status(403).json({ error: 'Access denied' });
  db.all(`SELECT * FROM applications WHERE user_id = ? ORDER BY created_at DESC`, [req.params.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/applications/me', requireUser, (req, res) => {
  const { user_id } = req.query;
  if (!user_id || user_id !== req.userId) return res.status(403).json({ error: 'user_id mismatch' });
  db.all(`SELECT * FROM applications WHERE user_id = ? ORDER BY created_at DESC`, [user_id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/applications/:id/accept', requireUser, (req, res) => {
  const { id } = req.params;
  db.get(`SELECT a.*, j.posted_by as job_owner FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'Application not found' });
    if (row.job_owner !== req.userId) return res.status(403).json({ error: 'Only the job owner can accept applications' });
    if (row.status !== 'pending') return res.status(400).json({ error: 'Application already processed' });

    db.run(`UPDATE applications SET status = 'accepted' WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to accept' });
      res.json({ success: true, status: 'accepted' });
    });
  });
});

app.post('/api/applications/:id/reject', requireUser, (req, res) => {
  const { id } = req.params;
  db.get(`SELECT a.*, j.posted_by as job_owner FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'Application not found' });
    if (row.job_owner !== req.userId) return res.status(403).json({ error: 'Only the job owner can reject applications' });
    if (row.status !== 'pending') return res.status(400).json({ error: 'Application already processed' });

    db.run(`UPDATE applications SET status = 'rejected' WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to reject' });
      res.json({ success: true, status: 'rejected' });
    });
  });
});

// ─── Escrows ──────────────────────────────────────────────────
app.get('/api/escrows/user/:userId', requireUser, (req, res) => {
  if (req.userId !== req.params.userId) return res.status(403).json({ error: 'Access denied' });
  db.all(`SELECT * FROM escrows WHERE client_id = ? OR freelancer_id = ? ORDER BY created_at DESC`, [req.params.userId, req.params.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/escrows', requireUser, requireBodyUserMatch, (req, res) => {
  const { job_id, client_id, freelancer_id, amount } = req.body;
  if (!job_id || !client_id || !freelancer_id || !amount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  getJob(job_id, (err, job) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Only the job owner can create escrow' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });

    const id = 'esc_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    db.run(`INSERT INTO escrows (id, job_id, client_id, freelancer_id, amount) VALUES (?, ?, ?, ?, ?)`,
      [id, job_id, client_id, freelancer_id, amount],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to create escrow' });
        db.run(`UPDATE jobs SET status = 'in_progress' WHERE id = ?`, [job_id]);
        res.json({ id, success: true });
      }
    );
  });
});

app.post('/api/escrows/:id/fund', requireUser, (req, res) => {
  const { id } = req.params;
  getEscrow(id, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Only the client can fund escrow' });
    if (escrow.status !== 'pending') return res.status(400).json({ error: `Escrow is ${escrow.status}, not pending` });

    db.run(`UPDATE escrows SET status = 'funded', funded_at = CURRENT_TIMESTAMP WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to fund' });
      res.json({ success: true, status: 'funded' });
    });
  });
});

app.post('/api/escrows/:id/release', requireUser, (req, res) => {
  const { id } = req.params;
  getEscrow(id, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Only the client can release escrow' });
    if (escrow.status !== 'funded') return res.status(400).json({ error: `Escrow is ${escrow.status}, must be funded` });

    db.run('BEGIN TRANSACTION', (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      db.run(`UPDATE escrows SET status = 'released', released_at = CURRENT_TIMESTAMP WHERE id = ?`, [id], function(err) {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: 'Failed to release' });
        }

        db.run(`UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + ? WHERE id = ?`, [escrow.amount, escrow.freelancer_id], function(err) {
          if (err) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: 'Failed to transfer Pi to freelancer' });
          }

          db.run(`UPDATE jobs SET status = 'completed' WHERE id = ?`, [escrow.job_id], function(err) {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: 'Failed to mark job as completed' });
            }

            db.run('COMMIT', (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: 'Failed to commit transaction' });
              }

              db.get(`SELECT balance_pi FROM users WHERE id = ?`, [escrow.freelancer_id], (err, row) => {
                const newBalance = row ? row.balance_pi : null;
                res.json({ success: true, status: 'released', freelancer_new_balance: newBalance });
              });
            });
          });
        });
      });
    });
  });
});

app.post('/api/escrows/:id/dispute', requireUser, (req, res) => {
  const { id } = req.params;
  getEscrow(id, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== req.userId && escrow.freelancer_id !== req.userId) {
      return res.status(403).json({ error: 'Only escrow participants can dispute' });
    }
    if (!['funded', 'pending'].includes(escrow.status)) {
      return res.status(400).json({ error: `Cannot dispute escrow in ${escrow.status} status` });
    }

    db.run(`UPDATE escrows SET status = 'disputed' WHERE id = ?`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to dispute' });
      res.json({ success: true, status: 'disputed' });
    });
  });
});

app.post('/api/escrows/:id/cancel', requireUser, (req, res) => {
  const { id } = req.params;
  getEscrow(id, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Only the client can cancel escrow' });
    if (escrow.status !== 'pending') return res.status(400).json({ error: `Escrow is ${escrow.status}, only pending escrows can be cancelled` });

    db.run('BEGIN TRANSACTION', (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      db.run(`UPDATE escrows SET status = 'cancelled' WHERE id = ?`, [id], function(err) {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: 'Failed to cancel escrow' });
        }

        db.run(`UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + ? WHERE id = ?`, [escrow.amount, escrow.client_id], function(err) {
          if (err) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: 'Failed to return Pi to client' });
          }

          db.run(`UPDATE jobs SET status = 'cancelled' WHERE id = ?`, [escrow.job_id], function(err) {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: 'Failed to update job status' });
            }

            db.run('COMMIT', (err) => {
              if (err) {
                db.run('ROLLBACK');
                return res.status(500).json({ error: 'Failed to commit transaction' });
              }

              db.get(`SELECT balance_pi FROM users WHERE id = ?`, [escrow.client_id], (err, row) => {
                const newBalance = row ? row.balance_pi : null;
                res.json({ success: true, status: 'cancelled', client_new_balance: newBalance });
              });
            });
          });
        });
      });
    });
  });
});

app.get('/api/escrows/:escrowId/room', requireUser, (req, res) => {
  const { escrowId } = req.params;
  getEscrow(escrowId, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== req.userId && escrow.freelancer_id !== req.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }
    db.all(`SELECT * FROM escrow_messages WHERE escrow_id = ? ORDER BY created_at ASC`, [escrowId], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ messages: rows, escrow_id: escrowId });
    });
  });
});

app.post('/api/escrows/:escrowId/message', requireUser, requireBodyUserMatch, (req, res) => {
  const { escrowId } = req.params;
  const { sender_id, sender_name, message } = req.body;
  const safeMessage = sanitizeString(message, 1000);
  if (!safeMessage) return res.status(400).json({ error: 'Message is required (1-1000 characters)' });

  getEscrow(escrowId, (err, escrow) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== req.userId && escrow.freelancer_id !== req.userId) {
      return res.status(403).json({ error: 'Only escrow participants can send messages' });
    }
    db.run(`INSERT INTO escrow_messages (escrow_id, sender_id, sender_name, message) VALUES (?, ?, ?, ?)`,
      [escrowId, sender_id, sanitizeString(sender_name, 50) || 'User', safeMessage],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to send message' });
        res.json({ id: this.lastID, success: true });
      }
    );
  });
});

// ─── Reviews ──────────────────────────────────────────────────
app.post('/api/reviews', requireUser, requireBodyUserMatch, (req, res) => {
  const { reviewer_id, reviewer_name, target_id, target_name, job_id, job_title, rating, text } = req.body;
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
  const safeText = sanitizeString(text, 1000) || '';
  const safeReviewerName = sanitizeString(reviewer_name, 50) || 'User';
  const safeTargetName = sanitizeString(target_name, 50) || 'User';
  const safeJobTitle = sanitizeString(job_title, 120) || '';
  const id = 'rev_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
  db.run(
    `INSERT INTO reviews (id, reviewer_id, reviewer_name, target_id, target_name, job_id, job_title, rating, text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, reviewer_id, safeReviewerName, target_id, safeTargetName, job_id, safeJobTitle, rating, safeText],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to submit review' });
      res.json({ success: true, id });
    }
  );
});

app.get('/api/reviews/:username', (req, res) => {
  db.all(`SELECT * FROM reviews WHERE target_name = ? ORDER BY created_at DESC`, [req.params.username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/reviews/stats/:username', (req, res) => {
  db.all(`SELECT rating FROM reviews WHERE target_name = ?`, [req.params.username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const count = rows.length;
    const average_rating = count > 0 ? (rows.reduce((sum, r) => sum + r.rating, 0) / count).toFixed(1) : 0;
    res.json({ count, average_rating: parseFloat(average_rating) });
  });
});

// ─── Offers ───────────────────────────────────────────────────
app.get('/api/offers/:userId', requireUser, (req, res) => {
  if (req.userId !== req.params.userId) return res.status(403).json({ error: 'Access denied' });
  db.all(`SELECT * FROM offers WHERE freelancer_id = ? ORDER BY created_at DESC`, [req.params.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/offers/:offerId/accept', requireUser, (req, res) => {
  db.get(`SELECT * FROM offers WHERE id = ?`, [req.params.offerId], (err, offer) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    if (offer.freelancer_id !== req.userId) return res.status(403).json({ error: 'Only the freelancer can accept this offer' });
    db.run(`UPDATE offers SET status = 'accepted' WHERE id = ?`, [req.params.offerId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to accept offer' });
      res.json({ success: true });
    });
  });
});

app.post('/api/offers/:offerId/decline', requireUser, (req, res) => {
  db.get(`SELECT * FROM offers WHERE id = ?`, [req.params.offerId], (err, offer) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    if (offer.freelancer_id !== req.userId) return res.status(403).json({ error: 'Only the freelancer can decline this offer' });
    db.run(`UPDATE offers SET status = 'declined' WHERE id = ?`, [req.params.offerId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to decline offer' });
      res.json({ success: true });
    });
  });
});

// ─── Admin (Protected) ────────────────────────────────────────
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

app.get('/api/admin/earnings', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM payments WHERE status = 'completed' ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    db.get(`SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'completed'`, [], (err, sumRow) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ payments: rows, total: sumRow?.total || 0 });
    });
  });
});

app.get('/api/admin/escrows', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM escrows ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// ─── Chat ─────────────────────────────────────────────────────
app.get('/api/chat/rooms/:userId', requireUser, (req, res) => {
  if (req.userId !== req.params.userId) return res.status(403).json({ error: 'Access denied' });
  const { userId } = req.params;
  db.all(
    `SELECT r.*,
      CASE WHEN r.user1_id = ? THEN r.user2_id ELSE r.user1_id END as other_user_id
     FROM chat_rooms r WHERE r.user1_id = ? OR r.user2_id = ? ORDER BY r.created_at DESC`,
    [userId, userId, userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

app.get('/api/chat/:roomId/messages', requireUser, (req, res) => {
  const { roomId } = req.params;
  db.get(`SELECT * FROM chat_rooms WHERE id = ? AND (user1_id = ? OR user2_id = ?)`, [roomId, req.userId, req.userId], (err, room) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!room) return res.status(403).json({ error: 'Access denied' });
    db.all(`SELECT * FROM chat_messages WHERE room_id = ? ORDER BY created_at ASC`, [roomId], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
  });
});

app.post('/api/chat/:roomId/messages', requireUser, (req, res) => {
  const { roomId } = req.params;
  // Support both API format (sender_id, sender_name, message) and bundle format (user_id, user_name, text)
  // HIGH-003 FIX: Override sender_id with authenticated user to prevent impersonation
  const sender_name = req.body.sender_name || req.body.user_name;
  const message = req.body.message || req.body.text;
  const safeMessage = sanitizeString(message, 1000);
  if (!safeMessage) return res.status(400).json({ error: 'Message is required (1-1000 characters)' });

  db.get(`SELECT * FROM chat_rooms WHERE id = ? AND (user1_id = ? OR user2_id = ?)`, [roomId, req.userId, req.userId], (err, room) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!room) return res.status(403).json({ error: 'Access denied' });

    db.run(
      `INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES (?, ?, ?, ?)`,
      // sender_id forced to req.userId — prevents impersonation
      [roomId, req.userId, sanitizeString(sender_name, 50) || 'User', safeMessage],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to send message' });
        res.json({ id: this.lastID, success: true });
      }
    );
  });
});

app.post('/api/chat/start', requireUser, (req, res) => {
  const { user_id, other_user_id } = req.body;
  if (!user_id || !other_user_id) return res.status(400).json({ error: 'Missing user_id or other_user_id' });
  if (req.userId !== user_id) return res.status(403).json({ error: 'Access denied' });
  if (user_id === other_user_id) return res.status(400).json({ error: 'Cannot start chat with yourself' });

  // Normalize ordering so room is unique regardless of who initiates
  const u1 = user_id < other_user_id ? user_id : other_user_id;
  const u2 = user_id < other_user_id ? other_user_id : user_id;

  db.get(
    `SELECT * FROM chat_rooms WHERE user1_id = ? AND user2_id = ?`,
    [u1, u2],
    (err, room) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (room) return res.json({ room_id: room.id, existing: true });

      const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
      db.run(
        `INSERT INTO chat_rooms (id, user1_id, user2_id) VALUES (?, ?, ?)`,
        [roomId, u1, u2],
        function(err) {
          if (err) return res.status(500).json({ error: 'Failed to create chat room' });
          res.json({ room_id: roomId, existing: false });
        }
      );
    }
  );
});

// ─── Graceful Shutdown ────────────────────────────────────────
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

// ─── Start Server ───────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`[WorkPro Backend] Running on port ${PORT}`);
  console.log(`[WorkPro Backend] Environment: ${NODE_ENV}`);
  console.log(`[WorkPro Backend] Frontend allowed: ${corsOrigins.join(', ')}`);
  console.log(`[WorkPro Backend] Pi API Key: ${PI_API_KEY ? 'Configured' : 'MISSING!'}`);
  console.log(`[WorkPro Backend] Admin API Key: ${ADMIN_API_KEY ? 'Configured' : 'MISSING!'}`);
});
// Render deploy trigger: Thu May  7 05:24:11 AM CST 2026
// Render deploy trigger: Thu May  7 22:01:55 UTC 2026

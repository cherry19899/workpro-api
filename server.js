/**
 * WorkPro API v3.2.0
 * Freelance Marketplace — thin entry point
 *
 * Route modules:
 *   routes/auth.js          — /api/me, /api/auth/*, /api/users/me
 *   routes/users.js         — /api/users/:id, ratings, level, portfolio, /api/reviews/*
 *   routes/jobs.js          — /api/jobs/*, /api/applications/*
 *   routes/payments.js      — /api/payments/*, /api/connects/*, /api/escrows/*, /api/offers/*
 *   routes/chat.js          — /api/chat/*, /api/push/*
 *   routes/admin.js         — /api/admin/*
 *   routes/notifications.js — /api/notifications/*
 *
 * Shared modules:
 *   src/db.js         — pool, query, getPool (re-exports from root db.js)
 *   src/helpers.js    — piApprovePayment, piCompletePayment, piGetPayment, notify, audit, serverError
 *   src/middleware.js — auth, softAuth, adminAuth, checkBlocked, rate limiters
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const { query, initDb } = require('./db');

const app = express();
// Render sits behind a proxy — needed so req.ip reflects the real client for rate limiting
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Warn if secrets are defaults — do this at startup before routes load
if (!process.env.JWT_SECRET) {
  console.warn('[SECURITY] JWT_SECRET env var is not set — using a random secret. All sessions will be invalidated on each restart.');
}
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'admin-secret-key';
if (ADMIN_API_KEY === 'admin-secret-key') {
  console.warn('[SECURITY] ADMIN_API_KEY is the default value — set a strong ADMIN_API_KEY env var, otherwise the admin panel is publicly accessible.');
}
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';

// ─── Core middleware ──────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true, limit: '4mb' }));
app.use(cors({
  origin: [FRONTEND_URL, 'https://cherry19899.github.io', 'http://localhost:3000', 'http://localhost:5173', 'http://localhost:3001'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-pi-token', 'x-admin-key', 'x-username'],
  credentials: true,
}));

// Global rate limit (all endpoints except /api/health)
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  skip: (req) => req.path === '/api/health',
}));

// Import route-specific limiters from middleware so we can apply them globally here
// (same pattern as the original server.js — mount before route modules so the limiter
// fires regardless of which module handles the request)
const {
  authLimiter,
  adminLimiter,
  connectsLimiter,
  messageLimiter,
} = require('./src/middleware');

app.use('/api/auth', authLimiter);
// authLimiter applied directly to POST /api/me (login) inside routes/auth.js
app.use('/api/admin', adminLimiter);
app.use('/api/connects/purchase', connectsLimiter);
app.use('/api/connects/buy', connectsLimiter);
app.use('/api/payments', connectsLimiter);
// Apply message limiter only to chat WRITE endpoints (not GET reads)
app.use(['/api/chat/start', '/api/chat/read-all'], messageLimiter);
app.use('/api/chat/rooms', (req, res, next) => { if (req.method === 'POST') return messageLimiter(req, res, next); next(); });
app.use('/api/chat/conversations', (req, res, next) => { if (req.method === 'POST') return messageLimiter(req, res, next); next(); });

// ─── Static endpoints ──────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ name: 'WorkPro API', version: '3.2.0', status: 'ok' });
});

// Pi Network calls this to verify backend ownership
app.get('/.well-known/pi-network', (req, res) => {
  res.json({ app: 'workpro', backend: true, version: '3.2.0' });
});

app.get('/api/health', async (req, res) => {
  try {
    await query('SELECT 1');
    res.json({ status: 'ok', version: '3.2.0', database: 'connected', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('[Health] DB check failed:', err.message);
    res.status(500).json({ status: 'error', database: 'disconnected' });
  }
});

// ─── Route modules ──────────────────────────────────────────────
// Order matters: more-specific paths (e.g. /api/users/me) must be mounted
// before wildcard siblings (e.g. /api/users/:id). Each router registers full
// /api/... paths so app.use() here is prefix-free.
app.use(require('./routes/auth'));          // /api/me, /api/auth/*, /api/users/me (and sub-paths)
app.use(require('./routes/notifications')); // /api/notifications/*
app.use(require('./routes/admin'));         // /api/admin/*
app.use(require('./routes/chat'));          // /api/chat/*, /api/push/*
app.use(require('./routes/payments'));      // /api/payments/*, /api/connects/*, /api/escrows/*, /api/escrow/*, /api/offers/*
app.use(require('./routes/jobs'));          // /api/jobs/*, /api/applications/*
app.use(require('./routes/users'));         // /api/users/:id, /api/reviews/*, /api/ratings/*

// ─── 404 & error handler ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  console.error('[Error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Schema migrations run on startup ──────────────────────────────────────────────
async function ensureNotificationsTable() {
  try {
    await query(`CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      job_id INTEGER,
      room_id TEXT,
      is_read BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await query(`CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at DESC)`);
    await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_chat_read_at TIMESTAMPTZ`);
    await query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_unique_apply ON applications(job_id, freelancer_id)`);
    await query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_escrows_payment ON escrows(payment_id)`);
    await query(`UPDATE jobs SET apply_cost = CEIL(budget::numeric / 50.0)::int, connects_spent = CEIL(budget::numeric / 50.0)::int WHERE CEIL(budget::numeric / 50.0)::int != apply_cost`).catch((e) => console.error('[Migration] apply_cost fix error:', e.message));
    await query(`CREATE TABLE IF NOT EXISTS portfolios (
      id SERIAL PRIMARY KEY, user_id VARCHAR(255) UNIQUE, headline TEXT, summary TEXT,
      experience_years INTEGER DEFAULT 0, website TEXT, github TEXT, linkedin TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS portfolio_items (
      id SERIAL PRIMARY KEY, user_id VARCHAR(255), title VARCHAR(500) NOT NULL,
      description TEXT, image_url TEXT, category VARCHAR(100), tags TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL,
      endpoint TEXT NOT NULL,
      keys JSONB,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await query(`CREATE TABLE IF NOT EXISTS chat_room_reads (
      room_id VARCHAR(255) NOT NULL,
      user_id VARCHAR(255) NOT NULL,
      last_read_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (room_id, user_id)
    )`);
    await query(`ALTER TABLE ratings ADD COLUMN IF NOT EXISTS reply TEXT`);
    await query(`ALTER TABLE ratings ADD COLUMN IF NOT EXISTS replied_at TIMESTAMPTZ`);
  } catch (_) {}
}

// ─── Start ──────────────────────────────────────────────
initDb().then(async () => {
  await ensureNotificationsTable();
  // Ensure the canonical owner always has admin role
  await query(`UPDATE users SET role = 'admin' WHERE id = 'pi_cherry19899' AND role != 'admin'`).catch(() => {});
  app.listen(PORT, () => {
    console.log(`[WorkPro API] v3.2.0 on port ${PORT} (${NODE_ENV})`);
  });
}).catch(err => {
  console.error('[Server] Failed to start:', err);
  process.exit(1);
});

module.exports = app;

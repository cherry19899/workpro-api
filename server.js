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
const RATE_LIMIT_BYPASS_KEY = process.env.RATE_LIMIT_BYPASS_KEY || null;
function _skipRateLimit(req) {
  if (req.path === '/api/health') return true;
  if (!RATE_LIMIT_BYPASS_KEY) return false;
  const h = req.headers['x-rate-bypass'] || '';
  try {
    return h.length === RATE_LIMIT_BYPASS_KEY.length &&
      require('crypto').timingSafeEqual(Buffer.from(h), Buffer.from(RATE_LIMIT_BYPASS_KEY));
  } catch { return false; }
}
const GLOBAL_RATE_MAX = process.env.SANDBOX_MODE ? 5000 : 500;
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: GLOBAL_RATE_MAX,
  skip: _skipRateLimit,
}));

// Import route-specific limiters from middleware so we can apply them globally here
// (same pattern as the original server.js — mount before route modules so the limiter
// fires regardless of which module handles the request)
const {
  authLimiter,
  adminLimiter,
  adminStrictLimiter,
  connectsLimiter,
  messageLimiter,
} = require('./src/middleware');

app.use('/api/auth', authLimiter);
// authLimiter applied directly to POST /api/me (login) inside routes/auth.js
app.use('/api/admin', adminStrictLimiter); // IP-level DDoS guard (50/15min)
app.use('/api/admin', adminLimiter);       // Functional limit (100/15min per IP)
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
  const run = (sql, tag) => query(sql).catch(e => console.error(`[Migration] ${tag}:`, e.message));
  await run(`CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT,
    job_id INTEGER,
    room_id TEXT,
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`, 'notifications table');
  await run(`CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at DESC)`, 'idx_notifications_user');
  await run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_chat_read_at TIMESTAMPTZ`, 'users.last_chat_read_at');
  // Critical: must run before any UPDATE that references updated_at
  await run(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`, 'applications.updated_at');
  await run(`ALTER TABLE offers ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`, 'offers.updated_at');
  // Unique indexes — may fail if duplicate rows exist in DB; logged but non-fatal
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_unique_apply ON applications(job_id, freelancer_id)`, 'idx_applications_unique_apply');
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_escrows_payment ON escrows(payment_id)`, 'idx_escrows_payment');
  await run(`UPDATE jobs SET apply_cost = CEIL(budget::numeric / 50.0)::int, connects_spent = CEIL(budget::numeric / 50.0)::int WHERE CEIL(budget::numeric / 50.0)::int != apply_cost`, 'apply_cost fix');
  await run(`CREATE TABLE IF NOT EXISTS portfolios (
    id SERIAL PRIMARY KEY, user_id VARCHAR(255) UNIQUE, headline TEXT, summary TEXT,
    experience_years INTEGER DEFAULT 0, website TEXT, github TEXT, linkedin TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`, 'portfolios table');
  await run(`CREATE TABLE IF NOT EXISTS portfolio_items (
    id SERIAL PRIMARY KEY, user_id VARCHAR(255), title VARCHAR(500) NOT NULL,
    description TEXT, image_url TEXT, category VARCHAR(100), tags TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`, 'portfolio_items table');
  await run(`CREATE TABLE IF NOT EXISTS push_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    endpoint TEXT NOT NULL,
    keys JSONB,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )`, 'push_subscriptions table');
  await run(`CREATE TABLE IF NOT EXISTS chat_room_reads (
    room_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    last_read_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (room_id, user_id)
  )`, 'chat_room_reads table');
  await run(`ALTER TABLE ratings ADD COLUMN IF NOT EXISTS reply TEXT`, 'ratings.reply');
  await run(`ALTER TABLE ratings ADD COLUMN IF NOT EXISTS replied_at TIMESTAMPTZ`, 'ratings.replied_at');
  // ─── Performance indexes ───────────────────────────────────────────────
  await run(`CREATE INDEX IF NOT EXISTS idx_jobs_posted_by ON jobs(posted_by)`, 'idx_jobs_posted_by');
  await run(`CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)`, 'idx_jobs_status');
  await run(`CREATE INDEX IF NOT EXISTS idx_applications_job_id ON applications(job_id)`, 'idx_applications_job_id');
  await run(`CREATE INDEX IF NOT EXISTS idx_applications_freelancer_id ON applications(freelancer_id)`, 'idx_applications_freelancer_id');
  await run(`CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status)`, 'idx_applications_status');
  await run(`CREATE INDEX IF NOT EXISTS idx_escrows_client_id ON escrows(client_id)`, 'idx_escrows_client_id');
  await run(`CREATE INDEX IF NOT EXISTS idx_escrows_freelancer_id ON escrows(freelancer_id)`, 'idx_escrows_freelancer_id');
  await run(`CREATE INDEX IF NOT EXISTS idx_escrows_job_id ON escrows(job_id)`, 'idx_escrows_job_id');
  await run(`CREATE INDEX IF NOT EXISTS idx_chat_messages_room_id ON chat_messages(room_id)`, 'idx_chat_messages_room_id');
  await run(`CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)`, 'idx_payments_user_id');
  await run(`CREATE INDEX IF NOT EXISTS idx_ratings_to_user_id ON ratings(to_user_id)`, 'idx_ratings_to_user_id');
  // ─── Data integrity ───────────────────────────────────────────────
  // Unique pair per (client, freelancer, job) prevents duplicate chat rooms.
  // job_id can be NULL so we use a partial index trick: two separate indexes.
  await run(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_rooms_pair_with_job
     ON chat_rooms(client_id, freelancer_id, job_id)
     WHERE job_id IS NOT NULL`,
    'idx_chat_rooms_pair_with_job'
  );
  await run(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_rooms_pair_no_job
     ON chat_rooms(client_id, freelancer_id)
     WHERE job_id IS NULL`,
    'idx_chat_rooms_pair_no_job'
  );
  // FK-style index on chat_messages.room_id for join performance
  await run(
    `CREATE INDEX IF NOT EXISTS idx_chat_messages_room_id2 ON chat_messages(room_id, created_at DESC)`,
    'idx_chat_messages_room_id2'
  );
  // Foreign key: chat_messages.room_id → chat_rooms.id (NOT VALID = doesn't scan existing rows)
  await run(
    `DO $$ BEGIN
       IF NOT EXISTS (
         SELECT 1 FROM information_schema.table_constraints
         WHERE constraint_name = 'fk_chat_messages_room_id'
           AND table_name = 'chat_messages'
       ) THEN
         ALTER TABLE chat_messages
           ADD CONSTRAINT fk_chat_messages_room_id
           FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE NOT VALID;
       END IF;
     END $$`,
    'fk_chat_messages_room_id'
  );
}

// ─── Start ──────────────────────────────────────────────
initDb().then(async () => {
  await ensureNotificationsTable();
  // Ensure the canonical owner always has admin role
  await query(`UPDATE users SET role = 'admin' WHERE id = 'pi_cherry19899' AND role != 'admin'`).catch(() => {});
  // Fix double-prefix corruption from old registration bug (idempotent)
  await query(`UPDATE jobs SET posted_by = 'pi_cherry19899' WHERE posted_by = 'pi_pi_cherry19899'`).catch(() => {});
  await query(`UPDATE applications SET freelancer_id = 'pi_cherry19899' WHERE freelancer_id = 'pi_pi_cherry19899'`).catch(() => {});
  // Remove test clutter jobs (description='test', title contains 'test') — idempotent
  await query(`DELETE FROM applications WHERE job_id IN (SELECT id FROM jobs WHERE description = 'test' AND title ILIKE '%test%')`).catch(() => {});
  await query(`DELETE FROM jobs WHERE description = 'test' AND title ILIKE '%test%'`).catch(() => {});
  app.listen(PORT, () => {
    console.log(`[WorkPro API] v3.2.0 on port ${PORT} (${NODE_ENV})`);
  });
}).catch(err => {
  console.error('[Server] Failed to start:', err);
  process.exit(1);
});

module.exports = app;

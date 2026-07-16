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
const logger = require('./src/logger');
const express = require('express');
const compression = require('compression');
const http = require('http');
const { Server: SocketIOServer } = require('socket.io');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { query, initDb } = require('./db');
const { PI_API_KEY: piKey } = require('./src/helpers');

const app = express();
const httpServer = http.createServer(app);

// Render sits behind a proxy — needed so req.ip reflects the real client for rate limiting
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// ── Pre-flight secret checks (fatal in production without SANDBOX escape hatch) ──
const IS_SANDBOX = !!process.env.SANDBOX_MODE;
if (NODE_ENV === 'production') {
  if (IS_SANDBOX) {
    logger.warn('[WARN] SANDBOX_MODE is enabled — testnet mode active. Remove before switching to mainnet.');
  }
  if (!process.env.JWT_SECRET) {
    logger.error('[FATAL] JWT_SECRET env var is not set. Set a strong JWT_SECRET in Render env vars. Refusing to start.');
    process.exit(1);
  }
  const _adminKey = process.env.ADMIN_API_KEY;
  if (!_adminKey || _adminKey === 'admin-secret-key') {
    logger.error('[FATAL] ADMIN_API_KEY is missing or using the default value. Set a strong ADMIN_API_KEY in Render env vars. Refusing to start.');
    process.exit(1);
  }
}
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'admin-secret-key';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';

// ─── Helpers ─────────────────────────────────────────────────
const normalizeId = (id) => (id || '').toString().toLowerCase().replace(/^pi_/, '');

// ─── Core middleware ──────────────────────────────────────────────
app.use(compression());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'cdn.minepi.com', 'sdk.minepi.com'],
      connectSrc: ["'self'", 'api.minepi.com', 'api.testnet.minepi.com', 'workpro-api.onrender.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'", 'data:'],
      frameSrc: ['cdn.minepi.com'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: NODE_ENV === 'production' ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: NODE_ENV === 'production' ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true,
  noSniff: true,
  frameguard: { action: 'deny' },
}));
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true, limit: '4mb' }));
app.use(cors({
  origin: [
    FRONTEND_URL,
    'https://cherry19899.github.io',
    ...(process.env.NODE_ENV !== 'production' ? ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:3001'] : []),
  ],
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
// Method-aware global limit: read-heavy GETs capped tighter than mutations.
// SANDBOX_MODE relaxes 10× for automated testing.
const _rateMult = process.env.SANDBOX_MODE ? 10 : 1;
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: (req) => (req.method === 'GET' ? 100 : 500) * _rateMult,
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
  res.json({ name: 'WorkPro API', version: '3.2.0', status: 'ok', docs: '/api/docs' });
});

// GET /api/docs — Swagger UI (CDN-hosted, no npm package needed)
app.get('/api/docs', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html>
<head><title>WorkPro API Docs</title>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
  url: '/api/openapi.json',
  dom_id: '#swagger-ui',
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  layout: 'BaseLayout',
  deepLinking: true,
});
</script>
</body>
</html>`);
});

// GET /api/openapi.json — OpenAPI 3.0 spec
app.get('/api/openapi.json', (req, res) => {
  const base = process.env.API_BASE_URL || 'https://workpro-api.onrender.com';
  res.json({
    openapi: '3.0.3',
    info: { title: 'WorkPro API', version: '3.2.0', description: 'Pi Network freelance marketplace API' },
    servers: [{ url: base }],
    components: {
      securitySchemes: {
        BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        AdminKey: { type: 'apiKey', in: 'header', name: 'x-admin-key' },
      },
    },
    security: [{ BearerAuth: [] }],
    paths: {
      '/api/health': { get: { tags: ['System'], summary: 'Health check', security: [], responses: { '200': { description: 'OK' } } } },
      '/api/me': { post: { tags: ['Auth'], summary: 'Login / register', security: [], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { uid: { type: 'string' }, username: { type: 'string' }, accessToken: { type: 'string' } }, required: ['uid', 'username'] } } } }, responses: { '200': { description: 'JWT token' } } } },
      '/api/jobs': {
        get: { tags: ['Jobs'], summary: 'List open jobs (cursor or page)', parameters: [ { name: 'cursor', in: 'query', schema: { type: 'string' } }, { name: 'page', in: 'query', schema: { type: 'integer' } }, { name: 'limit', in: 'query', schema: { type: 'integer' } }, { name: 'search', in: 'query', schema: { type: 'string' } }, { name: 'category', in: 'query', schema: { type: 'string' } }, { name: 'sort', in: 'query', schema: { type: 'string', enum: ['newest','oldest','budget_asc','budget_desc','popular'] } } ], security: [], responses: { '200': { description: 'Jobs list' } } },
        post: { tags: ['Jobs'], summary: 'Create job', responses: { '201': { description: 'Created' } } },
      },
      '/api/jobs/search/autocomplete': { get: { tags: ['Jobs'], summary: 'Title autocomplete', parameters: [{ name: 'q', in: 'query', required: true, schema: { type: 'string' } }], security: [], responses: { '200': { description: 'Suggestions' } } } },
      '/api/jobs/{id}': {
        get: { tags: ['Jobs'], summary: 'Get job detail', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }], security: [], responses: { '200': { description: 'Job' } } },
        put: { tags: ['Jobs'], summary: 'Update job', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }], responses: { '200': { description: 'Updated' } } },
        delete: { tags: ['Jobs'], summary: 'Delete job', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }], responses: { '204': { description: 'Deleted' } } },
      },
      '/api/jobs/{id}/apply': { post: { tags: ['Jobs'], summary: 'Apply to job (costs connects)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }], responses: { '200': { description: 'Applied' }, '409': { description: 'Already applied' } } } },
      '/api/jobs/{id}/hire': { post: { tags: ['Jobs'], summary: 'Hire a freelancer', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }], responses: { '200': { description: 'Hired' } } } },
      '/api/connects/balance': { get: { tags: ['Connects'], summary: 'Get connects balance', responses: { '200': { description: 'Balance' } } } },
      '/api/connects/buy': { post: { tags: ['Connects'], summary: 'Buy connects via Pi payment', responses: { '200': { description: 'Credited' } } } },
      '/api/payments/approve': { post: { tags: ['Payments'], summary: 'Approve Pi payment', responses: { '200': { description: 'Approved' } } } },
      '/api/payments/complete': { post: { tags: ['Payments'], summary: 'Complete Pi payment', responses: { '200': { description: 'Completed' } } } },
      '/api/escrow/{id}/release': { post: { tags: ['Escrow'], summary: 'Release escrow to freelancer', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }], responses: { '200': { description: 'Released' } } } },
      '/api/chat/conversations': { get: { tags: ['Chat'], summary: 'List conversations', responses: { '200': { description: 'Conversations' } } } },
      '/api/notifications': { get: { tags: ['Notifications'], summary: 'Get notifications', responses: { '200': { description: 'Notifications' } } } },
      '/api/users/{id}': { get: { tags: ['Users'], summary: 'Get user profile', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], security: [], responses: { '200': { description: 'User' } } } },
      '/api/admin/stats': { get: { tags: ['Admin'], summary: 'Platform stats', security: [{ AdminKey: [] }], responses: { '200': { description: 'Stats' } } } },
      '/api/admin/analytics': { get: { tags: ['Admin'], summary: 'Analytics dashboard', security: [{ AdminKey: [] }], responses: { '200': { description: 'Analytics' } } } },
      '/api/admin/settings': {
        get: { tags: ['Admin'], summary: 'Get platform settings', security: [{ AdminKey: [] }], responses: { '200': { description: 'Settings' } } },
        patch: { tags: ['Admin'], summary: 'Update platform setting', security: [{ AdminKey: [] }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { key: { type: 'string' }, value: { type: 'number' } }, required: ['key','value'] } } } }, responses: { '200': { description: 'Updated' } } },
      },
      '/api/admin/rate-limits': { get: { tags: ['Admin'], summary: 'List rate-limited IPs', security: [{ AdminKey: [] }], responses: { '200': { description: 'Blocked IPs' } } } },
      '/api/admin/rate-limits/unblock': { post: { tags: ['Admin'], summary: 'Unblock an IP', security: [{ AdminKey: [] }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { ip: { type: 'string' } }, required: ['ip'] } } } }, responses: { '200': { description: 'Unblocked' } } } },
    },
  });
});

// Pi Network calls this to verify backend ownership
app.get('/privacy', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Work Pro Privacy Policy</title></head><body><h1>Work Pro Privacy Policy</h1><p>Work Pro is a freelance marketplace on the Pi Network. We collect your Pi username and profile information to facilitate job postings and payments between job creators and freelancers. Payment data is processed via the Pi Network SDK. We do not sell your data to third parties. Contact: support via the Work Pro app.</p></body></html>`);
});

// TEMPORARY: sandbox A2U test endpoint — remove after 5 testnet transactions qualify wallet
app.post('/api/sandbox/test-a2u', async (req, res) => {
  const sandboxKey = process.env.SANDBOX_PI_API_KEY;
  if (!sandboxKey || req.headers['x-sandbox-key'] !== sandboxKey) return res.status(403).json({ error: 'forbidden' });
  const { sendA2U, a2uEnabled } = require('./src/pi-a2u');
  if (!a2uEnabled()) return res.status(503).json({ error: 'a2u_not_configured' });
  const { rows } = await require('./src/db').getPool().query(
    "SELECT DISTINCT id FROM users WHERE id LIKE 'pi_%' ORDER BY created_at ASC LIMIT 5"
  );
  const results = [];
  for (const row of rows) {
    try {
      const r = await sendA2U(row.pi_uid, 0.001, 'WorkPro sandbox qualification', { test: true });
      results.push({ uid: row.pi_uid, ok: true, paymentId: r.paymentId, txid: r.txid });
    } catch (e) {
      const msg = e?.response?.data ? JSON.stringify(e.response.data) : (e.message || String(e));
      results.push({ uid: row.pi_uid, ok: false, error: String(msg).slice(0, 300) });
    }
  }
  res.json({ results, count: rows.length });
});

app.get('/.well-known/pi-network', (req, res) => {
  res.json({
    app: 'workpro',
    backend: true,
    version: '3.2.0',
    app_identifier: process.env.PI_APP_IDENTIFIER || 'workpro',
  });
});

const _serverStartTime = Date.now();
let _lastError = null; // set by the global error handler
let _piHealthCache = null; // { ts, reachable, latency_ms } — 60s TTL

app.get('/api/health', async (req, res) => {
  const result = {
    status: 'ok',
    version: '3.2.0',
    timestamp: new Date().toISOString(),
    uptime_seconds: Math.floor((Date.now() - _serverStartTime) / 1000),
    memory_mb: parseFloat((process.memoryUsage().rss / 1024 / 1024).toFixed(1)),
  };

  // DB latency
  const dbStart = Date.now();
  try {
    const pool = require('./src/db').getPool();
    result.db_connections = { total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount };
    await query('SELECT 1');
    result.db_latency_ms = Date.now() - dbStart;
    result.database = 'connected';
  } catch (err) {
    logger.error('[Health] DB check failed:', err.message);
    result.status = 'degraded';
    result.database = 'disconnected';
    result.db_latency_ms = null;
  }

  result.pi_api = piKey ? 'configured' : 'missing';
  // A2U (real payout to freelancer) requires both the API key and the wallet seed.
  result.a2u = (piKey && process.env.PI_WALLET_PRIVATE_SEED) ? 'configured' : 'missing';
  try { result.a2u_last = require('./src/pi-a2u').a2uStatus(); } catch {}
  try { result.last_500 = require('./src/helpers').last500(); } catch {}

  // Pi API latency (only on deep=1 to avoid slowing every ping) — cached 60s
  if (piKey && process.env.SANDBOX_MODE !== 'true' && req.query.deep === '1') {
    const now = Date.now();
    if (_piHealthCache && (now - _piHealthCache.ts) < 60000) {
      result.pi_api_reachable = _piHealthCache.reachable;
      result.pi_api_latency_ms = _piHealthCache.latency_ms;
      result.pi_api_cached = true;
    } else {
      const piStart = now;
      try {
        const r = await fetch('https://api.minepi.com/v2/payments/health_check_nonexistent', {
          headers: { Authorization: `Key ${piKey}` },
        }).catch(() => null);
        result.pi_api_reachable = r ? (r.status < 500 ? 'ok' : 'error') : 'unreachable';
        result.pi_api_latency_ms = Date.now() - piStart;
      } catch (_) { result.pi_api_reachable = 'unreachable'; result.pi_api_latency_ms = null; }
      _piHealthCache = { ts: Date.now(), reachable: result.pi_api_reachable, latency_ms: result.pi_api_latency_ms };
    }
  }

  if (_lastError) result.last_error = _lastError;

  res.status(result.status === 'ok' ? 200 : 500).json(result);
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
app.use(require('./routes/users').router);  // /api/users/:id, /api/reviews/*, /api/ratings/*

// ─── 404 & error handler ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  logger.error('[Error]', err);
  _lastError = { message: err.message, path: req.path, time: new Date().toISOString() };
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Schema migrations run on startup ──────────────────────────────────────────────
async function ensureNotificationsTable() {
  const run = (sql, tag) => query(sql).catch(e => logger.error(`[Migration] ${tag}:`, e.message));
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
  await run(`CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users(LOWER(username))`, 'idx_users_username_lower');
  await run(`CREATE INDEX IF NOT EXISTS idx_users_id_lower ON users(LOWER(id))`, 'idx_users_id_lower');
  await run(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_chat_read_at TIMESTAMPTZ`, 'users.last_chat_read_at');
  // Critical: must run before any UPDATE that references updated_at
  await run(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`, 'applications.updated_at');
  // NOTE: there is no separate "offers" table — offers are stored in `applications`
  // with status='offer'. The old ALTER TABLE offers migration referenced a
  // non-existent relation and logged an error on every boot; removed.
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
  // Foreign key: chat_messages.room_id → chat_rooms.id
  await run(
    `DO $$ BEGIN
       IF NOT EXISTS (
         SELECT 1 FROM information_schema.table_constraints
         WHERE constraint_name = 'fk_chat_messages_room_id' AND table_name = 'chat_messages'
       ) THEN
         ALTER TABLE chat_messages
           ADD CONSTRAINT fk_chat_messages_room_id
           FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE NOT VALID;
       END IF;
     END $$`,
    'fk_chat_messages_room_id'
  );
  // Foreign key: applications.job_id → jobs(id) ON DELETE CASCADE
  await run(
    `DO $$ BEGIN
       IF NOT EXISTS (
         SELECT 1 FROM information_schema.table_constraints
         WHERE constraint_name = 'fk_applications_job_id' AND table_name = 'applications'
       ) THEN
         ALTER TABLE applications
           ADD CONSTRAINT fk_applications_job_id
           FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE NOT VALID;
       END IF;
     END $$`,
    'fk_applications_job_id'
  );
  // Foreign key: escrows.job_id → jobs(id) ON DELETE CASCADE
  await run(
    `DO $$ BEGIN
       IF NOT EXISTS (
         SELECT 1 FROM information_schema.table_constraints
         WHERE constraint_name = 'fk_escrows_job_id' AND table_name = 'escrows'
       ) THEN
         ALTER TABLE escrows
           ADD CONSTRAINT fk_escrows_job_id
           FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE NOT VALID;
       END IF;
     END $$`,
    'fk_escrows_job_id'
  );
  await run(`ALTER TABLE escrows ADD COLUMN IF NOT EXISTS dispute_reason TEXT`, 'escrows.dispute_reason');
  // Backfill applications.updated_at for rows created before the column existed
  await run(
    `UPDATE applications SET updated_at = created_at WHERE updated_at IS NULL`,
    'backfill applications.updated_at'
  );
  // Platform settings table — key/value store for runtime-configurable parameters
  await run(`CREATE TABLE IF NOT EXISTS platform_settings (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by TEXT
  )`, 'platform_settings table');
  // Seed default platform fee (2%) — INSERT only if row doesn't already exist
  await run(
    `INSERT INTO platform_settings (key, value, updated_at)
     VALUES ('platform_fee_percent', '2', NOW())
     ON CONFLICT (key) DO NOTHING`,
    'seed platform_fee_percent'
  );
  await run(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS payments_enabled BOOLEAN DEFAULT NULL`,
    'users.payments_enabled'
  );
  await run(
    `INSERT INTO platform_settings (key, value, updated_at)
     VALUES ('connect_price_base','0.1',NOW()),('min_job_budget','1',NOW()),('max_job_budget','10000',NOW())
     ON CONFLICT (key) DO NOTHING`,
    'seed connect_price_base, min/max_job_budget'
  );
  // Indexes for admin user search (LOWER() expressions used in ILIKE queries)
  await run(`CREATE INDEX IF NOT EXISTS idx_users_lower_username ON users(LOWER(username))`, 'idx_users_lower_username');
  await run(`CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC)`, 'idx_users_created_at');
  await run(`CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC)`, 'idx_jobs_created_at');
  await run(`CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at DESC)`, 'idx_payments_created_at');
}

// ─── Start ──────────────────────────────────────────────
initDb().then(async () => {
  await ensureNotificationsTable();
  // Ensure the canonical owner always has admin role (by uid AND by username, case-insensitive)
  await query(`UPDATE users SET role = 'admin' WHERE id IN ('pi_cherry19899','pi_a2b617f7-f510-4502-a046-805facedcc29') AND role != 'admin'`).catch(() => {});
  await query(`UPDATE users SET role = 'admin' WHERE LOWER(username) = 'cherry19899' AND role != 'admin'`).catch(() => {});
  // Fix double-prefix corruption from old registration bug (idempotent)
  await query(`UPDATE jobs SET posted_by = 'pi_cherry19899' WHERE posted_by = 'pi_pi_cherry19899'`).catch(() => {});
  await query(`UPDATE applications SET freelancer_id = 'pi_cherry19899' WHERE freelancer_id = 'pi_pi_cherry19899'`).catch(() => {});
  // Remove test clutter jobs (description='test', title contains 'test') — idempotent
  await query(`DELETE FROM applications WHERE job_id IN (SELECT id FROM jobs WHERE description = 'test' AND title ILIKE '%test%')`).catch(() => {});
  await query(`DELETE FROM jobs WHERE description = 'test' AND title ILIKE '%test%'`).catch(() => {});
  // Pre-warm admin stats cache so the first admin load shows data instantly
  // (avoids empty Statistics tab during Render free-tier cold start).
  const _adminRouter = require('./routes/admin');
  if (_adminRouter.warmStats) _adminRouter.warmStats().catch(() => {});
  // ─── Socket.io setup ──────────────────────────────────────────────
  const { JWT_SECRET: _jwtSecret } = require('./src/middleware');
  const FRONTEND_ORIGIN = process.env.FRONTEND_URL || 'https://cherry19899.github.io';
  const io = new SocketIOServer(httpServer, {
    cors: {
      origin: [
        FRONTEND_ORIGIN,
        'https://cherry19899.github.io',
        ...(process.env.NODE_ENV !== 'production' ? ['http://localhost:3000', 'http://localhost:5173'] : []),
      ],
      methods: ['GET', 'POST'],
      credentials: true,
    },
    transports: ['websocket', 'polling'],
  });

  // Socket.io auth middleware — verify JWT token
  io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication required'));
    try {
      const decoded = jwt.verify(token, _jwtSecret);
      socket.userId = decoded.id;
      next();
    } catch (err) {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    const userId = socket.userId;

    socket.on('join_room', async (roomId) => {
      if (typeof roomId !== 'string' || roomId.length >= 200) return;
      try {
        const room = await query(
          'SELECT client_id, freelancer_id FROM chat_rooms WHERE id = $1 LIMIT 1',
          [roomId]
        );
        if (!room.rows.length) return;
        const r = room.rows[0];
        if (r.client_id === userId || r.freelancer_id === userId) {
          socket.join(roomId);
        }
      } catch (_) {}
    });

    socket.on('leave_room', (roomId) => {
      socket.leave(roomId);
    });

    socket.on('typing', ({ roomId, userId: uid }) => {
      if (typeof roomId === 'string') {
        socket.to(roomId).emit('typing', { userId: uid || userId });
      }
    });

    socket.on('stop_typing', ({ roomId, userId: uid }) => {
      if (typeof roomId === 'string') {
        socket.to(roomId).emit('stop_typing', { userId: uid || userId });
      }
    });
  });

  // Export io for use in route handlers (push new messages to connected clients)
  app.set('io', io);
  logger.info('[WorkPro API] Socket.io ready');

  // ─── Web Push VAPID setup ──────────────────────────────────────────────
  const webpush = require('web-push');
  const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY  || null;
  const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || null;
  const VAPID_EMAIL   = process.env.VAPID_EMAIL || 'mailto:admin@workpro.app';
  if (VAPID_PUBLIC && VAPID_PRIVATE) {
    webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC, VAPID_PRIVATE);
    app.set('webpush', webpush);
    logger.info('[WorkPro API] Web Push VAPID configured');
  } else {
    logger.warn('[WorkPro API] Web Push disabled — set VAPID_PUBLIC_KEY + VAPID_PRIVATE_KEY env vars');
    // Generate keys and print them to logs (one-time helper)
    if (process.env.GENERATE_VAPID === '1') {
      const keys = webpush.generateVAPIDKeys();
      logger.info('[VAPID] Add these to Render env vars:');
      logger.info('  VAPID_PUBLIC_KEY =', keys.publicKey);
      logger.info('  VAPID_PRIVATE_KEY =', keys.privateKey);
    }
  }

  const server = httpServer.listen(PORT, () => {
    logger.info(`[WorkPro API] v3.3.0 on port ${PORT} (${NODE_ENV})`);
  });

  // ─── Keep-alive self-ping ──────────────────────────────────────────────
  // Render's free tier spins the instance down after ~15 min without inbound
  // traffic. A cold start then takes 30-60s — which exceeds the Pi payment
  // approval window (~60s) and makes admin requests time out. Pinging our own
  // public URL through Render's load balancer every 10 min counts as inbound
  // traffic and keeps the instance warm. (Requests to localhost would NOT count.)
  const SELF_URL = process.env.RENDER_EXTERNAL_URL || 'https://workpro-api.onrender.com';
  if (NODE_ENV === 'production') {
    setInterval(() => {
      fetch(`${SELF_URL}/api/health`, { method: 'GET' })
        .then(r => logger.info(`[keep-alive] self-ping ${r.status}`))
        .catch(e => logger.warn('[keep-alive] self-ping failed:', e.message));
    }, 10 * 60 * 1000); // every 10 minutes
  }

  // ─── Auto-release escrow after 14 days ─────────────────────────────────
  // If a funded escrow sits untouched for 14 days (no release, no dispute),
  // auto-release the funds to the freelancer and notify both parties.
  const { query: arQuery, getPool: arGetPool } = require('./src/db');
  const { getPlatformFee: arGetFee, notify: arNotify, audit: arAudit } = require('./src/helpers');
  const { a2uEnabled: arA2uEnabled, sendA2U: arSendA2U } = require('./src/pi-a2u');
  async function autoReleaseExpiredEscrows() {
    try {
      // Sweep zombie escrows: 'pending' means the Pi payment was never completed,
      // so there is no money in them — after 7 days they only clutter the Active
      // tab (the client has no button to remove them). Cancel them silently.
      const zombie = await arQuery(
        `UPDATE escrows SET status='cancelled', updated_at=NOW()
         WHERE status='pending' AND created_at < NOW() - INTERVAL '7 days'
         RETURNING id`
      ).catch(() => ({ rows: [] }));
      if (zombie.rows.length) {
        logger.info(`[auto-release] cancelled ${zombie.rows.length} stale pending escrow(s): ${zombie.rows.map(r => r.id).join(', ')}`);
      }
      // Only auto-release when the freelancer actually SUBMITTED the work and the
      // client failed to review it within 14 days. Funded-but-not-submitted escrows
      // are never auto-paid (protects the client from a freelancer who did nothing).
      const due = await arQuery(
        `SELECT e.* FROM escrows e
         JOIN jobs j ON j.id = e.job_id
         WHERE e.status = 'funded' AND j.status = 'submitted'
           AND j.updated_at < NOW() - INTERVAL '14 days'`
      );
      if (!due.rows.length) return;
      const fee = await arGetFee();
      for (const escrow of due.rows) {
        const net = parseFloat((escrow.amount * (1 - fee)).toFixed(8));
        const client = await arGetPool().connect();
        try {
          await client.query('BEGIN');
          const upd = await client.query(
            "UPDATE escrows SET status='released', updated_at=NOW() WHERE id=$1 AND status='funded' RETURNING id",
            [escrow.id]
          );
          if (!upd.rows.length) { await client.query('ROLLBACK'); client.release(); continue; }
          await client.query('UPDATE users SET balance_pi = COALESCE(balance_pi,0) + $1, total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $2', [net, escrow.freelancer_id]);
          await client.query("UPDATE jobs SET status='completed', updated_at=NOW() WHERE id=$1", [escrow.job_id]);
          await client.query('COMMIT');
        } catch (e) {
          await client.query('ROLLBACK').catch(() => {});
          client.release();
          logger.warn(`[auto-release] escrow ${escrow.id} failed:`, e.message);
          continue;
        }
        client.release();
        // Real A2U payout (same as manual release)
        let arTxid = null;
        if (arA2uEnabled()) {
          try {
            const r = await arSendA2U(escrow.freelancer_id, net, 'WorkPro payment', { type: 'escrow_auto_release', escrow_id: escrow.id, job_id: escrow.job_id });
            arTxid = r.txid;
            await arQuery('UPDATE users SET balance_pi = GREATEST(COALESCE(balance_pi,0) - $1, 0), updated_at = NOW() WHERE id = $2', [net, escrow.freelancer_id]).catch(() => {});
            await arQuery('UPDATE escrows SET payout_txid = $1, updated_at = NOW() WHERE id = $2', [arTxid, escrow.id]).catch(() => {});
          } catch (e) { logger.warn(`[a2u] auto-release payout failed for escrow ${escrow.id}: ${e.message}`); }
        }
        await arNotify(escrow.freelancer_id, 'payment', 'Авто-выплата эскроу', arTxid ? `${net}π отправлено на ваш Pi-кошелёк (14 дней без спора).` : `${net}π зачислено автоматически (14 дней без спора).`, escrow.job_id, null).catch(() => {});
        await arNotify(escrow.client_id, 'escrow', 'Эскроу авто-выплачен', 'Средства по задаче автоматически переведены фрилансеру через 14 дней.', escrow.job_id, null).catch(() => {});
        await arAudit('escrow_auto_released', { escrow_id: escrow.id, freelancer_id: escrow.freelancer_id, net_paid: net, payout_txid: arTxid }).catch(() => {});
        logger.info(`[auto-release] escrow ${escrow.id} released (${net}π)${arTxid ? ' + A2U ' + arTxid : ''}`);
      }
      // Milestone auto-release: freelancer requested a milestone payout and the
      // client stayed silent past auto_release_at (14 days) — release that stage.
      const msDue = await arQuery(
        `SELECT m.*, e.client_id, e.freelancer_id, e.job_id FROM escrow_milestones m
         JOIN escrows e ON e.id = m.escrow_id
         WHERE m.status = 'requested' AND m.auto_release_at IS NOT NULL AND m.auto_release_at < NOW()
           AND e.status = 'funded'`
      ).catch(() => ({ rows: [] }));
      for (const m of msDue.rows) {
        const msFee = await arGetFee();
        const msNet = parseFloat((parseFloat(m.amount) * (1 - msFee)).toFixed(2));
        const cl = await arGetPool().connect();
        try {
          await cl.query('BEGIN');
          const upd = await cl.query("UPDATE escrow_milestones SET status='auto_released', approved_at=NOW() WHERE id=$1 AND status='requested' RETURNING id", [m.id]);
          if (!upd.rows.length) { await cl.query('ROLLBACK'); cl.release(); continue; }
          await cl.query('UPDATE users SET balance_pi = COALESCE(balance_pi,0) + $1, updated_at=NOW() WHERE id=$2', [msNet, m.freelancer_id]);
          await cl.query('INSERT INTO escrow_transactions (escrow_id, milestone_id, type, amount, note) VALUES ($1,$2,$3,$4,$5)',
            [m.escrow_id, m.id, 'release', parseFloat(m.amount), `Milestone ${m.milestone_index + 1} auto-released`]);
          const left = await cl.query("SELECT COUNT(*) FROM escrow_milestones WHERE escrow_id=$1 AND status IN ('pending','requested')", [m.escrow_id]);
          if (parseInt(left.rows[0].count) === 0) {
            await cl.query("UPDATE escrows SET status='completed', updated_at=NOW() WHERE id=$1", [m.escrow_id]);
          }
          await cl.query('COMMIT');
        } catch (e) {
          await cl.query('ROLLBACK').catch(() => {});
          cl.release();
          logger.warn(`[auto-release] milestone ${m.id} failed:`, e.message);
          continue;
        }
        cl.release();
        let msTxid = null;
        if (arA2uEnabled()) {
          try {
            const r = await arSendA2U(m.freelancer_id, msNet, 'WorkPro milestone payment', { type: 'milestone_auto_release', escrow_id: m.escrow_id, milestone_id: m.id });
            msTxid = r.txid;
            await arQuery('UPDATE users SET balance_pi = GREATEST(COALESCE(balance_pi,0) - $1, 0), updated_at = NOW() WHERE id = $2', [msNet, m.freelancer_id]).catch(() => {});
          } catch (e) { logger.warn(`[a2u] milestone auto-release payout failed ${m.id}: ${e.message}`); }
        }
        await arNotify(m.freelancer_id, 'milestone_approved', 'Этап авто-выплачен', msTxid ? `${msNet}π за этап ${m.milestone_index + 1} отправлено на ваш Pi-кошелёк (14 дней без ответа заказчика).` : `${msNet}π зачислено за этап ${m.milestone_index + 1} автоматически.`, m.job_id, null).catch(() => {});
        await arNotify(m.client_id, 'escrow', 'Этап авто-выплачен', `Этап ${m.milestone_index + 1} автоматически выплачен фрилансеру через 14 дней.`, m.job_id, null).catch(() => {});
        await arAudit('milestone_auto_released', { escrow_id: m.escrow_id, milestone_id: m.id, net_paid: msNet, payout_txid: msTxid }).catch(() => {});
        logger.info(`[auto-release] milestone ${m.id} released (${msNet}π)${msTxid ? ' + A2U ' + msTxid : ''}`);
      }
    } catch (e) { logger.warn('[auto-release] sweep error:', e.message); }
  }
  const { checkSavedSearchAlerts } = require('./src/saved-search-alerts');
  async function hourlySweep() {
    await autoReleaseExpiredEscrows();
    await checkSavedSearchAlerts().then(r => {
      if (r.alerted) logger.info(`[saved-search] alerted ${r.alerted}/${r.total}`);
    }).catch(e => logger.warn('[saved-search] sweep error:', e.message));
  }
  if (NODE_ENV === 'production') {
    setInterval(hourlySweep, 60 * 60 * 1000); // hourly sweep
    setTimeout(hourlySweep, 30 * 1000);       // once shortly after boot
  }

  // Graceful shutdown — Render sends SIGTERM before killing the process
  const shutdown = (signal) => {
    logger.info(`[WorkPro API] ${signal} received — graceful shutdown`);
    io.close();
    server.close(() => {
      logger.info('[WorkPro API] HTTP server closed');
      // Use getPool() — db.js exports `pool` by value at load time (null then),
      // so destructuring `{ pool }` would always be null. getPool() returns the live pool.
      const { getPool } = require('./src/db');
      const livePool = getPool && getPool();
      if (livePool) livePool.end(() => {
        logger.info('[WorkPro API] DB pool closed');
        process.exit(0);
      });
      else process.exit(0);
    });
    // Force-kill after 10s if connections don't drain
    setTimeout(() => { logger.error('[WorkPro API] Forced exit after timeout'); process.exit(1); }, 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
}).catch(err => {
  logger.error('[Server] Failed to start:', err);
  process.exit(1);
});

module.exports = app;

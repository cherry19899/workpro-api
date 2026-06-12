/**
 * WorkPro API v3.1.0
 * Freelance Marketplace
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fetch = require('node-fetch');
const { query, initDb, getPool } = require('./db');

const app = express();
// Render sits behind a proxy — needed so req.ip reflects the real client for rate limiting
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  console.warn('[SECURITY] JWT_SECRET env var is not set — using a random secret. All sessions will be invalidated on each restart.');
  return crypto.randomBytes(64).toString('hex');
})();
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'admin-secret-key';
if (ADMIN_API_KEY === 'admin-secret-key') {
  console.warn('[SECURITY] ADMIN_API_KEY is the default value — set a strong ADMIN_API_KEY env var, otherwise the admin panel is publicly accessible.');
}
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';
const PI_API_KEY = process.env.PI_API_KEY || '';
const PI_API_BASE = 'https://api.minepi.com';

// ─── Middleware ──────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true, limit: '4mb' }));
app.use(cors({
  origin: [FRONTEND_URL, 'https://cherry19899.github.io', 'http://localhost:3000', 'http://localhost:5173', 'http://localhost:3001'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-pi-token', 'x-admin-key', 'x-username'],
  credentials: true,
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  skip: (req) => req.path === '/api/health',
}));

// Stricter rate limits for sensitive endpoints (per IP)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
  message: { error: 'Too many auth attempts, try again later' },
});
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 100,
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
  message: { error: 'Too many admin requests' },
});
// Strict limiter for connects/payments to prevent abuse
const connectsLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20,
  // Key by IP, NOT x-user-id — the user header is client-controlled and trivially rotated to bypass the cap
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
  message: { error: 'Too many connect operations, try again later' },
});
// Strict limiter for chat message sending — 30 messages per minute per IP
const messageLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
  message: { error: 'Too many messages, slow down' },
});
const jobPostLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
  message: { error: 'Too many jobs posted, try again later' },
});
app.use('/api/auth', authLimiter);
app.use('/api/me', authLimiter); // POST /api/me is a login endpoint — same rate limit
app.use('/api/admin', adminLimiter);
app.use('/api/connects/purchase', connectsLimiter);
app.use('/api/connects/buy', connectsLimiter);
app.use('/api/payments', connectsLimiter);
// Apply message limiter to all chat endpoints (covers /rooms, /conversations, /:roomId)
app.use('/api/chat/', messageLimiter);

// ─── Helpers ──────────────────────────────────────────────
function now() { return new Date().toISOString(); }
async function audit(action, data) {
  try {
    await query('INSERT INTO audit_logs (action, data) VALUES ($1, $2)', [action, JSON.stringify(data)]);
  } catch (_) {}
}

async function notify(userId, type, title, body, jobId, roomId) {
  try {
    await query(
      `INSERT INTO notifications (user_id, type, title, body, job_id, room_id, is_read, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,false,NOW())`,
      [userId, type, title, body || null, jobId || null, roomId || null]
    );
  } catch (_) {}
}

// Ensure schema patches (idempotent, run on startup)
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
    // Add last_chat_read_at to users if not exists (idempotent)
    await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_chat_read_at TIMESTAMPTZ`);
    // Ensure unique constraint on applications(job_id, freelancer_id) to prevent duplicate apply race
    await query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_unique_apply ON applications(job_id, freelancer_id)`);
  } catch (_) {}
}

// ─── Pi Platform API ──────────────────────────────────────────────
// userAccessToken: when provided (e.g. for /v2/me identity check), use user Bearer token instead of server Key
async function piApiRequest(path, method = 'GET', body = null, userAccessToken = null) {
  const opts = {
    method,
    headers: {
      'Authorization': userAccessToken ? `Bearer ${userAccessToken}` : `Key ${PI_API_KEY}`,
      'Content-Type': 'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${PI_API_BASE}${path}`, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_message || `Pi API error: ${res.status}`);
  return data;
}

async function piApprovePayment(paymentId) {
  return piApiRequest(`/v2/payments/${paymentId}/approve`, 'POST');
}

async function piCompletePayment(paymentId, txid) {
  return piApiRequest(`/v2/payments/${paymentId}/complete`, 'POST', { txid });
}

async function piGetPayment(paymentId) {
  return piApiRequest(`/v2/payments/${paymentId}`);
}

// ─── Auth Middleware ──────────────────────────────────────────────
async function auth(req, res, next) {
  // Prefer JWT from Authorization: Bearer header — verified, not spoofable
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
      req.userId = decoded.id;
      req.jwtVerified = true;
      return next();
    } catch (_) { /* invalid/expired JWT — fall through to x-user-id */ }
  }
  // Legacy: accept user ID from x-user-id or x-pi-token headers
  let userId = req.headers['x-user-id'] || req.headers['x-pi-token'];
  if (!userId) return res.status(401).json({ error: 'Access token required' });
  // Alias cherry19899 (username) → pi_cherry19899 (canonical ID) so all data stays unified
  if (userId === 'cherry19899') userId = 'pi_cherry19899';
  req.userId = userId;

  // Auto-register user in DB on first API call
  try {
    const username = req.headers['x-username'] || userId.replace(/^pi_/, '');
    const existing = await query(
      `SELECT id, username FROM users WHERE id = $1 LIMIT 1`,
      [userId]
    );
    if (!existing.rows.length) {
      // New user — default role is freelancer; admin role is only granted via DB
      await query(
        `INSERT INTO users (id, username, role, balance_connects, created_at, updated_at)
         VALUES ($1, $2, 'freelancer', 10, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING`,
        [userId, username]
      );
    } else if (req.headers['x-username'] && existing.rows[0].username !== req.headers['x-username']) {
      // Sync username only (never change role via header)
      await query(
        `UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2`,
        [req.headers['x-username'], userId]
      );
    }
  } catch (_) { /* ignore — user already exists or table error */ }

  next();
}

// softAuth — extracts userId but NEVER rejects (for endpoints where bundle sends no auth)
function softAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
      req.userId = decoded.id;
      req.jwtVerified = true;
      return next();
    } catch (_) { /* invalid/expired — fall through to x-user-id */ }
  }
  let uid = req.headers['x-user-id'] || req.headers['x-pi-token'] || null;
  if (uid === 'cherry19899') uid = 'pi_cherry19899';
  req.userId = uid;
  next();
}

async function adminAuth(req, res, next) {
  // SECURITY: the x-user-id header is client-controlled — anyone could send the owner's
  // id and pass a DB role check. Admin access therefore REQUIRES the shared ADMIN_API_KEY
  // secret, sent as `x-admin-key`, `Authorization: Bearer <key>`, or `?admin_key=`.
  // The frontend admin panel attaches it from localStorage.workpro_admin_token.
  let key = req.headers['x-admin-key'] || req.headers['authorization'] || req.query.admin_key || '';
  if (typeof key === 'string' && key.startsWith('Bearer ')) key = key.slice(7);
  const keyOk = key.length > 0 && key.length === ADMIN_API_KEY.length &&
    crypto.timingSafeEqual(Buffer.from(key), Buffer.from(ADMIN_API_KEY));
  if (!keyOk) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  // Resolve acting user id for audit logging only — the secret is what authorizes.
  let userId = req.headers['x-user-id'] || req.query._uid || req.query.user_id || null;
  if (userId === 'cherry19899') userId = 'pi_cherry19899';
  req.userId = userId;
  req.isAdmin = true;
  return next();
}

async function checkBlocked(req, res, next) {
  try {
    const result = await query('SELECT is_blocked FROM users WHERE id = $1', [req.userId]);
    if (result.rows[0]?.is_blocked) {
      return res.status(403).json({ error: 'Account blocked' });
    }
    next();
  } catch (_) { next(); }
}

function serverError(err, res) {
  console.error('[Error]', err);
  return res.status(500).json({ error: 'Internal server error' });
}

// ─── Root & Pi Network verification ──────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ name: 'WorkPro API', version: '3.2.0', status: 'ok' });
});

// Pi Network calls this to verify backend ownership
app.get('/.well-known/pi-network', (req, res) => {
  res.json({ app: 'workpro', backend: true, version: '3.2.0' });
});

// ─── Health ──────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await query('SELECT 1');
    res.json({ status: 'ok', version: '3.2.0', database: 'connected', timestamp: now() });
  } catch (err) {
    console.error('[Health] DB check failed:', err.message);
    res.status(500).json({ status: 'error', database: 'disconnected' });
  }
});

// PUT /api/me — update profile (used by Profile.js)
app.put('/api/me', auth, async (req, res) => {
  const { username, bio, skills, display_name } = req.body;
  if (bio && bio.length > 1000) return res.status(400).json({ error: 'Bio too long (max 1000)' });
  if (skills && skills.length > 300) return res.status(400).json({ error: 'Skills too long (max 300)' });
  try {
    const uname = display_name || username;
    if (uname && uname.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
    const skillsStr = Array.isArray(skills) ? skills.join(',') : (skills || null);
    await query(
      'UPDATE users SET username = COALESCE($1, username), bio = COALESCE($2, bio), skills = COALESCE($3, skills), updated_at = NOW() WHERE id = $4',
      [uname || null, bio || null, skillsStr, req.userId]
    );
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1', [req.userId]);
    const u = result.rows[0];
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { serverError(err, res); }
});

// GET /api/me — get current user profile (used by Profile.js) — auth required
app.get('/api/me', auth, async (req, res) => {
  try {
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1', [req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    const levelInfo = computeLevel(u.total_jobs_completed, u.rating);
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin', level: levelInfo });
  } catch (err) { serverError(err, res); }
});

// POST /api/me — alias login endpoint used by Auth.js + bundle registration
app.post('/api/me', async (req, res) => {
  const { uid, username, accessToken } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid required' });
  if (username && username.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
  try {
    // Verify Pi accessToken when provided; for new accounts it is required
    if (accessToken) {
      try {
        const piUser = await piApiRequest('/v2/me', 'GET', null, accessToken);
        const piUid = piUser && (piUser.uid || piUser.username);
        const normalizedPiUid = piUid && (piUid.startsWith('pi_') ? piUid : 'pi_' + piUid);
        if (normalizedPiUid && normalizedPiUid !== uid && piUid !== uid) {
          return res.status(403).json({ error: 'Token does not match uid' });
        }
      } catch (e) {
        return res.status(401).json({ error: 'Pi token verification failed. Please re-authenticate.' });
      }
    } else {
      // No accessToken: only allow existing accounts (prevent account hijacking)
      const existing = await query('SELECT id FROM users WHERE id = $1', [uid]);
      if (!existing.rows.length) {
        return res.status(401).json({ error: 'accessToken required for new account registration' });
      }
    }
    const uname = username || uid.replace(/^pi_/, '') || uid;
    // UPSERT: create or update user — role is never changed here (only via adminAuth-protected endpoints)
    await query(
      `INSERT INTO users (id, username, role, balance_connects, created_at, updated_at)
       VALUES ($1, $2, 'freelancer', 10, NOW(), NOW())
       ON CONFLICT (id) DO UPDATE SET username = EXCLUDED.username, updated_at = NOW()`,
      [uid, uname]
    );
    // Migrate legacy 'cherry19899' records to 'pi_cherry19899' (idempotent, runs every login)
    if (uid === 'pi_cherry19899') {
      try {
        const r1 = await query(`UPDATE jobs SET posted_by = 'pi_cherry19899' WHERE posted_by = 'cherry19899'`);
        const r2 = await query(`UPDATE applications SET freelancer_id = 'pi_cherry19899' WHERE freelancer_id = 'cherry19899'`);
        await query(`UPDATE escrows SET client_id = 'pi_cherry19899' WHERE client_id = 'cherry19899'`);
        await query(`UPDATE escrows SET freelancer_id = 'pi_cherry19899' WHERE freelancer_id = 'cherry19899'`);
        const legacyUser = await query(`SELECT balance_connects, bio, skills FROM users WHERE id = 'cherry19899'`);
        if (legacyUser.rows.length > 0) {
          const old = legacyUser.rows[0];
          await query(`UPDATE users SET balance_connects = GREATEST(balance_connects, $1), bio = COALESCE(NULLIF(bio,''), $2), skills = COALESCE(NULLIF(skills,''), $3) WHERE id = 'pi_cherry19899'`,
            [old.balance_connects || 0, old.bio || '', old.skills || '']);
          await query(`DELETE FROM users WHERE id = 'cherry19899'`);
        }
        // Migrate notifications sent to old user_id
        await query(`UPDATE notifications SET user_id = 'pi_cherry19899' WHERE user_id = 'cherry19899'`);
        if (r1.rowCount > 0 || r2.rowCount > 0) console.log(`[Migration] cherry19899→pi_cherry19899: jobs=${r1.rowCount} apps=${r2.rowCount}`);
      } catch (mErr) { console.error('[Migration] error:', mErr.message); }
    }
    // Always sync total_jobs_posted from real DB count to fix drift
    await query(`UPDATE users SET total_jobs_posted = (SELECT COUNT(*) FROM jobs WHERE posted_by = $1), updated_at = NOW() WHERE id = $1`, [uid]).catch(() => {});
    // Recalculate apply_cost for all jobs that still have the old default (1) — one-time migration
    await query(`UPDATE jobs SET apply_cost = CEIL(budget::numeric / 50.0)::int, connects_spent = CEIL(budget::numeric / 50.0)::int WHERE CEIL(budget::numeric / 50.0)::int != apply_cost`).catch((e) => console.error('[Migration] apply_cost fix error:', e.message));
    const user = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, status, created_at FROM users WHERE id = $1', [uid]);
    await audit('user_login', { user_id: uid });
    const u = user.rows[0];
    // Issue a real JWT instead of predictable dummy token
    const token = jwt.sign({ id: uid, username: uname }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin', token });
  } catch (err) { serverError(err, res); }
});

// ─── Auth ──────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { userId, username, accessToken } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  if (username && username.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });

  try {
    // accessToken is required to create or authenticate any account
    let piUser = null;
    if (accessToken) {
      try {
        piUser = await piApiRequest('/v2/me', 'GET', null, accessToken);
      } catch (e) {
        return res.status(401).json({ error: 'Pi token verification failed. Please re-authenticate.' });
      }
      // Verify the token belongs to the claimed userId
      const piUid = piUser && (piUser.uid || piUser.username);
      const normalizedPiUid = piUid && (piUid.startsWith('pi_') ? piUid : 'pi_' + piUid);
      if (normalizedPiUid && normalizedPiUid !== userId && piUid !== userId) {
        return res.status(403).json({ error: 'Token does not match userId' });
      }
    } else {
      // No accessToken: only allow if user already exists in DB (no new account creation without Pi token)
      const existing = await query('SELECT id FROM users WHERE id = $1', [userId]);
      if (!existing.rows.length) {
        return res.status(401).json({ error: 'accessToken required for new account registration' });
      }
    }

    const uid = userId;
    const uname = (piUser && piUser.username) || username || uid;
    const paymentsEnabled = piUser ? piUser.payments_enabled === true : false;

    const existing = await query('SELECT id, username, role FROM users WHERE id = $1', [uid]);
    if (!existing.rows.length) {
      // New user — default role is freelancer; admin is only assigned via DB directly
      await query(
        'INSERT INTO users (id, username, role, balance_connects, created_at, updated_at) VALUES ($1, $2, $3, 10, NOW(), NOW())',
        [uid, uname, 'freelancer']
      );
    } else if (piUser) {
      await query('UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2', [uname, uid]);
    } else {
      await query('UPDATE users SET updated_at = NOW() WHERE id = $1', [uid]);
    }

    const token = jwt.sign({ id: uid, username: uname }, JWT_SECRET, { expiresIn: '7d' });
    const user = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at FROM users WHERE id = $1', [uid]);
    await audit('user_login', { user_id: uid });
    res.json({ token, user: { ...user.rows[0], payments_enabled: paymentsEnabled } });
  } catch (err) {
    serverError(err, res);
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1',
      [req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Users ──────────────────────────────────────────────
app.get('/api/users', softAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = parseInt(req.query.offset) || 0;
    // Never expose role (hides who is admin) or any sensitive fields
    const result = await query(
      'SELECT id, username, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, created_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset]
    );
    const total = await query('SELECT COUNT(*) FROM users');
    res.json({ users: result.rows, count: result.rowCount, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.get('/api/users/:id', softAuth, async (req, res) => {
  const callerId = req.userId || null;
  const userId = req.params.id === 'me' ? (callerId || '') : req.params.id;
  if (!userId) return res.status(401).json({ error: 'User ID required' });
  try {
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at FROM users WHERE id = $1', [userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    const isOwner = callerId === u.id;
    // Sensitive fields only for the owner themselves
    if (!isOwner) {
      delete u.balance_connects;
      delete u.balance_pi;
      delete u.is_blocked;
      delete u.status;
    }
    // Never expose internal role string publicly — use boolean flag
    const is_admin = u.role === 'admin';
    delete u.role;
    res.json({ ...u, uid: u.id, is_admin });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/users/:id', auth, async (req, res) => {
  if (req.userId !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
  const { username, email, bio, skills, availability, avatar } = req.body;
  if (username && username.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
  if (bio && bio.length > 1000) return res.status(400).json({ error: 'Bio too long (max 1000)' });
  if (email && (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).json({ error: 'Invalid email address' });
  // Limit base64 avatar to 2MB to prevent DoS
  if (avatar && avatar.length > 2 * 1024 * 1024 * 1.37) {
    return res.status(400).json({ error: 'Фото слишком большое (макс. 2MB)' });
  }
  try {
    const result = await query(
      'UPDATE users SET username = COALESCE($1, username), email = COALESCE($2, email), bio = COALESCE($3, bio), skills = COALESCE($4, skills), availability = COALESCE($5, availability), avatar = COALESCE($6, avatar), updated_at = NOW() WHERE id = $7 RETURNING id, username, email, role, bio, skills, avatar, availability, balance_connects, rating, kyc_verified',
      [username, email, bio, skills, availability, avatar, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    serverError(err, res);
  }
});

app.get('/api/users/:id/ratings', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM ratings WHERE to_user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.params.id, limit, offset]);
    const totalRes = await query('SELECT COUNT(*), AVG(rating) FROM ratings WHERE to_user_id = $1', [req.params.id]);
    const avg = parseFloat(totalRes.rows[0].avg) || 0;
    res.json({ ratings: result.rows, average: Math.round(avg * 10) / 10, count: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Jobs ──────────────────────────────────────────────
// Normalize images before DB write: array→JSON string, {}→null, falsy→null
function serializeImages(images) {
  if (!images) return null;
  if (typeof images === 'string') {
    const s = images.trim();
    if (!s || s === '{}' || s === '[]' || s === 'null') return null;
    return s;
  }
  if (Array.isArray(images)) return images.length > 0 ? JSON.stringify(images) : null;
  if (typeof images === 'object') {
    const keys = Object.keys(images);
    return keys.length > 0 ? JSON.stringify(images) : null;
  }
  return null;
}
// Parse images on DB read: JSON string→array, null→null
function parseImages(images) {
  if (!images || images === '[object Object]') return null;
  if (typeof images === 'string') {
    try { return JSON.parse(images); } catch(e) { return null; }
  }
  return images;
}
function parseJobRow(job) {
  if (!job) return job;
  return { ...job, images: parseImages(job.images) };
}

app.get('/api/jobs', async (req, res) => {
  const { status, category, posted_by, client_uid, search, min_budget, max_budget, sort } = req.query;
  const limit = Math.min(parseInt(req.query.limit) || 20, 200);
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const ownerFilter = posted_by || client_uid;
  try {
    let conditions = [];
    const params = [];
    let idx = 1;

    if (status) { conditions.push(`status = $${idx++}`); params.push(status); }
    if (category && category !== 'all' && category !== 'All') { conditions.push(`LOWER(category) = LOWER($${idx++})`); params.push(category); }
    if (ownerFilter) { conditions.push(`posted_by = $${idx++}`); params.push(ownerFilter); }
    if (search) { conditions.push(`(title ILIKE $${idx} OR description ILIKE $${idx})`); params.push(`%${search}%`); idx++; }
    if (min_budget) { conditions.push(`budget >= $${idx++}`); params.push(parseFloat(min_budget)); }
    if (max_budget) { conditions.push(`budget <= $${idx++}`); params.push(parseFloat(max_budget)); }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    // Sort order: newest (default), oldest, budget_asc, budget_desc, budget_low, budget_high, popular
    const orderMap = {
      'newest': 'created_at DESC',
      'oldest': 'created_at ASC',
      'budget_asc': 'budget ASC',
      'budget_desc': 'budget DESC',
      'budget-asc': 'budget ASC',
      'budget-desc': 'budget DESC',
      'budget_low': 'budget ASC',
      'budget_high': 'budget DESC',
      'popular': 'applications DESC, created_at DESC',
    };
    const orderBy = orderMap[sort] || 'created_at DESC';

    const countResult = await query(`SELECT COUNT(*) FROM jobs ${where}`, params);
    const total = parseInt(countResult.rows[0].count);

    const offset = (parseInt(page) - 1) * parseInt(limit);
    const dataResult = await query(
      `SELECT * FROM jobs ${where} ORDER BY ${orderBy} LIMIT $${idx} OFFSET $${idx + 1}`,
      [...params, parseInt(limit), offset]
    );

    // Workaround: bundle v200 has inverted filter hiding 'open' jobs in Find Work feed.
    // Remap status open→in_progress in the LIST response only.
    // Individual job detail (/api/jobs/:id) is unaffected, keeping 'open' for Apply logic.
    const jobs = dataResult.rows.map(parseJobRow).map(function(j) {
      if (j.status === 'open') return Object.assign({}, j, { status: 'in_progress', _open: true });
      return j;
    });
    res.json({ jobs, total, page: parseInt(page), total_pages: Math.ceil(total / parseInt(limit)) });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/jobs', auth, checkBlocked, jobPostLimiter, async (req, res) => {
  const { title, description, category, budget, skills, deadline, images } = req.body;
  if (!title || !description || !budget) {
    return res.status(400).json({ error: 'Title, description, and budget are required' });
  }
  const budgetNum = parseFloat(budget);
  if (isNaN(budgetNum) || budgetNum < 1) return res.status(400).json({ error: 'Budget must be at least 1 Pi' });
  if (budgetNum > 10000) return res.status(400).json({ error: 'Budget cannot exceed 10000 Pi' });
  if (String(title).length > 200) return res.status(400).json({ error: 'Title too long (max 200 chars)' });
  if (String(description).length > 5000) return res.status(400).json({ error: 'Description too long (max 5000 chars)' });
  if (images && Array.isArray(images) && images.length > 10) return res.status(400).json({ error: 'Too many images (max 10)' });
  if (skills && String(skills).length > 500) return res.status(400).json({ error: 'Skills too long (max 500)' });
  const applyCost = Math.ceil(budgetNum / 50); // 1-50π→1, 51-100π→2, 101-150π→3, ...
  try {
    const userRes = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const username = userRes.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO jobs (title, description, category, budget, skills, images, deadline, posted_by, posted_by_name, apply_cost, connects_spent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10) RETURNING *',
      [title, description, (category || 'other').toLowerCase(), budgetNum, skills || null, serializeImages(images), deadline || null, req.userId, username, applyCost]
    );
    await query('UPDATE users SET total_jobs_posted = total_jobs_posted + 1, updated_at = NOW() WHERE id = $1', [req.userId]);
    await audit('job_created', { job_id: result.rows[0].id, user_id: req.userId });
    res.json({ job: parseJobRow(result.rows[0]), success: true });
  } catch (err) {
    serverError(err, res);
  }
});

// GET /api/jobs/user/:userId — jobs posted by a specific user (MUST be before /:id)
app.get('/api/jobs/user/:userId', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const userId = req.params.userId;
    const result = await query(
      `SELECT j.*, u.username as client_username
       FROM jobs j LEFT JOIN users u ON u.id = j.posted_by
       WHERE j.posted_by = $1 OR LOWER(u.username) = LOWER($1)
       ORDER BY j.created_at DESC LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    res.json({ jobs: result.rows.map(parseJobRow), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs/as-freelancer — jobs where current user is the hired freelancer
app.get('/api/jobs/as-freelancer', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query(
      `SELECT j.*, u.username as client_username
       FROM jobs j
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE j.hired_freelancer_id = $1
       ORDER BY j.updated_at DESC LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    res.json({ jobs: result.rows.map(parseJobRow), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs/my — client's own posted jobs (must be before /:id to avoid conflict)
app.get('/api/jobs/my', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query(
      'SELECT j.*, u.username as client_username FROM jobs j LEFT JOIN users u ON u.id = j.posted_by WHERE j.posted_by = $1 ORDER BY j.created_at DESC LIMIT $2 OFFSET $3',
      [req.userId, limit, offset]
    );
    res.json({ jobs: result.rows.map(parseJobRow), limit, offset });
  } catch (err) { serverError(err, res); }
});

app.get('/api/jobs/:id', softAuth, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job_row = jobResult.rows[0];
    const callerId = req.userId || null;
    // Only return application details to the job owner (capped to prevent huge payloads)
    let applications = [];
    if (callerId && callerId === job_row.posted_by) {
      const appsResult = await query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC LIMIT 200', [req.params.id]);
      applications = appsResult.rows;
    }
    // Include chat room_id so frontend can show "Open chat" button
    const roomResult = await query('SELECT id FROM chat_rooms WHERE job_id = $1 LIMIT 1', [req.params.id]);
    const job = parseJobRow({ ...job_row, room_id: roomResult.rows[0]?.id || null });
    res.json({ job, applications });
  } catch (err) {
    serverError(err, res);
  }
});

app.patch('/api/jobs/:id', auth, checkBlocked, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    const { status } = req.body;
    const isHiredFreelancer = job.hired_freelancer_id === req.userId;
    // Only hired freelancer can use PATCH, and only to submit work for review
    if (!(isHiredFreelancer && status === 'submitted')) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (job.status !== 'in_progress') return res.status(400).json({ error: 'Job is not in progress' });
    const result = await query('UPDATE jobs SET status = COALESCE($1, status), updated_at = NOW() WHERE id = $2 RETURNING *', [status, req.params.id]);
    // Notify client when freelancer submits work for review
    if (status === 'submitted' && isHiredFreelancer) {
      await notify(job.posted_by, 'submitted', `Фрилансер сдал работу по задаче "${job.title}"`,
        'Проверьте результат и примите работу или откройте спор.', parseInt(req.params.id), null);
    }
    res.json({ job: result.rows[0], success: true });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/jobs/:id/apply', auth, checkBlocked, async (req, res) => {
  if (req.body.message && req.body.message.length > 2000) {
    return res.status(400).json({ error: 'Cover letter too long (max 2000 chars)' });
  }
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by === req.userId) return res.status(400).json({ error: 'Cannot apply to own job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });

    const existingApp = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2', [req.params.id, req.userId]);
    if (existingApp.rows.length) return res.status(400).json({ error: 'Already applied' });

    const userResult = await query('SELECT id, username, balance_connects, is_blocked FROM users WHERE id = $1', [req.userId]);
    const user = userResult.rows[0];
    const cost = job.apply_cost || 1;
    if (!user || user.balance_connects < cost) {
      return res.status(400).json({ error: 'Not enough connects', required: cost, current: user?.balance_connects || 0 });
    }

    // Atomic: deduct connects AND insert application in one transaction
    let appResult;
    const pgClient = await getPool().connect();
    try {
      await pgClient.query('BEGIN');
      await pgClient.query('UPDATE users SET balance_connects = balance_connects - $1, updated_at = NOW() WHERE id = $2', [cost, req.userId]);
      appResult = await pgClient.query(
        'INSERT INTO applications (job_id, job_title, freelancer_id, freelancer_name, message) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (job_id, freelancer_id) DO NOTHING RETURNING *',
        [req.params.id, job.title, req.userId, user.username || req.userId, req.body.message || '']
      );
      if (!appResult.rows.length) {
        await pgClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Already applied' });
      }
      await pgClient.query('UPDATE jobs SET applications = applications + 1, updated_at = NOW() WHERE id = $1', [req.params.id]);
      await pgClient.query('COMMIT');
    } catch (txErr) {
      await pgClient.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally {
      pgClient.release();
    }
    await audit('job_applied', { job_id: req.params.id, user_id: req.userId });
    await notify(job.posted_by, 'application', `Новый отклик на задачу "${job.title}"`,
      `${user.username || 'Фрилансер'} откликнулся на вашу задачу`, parseInt(req.params.id), null);
    const newBalance = (user.balance_connects || 0) - cost;
    res.json({ application: appResult.rows[0], success: true, remaining_connects: newBalance, new_balance: newBalance });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/jobs/:id/hire', auth, checkBlocked, async (req, res) => {
  const { application_id, freelancer_id } = req.body;
  if (!application_id || !freelancer_id) return res.status(400).json({ error: 'application_id and freelancer_id required' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });

    const appResult = await query('SELECT * FROM applications WHERE id = $1 AND job_id = $2', [application_id, req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app = appResult.rows[0];
    if (app.freelancer_id !== freelancer_id) return res.status(400).json({ error: 'freelancer_id does not match application' });

    // Accept chosen application, reject all others
    await query('UPDATE applications SET status = $1 WHERE id = $2', ['accepted', application_id]);
    await query('UPDATE applications SET status = $1 WHERE job_id = $2 AND id != $3 AND status = $4', ['rejected', req.params.id, application_id, 'pending']);

    // Update job
    const freelancerRes = await query('SELECT username FROM users WHERE id = $1', [freelancer_id]);
    const freelancerName = freelancerRes.rows[0]?.username || freelancer_id;
    await query(
      'UPDATE jobs SET status = $1, hired_freelancer_id = $2, hired_freelancer_name = $3, updated_at = NOW() WHERE id = $4',
      ['in_progress', freelancer_id, freelancerName, req.params.id]
    );

    // Create or get chat room between client and freelancer
    const existingRoom = await query(
      'SELECT id FROM chat_rooms WHERE job_id = $1 AND client_id = $2 AND freelancer_id = $3',
      [req.params.id, req.userId, freelancer_id]
    );
    let roomId;
    if (existingRoom.rows.length) {
      roomId = existingRoom.rows[0].id;
    } else {
      roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
      await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4)', [roomId, req.userId, freelancer_id, req.params.id]);
    }

    await audit('job_hired', { job_id: req.params.id, freelancer_id, application_id });
    await notify(freelancer_id, 'hired', `Вас наняли на задачу "${job.title}"`,
      'Заказчик выбрал вас. Обсудите детали в чате.', parseInt(req.params.id), roomId);
    res.json({ success: true, room_id: roomId, freelancer_name: freelancerName });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/jobs/:id/complete', auth, checkBlocked, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    if (!['in_progress', 'submitted'].includes(job.status)) return res.status(400).json({ error: 'Job is not in progress' });

    let paidAmount = 0;
    const pgClient5 = await getPool().connect();
    try {
      await pgClient5.query('BEGIN');
      // Idempotency guard: only complete if still in_progress or submitted
      const jobUpdate = await pgClient5.query(
        "UPDATE jobs SET status='completed', updated_at=NOW() WHERE id=$1 AND status = ANY($2) RETURNING id",
        [req.params.id, ['in_progress', 'submitted']]
      );
      if (!jobUpdate.rows.length) { await pgClient5.query('ROLLBACK'); return res.status(400).json({ error: 'Job already completed or status changed' }); }
      const escrow = await pgClient5.query(
        "UPDATE escrows SET status='released', updated_at=NOW() WHERE job_id=$1 AND status='funded' RETURNING *",
        [req.params.id]
      );
      if (escrow.rows.length) {
        const e = escrow.rows[0];
        const net = parseFloat((e.amount * 0.98).toFixed(8)); // 2% platform commission
        await pgClient5.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, updated_at = NOW() WHERE id = $2', [net, e.freelancer_id]);
        paidAmount = net;
      }
      if (job.hired_freelancer_id) {
        await pgClient5.query('UPDATE users SET total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $1', [job.hired_freelancer_id]);
      }
      await pgClient5.query('COMMIT');
    } catch (txErr) { await pgClient5.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient5.release(); }

    await audit('job_completed', { job_id: req.params.id, paid: paidAmount });
    if (job.hired_freelancer_id) {
      const payMsg = paidAmount > 0
        ? `Заказчик принял работу. Зачислено ${paidAmount}π на ваш счёт.`
        : 'Заказчик принял работу. Оплата была согласована отдельно.';
      await notify(job.hired_freelancer_id, 'completed', `Задача "${job.title}" принята`, payMsg, parseInt(req.params.id), null);
    }
    res.json({ success: true, paid: paidAmount });
  } catch (err) {
    serverError(err, res);
  }
});

app.delete('/api/jobs/:id', auth, checkBlocked, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    if (['in_progress', 'submitted'].includes(job.status)) return res.status(400).json({ error: 'Cannot delete a job that is in progress' });
    await query('DELETE FROM applications WHERE job_id = $1', [req.params.id]);
    await query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Applications ──────────────────────────────────────────────
app.get('/api/applications', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM applications WHERE freelancer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM applications WHERE freelancer_id = $1', [req.userId]);
    res.json({ applications: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.patch('/api/applications/:id', auth, async (req, res) => {
  const { status } = req.body;
  const OWNER_ALLOWED = ['accepted', 'rejected'];
  if (!OWNER_ALLOWED.includes(status)) return res.status(400).json({ error: `Invalid status. Allowed: ${OWNER_ALLOWED.join(', ')}` });
  try {
    const appResult = await query('SELECT a.*, j.posted_by FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (appResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 RETURNING *', [status, req.params.id]);
    await audit('application_status_changed', { app_id: req.params.id, status });
    res.json({ application: result.rows[0], success: true });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Chat ──────────────────────────────────────────────
app.get('/api/chat/rooms', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query(
      `SELECT r.*,
        (SELECT message FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message,
        (SELECT created_at FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
        j.title as job_title,
        CASE WHEN r.client_id = $1 THEN r.freelancer_id ELSE r.client_id END as other_user_id,
        CASE WHEN r.client_id = $1 THEN uf.username ELSE uc.username END as other_user_name
       FROM chat_rooms r
       LEFT JOIN jobs j ON j.id = r.job_id
       LEFT JOIN users uc ON uc.id = r.client_id
       LEFT JOIN users uf ON uf.id = r.freelancer_id
       WHERE r.client_id = $1 OR r.freelancer_id = $1
       ORDER BY last_message_at DESC NULLS LAST
       LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    res.json({ rooms: result.rows, limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/chat/rooms', auth, checkBlocked, async (req, res) => {
  const { freelancer_id, job_id } = req.body;
  const cId = req.userId; // always use authenticated user as client
  if (!freelancer_id || !job_id) return res.status(400).json({ error: 'freelancer_id and job_id required' });
  try {
    // Verify caller is actually involved in this job (poster or applicant/hired freelancer)
    const jobCheck = await query('SELECT posted_by, hired_freelancer_id FROM jobs WHERE id = $1', [job_id]);
    if (!jobCheck.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobCheck.rows[0];
    if (job.posted_by !== cId && freelancer_id !== cId) {
      const appCheck = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2 LIMIT 1', [job_id, cId]);
      if (!appCheck.rows.length) return res.status(403).json({ error: 'You are not a participant in this job' });
    }
    // Check if room already exists
    const existing = await query(
      'SELECT * FROM chat_rooms WHERE job_id = $1 AND ((client_id = $2 AND freelancer_id = $3) OR (client_id = $3 AND freelancer_id = $2))',
      [job_id, cId, freelancer_id]
    );
    if (existing.rows.length) return res.json({ room: existing.rows[0] });

    const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
    const result = await query(
      'INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [roomId, cId, freelancer_id, job_id]
    );
    res.json({ room: result.rows[0] });
  } catch (err) {
    serverError(err, res);
  }
});

app.get('/api/chat/rooms/:id/messages', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3', [req.params.id, limit, offset]);
    const messages = result.rows.map(m => ({ ...m, content: m.message, text: m.message }));
    res.json({ messages, limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/chat/rooms/:id/messages', auth, checkBlocked, async (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });
  if (message.length > 2000) return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const userResult = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userResult.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.id, req.userId, senderName, message.trim()]
    );
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.id]);

    // Notify the other party in the chat room
    const otherUserId = room.rows[0].client_id === req.userId
      ? room.rows[0].freelancer_id
      : room.rows[0].client_id;
    if (otherUserId) {
      await notify(otherUserId, 'message', `Новое сообщение от ${senderName}`, message.trim().substring(0, 100), null, req.params.id);
    }

    res.json({ message: result.rows[0] });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Escrow ──────────────────────────────────────────────
app.get('/api/escrow', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
    res.json({ escrows: result.rows, limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/escrow', auth, checkBlocked, async (req, res) => {
  const { job_id, freelancer_id, amount, payment_id } = req.body;
  if (!job_id || !freelancer_id || !amount) return res.status(400).json({ error: 'job_id, freelancer_id, amount required' });
  try {
    const jobCheck = await query('SELECT posted_by, hired_freelancer_id FROM jobs WHERE id = $1', [job_id]);
    if (!jobCheck.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (jobCheck.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    if (jobCheck.rows[0].hired_freelancer_id && jobCheck.rows[0].hired_freelancer_id !== freelancer_id) {
      return res.status(400).json({ error: 'freelancer_id does not match hired freelancer' });
    }
    // Atomic: check + insert in one transaction to prevent duplicate escrow race
    const pgClientE = await getPool().connect();
    let escrowRow;
    try {
      await pgClientE.query('BEGIN');
      const existing = await pgClientE.query('SELECT id FROM escrows WHERE job_id = $1 AND status = ANY($2) FOR UPDATE', [job_id, ['pending', 'funded']]);
      if (existing.rows.length) { await pgClientE.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already exists for this job' }); }
      const result = await pgClientE.query(
        'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [job_id, req.userId, freelancer_id, parseFloat(amount), payment_id || null]
      );
      await pgClientE.query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['in_progress', job_id]);
      await pgClientE.query('COMMIT');
      escrowRow = result.rows[0];
    } catch (txErr) { await pgClientE.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClientE.release(); }
    await audit('escrow_created', { escrow_id: escrowRow.id, job_id });
    res.json({ escrow: escrowRow });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/escrow/:id/release', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status !== 'funded') return res.status(400).json({ error: 'Escrow is not funded' });
    const net = parseFloat((escrow.amount * 0.98).toFixed(8)); // 2% platform commission
    // Atomic: update escrow status WHERE funded; concurrent calls fail here
    const pgClient3 = await getPool().connect();
    try {
      await pgClient3.query('BEGIN');
      const updated = await pgClient3.query(
        "UPDATE escrows SET status='released', updated_at=NOW() WHERE id=$1 AND status='funded' RETURNING id",
        [req.params.id]
      );
      if (!updated.rows.length) { await pgClient3.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already processed' }); }
      await pgClient3.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $2', [net, escrow.freelancer_id]);
      await pgClient3.query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['completed', escrow.job_id]);
      await pgClient3.query('COMMIT');
    } catch (txErr) { await pgClient3.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient3.release(); }
    await notify(escrow.freelancer_id, 'payment', 'Оплата получена', `${net}π зачислено на ваш счёт после завершения задачи.`, escrow.job_id, null);
    await audit('escrow_released', { escrow_id: req.params.id, freelancer_id: escrow.freelancer_id, amount: escrow.amount, net_paid: net });
    res.json({ escrow: { ...escrow, status: 'released' }, success: true });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Pi Payments ──────────────────────────────────────────────
app.post('/api/payments/:paymentId/approve', auth, async (req, res) => {
  const { paymentId } = req.params;
  const { metadata } = req.body;
  try {
    // Verify ownership if payment already in DB
    const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
    if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== req.userId) {
      return res.status(403).json({ error: 'Payment does not belong to you' });
    }
    let piPayment = { amount: 0 };
    // When PI_API_KEY is configured, verification with Pi Platform is mandatory
    if (PI_API_KEY) {
      try {
        piPayment = await piApprovePayment(paymentId);
      } catch (piErr) {
        console.error('[Payment] Pi approval failed:', piErr.message);
        return res.status(502).json({ error: 'Pi payment verification failed. Try again.' });
      }
    }

    // Store in DB (UPSERT — idempotent)
    await query(
      `INSERT INTO payments (id, user_id, type, amount, metadata, status, payment_id)
       VALUES ($1,$2,$3,$4,$5,'approved',$1)
       ON CONFLICT (id) DO UPDATE SET status='approved', updated_at=NOW()`,
      [paymentId, req.userId, metadata?.type || 'payment', piPayment.amount || 0, JSON.stringify(metadata || {})]
    ).catch(() => {});

    await audit('payment_approved', { payment_id: paymentId, user_id: req.userId, amount: piPayment.amount });
    res.json({ success: true, payment: piPayment });
  } catch (err) {
    console.error('[Payment] Approve error:', err.message);
    serverError(err, res);
  }
});

app.post('/api/payments/:paymentId/complete', auth, async (req, res) => {
  const { paymentId } = req.params;
  const { txid, metadata } = req.body;
  if (!txid) return res.status(400).json({ error: 'txid required' });
  try {
    // Verify ownership if payment already in DB
    const ownerCheck2 = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
    if (ownerCheck2.rows.length && ownerCheck2.rows[0].user_id && ownerCheck2.rows[0].user_id !== req.userId) {
      return res.status(403).json({ error: 'Payment does not belong to you' });
    }
    let piPayment = { amount: 0 };
    // When PI_API_KEY is configured, completion with Pi Platform is mandatory
    if (PI_API_KEY) {
      try {
        piPayment = await piCompletePayment(paymentId, txid);
      } catch (piErr) {
        console.error('[Payment] Pi complete failed:', piErr.message);
        return res.status(502).json({ error: 'Pi payment completion failed. Try again.' });
      }
    }

    // Update payment record
    await query(
      'UPDATE payments SET status = $1, txid = $2, updated_at = NOW() WHERE id = $3',
      ['completed', txid, paymentId]
    );

    // Handle business logic based on payment type
    const paymentRecord = await query('SELECT * FROM payments WHERE id = $1', [paymentId]);
    if (paymentRecord.rows.length) {
      const meta = paymentRecord.rows[0].metadata || {};
      const paymentOwner = paymentRecord.rows[0].user_id || req.userId;
      if (meta.type === 'connects') {
        // SECURITY: derives connects strictly from Pi-verified amount; never from metadata
        const piAmountPaid = parseFloat(piPayment.amount || paymentRecord.rows[0].amount || 0);
        const amount = Math.floor(piAmountPaid * 10);
        if (amount <= 0) return res.status(400).json({ error: 'Payment amount too small to credit connects' });
        await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, paymentOwner]);
      } else if (meta.type === 'escrow' && meta.job_id && meta.freelancer_id) {
        // Create escrow record — hireFreelancer endpoint updates job status after this
        await query(
          'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING',
          [meta.job_id, req.userId, meta.freelancer_id, piPayment.amount || meta.amount || 0, paymentId, 'funded']
        );
      }
    }

    await audit('payment_completed', { payment_id: paymentId, txid, user_id: req.userId });
    res.json({ success: true, payment: piPayment });
  } catch (err) {
    console.error('[Payment] Complete error:', err.message);
    serverError(err, res);
  }
});

app.get('/api/payments', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM payments WHERE user_id = $1', [req.userId]);
    res.json({ payments: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/payments/incomplete', auth, async (req, res) => {
  // Called when Pi SDK finds an incomplete payment on app open
  const { paymentId } = req.body;
  if (!paymentId) return res.status(400).json({ error: 'paymentId required' });
  try {
    // Verify this payment belongs to the authenticated user
    const paymentRecord = await query('SELECT * FROM payments WHERE id = $1 AND user_id = $2', [paymentId, req.userId]);
    if (!paymentRecord.rows.length) return res.status(403).json({ error: 'Payment not found or does not belong to you' });

    const piPayment = await piGetPayment(paymentId);
    // If payment is pending server completion, complete it
    if (piPayment.status && piPayment.status.developer_completed === false && piPayment.transaction) {
      await piCompletePayment(paymentId, piPayment.transaction.txid);
      await query('UPDATE payments SET status = $1, txid = $2, updated_at = NOW() WHERE id = $3',
        ['completed', piPayment.transaction.txid, paymentId]);
    }
    res.json({ success: true, payment: piPayment });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Connects ──────────────────────────────────────────────
app.get('/api/connects/balance', auth, async (req, res) => {
  try {
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
    res.json({ balance: result.rows[0]?.balance_connects || 0 });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/connects/purchase', auth, checkBlocked, async (req, res) => {
  // Called after Pi payment is completed for connects — must supply a verified payment_id
  const { payment_id } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
  try {
    // Verify this payment_id exists in our DB and belongs to caller (set during approve step)
    const payRec = await query(
      "SELECT id, user_id, status, amount FROM payments WHERE id = $1",
      [payment_id]
    );
    if (!payRec.rows.length) return res.status(400).json({ error: 'Payment not found' });
    if (payRec.rows[0].user_id !== req.userId) return res.status(403).json({ error: 'Payment does not belong to you' });
    // Must be in 'approved' state — not yet processed, but verified by Pi
    if (payRec.rows[0].status === 'completed') return res.status(400).json({ error: 'Payment already processed' });
    if (payRec.rows[0].status !== 'approved') return res.status(400).json({ error: 'Payment not approved by Pi yet' });

    // Connects credited strictly from the Pi-verified amount recorded at approve time
    // (10 connects per 1 Pi) — never from a client-supplied number.
    const piAmount = parseFloat(payRec.rows[0].amount || 0);
    const connectsAmount = Math.floor(piAmount * 10);
    if (!(connectsAmount > 0)) {
      return res.status(400).json({ error: 'Payment amount too small to credit any connects' });
    }

    // Atomic: mark payment completed and credit connects; idempotent via UPDATE WHERE status='approved'
    const pgClient2 = await getPool().connect();
    let newBalance;
    try {
      await pgClient2.query('BEGIN');
      const updated = await pgClient2.query(
        "UPDATE payments SET status = 'completed', updated_at = NOW() WHERE id = $1 AND status = 'approved' RETURNING id",
        [payment_id]
      );
      if (!updated.rows.length) {
        await pgClient2.query('ROLLBACK');
        return res.status(400).json({ error: 'Payment already processed' });
      }
      const balRes = await pgClient2.query(
        'UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2 RETURNING balance_connects',
        [connectsAmount, req.userId]
      );
      newBalance = balRes.rows[0]?.balance_connects || 0;
      await pgClient2.query('COMMIT');
    } catch (txErr) {
      await pgClient2.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally { pgClient2.release(); }
    await audit('connects_purchased', { user_id: req.userId, amount: connectsAmount, payment_id });
    res.json({ balance: newBalance, success: true });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Ratings ──────────────────────────────────────────────
app.post('/api/ratings', auth, checkBlocked, async (req, res) => {
  const { to_user_id, job_id, rating, comment } = req.body;
  if (!to_user_id || !rating) return res.status(400).json({ error: 'to_user_id and rating required' });
  if (rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
  if (to_user_id === req.userId) return res.status(400).json({ error: 'Cannot rate yourself' });
  if (comment && comment.length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000)' });
  try {
    // Verify rater was a participant in this job
    if (job_id) {
      const jobCheck = await query('SELECT posted_by, hired_freelancer_id, status FROM jobs WHERE id = $1', [job_id]);
      if (jobCheck.rows.length) {
        const job = jobCheck.rows[0];
        const isParticipant = job.posted_by === req.userId || job.hired_freelancer_id === req.userId;
        if (!isParticipant) return res.status(403).json({ error: 'You were not a participant in this job' });
        if (job.status !== 'completed') return res.status(400).json({ error: 'Job must be completed before rating' });
      }
    }
    // Use IS NOT DISTINCT FROM to handle NULL job_id correctly (NULL = NULL is false in SQL)
    const existing = await query(
      'SELECT id FROM ratings WHERE from_user_id = $1 AND to_user_id = $2 AND job_id IS NOT DISTINCT FROM $3',
      [req.userId, to_user_id, job_id || null]
    );
    if (existing.rows.length) return res.status(400).json({ error: 'Already rated this job' });

    const result = await query(
      'INSERT INTO ratings (from_user_id, to_user_id, job_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.userId, to_user_id, job_id || null, parseInt(rating), comment || '']
    );
    // Update user average rating
    const avgResult = await query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [to_user_id]);
    const newAvg = Math.round(parseFloat(avgResult.rows[0].avg) * 10) / 10;
    await query('UPDATE users SET rating = $1, updated_at = NOW() WHERE id = $2', [newAvg, to_user_id]);
    await notify(to_user_id, 'rating', 'Новый отзыв', `Вы получили оценку ${rating}/5. Средний рейтинг: ${newAvg}`, job_id || null, null);
    res.json({ rating: result.rows[0], success: true });
  } catch (err) {
    serverError(err, res);
  }
});

// ─── Level System ──────────────────────────────────────────────
// Levels: Новичок (0) → Восходящий (3+jobs, 4.0+) → Профи (10+jobs, 4.3+) → Эксперт (25+jobs, 4.5+) → Легенда (50+jobs, 4.7+)
function computeLevel(completedJobs, rating) {
  const r = parseFloat(rating) || 0;
  const j = parseInt(completedJobs) || 0;
  if (j >= 50 && r >= 4.7) return { level: 5, title: 'Легенда', emoji: '🏆', nextJobs: null, nextRating: null };
  if (j >= 25 && r >= 4.5) return { level: 4, title: 'Эксперт', emoji: '💎', nextJobs: 50, nextRating: 4.7 };
  if (j >= 10 && r >= 4.3) return { level: 3, title: 'Профи', emoji: '🥇', nextJobs: 25, nextRating: 4.5 };
  if (j >= 3 && r >= 4.0) return { level: 2, title: 'Восходящий талант', emoji: '⭐', nextJobs: 10, nextRating: 4.3 };
  return { level: 1, title: 'Новичок', emoji: '🌱', nextJobs: 3, nextRating: 4.0 };
}

app.get('/api/users/:id/level', async (req, res) => {
  try {
    const result = await query('SELECT total_jobs_completed, rating FROM users WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    const levelInfo = computeLevel(u.total_jobs_completed, u.rating);
    res.json({ ...levelInfo, completed_jobs: u.total_jobs_completed, rating: u.rating });
  } catch (err) { serverError(err, res); }
});

// ─── Admin ──────────────────────────────────────────────
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [users, jobs, applications, escrows, activeEscrows, payments, revenue, ratings, chats] = await Promise.all([
      query('SELECT COUNT(*) FROM users'),
      query('SELECT COUNT(*) FROM jobs'),
      query('SELECT COUNT(*) FROM applications'),
      query('SELECT COUNT(*) FROM escrows'),
      query("SELECT COUNT(*) FROM escrows WHERE status IN ('pending','funded')"),
      query('SELECT COUNT(*) FROM payments'),
      query("SELECT COALESCE(SUM(amount*0.02),0) AS total FROM payments WHERE status='completed'"),
      query('SELECT COUNT(*) FROM ratings'),
      query('SELECT COUNT(*) FROM chat_rooms'),
    ]);
    const u = parseInt(users.rows[0].count);
    const j = parseInt(jobs.rows[0].count);
    const a = parseInt(applications.rows[0].count);
    const e = parseInt(escrows.rows[0].count);
    const ae = parseInt(activeEscrows.rows[0].count);
    const rev = parseFloat(revenue.rows[0].total);
    res.json({
      total_users: u, users: u,
      total_jobs: j, jobs: j,
      total_applications: a, applications: a,
      total_escrows: e, escrows: e,
      active_escrows: ae,
      total_revenue: rev,
      payments: parseInt(payments.rows[0].count),
      ratings: parseInt(ratings.rows[0].count),
      chats: parseInt(chats.rows[0].count),
    });
  } catch (err) {
    serverError(err, res);
  }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 500, 2000);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const search = req.query.search || '';
    const safeFields = 'id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at';
    let sql, params = [];
    if (search) {
      sql = `SELECT ${safeFields} FROM (SELECT DISTINCT ON (LOWER(username)) ${safeFields} FROM users WHERE username ILIKE $1 OR id ILIKE $1 ORDER BY LOWER(username), CASE role WHEN 'admin' THEN 0 ELSE 1 END, updated_at DESC) sub ORDER BY created_at DESC LIMIT $2 OFFSET $3`;
      params = [`%${search}%`, limit, offset];
    } else {
      sql = `SELECT ${safeFields} FROM (SELECT DISTINCT ON (LOWER(username)) ${safeFields} FROM users ORDER BY LOWER(username), CASE role WHEN 'admin' THEN 0 ELSE 1 END, updated_at DESC) sub ORDER BY created_at DESC LIMIT $1 OFFSET $2`;
      params = [limit, offset];
    }
    const result = await query(sql, params);
    const total = await query('SELECT COUNT(DISTINCT LOWER(username)) FROM users');
    res.json({ users: result.rows, count: result.rows.length, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/admin/users/:id/block', adminAuth, async (req, res) => {
  try {
    const target = await query('SELECT username FROM users WHERE id = $1', [req.params.id]);
    if (['cherry19899', 'pi_cherry19899'].includes(req.params.id) || target.rows[0]?.username === 'cherry19899') {
      return res.status(403).json({ error: 'Cannot block owner' });
    }
    await query('UPDATE users SET is_blocked = true, status = $1, updated_at = NOW() WHERE id = $2', ['blocked', req.params.id]);
    await audit('user_blocked', { user_id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  try {
    await query('UPDATE users SET is_blocked = false, status = $1, updated_at = NOW() WHERE id = $2', ['active', req.params.id]);
    await audit('user_unblocked', { user_id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    serverError(err, res);
  }
});

app.post('/api/admin/users/:id/make-admin', adminAuth, async (req, res) => {
  try {
    await query("UPDATE users SET role = 'admin', updated_at = NOW() WHERE id = $1", [req.params.id]);
    await audit('user_made_admin', { user_id: req.params.id, by: req.userId });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

app.post('/api/admin/users/:id/remove-admin', adminAuth, async (req, res) => {
  try {
    const target = await query('SELECT username FROM users WHERE id = $1', [req.params.id]);
    if (req.params.id === 'cherry19899' || req.params.id === 'pi_cherry19899' || target.rows[0]?.username === 'cherry19899') {
      return res.status(403).json({ error: 'Cannot remove owner admin' });
    }
    await query("UPDATE users SET role = 'freelancer', updated_at = NOW() WHERE id = $1", [req.params.id]);
    await audit('user_removed_admin', { user_id: req.params.id, by: req.userId });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

app.get('/api/admin/jobs', adminAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM jobs ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM jobs');
    res.json({ jobs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.delete('/api/admin/jobs/:id', adminAuth, async (req, res) => {
  try {
    await query('DELETE FROM applications WHERE job_id = $1', [req.params.id]);
    await query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    serverError(err, res);
  }
});

// POST /api/admin/users/:id/grant-connects — admin grants connects to user
app.post('/api/admin/users/:id/grant-connects', adminAuth, async (req, res) => {
  const { amount } = req.body;
  const qty = Math.max(1, Math.min(10000, parseInt(amount || 50) || 50));
  try {
    await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [qty, req.params.id]);
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.params.id]);
    await audit('admin_grant_connects', { user_id: req.params.id, amount: qty, granted_by: req.userId });
    res.json({ success: true, balance: result.rows[0]?.balance_connects || 0 });
  } catch (err) { serverError(err, res); }
});

app.get('/api/admin/escrows', adminAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    const result = await query(`
      SELECT e.*,
        uc.username AS client_name,
        uf.username AS freelancer_name,
        j.title AS job_title
      FROM escrows e
      LEFT JOIN users uc ON uc.id = e.client_id
      LEFT JOIN users uf ON uf.id = e.freelancer_id
      LEFT JOIN jobs j ON j.id = e.job_id
      ORDER BY e.created_at DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM escrows');
    res.json({ escrows: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.get('/api/admin/earnings', adminAuth, async (req, res) => {
  try {
    const [result, transactions, collected, pending, recentPayments] = await Promise.all([
      query("SELECT COALESCE(SUM(amount*0.02), 0) as total FROM payments WHERE status = 'completed'"),
      query('SELECT COUNT(*) FROM payments'),
      query("SELECT COALESCE(SUM(amount*0.02), 0) as total FROM payments WHERE status = 'completed'"),
      query("SELECT COALESCE(SUM(amount*0.02), 0) as total FROM payments WHERE status != 'completed'"),
      query(`
        SELECT p.*,
          u.username AS client_name,
          p.amount AS job_amount,
          CAST(ROUND(CAST(p.amount AS numeric) * 0.98, 4) AS float) AS freelancer_amount,
          CAST(ROUND(CAST(p.amount AS numeric) * 0.02, 4) AS float) AS developer_fee
        FROM payments p
        LEFT JOIN users u ON u.id = p.user_id
        ORDER BY p.created_at DESC LIMIT 50
      `),
    ]);
    const total_earnings = parseFloat(result.rows[0].total);
    const txCount = parseInt(transactions.rows[0].count);
    res.json({
      total_earnings,
      transactions: txCount,
      payments: recentPayments.rows,
      history: recentPayments.rows,
      summary: {
        total_earnings,
        total_transactions: txCount,
        collected: parseFloat(collected.rows[0].total),
        pending: parseFloat(pending.rows[0].total),
        average_transaction: txCount > 0 ? Math.round(total_earnings / txCount * 100) / 100 : 0,
      }
    });
  } catch (err) {
    serverError(err, res);
  }
});

app.get('/api/admin/audit-logs', adminAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM audit_logs');
    res.json({ logs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) {
    serverError(err, res);
  }
});

app.get('/api/admin/verify', async (req, res) => {
  const key = req.headers['x-admin-key'] || req.headers['authorization'] || req.query.admin_key;
  let token = key || '';
  if (token.startsWith('Bearer ')) token = token.substring(7);
  const valid = token.length > 0 && token.length === ADMIN_API_KEY.length &&
    crypto.timingSafeEqual(Buffer.from(token), Buffer.from(ADMIN_API_KEY));
  res.json({ valid });
});

// GET /api/jobs/:id/applications — used by JobDetail.js
app.get('/api/jobs/:id/applications', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const jobResult = await query('SELECT posted_by FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (jobResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.params.id, limit, offset]);
    res.json({ applications: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs?client_uid=xxx — filter by owner (client_uid alias for posted_by)
// Handled in existing GET /api/jobs — patching it to support client_uid param
// (done below in the jobs section override)

// GET /api/applications/me — alias for /my
// (added below)

// GET /api/escrows + /api/escrows/me — alias for /api/escrow
app.get('/api/escrows', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
    res.json({ escrows: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});
app.get('/api/escrows/me', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
    res.json({ escrows: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});
app.post('/api/escrows/:id/release', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status !== 'funded') return res.status(400).json({ error: 'Escrow is not funded' });
    const net2 = parseFloat((escrow.amount * 0.98).toFixed(8)); // 2% platform commission
    // Atomic: update escrow status WHERE funded; concurrent calls fail here
    const pgClient4 = await getPool().connect();
    try {
      await pgClient4.query('BEGIN');
      const updated = await pgClient4.query(
        "UPDATE escrows SET status='released', updated_at=NOW() WHERE id=$1 AND status='funded' RETURNING id",
        [req.params.id]
      );
      if (!updated.rows.length) { await pgClient4.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already processed' }); }
      await pgClient4.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $2', [net2, escrow.freelancer_id]);
      await pgClient4.query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['completed', escrow.job_id]);
      await pgClient4.query('COMMIT');
    } catch (txErr) { await pgClient4.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient4.release(); }
    await audit('escrow_released', { escrow_id: req.params.id, net_paid: net2 });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});
app.post('/api/escrows/:id/cancel', auth, checkBlocked, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (!['pending', 'funded'].includes(escrow.status)) return res.status(400).json({ error: 'Escrow already settled' });
    const wasFunded = escrow.status === 'funded';
    // Atomic: update escrow WHERE pending|funded; concurrent calls fail here
    const pgClient6 = await getPool().connect();
    try {
      await pgClient6.query('BEGIN');
      const updated = await pgClient6.query(
        "UPDATE escrows SET status='refunded', updated_at=NOW() WHERE id=$1 AND status = ANY($2) RETURNING id",
        [req.params.id, ['pending', 'funded']]
      );
      if (!updated.rows.length) { await pgClient6.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already settled' }); }
      await pgClient6.query('UPDATE jobs SET status = $1, hired_freelancer_id = NULL, updated_at = NOW() WHERE id = $2', ['open', escrow.job_id]);
      if (wasFunded) {
        await pgClient6.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, updated_at = NOW() WHERE id = $2', [escrow.amount, escrow.client_id]);
      }
      await pgClient6.query('COMMIT');
    } catch (txErr) { await pgClient6.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient6.release(); }
    if (wasFunded) {
      await notify(escrow.client_id, 'payment', 'Эскроу отменён', `${escrow.amount}π возвращено на ваш счёт.`, escrow.job_id, null);
      await audit('escrow_cancelled_refunded', { escrow_id: req.params.id, amount: escrow.amount, client_id: escrow.client_id });
    }
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/chat/start — start or get conversation
app.post('/api/chat/start', auth, checkBlocked, async (req, res) => {
  const { other_user_id, job_id } = req.body;
  if (!other_user_id) return res.status(400).json({ error: 'other_user_id required' });
  try {
    const jobId = job_id || 0;
    // For job-linked rooms: require caller to be owner or hired freelancer (same guard as /chat/rooms)
    if (jobId) {
      const jobCheck = await query('SELECT posted_by, hired_freelancer_id FROM jobs WHERE id = $1', [jobId]);
      if (jobCheck.rows.length) {
        const j = jobCheck.rows[0];
        if (j.posted_by !== req.userId && j.hired_freelancer_id !== req.userId && other_user_id !== req.userId) {
          return res.status(403).json({ error: 'You must be a participant in this job to start a chat' });
        }
      }
    }
    const existing = await query(
      'SELECT * FROM chat_rooms WHERE job_id = $3 AND ((client_id = $1 AND freelancer_id = $2) OR (client_id = $2 AND freelancer_id = $1))',
      [req.userId, other_user_id, jobId]
    );
    if (existing.rows.length) return res.json({ conversation: existing.rows[0], id: existing.rows[0].id });
    const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
    const result = await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *', [roomId, req.userId, other_user_id, jobId]);
    res.json({ conversation: result.rows[0], id: result.rows[0].id });
  } catch (err) { serverError(err, res); }
});

// ─── Alias endpoints for cherry19899.github.io frontend ──────────────────
// POST /api/applications — apply to job (frontend sends job_id in body)
app.post('/api/applications', auth, checkBlocked, async (req, res) => {
  const { job_id, message } = req.body;
  if (!job_id) return res.status(400).json({ error: 'job_id required' });
  if (message && message.length > 2000) return res.status(400).json({ error: 'Cover letter too long (max 2000 chars)' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [job_id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by === req.userId) return res.status(400).json({ error: 'Cannot apply to own job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });
    const existing = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2', [job_id, req.userId]);
    if (existing.rows.length) return res.status(400).json({ error: 'Already applied' });
    const userResult = await query('SELECT id, username, balance_connects, is_blocked FROM users WHERE id = $1', [req.userId]);
    const user = userResult.rows[0];
    const cost = job.apply_cost || 1;
    if (!user || user.balance_connects < cost) return res.status(400).json({ error: 'Not enough connects', required: cost, current: user?.balance_connects || 0 });
    let appResult;
    const pgClient = await getPool().connect();
    try {
      await pgClient.query('BEGIN');
      await pgClient.query('UPDATE users SET balance_connects = balance_connects - $1, updated_at = NOW() WHERE id = $2', [cost, req.userId]);
      appResult = await pgClient.query(
        'INSERT INTO applications (job_id, job_title, freelancer_id, freelancer_name, message) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (job_id, freelancer_id) DO NOTHING RETURNING *',
        [job_id, job.title, req.userId, user.username || req.userId, message || '']
      );
      if (!appResult.rows.length) { await pgClient.query('ROLLBACK'); return res.status(400).json({ error: 'Already applied' }); }
      await pgClient.query('UPDATE jobs SET applications = applications + 1, updated_at = NOW() WHERE id = $1', [job_id]);
      await pgClient.query('COMMIT');
    } catch (txErr) { await pgClient.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient.release(); }
    await audit('job_applied', { job_id, user_id: req.userId });
    await notify(job.posted_by, 'application', `Новый отклик на задачу "${job.title}"`,
      `${user.username || 'Фрилансер'} откликнулся на вашу задачу`, parseInt(job_id), null);
    const newBal = (user.balance_connects || 0) - cost;
    res.json({ application: appResult.rows[0], success: true, remaining_connects: newBal, new_balance: newBal });
  } catch (err) { serverError(err, res); }
});

// GET /api/applications/my + /api/applications/me — my applications as freelancer
app.get('/api/applications/my', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM applications WHERE freelancer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM applications WHERE freelancer_id = $1', [req.userId]);
    res.json({ applications: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});
app.get('/api/applications/me', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM applications WHERE freelancer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM applications WHERE freelancer_id = $1', [req.userId]);
    res.json({ applications: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/applications/job/:jobId — applications for a specific job (owner only)
app.get('/api/applications/job/:jobId', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const jobResult = await query('SELECT posted_by FROM jobs WHERE id = $1', [req.params.jobId]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (jobResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.params.jobId, limit, offset]);
    res.json({ applications: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/accept — accept application + create escrow record
app.post('/api/applications/:id/accept', auth, checkBlocked, async (req, res) => {
  try {
    const appResult = await query(
      'SELECT a.*, j.posted_by, j.budget, j.title FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1',
      [req.params.id]
    );
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = appResult.rows[0];
    if (app_.posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });

    // Accept the application
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 RETURNING *', ['accepted', req.params.id]);

    // Create escrow record (pending state — will be funded after Pi payment)
    const freelancerId = app_.freelancer_id;
    const escrowAmount = app_.bid_amount || app_.budget || 0;
    let escrow = null;
    if (freelancerId) {
      const existing = await query('SELECT * FROM escrows WHERE job_id = $1 AND status IN ($2, $3)', [app_.job_id, 'pending', 'funded']);
      if (!existing.rows.length) {
        const escrowResult = await query(
          `INSERT INTO escrows (job_id, client_id, freelancer_id, amount, status)
           VALUES ($1,$2,$3,$4,'pending') RETURNING *`,
          [app_.job_id, req.userId, freelancerId, escrowAmount]
        );
        escrow = escrowResult.rows[0];
      } else {
        escrow = existing.rows[0];
      }
      // Mark job as in-progress
      await query("UPDATE jobs SET status='in_progress', updated_at=NOW() WHERE id=$1", [app_.job_id]);
    }

    await audit('application_accepted', { app_id: req.params.id, job_id: app_.job_id, freelancer_id: freelancerId });
    res.json({ application: result.rows[0], escrow, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/reject — alias used by JobDetail.js
app.post('/api/applications/:id/reject', auth, checkBlocked, async (req, res) => {
  try {
    const appResult = await query('SELECT a.*, j.posted_by FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (appResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 RETURNING *', ['rejected', req.params.id]);
    res.json({ application: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/withdraw — freelancer withdraws their own pending application
app.post('/api/applications/:id/withdraw', auth, async (req, res) => {
  try {
    const appResult = await query('SELECT * FROM applications WHERE id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = appResult.rows[0];
    if (app_.freelancer_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    if (app_.status !== 'pending') return res.status(400).json({ error: 'Can only withdraw pending applications' });
    const result = await query('UPDATE applications SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *', ['withdrawn', req.params.id]);
    res.json({ application: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// PUT /api/applications/:id/status — update application status (job owner only: accepted/rejected)
app.put('/api/applications/:id/status', auth, checkBlocked, async (req, res) => {
  const { status } = req.body;
  const OWNER_ALLOWED = ['accepted', 'rejected'];
  if (!OWNER_ALLOWED.includes(status)) return res.status(400).json({ error: `Invalid status. Job owners may set: ${OWNER_ALLOWED.join(', ')}` });
  try {
    const appResult = await query('SELECT a.*, j.posted_by FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (appResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 RETURNING *', [status, req.params.id]);
    res.json({ application: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// PUT /api/jobs/:id — update job
app.put('/api/jobs/:id', auth, checkBlocked, async (req, res) => {
  // status is NOT accepted here — use dedicated endpoints (hire/complete/patch) for status transitions
  const { title, description, category, budget, skills, deadline, images } = req.body;
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    // Only allow editing while job is still open (not hired/in-progress/completed)
    if (job.status !== 'open') return res.status(400).json({ error: 'Can only edit open jobs' });
    const fields = [], vals = [];
    let i = 1;
    if (title !== undefined) {
      if (String(title).length > 200) return res.status(400).json({ error: 'Title too long (max 200)' });
      fields.push(`title=$${i++}`); vals.push(title);
    }
    if (description !== undefined) {
      if (String(description).length > 5000) return res.status(400).json({ error: 'Description too long (max 5000)' });
      fields.push(`description=$${i++}`); vals.push(description);
    }
    if (category !== undefined) { fields.push(`category=$${i++}`); vals.push(category ? category.toLowerCase() : category); }
    if (budget !== undefined) {
      const b = parseFloat(budget);
      if (isNaN(b) || b < 1) return res.status(400).json({ error: 'Budget must be at least 1 Pi' });
      if (b > 10000) return res.status(400).json({ error: 'Budget cannot exceed 10000 Pi' });
      fields.push(`budget=$${i++}`); vals.push(b);
      const newCost = Math.ceil(b / 50);
      fields.push(`apply_cost=$${i++}`); vals.push(newCost);
      fields.push(`connects_spent=$${i++}`); vals.push(newCost);
    }
    if (skills !== undefined) {
      if (skills && String(skills).length > 500) return res.status(400).json({ error: 'Skills too long (max 500)' });
      fields.push(`skills=$${i++}`); vals.push(skills);
    }
    if (deadline !== undefined) { fields.push(`deadline=$${i++}`); vals.push(deadline || null); }
    if (images !== undefined) {
      if (Array.isArray(images) && images.length > 10) return res.status(400).json({ error: 'Too many images (max 10)' });
      fields.push(`images=$${i++}`); vals.push(serializeImages(images));
    }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    fields.push(`updated_at=NOW()`);
    vals.push(req.params.id);
    const result = await query(`UPDATE jobs SET ${fields.join(',')} WHERE id=$${i} RETURNING *`, vals);
    res.json({ job: parseJobRow(result.rows[0]), success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/users/me — get current user profile
app.get('/api/users/me', auth, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1',
      [req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { serverError(err, res); }
});

// PUT /api/users/me — update current user profile
app.put('/api/users/me', auth, async (req, res) => {
  const { username, bio, skills, availability, avatar, email } = req.body;
  if (username && username.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
  if (bio && bio.length > 1000) return res.status(400).json({ error: 'Bio too long (max 1000)' });
  if (skills && skills.length > 300) return res.status(400).json({ error: 'Skills too long (max 300)' });
  if (avatar && !/^https?:\/\//i.test(avatar)) return res.status(400).json({ error: 'Avatar must be a valid URL (http/https)' });
  if (email && (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).json({ error: 'Invalid email address' });
  const ALLOWED_AVAILABILITY = ['available', 'busy', 'away', 'unavailable'];
  if (availability && !ALLOWED_AVAILABILITY.includes(availability)) {
    return res.status(400).json({ error: 'Invalid availability value' });
  }
  try {
    const fields = [], vals = [];
    let i = 1;
    if (username) { fields.push(`username=$${i++}`); vals.push(username); }
    if (bio !== undefined) { fields.push(`bio=$${i++}`); vals.push(bio); }
    if (skills !== undefined) { fields.push(`skills=$${i++}`); vals.push(skills); }
    if (availability) { fields.push(`availability=$${i++}`); vals.push(availability); }
    if (avatar) { fields.push(`avatar=$${i++}`); vals.push(avatar); }
    if (email) { fields.push(`email=$${i++}`); vals.push(email); }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    fields.push(`updated_at=NOW()`);
    vals.push(req.userId);
    await query(`UPDATE users SET ${fields.join(',')} WHERE id=$${i}`, vals);
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1', [req.userId]);
    const u = result.rows[0];
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { serverError(err, res); }
});

// ─── Chat alias endpoints (conversations = rooms) ──────────────────
app.get('/api/chat/conversations', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query(
      `SELECT r.*,
        (SELECT message FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message,
        (SELECT created_at FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
        j.title as job_title,
        CASE WHEN r.client_id = $1 THEN r.freelancer_id ELSE r.client_id END as other_user_id,
        CASE WHEN r.client_id = $1 THEN uf.username ELSE uc.username END as other_user_name
       FROM chat_rooms r
       LEFT JOIN jobs j ON j.id = r.job_id
       LEFT JOIN users uc ON uc.id = r.client_id
       LEFT JOIN users uf ON uf.id = r.freelancer_id
       WHERE r.client_id = $1 OR r.freelancer_id = $1
       ORDER BY last_message_at DESC NULLS LAST
       LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    res.json({ conversations: result.rows, rooms: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

app.post('/api/chat/conversations', auth, checkBlocked, async (req, res) => {
  const { freelancer_id, job_id, other_user_id } = req.body;
  const cId = req.userId; // always use authenticated user as client
  const fId = freelancer_id || other_user_id;
  if (!fId || !job_id) return res.status(400).json({ error: 'freelancer_id and job_id required' });
  try {
    // Verify caller is actually involved in this job (poster or applicant/hired freelancer)
    const jobCheck = await query('SELECT posted_by, hired_freelancer_id FROM jobs WHERE id = $1', [job_id]);
    if (!jobCheck.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobCheck.rows[0];
    const isJobPoster = job.posted_by === cId;
    const isFid = fId === cId; // caller is the freelancer side
    if (!isJobPoster && !isFid) {
      // Also allow if caller has an application for this job
      const appCheck = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2 LIMIT 1', [job_id, cId]);
      if (!appCheck.rows.length) return res.status(403).json({ error: 'You are not a participant in this job' });
    }
    const existing = await query('SELECT * FROM chat_rooms WHERE job_id = $1 AND ((client_id = $2 AND freelancer_id = $3) OR (client_id = $3 AND freelancer_id = $2))', [job_id, cId, fId]);
    if (existing.rows.length) return res.json({ conversation: existing.rows[0], room: existing.rows[0] });
    const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
    const result = await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *', [roomId, cId, fId, job_id]);
    res.json({ conversation: result.rows[0], room: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

app.get('/api/chat/conversations/:id/messages', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3', [req.params.id, limit, offset]);
    const messages = result.rows.map(m => ({ ...m, content: m.message, text: m.message }));
    res.json({ messages, limit, offset });
  } catch (err) { serverError(err, res); }
});

app.post('/api/chat/conversations/:id/messages', auth, checkBlocked, async (req, res) => {
  const msg = req.body.content || req.body.message;
  if (!msg || !msg.trim()) return res.status(400).json({ error: 'Message required' });
  if (msg.length > 2000) return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const userResult = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userResult.rows[0]?.username || req.userId;
    const result = await query('INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *', [req.params.id, req.userId, senderName, msg.trim()]);
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    res.json({ message: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

app.get('/api/chat/unread', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT COUNT(*) FROM chat_messages cm
       JOIN chat_rooms r ON r.id = cm.room_id
       WHERE (r.client_id = $1 OR r.freelancer_id = $1) AND cm.sender_id != $1
       AND cm.created_at > COALESCE(
         (SELECT last_chat_read_at FROM users WHERE id = $1),
         NOW() - INTERVAL '7 days'
       )`,
      [req.userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) { res.json({ count: 0 }); }
});

// Mark all chat messages as read (called when user opens chat)
app.post('/api/chat/read-all', auth, async (req, res) => {
  try {
    await query('UPDATE users SET last_chat_read_at = NOW() WHERE id = $1', [req.userId]);
    res.json({ success: true });
  } catch (_) { res.json({ success: true }); }
});

// ─── Reviews alias (= ratings) ──────────────────
// Bundle sends: {reviewer_id, reviewer_name, target_id, target_name, job_id, job_title, rating, text}
app.post('/api/reviews', auth, checkBlocked, async (req, res) => {
  const { to_user_id, target_id, job_id, rating, comment, text, reviewer_id } = req.body;
  const toId = to_user_id || target_id;  // bundle uses target_id
  const reviewComment = comment || text || '';
  if (!toId || !rating) return res.status(400).json({ error: 'to_user_id and rating required' });
  if (rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
  if (toId === req.userId) return res.status(400).json({ error: 'Cannot rate yourself' });
  if (reviewComment.length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000)' });
  try {
    // Verify rater was a participant in this job (same guard as /api/ratings)
    if (job_id) {
      const jobCheck = await query('SELECT posted_by, hired_freelancer_id, status FROM jobs WHERE id = $1', [job_id]);
      if (jobCheck.rows.length) {
        const job = jobCheck.rows[0];
        const isParticipant = job.posted_by === req.userId || job.hired_freelancer_id === req.userId;
        if (!isParticipant) return res.status(403).json({ error: 'You were not a participant in this job' });
        if (job.status !== 'completed') return res.status(400).json({ error: 'Job must be completed before rating' });
      }
    }
    // IS NOT DISTINCT FROM handles NULL job_id correctly
    const existing = await query(
      'SELECT id FROM ratings WHERE from_user_id = $1 AND to_user_id = $2 AND job_id IS NOT DISTINCT FROM $3',
      [req.userId, toId, job_id || null]
    );
    if (existing.rows.length) return res.status(400).json({ error: 'Already rated this job' });
    const result = await query('INSERT INTO ratings (from_user_id, to_user_id, job_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *', [req.userId, toId, job_id || null, parseInt(rating), reviewComment]);
    const avgResult = await query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [toId]);
    const newAvg = Math.round(parseFloat(avgResult.rows[0].avg) * 10) / 10;
    await query('UPDATE users SET rating = $1, updated_at = NOW() WHERE id = $2', [newAvg, toId]);
    res.json({ review: result.rows[0], rating: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

app.get('/api/reviews/user/:userId', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC LIMIT $2 OFFSET $3', [req.params.userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [req.params.userId]);
    res.json({ reviews: result.rows, ratings: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews?user_id=xxx — alias used by some frontend pages
app.get('/api/reviews', async (req, res) => {
  const userId = req.query.user_id || req.headers['x-user-id'];
  if (!userId) return res.json({ reviews: [], ratings: [] });
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC LIMIT $2 OFFSET $3', [userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [userId]);
    res.json({ reviews: result.rows, ratings: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/jobs/all — alias for /api/admin/jobs
app.get('/api/admin/jobs/all', adminAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
    const offset = parseInt(req.query.offset) || 0;
    const result = await query('SELECT j.*, u.username as posted_by_name FROM jobs j LEFT JOIN users u ON u.id = j.posted_by ORDER BY j.created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM jobs');
    res.json({ jobs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/connects/buy defined later (full version with package_amount + Pi payment support)

// ─── Escrow refund ──────────────────
app.post('/api/escrow/:id/refund', auth, checkBlocked, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status === 'released' || escrow.status === 'refunded') return res.status(400).json({ error: 'Already processed' });
    const wasFunded = escrow.status === 'funded';
    // Atomic: update escrow WHERE not already released/refunded
    const pgClient7 = await getPool().connect();
    try {
      await pgClient7.query('BEGIN');
      const updated = await pgClient7.query(
        "UPDATE escrows SET status='refunded', updated_at=NOW() WHERE id=$1 AND status NOT IN ('released','refunded') RETURNING id",
        [req.params.id]
      );
      if (!updated.rows.length) { await pgClient7.query('ROLLBACK'); return res.status(400).json({ error: 'Already processed' }); }
      await pgClient7.query('UPDATE jobs SET status = $1, hired_freelancer_id = NULL, hired_freelancer_name = NULL, updated_at = NOW() WHERE id = $2', ['open', escrow.job_id]);
      if (wasFunded) {
        await pgClient7.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, updated_at = NOW() WHERE id = $2', [escrow.amount, escrow.client_id]);
      }
      await pgClient7.query('COMMIT');
    } catch (txErr) { await pgClient7.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient7.release(); }
    if (wasFunded) {
      await notify(escrow.client_id, 'payment', 'Возврат средств', `${escrow.amount}π возвращено на ваш счёт.`, escrow.job_id, null);
    }
    await audit('escrow_refunded', { escrow_id: req.params.id, status_was: escrow.status, amount: escrow.amount });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// ─── Portfolio ──────────────────
app.get('/api/users/:id/portfolio', async (req, res) => {
  try {
    const userResult = await query('SELECT id, username, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar FROM users WHERE id = $1', [req.params.id]);
    if (!userResult.rows.length) return res.status(404).json({ error: 'User not found' });
    const portfolioResult = await query('SELECT * FROM portfolios WHERE user_id = $1', [req.params.id]).catch(() => ({ rows: [] }));
    const itemsResult = await query('SELECT * FROM portfolio_items WHERE user_id = $1 ORDER BY created_at DESC', [req.params.id]).catch(() => ({ rows: [] }));
    const owner = userResult.rows[0];
    res.json({
      owner,
      portfolio: portfolioResult.rows[0] || {},
      items: itemsResult.rows,
      stats: { jobs_posted: owner.total_jobs_posted, jobs_completed: owner.total_jobs_completed, rating: owner.rating }
    });
  } catch (err) { serverError(err, res); }
});

app.put('/api/users/me/portfolio', auth, async (req, res) => {
  const { headline, summary, experience_years, website, github, linkedin } = req.body;
  if (headline && headline.length > 200) return res.status(400).json({ error: 'Headline too long (max 200)' });
  if (summary && summary.length > 2000) return res.status(400).json({ error: 'Summary too long (max 2000)' });
  if (website && !/^https?:\/\//i.test(website)) return res.status(400).json({ error: 'Website must start with http:// or https://' });
  if (github && github.length > 200) return res.status(400).json({ error: 'GitHub URL too long (max 200)' });
  if (linkedin && linkedin.length > 200) return res.status(400).json({ error: 'LinkedIn URL too long (max 200)' });
  if (experience_years !== undefined && (parseInt(experience_years) < 0 || parseInt(experience_years) > 60)) {
    return res.status(400).json({ error: 'experience_years must be 0–60' });
  }
  try {
    await query(`CREATE TABLE IF NOT EXISTS portfolios (
      id SERIAL PRIMARY KEY, user_id VARCHAR(255) UNIQUE, headline TEXT, summary TEXT,
      experience_years INTEGER DEFAULT 0, website TEXT, github TEXT, linkedin TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`).catch(() => {});
    await query(
      `INSERT INTO portfolios (user_id, headline, summary, experience_years, website, github, linkedin)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (user_id) DO UPDATE SET headline=$2, summary=$3, experience_years=$4, website=$5, github=$6, linkedin=$7, updated_at=NOW()`,
      [req.userId, headline || '', summary || '', parseInt(experience_years || 0), website || '', github || '', linkedin || '']
    );
    const result = await query('SELECT * FROM portfolios WHERE user_id = $1', [req.userId]);
    res.json({ portfolio: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

app.post('/api/users/me/portfolio/items', auth, async (req, res) => {
  const { title, description, image_url, url, category, tags } = req.body;
  const finalUrl = image_url || url || '';
  if (!title) return res.status(400).json({ error: 'title required' });
  if (String(title).length > 200) return res.status(400).json({ error: 'Title too long (max 200)' });
  if (description && description.length > 2000) return res.status(400).json({ error: 'Description too long (max 2000)' });
  if (category && category.length > 100) return res.status(400).json({ error: 'Category too long (max 100)' });
  const tagsRaw = Array.isArray(tags) ? tags.join(',') : (tags || '');
  if (tagsRaw.length > 500) return res.status(400).json({ error: 'Tags too long (max 500 chars combined)' });
  if (finalUrl && !/^https?:\/\//i.test(finalUrl)) return res.status(400).json({ error: 'URL must start with http:// or https://' });
  try {
    await query(`CREATE TABLE IF NOT EXISTS portfolio_items (
      id SERIAL PRIMARY KEY, user_id VARCHAR(255), title VARCHAR(500) NOT NULL,
      description TEXT, image_url TEXT, category VARCHAR(100), tags TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`).catch(() => {});
    const result = await query(
      'INSERT INTO portfolio_items (user_id, title, description, image_url, category, tags) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.userId, title, description || '', finalUrl, category || 'Other', tagsRaw]
    );
    res.json({ item: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/users/me — account deletion
app.delete('/api/users/me', auth, async (req, res) => {
  try {
    const active = await query(
      `(SELECT 1 FROM jobs WHERE (posted_by=$1 OR hired_freelancer_id=$1) AND status IN ('in_progress','submitted') LIMIT 1)
       UNION ALL
       (SELECT 1 FROM escrows WHERE (client_id=$1 OR freelancer_id=$1) AND status='funded' LIMIT 1)`,
      [req.userId]
    );
    if (active.rows.length > 0) {
      return res.status(400).json({ error: 'Нельзя удалить аккаунт с активными задачами или эскроу' });
    }
    await query('UPDATE users SET is_blocked = true, status = $1, updated_at = NOW() WHERE id = $2', ['deleted', req.userId]);
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

app.delete('/api/users/me/portfolio/items/:id', auth, async (req, res) => {
  try {
    await query('DELETE FROM portfolio_items WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// ─── Notifications ──────────────────────────────────────────────
app.get('/api/notifications/unread-count', auth, async (req, res) => {
  try {
    const result = await query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false',
      [req.userId]
    );
    const unread_count = parseInt(result.rows[0].count) || 0;
    res.json({ unread_count, count: unread_count });
  } catch (err) {
    res.json({ unread_count: 0, count: 0 });
  }
});

app.get('/api/notifications', auth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = parseInt(req.query.offset) || 0;
    const result = await query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
      [req.userId, limit, offset]
    );
    const unread = result.rows.filter(r => !r.is_read).length;
    res.json({ notifications: result.rows, unread_count: unread, limit, offset });
  } catch (err) {
    res.json({ notifications: [], unread_count: 0 });
  }
});

app.post('/api/notifications/mark-read', auth, async (req, res) => {
  try {
    await query('UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false', [req.userId]);
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true });
  }
});

// ─── Hire with Pi payment (escrow) ──────────────────────────────────────────────
// POST /api/applications/:id/hire — initiate Pi escrow for hired freelancer
// Called from frontend after client decides to hire (Pi payment flow)
app.post('/api/applications/:id/hire', auth, checkBlocked, async (req, res) => {
  const { payment_id, txid, amount } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required — Pi payment must be completed before hiring' });
  try {
    // Verify payment belongs to this user and is completed
    const paymentCheck = await query(
      "SELECT * FROM payments WHERE id = $1 AND user_id = $2 AND status = 'completed'",
      [payment_id, req.userId]
    );
    if (!paymentCheck.rows.length) return res.status(402).json({ error: 'Valid completed payment required to hire' });

    const appResult = await query(
      'SELECT a.*, j.posted_by, j.budget, j.title as job_title FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1',
      [req.params.id]
    );
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = appResult.rows[0];
    if (app_.posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });

    const escrowAmount = amount || app_.bid_amount || app_.budget;
    const freelancerId = app_.freelancer_id;

    // Accept application
    await query('UPDATE applications SET status = $1 WHERE id = $2', ['accepted', req.params.id]);
    // Create escrow
    const escrow = await query(
      `INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status)
       VALUES ($1,$2,$3,$4,$5,'funded') ON CONFLICT DO NOTHING RETURNING *`,
      [app_.job_id, req.userId, freelancerId, escrowAmount, payment_id]
    );
    // Mark job as in-progress and set hired_freelancer_id
    const freelancerNameRes = await query('SELECT username FROM users WHERE id = $1', [freelancerId]);
    const freelancerName = freelancerNameRes.rows[0]?.username || freelancerId;
    await query(
      "UPDATE jobs SET status='in_progress', hired_freelancer_id=$1, hired_freelancer_name=$2, updated_at=NOW() WHERE id=$3",
      [freelancerId, freelancerName, app_.job_id]
    );
    await notify(freelancerId, 'hired', `Вас наняли на задачу "${app_.job_title || app_.job_id}"`,
      'Заказчик выбрал вас и создал эскроу. Можете приступать к работе.', parseInt(app_.job_id), null);
    await audit('hire_with_escrow', { app_id: req.params.id, job_id: app_.job_id, freelancer_id: freelancerId, amount: escrowAmount });
    res.json({ success: true, escrow: escrow.rows[0] || { job_id: app_.job_id, status: 'funded' } });
  } catch (err) { serverError(err, res); }
});

// POST /api/payments/approve — Pi payment server-side approval
app.post('/api/payments/approve', auth, async (req, res) => {
  const { payment_id, metadata } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
  try {
    // Verify ownership if payment already exists in DB
    const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [payment_id]).catch(() => ({ rows: [] }));
    if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== req.userId) {
      return res.status(403).json({ error: 'Payment does not belong to you' });
    }
    // Pi verification is mandatory when configured. piApprovePayment throws on a
    // non-OK Pi response (e.g. payment_not_found), so a forged payment id can never
    // be recorded as 'approved' — which would otherwise let it be redeemed for connects.
    let approveData = { amount: 0 };
    if (PI_API_KEY) {
      try {
        approveData = await piApprovePayment(payment_id);
      } catch (piErr) {
        console.error('[Payment] approve failed:', piErr.message);
        return res.status(502).json({ error: 'Pi payment verification failed' });
      }
    }
    // Record in DB using id as primary key (UPSERT). Store the Pi-verified amount.
    await query(
      `INSERT INTO payments (id, user_id, amount, status, metadata, payment_id)
       VALUES ($1,$2,$3,'approved',$4,$5)
       ON CONFLICT (id) DO UPDATE SET status='approved', amount=EXCLUDED.amount, updated_at=NOW()`,
      [payment_id, req.userId, approveData.amount || 0, JSON.stringify(metadata || {}), payment_id]
    ).catch(() => {});
    res.json({ success: true, payment: approveData });
  } catch (err) { serverError(err, res); }
});

// POST /api/payments/complete — Pi payment server-side completion
app.post('/api/payments/complete', auth, async (req, res) => {
  const { payment_id, txid, metadata } = req.body;
  if (!payment_id || !txid) return res.status(400).json({ error: 'payment_id and txid required' });
  try {
    // Verify payment ownership (allow if payment not in DB yet — first completion)
    const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [payment_id]).catch(() => ({ rows: [] }));
    if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== req.userId) {
      return res.status(403).json({ error: 'Payment does not belong to you' });
    }
    const completeRes = await fetch(`https://api.minepi.com/v2/payments/${payment_id}/complete`, {
      method: 'POST',
      headers: {
        'Authorization': `Key ${process.env.PI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ txid })
    });
    const completeData = await completeRes.json();
    if (!completeRes.ok) {
      return res.status(502).json({ error: 'Pi payment completion failed', details: completeData });
    }
    // Update using id (not payment_id column)
    await query(
      `UPDATE payments SET status='completed', txid=$1, updated_at=NOW() WHERE id=$2`,
      [txid, payment_id]
    ).catch(() => {});
    res.json({ success: true, payment: completeData });
  } catch (err) { serverError(err, res); }
});

// POST /api/connects/buy — credit connects ONLY after a Pi-verified payment.
// Connects are minted server-side strictly from the amount Pi confirms was paid —
// never from a client-supplied quantity, and never without a verified payment.
app.post('/api/connects/buy', auth, checkBlocked, async (req, res) => {
  const { payment_id, txid, amount, status } = req.body;

  // Approval / pending step: record intent only. NEVER credit connects here.
  if (status === 'pending') {
    const pid = payment_id || ('connects_' + req.userId + '_' + Date.now());
    const quantity = parseInt(req.body.quantity || req.body.package_amount) || 0;
    await query(
      `INSERT INTO payments (id, user_id, payment_id, amount, status, metadata)
       VALUES ($1,$2,$3,$4,'pending',$5)
       ON CONFLICT (id) DO UPDATE SET status='pending', updated_at=NOW()`,
      [pid, req.userId, pid, amount || 0, JSON.stringify({ type: 'connects', quantity })]
    ).catch(() => {});
    return res.json({ success: true, status: 'pending' });
  }

  // Completion step: a real Pi payment (payment_id + txid) is mandatory.
  if (!payment_id || !txid) {
    return res.status(400).json({ error: 'payment_id and txid required to credit connects' });
  }
  if (!PI_API_KEY) {
    return res.status(503).json({ error: 'Payments are not configured on the server' });
  }
  try {
    // Reject if this payment was already credited, or belongs to someone else
    const payRec = await query('SELECT id, user_id, status FROM payments WHERE id = $1', [payment_id]);
    if (payRec.rows.length) {
      if (payRec.rows[0].user_id && payRec.rows[0].user_id !== req.userId) {
        return res.status(403).json({ error: 'Payment does not belong to you' });
      }
      if (payRec.rows[0].status === 'completed') {
        return res.status(400).json({ error: 'Payment already processed' });
      }
    }

    // Verify with Pi Platform — approve then complete. Throw (→ 502) on any failure
    // so a forged/unpaid payment id can never reach the credit step.
    let piPayment;
    try {
      await piApprovePayment(payment_id).catch(() => {}); // may already be approved
      piPayment = await piCompletePayment(payment_id, txid);
    } catch (piErr) {
      console.error('[Connects] Pi verification failed:', piErr.message);
      return res.status(502).json({ error: 'Pi payment verification failed' });
    }

    // Credit is derived ONLY from the Pi-confirmed amount (10 connects per 1 Pi).
    const piAmount = parseFloat(piPayment.amount || 0);
    const credited = Math.floor(piAmount * 10);
    if (!(credited > 0)) {
      return res.status(400).json({ error: 'Payment amount too small to credit any connects' });
    }

    // Atomic: mark payment completed + credit connects. Uses conditional UPDATE (not DO UPDATE)
    // so concurrent calls hit the WHERE status!='completed' guard and ROLLBACK rather than
    // double-crediting (same pattern as /api/connects/purchase).
    const pgClient = await getPool().connect();
    try {
      await pgClient.query('BEGIN');
      await pgClient.query(
        `INSERT INTO payments (id, user_id, payment_id, amount, status, txid, metadata)
         VALUES ($1,$2,$1,$3,'pending',$4,$5)
         ON CONFLICT (id) DO NOTHING`,
        [payment_id, req.userId, piAmount, txid, JSON.stringify({ type: 'connects', credited })]
      );
      const updated = await pgClient.query(
        `UPDATE payments SET status='completed', txid=$2, amount=$3, updated_at=NOW()
         WHERE id=$1 AND status != 'completed' RETURNING id`,
        [payment_id, txid, piAmount]
      );
      if (!updated.rows.length) { await pgClient.query('ROLLBACK'); return res.status(400).json({ error: 'Payment already processed' }); }
      await pgClient.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [credited, req.userId]);
      await pgClient.query('COMMIT');
    } catch (txErr) {
      await pgClient.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally { pgClient.release(); }

    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
    const balance = result.rows[0]?.balance_connects || 0;
    await audit('connects_purchased', { user_id: req.userId, credited, payment_id, txid });
    res.json({ success: true, credited, balance, balance_connects: balance, new_balance: balance, remaining_connects: balance });
  } catch (err) { serverError(err, res); }
});

// (jobs/my is defined above, before /jobs/:id)

// ─── Missing endpoint aliases found from bundle analysis ──────────────────────────────────────────────

// GET /api/applications/user/:userId — list applications for a user
app.get('/api/applications/user/:userId', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    // Alias cherry19899 → pi_cherry19899 in URL param for consistency
    const paramUserId = req.params.userId === 'cherry19899' ? 'pi_cherry19899' : req.params.userId;
    if (paramUserId !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const userId = req.userId;
    const result = await query(
      `SELECT a.*, j.title as job_title, j.budget, j.status as job_status,
              u.username as client_username
       FROM applications a
       JOIN jobs j ON a.job_id = j.id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.freelancer_id = $1
       ORDER BY a.created_at DESC LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    res.json({ applications: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/escrows/user/:userId — list escrows for a user
app.get('/api/escrows/user/:userId', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const paramUserId = req.params.userId === 'cherry19899' ? 'pi_cherry19899' : req.params.userId;
    if (paramUserId !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const userId = req.userId;
    const result = await query(
      `SELECT e.*, j.title as job_title,
              c.username as client_name, f.username as freelancer_name
       FROM escrows e
       LEFT JOIN jobs j ON j.id = e.job_id
       LEFT JOIN users c ON c.id = e.client_id
       LEFT JOIN users f ON f.id = e.freelancer_id
       WHERE e.client_id = $1 OR e.freelancer_id = $1
       ORDER BY e.created_at DESC LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    res.json({ escrows: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/offers — client sends a direct offer to a freelancer
app.post('/api/offers', auth, checkBlocked, async (req, res) => {
  const { to_user_id, job_id, amount, message } = req.body;
  if (!to_user_id || !job_id) return res.status(400).json({ error: 'to_user_id and job_id required' });
  if (message && message.length > 2000) return res.status(400).json({ error: 'Message too long (max 2000)' });
  try {
    // Verify the job belongs to the requester
    const jobRes = await query('SELECT * FROM jobs WHERE id = $1', [job_id]);
    if (!jobRes.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobRes.rows[0];
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    if (to_user_id === req.userId) return res.status(400).json({ error: 'Cannot send offer to yourself' });
    const freelancerRes = await query('SELECT id, username FROM users WHERE id = $1', [to_user_id]);
    if (!freelancerRes.rows.length) return res.status(404).json({ error: 'Freelancer not found' });
    const freelancer = freelancerRes.rows[0];
    const callerRes = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const callerName = callerRes.rows[0]?.username || req.userId;
    // Create application record with status='offer'
    const result = await query(
      `INSERT INTO applications (job_id, job_title, freelancer_id, freelancer_name, message, bid_amount, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'offer', NOW()) RETURNING *`,
      [job_id, job.title, to_user_id, freelancer.username, message || '', amount || job.budget]
    );
    await notify(to_user_id, 'offer', `Вам отправлено предложение по задаче "${job.title}"`,
      `${callerName} предлагает вам работу. Сумма: ${amount || job.budget} π`, job_id, null);
    res.json({ offer: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/offers — direct offers (job invitations) for freelancer
app.get('/api/offers', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query(
      `SELECT a.*, j.title as job_title, j.budget, j.status as job_status,
              u.username as client_username
       FROM applications a
       JOIN jobs j ON a.job_id = j.id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.freelancer_id = $1
         AND a.status = 'offer'
       ORDER BY a.created_at DESC LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    res.json({ offers: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews/stats — review statistics for logged-in user
app.get('/api/reviews/stats', auth, async (req, res) => {
  try {
    const userId = req.query.user_id || req.userId;
    const [totalResult, avgResult, distResult] = await Promise.all([
      query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [userId]),
      query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [userId]),
      query(
        'SELECT rating, COUNT(*) as count FROM ratings WHERE to_user_id = $1 GROUP BY rating ORDER BY rating DESC',
        [userId]
      ),
    ]);
    const total = parseInt(totalResult.rows[0].count);
    const avg = parseFloat(avgResult.rows[0].avg || 0).toFixed(1);
    const distribution = {};
    distResult.rows.forEach(r => { distribution[r.rating] = parseInt(r.count); });
    res.json({ total, avg: parseFloat(avg), distribution, rating: parseFloat(avg) });
  } catch (err) { serverError(err, res); }
});

// ─── Additional endpoints from bundle analysis ──────────────────────────────────────────────

// POST /api/chat/:roomId/messages — send message (alias for /chat/rooms/:id/messages)
app.post('/api/chat/:roomId/messages', auth, checkBlocked, async (req, res) => {
  const { content, message, text } = req.body;
  const msg = content || message || text || '';
  if (!msg.trim()) return res.status(400).json({ error: 'Message content required' });
  if (msg.length > 2000) return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
  try {
    const roomCheck = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.roomId, req.userId]);
    if (!roomCheck.rows.length) return res.status(403).json({ error: 'Not in this room' });
    const userRes = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userRes.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.roomId, req.userId, senderName, msg]
    );
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.roomId]);
    res.json({ message: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/offers/:id — get a specific offer
app.get('/api/offers/:id', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT a.*, j.title as job_title, j.budget, u.username as client_username
       FROM applications a
       JOIN jobs j ON a.job_id = j.id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.id = $1 AND a.freelancer_id = $2`,
      [req.params.id, req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Offer not found' });
    res.json({ offer: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/view — mark application as viewed
app.post('/api/applications/:id/view', auth, async (req, res) => {
  try {
    await query('UPDATE applications SET viewed = true, viewed_at = NOW() WHERE id = $1', [req.params.id]).catch(() => {
      // viewed column may not exist, ignore
    });
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

// GET /api/chat/:roomId/messages — messages in a chat room (uses chat_messages table)
app.get('/api/chat/:roomId/messages', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const roomCheck = await query(
      'SELECT id FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)',
      [req.params.roomId, req.userId]
    );
    if (!roomCheck.rows.length) return res.status(403).json({ error: 'Access denied' });
    const result = await query(
      `SELECT cm.*, u.username as sender_username,
              cm.message as content, cm.message as text
       FROM chat_messages cm
       LEFT JOIN users u ON u.id = cm.sender_id
       WHERE cm.room_id = $1
       ORDER BY cm.created_at ASC
       LIMIT $2 OFFSET $3`,
      [req.params.roomId, limit, offset]
    );
    res.json({ messages: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/chat/rooms/:id — specific chat room details
app.get('/api/chat/rooms/:id', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT cr.*,
              u1.username as client_username, u2.username as freelancer_username
       FROM chat_rooms cr
       LEFT JOIN users u1 ON u1.id = cr.client_id
       LEFT JOIN users u2 ON u2.id = cr.freelancer_id
       WHERE cr.id = $1 AND (cr.client_id = $2 OR cr.freelancer_id = $2)`,
      [req.params.id, req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Room not found' });
    res.json({ room: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

// POST /api/escrows/:id/fund — fund an escrow after Pi payment
app.post('/api/escrows/:id/fund', auth, async (req, res) => {
  const { payment_id, txid } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required — provide the Pi payment identifier' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status !== 'pending') return res.status(400).json({ error: 'Escrow already funded or settled' });
    // Require that the payment record exists in our DB (created by Pi payment webhook)
    const pmtCheck = await query('SELECT id FROM payments WHERE payment_id = $1 AND status = $2 LIMIT 1', [payment_id, 'completed']);
    if (!pmtCheck.rows.length) return res.status(402).json({ error: 'Payment not verified — complete Pi payment first' });
    await query('UPDATE escrows SET status = $1, payment_id = $2, updated_at = NOW() WHERE id = $3', ['funded', payment_id, req.params.id]);
    await audit('escrow_funded', { escrow_id: req.params.id, payment_id, txid });
    res.json({ escrow: { ...escrow, status: 'funded' }, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/escrows/:id/dispute — open a dispute
app.post('/api/escrows/:id/dispute', auth, async (req, res) => {
  const { reason } = req.body;
  if (reason && reason.length > 1000) return res.status(400).json({ error: 'Reason too long (max 1000 chars)' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId && escrow.freelancer_id !== req.userId) {
      return res.status(403).json({ error: 'Not your escrow' });
    }
    await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['disputed', req.params.id]);
    await audit('escrow_disputed', { escrow_id: req.params.id, reason, user_id: req.userId });
    // Notify the other party
    const otherParty = req.userId === escrow.client_id ? escrow.freelancer_id : escrow.client_id;
    await notify(otherParty, 'dispute', 'Открыт спор по задаче',
      reason || 'Одна из сторон открыла спор. Пожалуйста, свяжитесь с поддержкой.', escrow.job_id, null);
    res.json({ escrow: { ...escrow, status: 'disputed' }, success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/escrows/:id/room — chat room for an escrow
app.get('/api/escrows/:id/room', auth, async (req, res) => {
  try {
    const escResult = await query('SELECT * FROM escrows WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!escResult.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = escResult.rows[0];
    // Find or create chat room between client and freelancer
    const roomResult = await query(
      `SELECT * FROM chat_rooms WHERE (client_id = $1 AND freelancer_id = $2) OR (client_id = $2 AND freelancer_id = $1) LIMIT 1`,
      [escrow.client_id, escrow.freelancer_id]
    );
    if (roomResult.rows.length) {
      return res.json({ room: roomResult.rows[0], room_id: roomResult.rows[0].id });
    }
    // Create room if not exists
    const roomId = `room_${escrow.client_id}-${escrow.freelancer_id}-${Date.now()}`;
    const newRoom = await query(
      'INSERT INTO chat_rooms (id, client_id, freelancer_id) VALUES ($1, $2, $3) RETURNING *',
      [roomId, escrow.client_id, escrow.freelancer_id]
    );
    res.json({ room: newRoom.rows[0], room_id: newRoom.rows[0].id });
  } catch (err) { serverError(err, res); }
});


// POST /api/offers/:id/accept — accept a job offer
app.post('/api/offers/:id/accept', auth, async (req, res) => {
  try {
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 AND freelancer_id = $3 RETURNING *', ['accepted', req.params.id, req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Offer not found' });
    res.json({ application: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/offers/:id/decline — decline a job offer
app.post('/api/offers/:id/decline', auth, async (req, res) => {
  try {
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 AND freelancer_id = $3 RETURNING *', ['declined', req.params.id, req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Offer not found' });
    res.json({ application: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews/stats/:userId — review stats for a specific user (path param, MUST be before /:id)
app.get('/api/reviews/stats/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const [totalResult, avgResult, distResult] = await Promise.all([
      query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [userId]),
      query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [userId]),
      query('SELECT rating, COUNT(*) as count FROM ratings WHERE to_user_id = $1 GROUP BY rating ORDER BY rating DESC', [userId]),
    ]);
    const total = parseInt(totalResult.rows[0].count);
    const avg = parseFloat(avgResult.rows[0].avg || 0).toFixed(1);
    const distribution = {};
    distResult.rows.forEach(r => { distribution[r.rating] = parseInt(r.count); });
    res.json({ total, avg: parseFloat(avg), distribution, rating: parseFloat(avg) });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews/:id — get review by ID, OR if id is non-integer, treat as user ID
app.get('/api/reviews/:id', async (req, res) => {
  const id = req.params.id;
  const isNumeric = /^\d+$/.test(id);
  try {
    if (isNumeric) {
      // Get specific review by integer ID
      const result = await query(
        'SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.id = $1',
        [id]
      );
      if (!result.rows.length) return res.status(404).json({ error: 'Review not found' });
      res.json({ review: result.rows[0] });
    } else {
      // Treat as user ID — return all reviews for this user
      const limit2 = Math.min(parseInt(req.query.limit) || 50, 200);
      const offset2 = parseInt(req.query.offset) || 0;
      const result = await query(
        'SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC LIMIT $2 OFFSET $3',
        [id, limit2, offset2]
      );
      res.json({ reviews: result.rows, ratings: result.rows, limit: limit2, offset: offset2 });
    }
  } catch (err) { serverError(err, res); }
});

// POST + PUT /api/users/:id/availability — update user availability status
// Bundle sends POST (not PUT), so we handle both
async function handleAvailability(req, res) {
  const { available, availability } = req.body;
  if (req.params.id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  const targetId = req.params.id;
  try {
    const isAvailable = available !== undefined ? available : (availability === 'available');
    // Update availability column (try both availability string and is_available bool)
    await query(
      `UPDATE users SET availability = $1, updated_at = NOW() WHERE id = $2`,
      [isAvailable ? 'available' : 'unavailable', targetId]
    ).catch(async () => {
      await query('UPDATE users SET updated_at = NOW() WHERE id = $1', [targetId]).catch(() => {});
    });
    const result = await query(
      'SELECT id, username, role, rating, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, status, updated_at FROM users WHERE id = $1',
      [targetId]
    );
    const u = result.rows[0] || {};
    res.json({ ...u, uid: u.id, is_admin: u?.role === 'admin', success: true });
  } catch (err) { serverError(err, res); }
}
app.put('/api/users/:id/availability', auth, handleAvailability);
app.post('/api/users/:id/availability', auth, handleAvailability);

// ─── Pi Payment additional endpoints ──────────────────────────────────────────────

// POST /api/payments/:paymentId/cancelled — called by bundle when Pi payment is cancelled
app.post('/api/payments/:paymentId/cancelled', auth, async (req, res) => {
  try {
    await query(
      `UPDATE payments SET status = 'cancelled', updated_at = NOW() WHERE id = $1 AND user_id = $2`,
      [req.params.paymentId, req.userId]
    ).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

// POST /api/payments/clear-pending — called by bundle to clear old pending payments
// Uses auth (not softAuth) to prevent spoofing another user's x-user-id
app.post('/api/payments/clear-pending', auth, async (req, res) => {
  try {
    // Only cancel payments older than 10 minutes to avoid cancelling in-flight payments
    await query(
      `UPDATE payments SET status = 'cancelled', updated_at = NOW() WHERE user_id = $1 AND status = 'pending' AND created_at < NOW() - INTERVAL '10 minutes'`,
      [req.userId]
    ).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

// POST /api/payments/:paymentId/resolve-complete — called by bundle when Pi payment is developer_completed
// Pi SDK's onIncompletePaymentFound triggers this for payments that need server-side completion
app.post('/api/payments/:paymentId/resolve-complete', auth, async (req, res) => {
  const paymentId = req.params.paymentId;
  // Verify payment ownership before allowing server-side completion
  const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
  if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== req.userId) {
    return res.status(403).json({ error: 'Payment does not belong to you' });
  }
  try {
    // Fetch payment details from Pi API to get txid
    const piRes = await fetch(`https://api.minepi.com/v2/payments/${paymentId}`, {
      headers: { 'Authorization': `Key ${process.env.PI_API_KEY}` }
    }).catch(() => null);

    let txid = null;
    if (piRes && piRes.ok) {
      const piData = await piRes.json().catch(() => ({}));
      txid = piData.transaction?.txid || piData.txid || null;
      // Tell Pi to mark it as complete
      if (txid) {
        await fetch(`https://api.minepi.com/v2/payments/${paymentId}/complete`, {
          method: 'POST',
          headers: { 'Authorization': `Key ${process.env.PI_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ txid })
        }).catch(() => {});
      }
    }

    // Mark as completed in our DB (idempotent)
    await query(
      `UPDATE payments SET status = 'completed', txid = COALESCE($1, txid), updated_at = NOW() WHERE id = $2`,
      [txid, paymentId]
    ).catch(() => {});

    // Run the same business logic as /complete to avoid stale credited connects or escrow
    const paymentRecord = await query('SELECT * FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
    if (paymentRecord.rows.length) {
      const meta = paymentRecord.rows[0].metadata || {};
      const paymentOwner = paymentRecord.rows[0].user_id || req.userId;
      if (meta.type === 'connects') {
        const piAmountPaid = parseFloat(txid ? (paymentRecord.rows[0].amount || 0) : 0);
        const amount = Math.floor(piAmountPaid * 10);
        if (amount > 0) {
          await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, paymentOwner]).catch(() => {});
        }
      } else if (meta.type === 'escrow' && meta.job_id && meta.freelancer_id) {
        await query(
          'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING',
          [meta.job_id, paymentOwner, meta.freelancer_id, paymentRecord.rows[0].amount || meta.amount || 0, paymentId, 'funded']
        ).catch(() => {});
      }
    }

    res.json({ success: true, resolved: true, txid });
  } catch (err) { res.json({ success: true, resolved: false }); }
});

// GET /api/users/:id/connects — get user's connects balance (owner only)
app.get('/api/users/:id/connects', auth, async (req, res) => {
  if (req.params.id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  try {
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.params.id]);
    res.json({ balance: result.rows[0]?.balance_connects || 0, connects: result.rows[0]?.balance_connects || 0 });
  } catch (err) { res.json({ balance: 0, connects: 0 }); }
});

// NOTE: GET /api/reviews/:id above already handles userId as non-numeric param (returns all reviews for that user).
// This duplicate handler is intentionally removed — Express would never reach it.

// POST /api/push/subscribe — Web Push notification subscription
app.post('/api/push/subscribe', softAuth, async (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (endpoint && !endpoint.startsWith('https://')) {
    return res.status(400).json({ error: 'Invalid push endpoint' });
  }
  if (req.userId && endpoint) {
    await query(
      `INSERT INTO push_subscriptions (user_id, endpoint, keys, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id) DO UPDATE SET endpoint=$2, keys=$3, updated_at=NOW()`,
      [req.userId, endpoint, JSON.stringify(keys || {})]
    ).catch(() => {
      // Table may not exist yet — create it and retry
      query(`CREATE TABLE IF NOT EXISTS push_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id TEXT UNIQUE NOT NULL,
        endpoint TEXT NOT NULL,
        keys JSONB,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )`).then(() =>
        query(
          `INSERT INTO push_subscriptions (user_id, endpoint, keys, updated_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (user_id) DO UPDATE SET endpoint=$2, keys=$3, updated_at=NOW()`,
          [req.userId, endpoint, JSON.stringify(keys || {})]
        )
      ).catch(() => {});
    });
  }
  res.json({ success: true });
});

// ─── 404 ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ─── Error handler ──────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ──────────────────────────────────────────────
initDb().then(async () => {
  await ensureNotificationsTable();
  app.listen(PORT, () => {
    console.log(`[WorkPro API] v3.1.0 on port ${PORT} (${NODE_ENV})`);
  });
}).catch(err => {
  console.error('[Server] Failed to start:', err);
  process.exit(1);
});

module.exports = app;

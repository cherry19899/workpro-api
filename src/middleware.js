/**
 * src/middleware.js — Auth middleware and rate limiters.
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { query } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || (() => {
  // This warning is also emitted in server.js; the module-level call here is only reached
  // when middleware.js is loaded outside the main server (e.g. tests). The canonical warning
  // lives in server.js.
  return crypto.randomBytes(64).toString('hex');
})();

const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'admin-secret-key';

// RATE_LIMIT_BYPASS_KEY — set this env var to skip rate limiting for automated
// testing / CI. Callers pass it as x-rate-bypass header. Never expose in client code.
const RATE_LIMIT_BYPASS_KEY = process.env.RATE_LIMIT_BYPASS_KEY || null;

function skipIfBypassed(req) {
  if (!RATE_LIMIT_BYPASS_KEY) return false;
  const header = req.headers['x-rate-bypass'] || '';
  return header.length === RATE_LIMIT_BYPASS_KEY.length &&
    crypto.timingSafeEqual(Buffer.from(header), Buffer.from(RATE_LIMIT_BYPASS_KEY));
}

// In dev/sandbox mode all per-endpoint limits are relaxed 10×.
const DEV_MULTIPLIER = process.env.SANDBOX_MODE ? 10 : 1;

// ─── Rate limiters ──────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  message: { error: 'Too many auth attempts, try again later' },
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 100 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  message: { error: 'Too many admin requests' },
});

// Strict limiter for connects/payments to prevent abuse
const connectsLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20 * DEV_MULTIPLIER,
  // Key by IP, NOT x-user-id — the user header is client-controlled and trivially rotated to bypass the cap
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  message: { error: 'Too many connect operations, try again later' },
});

// Strict limiter for chat message sending — 30 messages per minute per IP
const messageLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  message: { error: 'Too many messages, slow down' },
});

const jobPostLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  message: { error: 'Too many jobs posted, try again later' },
});

// ─── Auth middleware ──────────────────────────────────────────────
async function auth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
      req.userId = decoded.id;
      req.jwtVerified = true;
      return next();
    } catch (_) { /* invalid/expired JWT */ }
  }
  return res.status(401).json({ error: 'Access token required' });
}

// softAuth — extracts userId from JWT but NEVER rejects (for public endpoints)
function softAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
      req.userId = decoded.id;
      req.jwtVerified = true;
    } catch (_) { /* invalid/expired — anonymous */ }
  }
  next();
}

async function adminAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const rawKey = req.headers['x-admin-key'] || req.query.admin_key || '';
  // Path 1: shared ADMIN_API_KEY secret (for direct API / scripts)
  let key = rawKey || (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader);
  const keyOk = key.length > 0 && key.length === ADMIN_API_KEY.length &&
    crypto.timingSafeEqual(Buffer.from(key), Buffer.from(ADMIN_API_KEY));
  if (keyOk) {
    req.isAdmin = true;
    return next();
  }
  // Path 2: valid JWT from a user with role='admin' (for the in-app admin panel)
  if (authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
      const userRow = await query("SELECT id FROM users WHERE id = $1 AND role = 'admin' LIMIT 1", [decoded.id]);
      if (userRow.rows.length) {
        req.userId = decoded.id;
        req.isAdmin = true;
        return next();
      }
    } catch (_) {}
  }
  return res.status(403).json({ error: 'Admin access required' });
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

module.exports = {
  auth,
  softAuth,
  adminAuth,
  checkBlocked,
  authLimiter,
  adminLimiter,
  connectsLimiter,
  messageLimiter,
  jobPostLimiter,
  JWT_SECRET,
  ADMIN_API_KEY,
};

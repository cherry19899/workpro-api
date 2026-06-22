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

// ─── Rate-limit block tracker ──────────────────────────────────────────────
// In-memory map: ip → { endpoint, count, firstHit, lastHit }
const _rlBlocks = new Map();

function _rlHandler(endpoint) {
  return (req, res) => {
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const entry = _rlBlocks.get(ip) || { endpoint, count: 0, firstHit: Date.now(), lastHit: 0 };
    entry.count += 1;
    entry.lastHit = Date.now();
    entry.endpoint = endpoint; // update to most recent endpoint blocked
    _rlBlocks.set(ip, entry);
    res.status(429).json({ error: `Too many requests (${endpoint})` });
  };
}

// ─── Rate limiters ──────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  handler: _rlHandler('auth'),
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 100 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  handler: _rlHandler('admin'),
});

// Strict limiter for connects/payments to prevent abuse
const connectsLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20 * DEV_MULTIPLIER,
  // Key by IP, NOT x-user-id — the user header is client-controlled and trivially rotated to bypass the cap
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  handler: _rlHandler('connects'),
});

// Strict limiter for chat message sending — 30 messages per minute per IP
const messageLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  handler: _rlHandler('messages'),
});

const jobPostLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  handler: _rlHandler('job_post'),
});

// Strict IP limiter for admin endpoints — 50 failed-or-brute-force attempts/15min
// Note: legitimate automated admin scripts should use RATE_LIMIT_BYPASS_KEY instead
const adminStrictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 50 * DEV_MULTIPLIER,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  skip: skipIfBypassed,
  handler: _rlHandler('admin_strict'),
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
      // Also check by decoded.username in case the DB uid differs from JWT uid (migration edge case)
      const jwtUsername = decoded.username || '';
      const userRow = await query(
        "SELECT id, role, username FROM users WHERE id = $1 OR (LOWER(username) = $2 AND $2 <> '') LIMIT 1",
        [decoded.id, jwtUsername.toLowerCase()]
      );
      const ur = userRow.rows[0];
      if (ur) {
        // Owner self-heal: bundle never calls GET /api/me, so role may be stale here.
        const isOwner = (ur.username && ur.username.toLowerCase() === 'cherry19899') ||
          (jwtUsername && jwtUsername.toLowerCase() === 'cherry19899') ||
          ur.id === 'pi_cherry19899' || ur.id === 'pi_a2b617f7-f510-4502-a046-805facedcc29';
        if (ur.role === 'admin' || isOwner) {
          if (ur.role !== 'admin' && isOwner) {
            await query("UPDATE users SET role = 'admin' WHERE id = $1", [ur.id]).catch(() => {});
          }
          req.userId = ur.id;
          req.isAdmin = true;
          return next();
        }
      }
    } catch (_) {}
  }
  return res.status(403).json({ error: 'Admin access required' });
}

// Returns the duplicate-account "twin" id for a uid. The frontend builds ids as
// "pi_" + uid, but some Pi uids already start with "pi_", so the same person can
// end up with both `X` and `pi_X` records. A block on one must apply to the other,
// otherwise the blocked user simply logs in as the unblocked twin and continues.
function twinId(id) {
  if (!id) return id;
  return id.startsWith('pi_') ? id.slice(3) : 'pi_' + id;
}

async function checkBlocked(req, res, next) {
  try {
    const id = req.userId;
    const result = await query(
      'SELECT 1 FROM users WHERE id IN ($1, $2) AND is_blocked = true LIMIT 1',
      [id, twinId(id)]
    );
    if (result.rows.length) {
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
  twinId,
  authLimiter,
  adminLimiter,
  adminStrictLimiter,
  connectsLimiter,
  messageLimiter,
  jobPostLimiter,
  JWT_SECRET,
  ADMIN_API_KEY,
  _rlBlocks,
};

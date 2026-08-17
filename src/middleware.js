/**
 * src/middleware.js — Auth middleware and rate limiters.
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { query } = require('./db');
const { isOwnerId } = require('./helpers');

const _isProd = (process.env.NODE_ENV || 'production') === 'production';
const _isSandbox = !!process.env.SANDBOX_MODE;

const JWT_SECRET = process.env.JWT_SECRET || (() => {
  if (_isProd && !_isSandbox) {
    console.error('[FATAL] JWT_SECRET is not set in production. Refusing to start.');
    process.exit(1);
  }
  return crypto.randomBytes(64).toString('hex');
})();

const ADMIN_API_KEY = process.env.ADMIN_API_KEY || (() => {
  if (_isProd && !_isSandbox) {
    console.error('[FATAL] ADMIN_API_KEY is not set in production. Refusing to start.');
    process.exit(1);
  }
  return 'admin-secret-key';
})();

// RATE_LIMIT_BYPASS_KEY — set this env var to skip rate limiting for automated
// testing / CI. Callers pass it as x-rate-bypass header. Never expose in client code.
const RATE_LIMIT_BYPASS_KEY = process.env.RATE_LIMIT_BYPASS_KEY || null;

function skipIfBypassed(req) {
  if (!RATE_LIMIT_BYPASS_KEY) return false;
  // The old comparison gated timingSafeEqual on *character* length while
  // timingSafeEqual measures *bytes*, and there is no try/catch here:
  // an x-rate-bypass header of multi-byte characters whose character count
  // matched the key threw RangeError inside express-rate-limit's synchronous
  // skip(), turning every rate-limited endpoint into a 500 for that request.
  return timingSafeStrEqual(req.headers['x-rate-bypass'], RATE_LIMIT_BYPASS_KEY);
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

// Strict limiter for connects/payments — key by userId (from JWT) so multiple
// users behind the same NAT IP don't share the cap, and IP rotation doesn't bypass it.
const connectsLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20 * DEV_MULTIPLIER,
  keyGenerator: (req) => {
    try {
      const h = req.headers['authorization'];
      if (h && h.startsWith('Bearer ')) {
        const decoded = jwt.verify(h.slice(7), JWT_SECRET);
        if (decoded && decoded.id) return 'user_' + decoded.id;
      }
    } catch (_) {}
    return req.ip || req.socket?.remoteAddress || 'unknown';
  },
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

/**
 * Constant-time compare of a caller-supplied secret against the real one.
 *
 * The call sites used to gate timingSafeEqual on `a.length === b.length` —
 * *string* length — then hand it Buffers. A token of N multi-byte characters
 * passes that gate and produces a Buffer of 2N bytes, and timingSafeEqual
 * throws RangeError on mismatched byte lengths: inside an async handler that
 * becomes an unhandled rejection and the request never answers. Comparing the
 * Buffers' own lengths makes the mismatch a plain `false`.
 */
function timingSafeStrEqual(a, b) {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length === 0 || bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

async function adminAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const rawKey = req.headers['x-admin-key'] || req.query.admin_key || '';
  // Path 1: shared ADMIN_API_KEY secret (for direct API / scripts)
  let key = rawKey || (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader);
  const keyOk = timingSafeStrEqual(key, ADMIN_API_KEY);
  if (keyOk) {
    req.isAdmin = true;
    return next();
  }
  // Path 2: valid JWT from a user with role='admin' (for the in-app admin panel).
  //
  // Nothing below may key off a username. A username is not a credential here:
  // there is no UNIQUE index on users.username, and the login routes used to
  // copy a request-BODY username straight into the JWT claim and into the stored
  // row. So neither the claim (a signature proves only that we issued the token,
  // not that the name inside it is true) nor the stored name can be trusted, and
  // tokens minted before that was fixed stay valid for 30 days. Admin is decided
  // by the shared key above, by role='admin' on a row found BY ID, or by the
  // owner's own uid — never by a name.
  if (authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
      const jwtId = decoded.id || '';
      // Fast-path: the JWT's *id* is the owner's. Ids come from the Pi-verified
      // uid, unlike the username claim, so this one is safe to trust.
      if (isOwnerId(jwtId)) {
        // Self-heal this row only. The old statement promoted every row whose
        // username was 'cherry19899', which handed admin to impostor rows.
        query("UPDATE users SET role='admin' WHERE id = $1 AND role != 'admin'", [jwtId]).catch(() => {});
        req.isAdmin = true;
        req.userId = jwtId;
        return next();
      }
      const userRow = await query(
        // Also try pi_+id so old JWTs with id='cherry19899' find row stored as 'pi_cherry19899'
        'SELECT id, role FROM users WHERE id = $1 OR id = $2 LIMIT 1',
        [jwtId, 'pi_' + jwtId]
      );
      const ur = userRow.rows[0];
      if (ur) {
        const isOwner = isOwnerId(ur.id);
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
  timingSafeStrEqual,
  _rlBlocks,
};

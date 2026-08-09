/**
 * src/helpers.js — Shared helper functions used across route modules.
 */
const fetch = require('node-fetch');
const { query, getPool } = require('./db');

const PI_API_KEY = process.env.PI_API_KEY || '';

// ─── Sandbox switch ──────────────────────────────────────────────
// Only the exact string 'true' turns sandbox on. This was a truthiness check on
// the raw env var, which made SANDBOX_MODE="false" — the obvious way to turn it
// off — read as ON, and sandbox skips Pi accessToken verification entirely: any
// caller could POST /api/me with someone else's uid and be handed their JWT.
// Every reader must go through this constant so the rule cannot drift again.
const SANDBOX_MODE = process.env.SANDBOX_MODE === 'true';
// The Pi Platform API (payments approve/complete/get) is served from api.minepi.com
// for BOTH testnet/sandbox and mainnet apps — sandbox is a frontend-SDK concern only.
// api.testnet.minepi.com is the Stellar testnet Horizon (blockchain), NOT the Platform
// API: calling it for /v2/payments/* returns Horizon "Resource Missing" 404s and the
// Pi wallet never gets approved. Always use api.minepi.com here.
const PI_API_BASE = 'https://api.minepi.com';

// ─── Platform fee ──────────────────────────────────────────────
// Hard limits — no matter what's in the DB or env, fee is capped at 20%.
const FEE_MIN = 0;
const FEE_MAX = 0.2;
const FEE_DEFAULT_PCT = parseFloat(process.env.PLATFORM_FEE_PERCENT || '2');
const FEE_DEFAULT = Math.min(Math.max(FEE_DEFAULT_PCT / 100, FEE_MIN), FEE_MAX);

// ─── Developer fee ──────────────────────────────────────────────
// Hard cap at 20%.
const DEV_FEE_MIN = 0;
const DEV_FEE_MAX = 0.2;
const DEV_FEE_DEFAULT_PCT = parseFloat(process.env.DEVELOPER_FEE_PERCENT || '0');
const DEV_FEE_DEFAULT = Math.min(Math.max(DEV_FEE_DEFAULT_PCT / 100, DEV_FEE_MIN), DEV_FEE_MAX);

let _feeCache = null;        // { value: number, expiresAt: number }
let _devFeeCache = null;     // { value: number, expiresAt: number }
const FEE_CACHE_TTL = 60000; // 60 seconds

async function getPlatformFee() {
  const now = Date.now();
  if (_feeCache && now < _feeCache.expiresAt) return _feeCache.value;
  try {
    const row = await query(
      "SELECT value FROM platform_settings WHERE key = 'platform_fee_percent' LIMIT 1"
    );
    if (row.rows.length) {
      const pct = parseFloat(row.rows[0].value);
      if (!isNaN(pct)) {
        const fee = Math.min(Math.max(pct / 100, FEE_MIN), FEE_MAX);
        _feeCache = { value: fee, expiresAt: now + FEE_CACHE_TTL };
        return fee;
      }
    }
  } catch (_) { /* DB unavailable — fall through to env default */ }
  _feeCache = { value: FEE_DEFAULT, expiresAt: now + FEE_CACHE_TTL };
  return FEE_DEFAULT;
}

async function getDeveloperFee() {
  const now = Date.now();
  if (_devFeeCache && now < _devFeeCache.expiresAt) return _devFeeCache.value;
  try {
    const row = await query(
      "SELECT value FROM platform_settings WHERE key = 'developer_fee_percent' LIMIT 1"
    );
    if (row.rows.length) {
      const pct = parseFloat(row.rows[0].value);
      if (!isNaN(pct)) {
        const fee = Math.min(Math.max(pct / 100, DEV_FEE_MIN), DEV_FEE_MAX);
        _devFeeCache = { value: fee, expiresAt: now + FEE_CACHE_TTL };
        return fee;
      }
    }
  } catch (_) {}
  _devFeeCache = { value: DEV_FEE_DEFAULT, expiresAt: now + FEE_CACHE_TTL };
  return DEV_FEE_DEFAULT;
}

function invalidatePlatformFeeCache() {
  _feeCache = null;
  _devFeeCache = null;
}

// ─── Connects economy ──────────────────────────────────────────────
// Both numbers are admin-configurable and cached like the fee. The formula was
// duplicated in the frontend with the divisor hardcoded — the same setup that
// let the published fee drift away from the one actually charged, so these are
// served to the client from /api/config instead.
const APPLY_DIVISOR_DEFAULT = 50;
const POST_JOB_COST_DEFAULT = 1;
let _econCache = null;
const ECON_CACHE_TTL = 60000;

async function getConnectsEconomy() {
  const now = Date.now();
  if (_econCache && now < _econCache.expiresAt) return _econCache.value;
  const value = { applyCostDivisor: APPLY_DIVISOR_DEFAULT, postJobCost: POST_JOB_COST_DEFAULT };
  try {
    const row = await query(
      "SELECT key, value FROM platform_settings WHERE key IN ('apply_cost_divisor','post_job_cost')"
    );
    for (const r of row.rows) {
      const n = parseFloat(r.value);
      if (isNaN(n)) continue;
      if (r.key === 'apply_cost_divisor' && n >= 1) value.applyCostDivisor = n;
      if (r.key === 'post_job_cost' && n >= 0) value.postJobCost = Math.round(n);
    }
  } catch (_) { /* DB unavailable — defaults are safe */ }
  _econCache = { value, expiresAt: now + ECON_CACHE_TTL };
  return value;
}

function invalidateConnectsEconomyCache() { _econCache = null; }

/** Connects required to apply for a job of this budget. Never below 1. */
function applyCostFor(budget, divisor) {
  const b = Number(budget) || 0;
  const d = Number(divisor) || APPLY_DIVISOR_DEFAULT;
  return Math.max(1, Math.ceil(b / d));
}

// ─── Support link ──────────────────────────────────────────────
// Empty by default: better no link than a dead one. Only surfaced in the app
// once an admin sets it.
let _supportCache = null;

async function getSupportUrl() {
  const now = Date.now();
  if (_supportCache && now < _supportCache.expiresAt) return _supportCache.value;
  let value = '';
  try {
    const row = await query("SELECT value FROM platform_settings WHERE key = 'support_url' LIMIT 1");
    const v = (row.rows[0]?.value || '').trim();
    // Re-checked on read, not just on write: a value could predate the
    // validation, and this string is handed to every user's browser.
    if (/^https?:\/\/[^\s]+$/i.test(v)) value = v;
  } catch (_) {}
  _supportCache = { value, expiresAt: now + 60000 };
  return value;
}

function invalidateSupportUrlCache() { _supportCache = null; }

// ─── Connects pricing ──────────────────────────────────────────────
// Server-side package catalog — mirrors frontend packages. Never trust client-supplied quantity.
const CONNECT_PACKAGES = [
  { connects: 10,  price: 1 },
  { connects: 50,  price: 5 },
  { connects: 100, price: 7 },
];

// Resolve connects to credit for a given Pi amount.
// Package bonus is granted only when the Pi amount matches a known package price (±5%).
// Client-supplied package_amount / quantity are intentionally ignored.
function resolveConnects(piAmount) {
  const formula = Math.floor(piAmount * 10);
  const pkg = CONNECT_PACKAGES.find(p => Math.abs(p.price - piAmount) / p.price < 0.05);
  return Math.max(formula, pkg ? pkg.connects : 0);
}

// ─── Pi Platform API ──────────────────────────────────────────────
// userAccessToken: when provided (e.g. for /v2/me identity check), use user Bearer token instead of server Key
async function piApiRequest(path, method = 'GET', body = null, userAccessToken = null, { retries = 3, baseDelay = 300 } = {}) {
  const opts = {
    method,
    headers: {
      'Authorization': userAccessToken ? `Bearer ${userAccessToken}` : `Key ${PI_API_KEY}`,
      'Content-Type': 'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  let lastErr;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await fetch(`${PI_API_BASE}${path}`, opts);
      const data = await res.json();
      if (!res.ok) {
        console.error(`[Pi API] ${method} ${path} → HTTP ${res.status}:`, JSON.stringify(data));
        throw new Error(data.error_message || data.message || `Pi API error: ${res.status}`);
      }
      console.log(`[Pi API] ${method} ${path} → ${res.status} OK`);
      return data;
    } catch (err) {
      lastErr = err;
      const retryable = !err.message?.includes('Pi API error: 4'); // don't retry 4xx
      if (attempt < retries && retryable) {
        const delay = baseDelay * Math.pow(2, attempt - 1); // 300ms, 600ms, 1200ms
        console.warn(`[Pi API] ${method} ${path} attempt ${attempt} failed (${err.message}), retrying in ${delay}ms`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }
  throw lastErr;
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

// ─── Notification helper ──────────────────────────────────────────────
// `opts` may carry { key, params }. The key is what the client renders through
// its own translation dictionary, so a notification always appears in whatever
// UI language the reader currently has. `title`/`body` are still written
// verbatim as the fallback for rows created before this and for clients that
// don't recognise the key — never stop writing them or old rows go blank.
async function notify(userId, type, title, body, jobId, roomId, opts = {}) {
  try {
    await query(
      `INSERT INTO notifications (user_id, type, title, body, job_id, room_id, is_read, created_at, notif_key, params)
       VALUES ($1,$2,$3,$4,$5,$6,false,NOW(),$7,$8)`,
      [userId, type, title, body || null, jobId || null, roomId || null,
       opts.key || null, JSON.stringify(opts.params || {})]
    );
  } catch (_) {}
}

// ─── Audit helper ──────────────────────────────────────────────
async function audit(action, data) {
  try {
    await query('INSERT INTO audit_logs (action, data) VALUES ($1, $2)', [action, JSON.stringify(data)]);
  } catch (_) {}
}

// ─── Generic server error responder ──────────────────────────────────────────────
let _last500 = { error: null, stack: null, at: null };
function last500() { return _last500; }

/**
 * Postgres codes that only ever mean "the value the caller supplied is not a
 * value this column can hold". Every one of them is a bad request that was
 * answered with 500 because the check happened in the database instead of in
 * the route.
 *
 * Most id path params go straight into `WHERE id = $1` unparsed, and the id
 * columns of jobs, escrows, applications, reviews, notifications,
 * saved_searches and escrow_milestones are all SERIAL — so
 * `DELETE /api/saved-searches/abc` earned 22P02, and `/api/jobs/99999999999`
 * earned 22003. Mapping them here fixes every such route at once, which
 * hand-parsing thirty path params would not.
 */
const CLIENT_DATA_ERRORS = {
  '22P02': 'Invalid value in request',        // invalid_text_representation ('abc' as an integer)
  '22003': 'Value out of range',              // numeric_value_out_of_range (past int4)
  '22001': 'Value too long',                  // string_data_right_truncation (past VARCHAR(n))
};

function serverError(err, res) {
  const clientMsg = err && CLIENT_DATA_ERRORS[err.code];
  if (clientMsg) {
    // Still logged: our own code passing a malformed value would land here too,
    // and that is a bug worth seeing. But it is not recorded as the last 500 —
    // /api/health?deep=1 reports that field to diagnose server faults, and a
    // caller's typo is not one.
    console.error('[BadInput]', err.code, err.message);
    return res.status(400).json({ error: clientMsg });
  }
  console.error('[Error]', err);
  _last500 = {
    error: (err && (err.message || String(err))) || 'unknown',
    stack: err && err.stack ? String(err.stack).split('\n').slice(0, 4).join(' | ') : null,
    at: new Date().toISOString(),
  };
  return res.status(500).json({ error: 'Internal server error' });
}

// Lightweight uid extractor from request body (no DB lookup — use payments.js resolveUserId for that).
function resolveUserIdFromBody(body) {
  return body?.metadata?.uid
    || body?.metadata?.userId
    || body?.user?.id
    || body?.userId
    || body?.uid
    || null;
}

/**
 * What a Pi payment lookup entitles us to write to the payments table.
 *
 * /api/payments/webhook is unauthenticated and Pi sends no signature, so the
 * request body is entirely attacker-controlled: the only trustworthy input is
 * what Pi itself says when we ask. The webhook used to fall back to
 * `status || 'completed'` from the body whenever the lookup returned nothing —
 * which is any network blip, or an unset PI_API_KEY — so an anonymous POST of
 * {payment_id, status:'completed'} could mark a payment paid.
 *
 * Returns 'completed' | 'cancelled' | null (nothing conclusive — leave the row
 * alone), or throws nothing. A null piPayment means "could not verify".
 */
function resolveWebhookStatus(piPayment) {
  if (!piPayment) return null;
  const st = piPayment.status || {};
  if (st.developer_completed) return 'completed';
  if (st.cancelled || st.user_cancelled) return 'cancelled';
  return null;
}

// ─── Owner identity ────────────────────────────────────────────────
// Several places grant the admin role by matching a username, so the owner's
// name is effectively a credential and no other account may hold it. These are
// the two real uids the owner logs in with (see routes/auth.js self-heal).
const OWNER_UIDS = ['pi_cherry19899', 'pi_a2b617f7-f510-4502-a046-805facedcc29'];
const OWNER_USERNAME = 'cherry19899';

/** True when this uid is entitled to the owner's username. */
function isOwnerUid(uid) {
  // Strings only: String({toString:() => 'pi_cherry19899'}) and
  // String(['pi_cherry19899']) both stringify to the owner's uid, so coercing
  // would let a JSON body claim ownership through a route that passes one on.
  if (typeof uid !== 'string') return false;
  return OWNER_UIDS.includes(uid.toLowerCase());
}

/**
 * True when this path param can name a row in a SERIAL-id table
 * (jobs, escrows, applications, reviews, notifications, saved_searches…).
 *
 * Thirty-one routes guarded these with `isNaN(parseInt(req.params.id))`, and
 * `parseInt('5abc')` is 5 — so '5abc' passed the guard, went into
 * `WHERE id = $1` as the original string, and Postgres answered 22P02, which
 * the caller saw as a 500. `'99999999999'` got past it the same way and earned
 * 22003. Digits only, and inside int4, so neither reaches the database.
 */
function isIdParam(v) {
  if (typeof v !== 'string' || !/^\d{1,10}$/.test(v)) return false;
  const n = Number(v);
  return n > 0 && n <= 2147483647;
}

/** Longest URL a portfolio link or work-item image may be. */
const MAX_URL_LEN = 500;

/**
 * Normalizes a user-supplied link, or refuses it.
 *
 * Portfolio links are typed by one user and rendered as a clickable href to
 * every other user, so only http(s) may be stored: `javascript:alert(...)`
 * saved as a website would execute in the *viewer's* session when they tap it,
 * and `data:text/html,...` is the same hole with a different scheme. An
 * allowlist is the only filter that holds — blocklists lose to
 * `javascript://%0aalert(1)` and friends.
 *
 * Returns '' for a legitimately empty value (clearing the field), the
 * normalized URL when it is safe, or null when it must be rejected.
 */
function safeHttpUrl(u) {
  let s = String(u ?? '').trim();
  if (!s) return '';
  // "example.com" is what people actually type. Give it a scheme before
  // judging it — but only when it really looks like a hostname, or a stray "0"
  // would be stored as the perfectly valid-looking https://0. Anything that
  // already carries a scheme is judged exactly as written.
  if (!s.includes(':') && /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}([/?#]|$)/i.test(s)) s = 'https://' + s;
  if (s.length > MAX_URL_LEN) return null;
  return /^https?:\/\/[^\s/?#]+[^\s]*$/i.test(s) ? s : null;
}

// ─── Ratings ───────────────────────────────────────────────────────
const normalizeId = (id) => (id || '').toString().toLowerCase().replace(/^pi_/, '');

/**
 * The job a rating request refers to: a positive integer, or null when the
 * request names no job at all. Returns NaN when a value is present but is not
 * a job id, so the caller can answer 400 itself.
 *
 * The routes used to test `isNaN(parseInt(job_id))`, and parseInt('5abc') is 5
 * — so '5abc' passed validation and went straight into `WHERE id = $1`, where
 * Postgres refused the cast and the caller got a 500 instead of a 400.
 */
function parseJobId(v) {
  // 0 included: jobs.id is a SERIAL so there is no job 0, and the app's own
  // callers send `job_id: e.job_id || 0` when an escrow carries no job. That
  // used to reach `if (job_id)` and read as "no job named", and it still must.
  if (v === undefined || v === null || v === '' || v === 0 || v === '0') return null;
  // jobs.id is a SERIAL, so anything past int4 is not a job that can exist and
  // handing it to Postgres earns "value out of range for type integer" — a 500
  // where this function can say 400.
  const MAX = 2147483647;
  const ok = (n) => (Number.isInteger(n) && n > 0 && n <= MAX ? n : NaN);
  if (typeof v === 'number') return ok(v);
  if (typeof v !== 'string') return NaN;
  // Digits only, deliberately: Number() also reads '0x10' as 16 and '1e5' as
  // 100000, which would quietly look up a job the caller never named.
  const s = v.trim();
  return /^\d+$/.test(s) ? ok(Number(s)) : NaN;
}

/**
 * Who, if anyone, this caller may rate for this job.
 *
 * `job` is the row the requested job_id matched, or null when it matched
 * nothing — and nothing must be a refusal, not a pass. POST /api/ratings and
 * POST /api/reviews used to wrap this entire check in `if (jobCheck.rows.length)`,
 * so a job_id naming a job that does not exist skipped every check and fell
 * through to the INSERT. Any logged-in account could rate any user — once per
 * invented job_id, and there are unlimited invented job_ids because the
 * duplicate guard keys on job_id — and the handler then overwrote the victim's
 * public users.rating with the new average. One curl loop took a freelancer to
 * 1.0 stars, and rating is what decides who gets hired here.
 *
 * The target is returned as the *job row* spells it, not as the request body
 * spells it: ids are compared case- and prefix-insensitively, so accepting the
 * body's spelling would let 'PI_Bob' and 'pi_bob' accumulate separate ratings
 * and separate duplicate guards for one person.
 */
function ratingTarget(job, viewerId, requestedTarget) {
  if (!job) return { code: 404, error: 'Job not found' };
  const viewer = normalizeId(viewerId);
  const poster = normalizeId(job.posted_by);
  const hired = normalizeId(job.hired_freelancer_id);
  if (viewer !== poster && viewer !== hired) {
    return { code: 403, error: 'You were not a participant in this job' };
  }
  if (job.status !== 'completed') {
    return { code: 400, error: 'Job must be completed before rating' };
  }
  const other = viewer === poster ? job.hired_freelancer_id : job.posted_by;
  if (!other || normalizeId(requestedTarget) !== normalizeId(other)) {
    return { code: 403, error: 'You can only rate the other participant of this job' };
  }
  return { targetId: other };
}

module.exports = {
  piApiRequest,
  piApprovePayment,
  piCompletePayment,
  resolveWebhookStatus,
  ratingTarget,
  parseJobId,
  isIdParam,
  normalizeId,
  safeHttpUrl,
  MAX_URL_LEN,
  isOwnerUid,
  OWNER_USERNAME,
  piGetPayment,
  notify,
  audit,
  serverError,
  last500,
  PI_API_KEY,
  PI_API_BASE,
  SANDBOX_MODE,
  getPlatformFee,
  getDeveloperFee,
  invalidatePlatformFeeCache,
  getConnectsEconomy,
  getSupportUrl,
  invalidateSupportUrlCache,
  invalidateConnectsEconomyCache,
  applyCostFor,
  FEE_MIN,
  FEE_MAX,
  DEV_FEE_MIN,
  DEV_FEE_MAX,
  resolveUserIdFromBody,
  resolveConnects,
  CONNECT_PACKAGES,
};

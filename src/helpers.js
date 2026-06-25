/**
 * src/helpers.js — Shared helper functions used across route modules.
 */
const fetch = require('node-fetch');
const { query, getPool } = require('./db');

const PI_API_KEY = process.env.PI_API_KEY || '';
const PI_API_BASE = process.env.SANDBOX_MODE
  ? 'https://api.testnet.minepi.com'
  : 'https://api.minepi.com';

// ─── Platform fee ──────────────────────────────────────────────
// Hard limits — no matter what's in the DB or env, fee is capped at 10%.
const FEE_MIN = 0;
const FEE_MAX = 0.1;
const FEE_DEFAULT_PCT = parseFloat(process.env.PLATFORM_FEE_PERCENT || '2');
const FEE_DEFAULT = Math.min(Math.max(FEE_DEFAULT_PCT / 100, FEE_MIN), FEE_MAX);

let _feeCache = null;        // { value: number, expiresAt: number }
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

function invalidatePlatformFeeCache() {
  _feeCache = null;
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
async function notify(userId, type, title, body, jobId, roomId) {
  try {
    await query(
      `INSERT INTO notifications (user_id, type, title, body, job_id, room_id, is_read, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,false,NOW())`,
      [userId, type, title, body || null, jobId || null, roomId || null]
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
function serverError(err, res) {
  console.error('[Error]', err);
  return res.status(500).json({ error: 'Internal server error' });
}

module.exports = {
  piApiRequest,
  piApprovePayment,
  piCompletePayment,
  piGetPayment,
  notify,
  audit,
  serverError,
  PI_API_KEY,
  PI_API_BASE,
  getPlatformFee,
  invalidatePlatformFeeCache,
  FEE_MAX,
};

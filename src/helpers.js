/**
 * src/helpers.js — Shared helper functions used across route modules.
 */
const fetch = require('node-fetch');
const { query, getPool } = require('./db');

const PI_API_KEY = process.env.PI_API_KEY || '';
const PI_API_BASE = 'https://api.minepi.com';

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

// ─── Platform & Developer Fee ──────────────────────────────────────────────
const FEE_MIN = 0; const FEE_MAX = 0.1;
const FEE_DEFAULT_PCT = parseFloat(process.env.PLATFORM_FEE_PERCENT || '2');
const FEE_DEFAULT = Math.min(Math.max(FEE_DEFAULT_PCT / 100, FEE_MIN), FEE_MAX);
const DEV_FEE_MIN = 0; const DEV_FEE_MAX = 0.2;
const DEV_FEE_DEFAULT_PCT = parseFloat(process.env.DEVELOPER_FEE_PERCENT || '0');
const DEV_FEE_DEFAULT = Math.min(Math.max(DEV_FEE_DEFAULT_PCT / 100, DEV_FEE_MIN), DEV_FEE_MAX);
let _feeCache = null; let _devFeeCache = null;
const FEE_CACHE_TTL = 60000;

async function getPlatformFee() {
  if (_feeCache && Date.now() - _feeCache.time < FEE_CACHE_TTL) return _feeCache.value;
  try {
    const r = await query("SELECT value FROM platform_settings WHERE key = 'platform_fee_percent' LIMIT 1");
    const pct = r.rows.length ? parseFloat(r.rows[0].value) : FEE_DEFAULT_PCT;
    _feeCache = { value: Math.min(Math.max(pct / 100, FEE_MIN), FEE_MAX), time: Date.now() };
  } catch { _feeCache = { value: FEE_DEFAULT, time: Date.now() }; }
  return _feeCache.value;
}

async function getDeveloperFee() {
  if (_devFeeCache && Date.now() - _devFeeCache.time < FEE_CACHE_TTL) return _devFeeCache.value;
  try {
    const r = await query("SELECT value FROM platform_settings WHERE key = 'developer_fee_percent' LIMIT 1");
    const pct = r.rows.length ? parseFloat(r.rows[0].value) : DEV_FEE_DEFAULT_PCT;
    _devFeeCache = { value: Math.min(Math.max(pct / 100, DEV_FEE_MIN), DEV_FEE_MAX), time: Date.now() };
  } catch { _devFeeCache = { value: DEV_FEE_DEFAULT, time: Date.now() }; }
  return _devFeeCache.value;
}

function invalidatePlatformFeeCache() { _feeCache = null; _devFeeCache = null; }

module.exports = {
  piApiRequest,
  piApprovePayment,
  piCompletePayment,
  piGetPayment,
  notify,
  audit,
  serverError,
  PI_API_KEY,
  getPlatformFee,
  getDeveloperFee,
  invalidatePlatformFeeCache,
  FEE_MAX,
  DEV_FEE_MAX,
};

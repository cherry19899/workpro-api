/**
 * src/helpers.js — Shared helper functions used across route modules.
 */
const fetch = require('node-fetch');
const { query, getPool } = require('./db');

const PI_API_KEY = process.env.PI_API_KEY || '';
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
function serverError(err, res) {
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

module.exports = {
  piApiRequest,
  piApprovePayment,
  piCompletePayment,
  piGetPayment,
  notify,
  audit,
  serverError,
  last500,
  PI_API_KEY,
  PI_API_BASE,
  getPlatformFee,
  getDeveloperFee,
  invalidatePlatformFeeCache,
  FEE_MIN,
  FEE_MAX,
  DEV_FEE_MIN,
  DEV_FEE_MAX,
  resolveUserIdFromBody,
  resolveConnects,
  CONNECT_PACKAGES,
};

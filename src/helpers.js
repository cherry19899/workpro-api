/**
 * src/helpers.js — Shared helper functions used across route modules.
 */
const fetch = require('node-fetch');
const { query, getPool } = require('./db');

const PI_API_KEY = process.env.PI_API_KEY || '';
const PI_API_BASE = 'https://api.minepi.com';

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
      if (!res.ok) throw new Error(data.error_message || `Pi API error: ${res.status}`);
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
};

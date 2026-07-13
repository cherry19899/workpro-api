// App-to-User (A2U) payments via the official pi-backend SDK.
// Sends Pi from the app's wallet to a user. Requires:
//   PI_WALLET_PRIVATE_SEED   — app wallet private seed (starts with "S")
//   SANDBOX_PI_API_KEY       — testnet API key (for sandbox/5-wallet requirement phase)
//     OR PI_API_KEY          — mainnet API key (for production after wallet approved)
// If only PI_API_KEY is set (no SANDBOX_PI_API_KEY), uses mainnet mode.
// If SANDBOX_PI_API_KEY is set, uses it — Pi Platform routes to testnet automatically.
const logger = require('./logger');

let _pi = null;
let _lastApiKey = null;
let _last = { ok: null, stage: null, error: null, at: null };
function a2uStatus() { return _last; }

function getApiKey() {
  return process.env.SANDBOX_PI_API_KEY || process.env.PI_API_KEY;
}

function a2uEnabled() {
  return !!(getApiKey() && process.env.PI_WALLET_PRIVATE_SEED);
}

function getClient() {
  if (!a2uEnabled()) return null;
  const apiKey = getApiKey();
  if (!_pi || _lastApiKey !== apiKey) {
    const PiNetwork = require('pi-backend').default || require('pi-backend');
    _pi = new PiNetwork(apiKey, process.env.PI_WALLET_PRIVATE_SEED);
    _lastApiKey = apiKey;
  }
  return _pi;
}

// Full 3-step A2U flow: createPayment → submitPayment → completePayment.
// Returns { paymentId, txid } on success, throws on failure.
async function sendA2U(uid, amount, memo, metadata = {}) {
  let stage = 'init';
  try {
    const pi = getClient();
    if (!pi) throw new Error('A2U not configured (PI_WALLET_PRIVATE_SEED missing)');
    const amt = Number(parseFloat(amount).toFixed(7));
    if (!(amt > 0)) throw new Error('A2U amount must be > 0');
    // DB stores user ids as "pi_<uid>", Pi Platform API expects bare uid.
    const piUid = String(uid).replace(/^pi_/, '');
    stage = 'createPayment';
    const paymentId = await pi.createPayment({ amount: amt, memo, metadata, uid: piUid });
    logger.info(`[a2u] created payment ${paymentId} → ${uid} (${amt}π)`);
    stage = 'submitPayment';
    const txid = await pi.submitPayment(paymentId);
    logger.info(`[a2u] submitted ${paymentId} txid=${txid}`);
    stage = 'completePayment';
    await pi.completePayment(paymentId, txid);
    logger.info(`[a2u] completed ${paymentId}`);
    _last = { ok: true, stage: 'completed', error: null, at: new Date().toISOString() };
    return { paymentId, txid };
  } catch (e) {
    const msg = (e && (e.response?.data ? JSON.stringify(e.response.data) : e.message)) || String(e);
    _last = { ok: false, stage, error: String(msg).slice(0, 500), at: new Date().toISOString() };
    logger.warn(`[a2u] failed at ${stage}: ${msg}`);
    throw e;
  }
}

module.exports = { a2uEnabled, sendA2U, a2uStatus };

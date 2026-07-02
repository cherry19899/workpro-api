// App-to-User (A2U) payments via the official pi-backend SDK.
// Sends REAL Pi from the app's wallet to a user. Requires two env vars:
//   PI_API_KEY               — the app's Pi Platform API key (already used elsewhere)
//   PI_WALLET_PRIVATE_SEED   — the app wallet private seed (starts with "S")
// If the seed is not configured, a2uEnabled() is false and callers fall back to
// crediting the internal balance_pi ledger instead.
const logger = require('./logger');

let _pi = null;

function a2uEnabled() {
  return !!(process.env.PI_API_KEY && process.env.PI_WALLET_PRIVATE_SEED);
}

function getClient() {
  if (!a2uEnabled()) return null;
  if (!_pi) {
    const PiNetwork = require('pi-backend').default || require('pi-backend');
    _pi = new PiNetwork(process.env.PI_API_KEY, process.env.PI_WALLET_PRIVATE_SEED);
  }
  return _pi;
}

// Full 3-step A2U flow: createPayment → submitPayment → completePayment.
// Returns { paymentId, txid } on success, throws on failure.
async function sendA2U(uid, amount, memo, metadata = {}) {
  const pi = getClient();
  if (!pi) throw new Error('A2U not configured (PI_WALLET_PRIVATE_SEED missing)');
  const amt = Number(parseFloat(amount).toFixed(7));
  if (!(amt > 0)) throw new Error('A2U amount must be > 0');
  const paymentId = await pi.createPayment({ amount: amt, memo, metadata, uid });
  logger.info(`[a2u] created payment ${paymentId} → ${uid} (${amt}π)`);
  const txid = await pi.submitPayment(paymentId);
  logger.info(`[a2u] submitted ${paymentId} txid=${txid}`);
  await pi.completePayment(paymentId, txid);
  logger.info(`[a2u] completed ${paymentId}`);
  return { paymentId, txid };
}

module.exports = { a2uEnabled, sendA2U };

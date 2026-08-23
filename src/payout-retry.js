/**
 * src/payout-retry.js — background retry for payouts that failed to send.
 *
 * Releases, milestone approvals and dispute resolutions all fire sendA2U
 * automatically, and all of them deliberately swallow a failure: the amount
 * stays on the freelancer's `balance_pi` so the money is never lost. What was
 * missing is the other half — nothing ever tried again. A failed payout became
 * a debt that sat there until an admin manually pressed payout for that one
 * user, which is how production reached 20 released escrows with a single
 * recorded payout and nobody noticing.
 *
 * This sweep is that missing half. When A2U starts working (a wallet Pi has
 * confirmed, and funded), the whole backlog drains on its own.
 */

const { notify, audit } = require('./helpers');
const { query } = require('./db');
const { a2uEnabled, sendA2U } = require('./pi-a2u');

// Most owed first: if the wallet only partly covers the backlog, the largest
// debts — the ones a person is most likely to be chasing — clear first.
const BATCH = parseInt(process.env.PAYOUT_RETRY_BATCH || '25', 10);
// Below this a transfer costs more in fees and noise than it settles.
const MIN_PI = parseFloat(process.env.PAYOUT_RETRY_MIN_PI || '0.01');
// A2U being down looks identical for every user, so once a few in a row fail
// there is nothing to learn from trying the rest this hour.
const GIVE_UP_AFTER = parseInt(process.env.PAYOUT_RETRY_GIVE_UP || '3', 10);

async function retryOwedPayouts(logger = console) {
  if (!a2uEnabled()) return { skipped: 'a2u not configured' };

  const owed = await query(
    `SELECT id, COALESCE(balance_pi, 0) AS owed FROM users
      WHERE COALESCE(balance_pi, 0) >= $1 AND COALESCE(status, '') <> 'deleted'
      ORDER BY balance_pi DESC LIMIT $2`,
    [MIN_PI, BATCH]
  ).catch(() => ({ rows: [] }));

  if (!owed.rows.length) return { owed: 0 };

  const stats = { owed: owed.rows.length, paid: 0, failed: 0, pi_sent: 0 };
  let consecutiveFailures = 0;

  for (const row of owed.rows) {
    if (consecutiveFailures >= GIVE_UP_AFTER) {
      stats.gave_up = true;
      logger.error(`[payout-retry] ${consecutiveFailures} failures in a row — A2U looks down, stopping this run`);
      break;
    }

    const amount = parseFloat(row.owed);
    if (!(amount >= MIN_PI)) continue;

    // Reserve before sending, exactly as POST /api/admin/users/:id/payout-owed
    // does: deduct first, guarded by the balance still being at least this
    // much. Without it this sweep and a concurrent manual payout would both
    // read the same balance and both send — and an A2U transfer cannot be
    // taken back.
    const reserved = await query(
      `UPDATE users SET balance_pi = GREATEST(COALESCE(balance_pi, 0) - $1, 0), updated_at = NOW()
        WHERE id = $2 AND COALESCE(balance_pi, 0) >= $1 RETURNING id`,
      [amount, row.id]
    ).catch(() => ({ rows: [] }));
    if (!reserved.rows.length) continue; // someone else got there first

    let txid = null;
    try {
      ({ txid } = await sendA2U(row.id, amount, 'WorkPro payout', { type: 'owed_payout_retry' }));
      consecutiveFailures = 0;
      stats.paid++;
      stats.pi_sent = +(stats.pi_sent + amount).toFixed(7);
      await audit('payout_retry_sent', { user_id: row.id, amount, txid });
      await notify(row.id, 'payment', 'Выплата получена',
        `${amount}π отправлено на ваш Pi-кошелёк.`, null, null,
        { key: 'nPayoutSent', params: { amount } }).catch(() => {});
      logger.error(`[payout-retry] OK ${row.id} ${amount}π txid=${txid}`);
    } catch (e) {
      // Nothing was sent — hand the debt back so it is retried next hour.
      consecutiveFailures++;
      stats.failed++;
      stats.last_error = String(e && e.message || e).slice(0, 200);
      await query(
        'UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, updated_at = NOW() WHERE id = $2',
        [amount, row.id]
      ).catch((re) => logger.error(
        `[payout-retry] RESERVED BUT NOT REFUNDED — user ${row.id}, ${amount}π: ${re.message}`
      ));
      // logger.error, not .info: info is a no-op in production on Render, which
      // is precisely why every one of these failures was invisible for a month.
      logger.error(`[payout-retry] FAIL ${row.id} ${amount}π: ${stats.last_error}`);
    }
  }

  return stats;
}

module.exports = { retryOwedPayouts };

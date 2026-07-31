/**
 * src/stuck-payments.js — background reconciliation for payments left in 'pending'.
 *
 * The Pi SDK only surfaces an incomplete payment when the user next opens the App
 * (onIncompletePaymentFound). A user who never returns leaves the payment stranded:
 * connects stay uncredited and escrows stay unfunded even though the Pi may already
 * have moved on-chain. This sweep asks the Pi Platform API what actually happened to
 * each stale pending payment and settles it either way.
 */

const {
  piGetPayment, piApprovePayment, piCompletePayment,
  PI_API_KEY, notify, audit, resolveConnects,
} = require('./helpers');
const { query, getPool } = require('./db');

// Only touch payments old enough that the user's own flow has certainly finished.
const STALE_AFTER = process.env.STUCK_PAYMENT_STALE_MINUTES || '15';
// Past this age a payment Pi still reports as unpaid is abandoned, not in-flight.
const ABANDON_AFTER_HOURS = parseInt(process.env.STUCK_PAYMENT_ABANDON_HOURS || '48', 10);
const BATCH_LIMIT = parseInt(process.env.STUCK_PAYMENT_BATCH || '50', 10);

function isConnects(pay) {
  const meta = pay.metadata || {};
  return meta.type === 'connects' || pay.type === 'connects';
}

// Credit connects and mark the payment completed in one transaction, so a crash
// between the two can never double-credit or silently drop the purchase.
async function creditConnects(pay, txid, amount) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const claimed = await client.query(
      `UPDATE payments SET status='completed', txid=$1,
              metadata = COALESCE(metadata,'{}'::jsonb) || '{"connects_credited":true}'::jsonb,
              updated_at=NOW()
       WHERE id=$2 AND status <> 'completed'
         AND COALESCE((metadata->>'connects_credited')::boolean, false) = false
       RETURNING id`,
      [txid, pay.id]
    );
    if (!claimed.rows.length) { await client.query('ROLLBACK'); return false; }
    await client.query(
      'UPDATE users SET balance_connects = balance_connects + $1, updated_at=NOW() WHERE id=$2',
      [amount, pay.user_id]
    );
    await client.query('COMMIT');
    return true;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

async function sweepStuckPayments(logger = console) {
  if (!PI_API_KEY) return { skipped: 'no PI_API_KEY' };

  const stale = await query(
    `SELECT id, user_id, type, amount, status, metadata, created_at
       FROM payments
      WHERE status = 'pending'
        AND created_at < NOW() - ($1 || ' minutes')::interval
      ORDER BY created_at ASC
      LIMIT $2`,
    [STALE_AFTER, BATCH_LIMIT]
  ).catch(() => ({ rows: [] }));

  if (!stale.rows.length) return { checked: 0 };

  const stats = { checked: stale.rows.length, completed: 0, approved: 0, cancelled: 0, credited: 0, failed: 0 };

  for (const pay of stale.rows) {
    try {
      let piPayment = null;
      try {
        piPayment = await piGetPayment(pay.id);
      } catch (e) {
        // 404 means Pi never knew about it (user closed the dialog before submitting).
        if (String(e.message).includes('404') || /not found/i.test(e.message)) {
          const ageH = (Date.now() - new Date(pay.created_at)) / 3600000;
          if (ageH > ABANDON_AFTER_HOURS) {
            await query("UPDATE payments SET status='cancelled', updated_at=NOW() WHERE id=$1 AND status='pending'", [pay.id]);
            stats.cancelled++;
          }
          continue;
        }
        stats.failed++;
        continue;
      }
      if (!piPayment) { stats.failed++; continue; }

      const st = piPayment.status || {};
      const txid = piPayment.transaction?.txid || null;

      if (st.cancelled || st.user_cancelled) {
        await query("UPDATE payments SET status='cancelled', updated_at=NOW() WHERE id=$1 AND status='pending'", [pay.id]);
        stats.cancelled++;
        continue;
      }

      // The user paid but our server never got the callback — finish it for them.
      if (st.transaction_verified && txid) {
        if (!st.developer_approved) {
          await piApprovePayment(pay.id).catch(() => {});
        }
        if (!st.developer_completed) {
          await piCompletePayment(pay.id, txid).catch(() => {});
        }

        if (isConnects(pay) && pay.user_id && !(pay.metadata || {}).connects_credited) {
          const amount = resolveConnects(parseFloat(piPayment.amount || pay.amount || 0));
          if (amount > 0 && await creditConnects(pay, txid, amount)) {
            stats.credited++;
            stats.completed++;
            await notify(pay.user_id, 'payment', 'Коннекты зачислены',
              `${amount} коннектов зачислено — платёж завершён автоматически.`, null, null,
              { key: 'nConnectsCredited', params: { amount } });
            await audit('stuck_payment_recovered', { payment_id: pay.id, user_id: pay.user_id, connects: amount, txid });
            logger.info(`[stuck-payments] recovered ${pay.id} → +${amount} connects for ${pay.user_id}`);
            continue;
          }
        }

        await query("UPDATE payments SET status='completed', txid=$1, updated_at=NOW() WHERE id=$2 AND status='pending'", [txid, pay.id]);
        stats.completed++;
        await audit('stuck_payment_recovered', { payment_id: pay.id, user_id: pay.user_id, type: pay.type, txid });
        logger.info(`[stuck-payments] completed ${pay.id} (${pay.type || 'unknown'})`);
        continue;
      }

      // Approved on our side but the user never signed — nudge approval, then let it age out.
      if (!st.developer_approved) {
        await piApprovePayment(pay.id).catch(() => {});
        stats.approved++;
      }
      const ageH = (Date.now() - new Date(pay.created_at)) / 3600000;
      if (ageH > ABANDON_AFTER_HOURS) {
        await query("UPDATE payments SET status='cancelled', updated_at=NOW() WHERE id=$1 AND status='pending'", [pay.id]);
        stats.cancelled++;
        await audit('stuck_payment_abandoned', { payment_id: pay.id, user_id: pay.user_id, age_hours: Math.round(ageH) });
      }
    } catch (e) {
      stats.failed++;
      logger.warn(`[stuck-payments] ${pay.id} failed: ${e.message}`);
    }
  }

  return stats;
}

module.exports = { sweepStuckPayments };

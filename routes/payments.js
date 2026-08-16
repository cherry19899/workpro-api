const logger = require('../src/logger');
/**
 * routes/payments.js — /api/payments/*, /api/connects/*, /api/escrows/*, /api/escrow/*, /api/offers/*
 */
const router = require('express').Router();
const crypto = require('crypto');
const fetch = require('node-fetch');
const { query, getPool } = require('../src/db');
const { isIdParam, piApprovePayment, piCompletePayment, piGetPayment, notify, audit, serverError, resolveWebhookStatus, PI_API_KEY, PI_API_BASE, getPlatformFee } = require('../src/helpers');
const { auth, softAuth, checkBlocked } = require('../src/middleware');
const { a2uEnabled, sendA2U } = require('../src/pi-a2u');

const normalizeId = (id) => (id || '').toString().toLowerCase().replace(/^pi_/, '');

const { resolveConnects, CONNECT_PACKAGES } = require('../src/helpers');

// ─── Shared Pi payment handlers ────────────────────────────────────────────
// handlePaymentApprove and handlePaymentComplete: shared by RESTful /:id/approve|complete
// and legacy flat /approve|complete routes.

async function handlePaymentApprove(paymentId, metadata, userId, res, paymentsEnabled) {
  // payments_enabled is set by the Pi SDK on the frontend and passed through metadata.
  // In sandbox/testnet it may be absent — block only on mainnet (when PI_API_KEY is production).
  if (PI_API_KEY && paymentsEnabled === false && !process.env.SANDBOX_MODE) {
    return res.status(403).json({ error: 'Pi payments not enabled for this account. Complete KYC on Pi App first.' });
  }
  try {
    // Fast ownership check — only DB, no Pi API call yet.
    const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
    if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'Payment does not belong to you' });
    }

    // Pre-insert a pending row so /complete can find it even if async block below hasn't finished.
    await query(
      `INSERT INTO payments (id, user_id, type, amount, metadata, status, payment_id)
       VALUES ($1,$2,$3,0,$4,'pending',$1)
       ON CONFLICT (id) DO NOTHING`,
      [paymentId, userId, metadata?.type || 'payment', JSON.stringify(metadata || {})]
    ).catch(() => {});

    // Respond immediately — Pi wallet stays locked until Pi API receives /approve,
    // NOT until our server responds to the frontend. So respond fast then call Pi API async.
    res.json({ success: true });

    // Async: call Pi API /approve (unlocks the Pi wallet), then persist approved state.
    (PI_API_KEY
      ? piApprovePayment(paymentId)
          .then(p => { logger.info('[Payment] Pi /approve OK | paymentId:', paymentId); return p; })
          .catch(err => { logger.error('[Payment] Pi /approve FAILED:', err.message, '| paymentId:', paymentId); return { amount: 0 }; })
      : Promise.resolve({ amount: 0 })
    ).then(piPayment => query(
      `INSERT INTO payments (id, user_id, type, amount, metadata, status, payment_id)
       VALUES ($1,$2,$3,$4,$5,'approved',$1)
       ON CONFLICT (id) DO UPDATE SET status='approved', amount=EXCLUDED.amount, updated_at=NOW()`,
      [paymentId, userId, metadata?.type || 'payment', piPayment.amount || 0, JSON.stringify(metadata || {})]
    ).then(() => audit('payment_approved', { payment_id: paymentId, user_id: userId, amount: piPayment.amount }).catch(() => {}))
    ).catch(err => logger.error('[Payment] async approve post-processing failed:', err.message));
  } catch (err) {
    logger.error('[Payment] Approve error:', err.message);
    if (!res.headersSent) serverError(err, res);
  }
}

async function handlePaymentComplete(paymentId, txid, metadata, userId, res) {
  if (!txid && !process.env.SANDBOX_MODE) return res.status(400).json({ error: 'txid required' });
  if (!txid) txid = 'sandbox_' + paymentId;
  try {
    const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
    if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'Payment does not belong to you' });
    }
    let piPayment = { amount: 0 };
    if (PI_API_KEY) {
      try {
        piPayment = await piCompletePayment(paymentId, txid);
      } catch (piErr) {
        // Pi API failure means we have no confirmation the transaction is
        // real — txid is client-supplied and easily fabricated, so "the
        // client received a txid" is not proof funds moved. Do not mark the
        // payment completed or credit anything; let the client retry, or the
        // stuck-payments sweep / resolve-incomplete pick it up later.
        logger.error('[Payment] Pi complete failed:', piErr.message, '| paymentId:', paymentId);
        return res.status(502).json({ error: 'Could not verify payment with Pi — please retry' });
      }
    }
    const pgPmtC = await getPool().connect();
    try {
      await pgPmtC.query('BEGIN');
      // Lock payment row first to prevent concurrent complete calls double-crediting connects
      await pgPmtC.query('SELECT id FROM payments WHERE id = $1 FOR UPDATE', [paymentId]).catch(() => {});
      let markRes = await pgPmtC.query(
        "UPDATE payments SET status='completed', txid=$1, updated_at=NOW() WHERE id=$2 AND status='approved' RETURNING *",
        [txid, paymentId]
      );
      if (!markRes.rows.length) {
        // No approved row — check if already completed (idempotent) or never approved (approve step failed).
        const existingRow = await pgPmtC.query('SELECT * FROM payments WHERE id = $1 FOR UPDATE', [paymentId]);
        if (existingRow.rows.length && existingRow.rows[0].status === 'completed') {
          // Status is already 'completed' — but that alone isn't proof
          // crediting ran (e.g. the webhook flips status to 'completed'
          // without ever crediting connects or creating an escrow). Fall
          // through into the shared crediting logic below using this row;
          // its own connects_credited / existing-escrow checks keep it
          // idempotent even if crediting genuinely already happened.
          markRes = existingRow;
        } else if (!existingRow.rows.length) {
          // No row at all yet — approve step never even persisted (e.g. cold-start 502). Upsert as completed so connects can be credited.
          await pgPmtC.query(
            `INSERT INTO payments (id, user_id, type, amount, status, txid, metadata)
             VALUES ($1,$2,'connects',$3,'completed',$4,$5)
             ON CONFLICT (id) DO UPDATE SET status='completed', txid=EXCLUDED.txid, updated_at=NOW()`,
            [paymentId, userId, parseFloat(piPayment.amount || 0), txid, JSON.stringify({ type: 'connects' })]
          );
          markRes = await pgPmtC.query('SELECT * FROM payments WHERE id = $1', [paymentId]);
          if (!markRes.rows.length) { await pgPmtC.query('ROLLBACK'); return res.json({ success: true, payment: piPayment }); }
        } else {
          // Row exists but is stuck in some other terminal, non-completable
          // status (e.g. 'cancelled' via /api/payments/:id/cancelled) — do
          // not resurrect it into 'completed'.
          await pgPmtC.query('ROLLBACK');
          return res.status(400).json({ error: `Payment cannot be completed from status '${existingRow.rows[0].status}'` });
        }
      }
      const markDone = markRes.rows[0];
      const meta = markDone.metadata || {};
      const paymentOwner = markDone.user_id || userId;
      // meta.type may be missing when frontend didn't pass metadata on approve — treat unknown as connects
      const payType = meta.type || (meta.job_id ? 'escrow' : 'connects');
      if (payType === 'connects' && !meta.connects_credited) {
        const piAmountPaid = parseFloat(piPayment.amount || markDone.amount || 0);
        // Sanity check: Pi-confirmed amount must not be less than what was stored at approve time.
        // Prevents a tampered approve step from overstating the amount.
        const storedAmount = parseFloat(markDone.amount || 0);
        if (PI_API_KEY && piPayment.amount && storedAmount > 0 && piAmountPaid < storedAmount - 0.001) {
          await pgPmtC.query('ROLLBACK');
          logger.error(`[Payment] Amount mismatch: Pi returned ${piAmountPaid}, DB stored ${storedAmount}`);
          return res.status(400).json({ error: 'Payment amount mismatch — contact support' });
        }
        const amount = resolveConnects(piAmountPaid);
        if (amount <= 0) { await pgPmtC.query('ROLLBACK'); return res.status(400).json({ error: 'Payment amount too small to credit connects' }); }
        await pgPmtC.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, paymentOwner]);
        await pgPmtC.query("UPDATE payments SET metadata = jsonb_set(COALESCE(metadata,'{}'::jsonb), '{connects_credited}', 'true') WHERE id = $1", [paymentId]);
        const newBal = await pgPmtC.query('SELECT balance_connects FROM users WHERE id = $1', [paymentOwner]);
        logger.info(`[Payment] COMMIT connects +${amount} → user ${paymentOwner} new balance=${newBal.rows[0]?.balance_connects}`);
      } else if (meta.type === 'escrow' && meta.job_id && meta.freelancer_id) {
        const existingEscrow = await pgPmtC.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [paymentId]);
        if (!existingEscrow.rows.length) {
          const [jobCheck, freelancerCheck] = await Promise.all([
            pgPmtC.query('SELECT id, budget FROM jobs WHERE id = $1 LIMIT 1', [meta.job_id]),
            pgPmtC.query('SELECT id FROM users WHERE id = $1 LIMIT 1', [meta.freelancer_id]),
          ]);
          if (jobCheck.rows.length && freelancerCheck.rows.length) {
            const escrowAmount = parseFloat(piPayment.amount || markDone.amount || 0);
            const jobBudget = parseFloat(jobCheck.rows[0].budget || 0);
            if (jobBudget > 0 && escrowAmount > jobBudget * 1.01) {
              await pgPmtC.query('ROLLBACK');
              logger.error(`[Payment] Escrow amount ${escrowAmount} exceeds job budget ${jobBudget}`);
              return res.status(400).json({ error: 'Payment amount exceeds job budget' });
            }
            await pgPmtC.query(
              'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (payment_id) DO NOTHING',
              [meta.job_id, paymentOwner, meta.freelancer_id, escrowAmount, paymentId, 'funded']
            );
          }
        }
      }
      await pgPmtC.query('COMMIT');
    } catch (txErr) { await pgPmtC.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgPmtC.release(); }
    await audit('payment_completed', { payment_id: paymentId, txid, user_id: userId });
    res.json({ success: true, payment: piPayment });
  } catch (err) {
    logger.error('[Payment] Complete error:', err.message);
    serverError(err, res);
  }
}

// ─── Escrow release (merged from singular /api/escrow/:id/release + plural /api/escrows/:id/release) ───
// The plural version (line 2059 in original) is newer — has .catch(()=>{}) on notify and returns { success: true }.
// The singular version (line 1389) returns { escrow: {..., status:'released'}, success: true }.
// Merged: returns { success: true, escrow: { ...escrow, status: 'released' } } (both response formats).
async function handleEscrowRelease(req, res) {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (normalizeId(escrow.client_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status !== 'funded') return res.status(400).json({ error: 'Escrow is not funded' });
    // An escrow with milestones stays 'funded' until every milestone is
    // approved — releasing the full amount here on top of whatever milestones
    // already paid out would double-pay the freelancer.
    if (escrow.milestone_count > 0) {
      return res.status(400).json({ error: 'This escrow uses milestones — approve them individually instead of a full release' });
    }
    const fee = await getPlatformFee();
    const net = parseFloat((escrow.amount * (1 - fee)).toFixed(8)); // platform commission
    const pgClient3 = await getPool().connect();
    try {
      await pgClient3.query('BEGIN');
      const updated = await pgClient3.query(
        "UPDATE escrows SET status='released', updated_at=NOW() WHERE id=$1 AND status='funded' RETURNING id",
        [req.params.id]
      );
      if (!updated.rows.length) { await pgClient3.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already processed' }); }
      await pgClient3.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $2', [net, escrow.freelancer_id]);
      await pgClient3.query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['completed', escrow.job_id]);
      await pgClient3.query('COMMIT');
    } catch (txErr) { await pgClient3.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient3.release(); }
    // Send REAL Pi to the freelancer's wallet via A2U (if the app wallet seed is
    // configured). On success, deduct the just-credited balance_pi so the ledger
    // reflects "paid out". On failure/not-configured, balance_pi remains as an
    // amount still owed (retryable), so the money is never lost.
    let payoutTxid = null;
    if (a2uEnabled()) {
      try {
        const { txid } = await sendA2U(escrow.freelancer_id, net, 'WorkPro payment',
          { type: 'escrow_release', escrow_id: escrow.id, job_id: escrow.job_id });
        payoutTxid = txid;
        await query('UPDATE users SET balance_pi = GREATEST(COALESCE(balance_pi,0) - $1, 0), updated_at = NOW() WHERE id = $2', [net, escrow.freelancer_id]).catch(() => {});
        await query('UPDATE escrows SET payout_txid = $1, updated_at = NOW() WHERE id = $2', [txid, escrow.id]).catch(() => {});
        await audit('escrow_payout_a2u', { escrow_id: escrow.id, freelancer_id: escrow.freelancer_id, net_paid: net, txid });
      } catch (e) {
        logger.error(`[a2u] payout failed for escrow ${escrow.id}: ${e.message} — kept as balance_pi`);
      }
    }
    await notify(escrow.freelancer_id, 'payment', 'Оплата получена',
      payoutTxid ? `${net}π отправлено на ваш Pi-кошелёк.` : `${net}π зачислено на ваш счёт после завершения задачи.`,
      escrow.job_id, null,
      { key: payoutTxid ? 'nPaidToWallet' : 'nPaidToBalance', params: { amount: net } }).catch(() => {});
    await audit('escrow_released', { escrow_id: req.params.id, freelancer_id: escrow.freelancer_id, amount: escrow.amount, net_paid: net, payout_txid: payoutTxid });
    res.json({ success: true, payout_txid: payoutTxid, escrow: { ...escrow, status: 'released' } });
  } catch (err) { serverError(err, res); }
}

// ─── Escrow GET handler (shared by /api/escrow and /api/escrows) ──────────────
async function handleGetEscrow(req, res) {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  // Match both pi_xxx and xxx forms of the userId to handle legacy records
  const uid = req.userId;
  const uidAlt = uid.startsWith('pi_') ? uid.slice(3) : 'pi_' + uid;
  try {
    const [result, totalRes] = await Promise.all([
      query(
        `SELECT e.*, j.title AS job_title,
                uc.username AS client_username, uf.username AS freelancer_username
         FROM escrows e
         LEFT JOIN jobs j ON j.id = e.job_id
         LEFT JOIN users uc ON uc.id = e.client_id
         LEFT JOIN users uf ON uf.id = e.freelancer_id
         WHERE e.client_id = ANY($1) OR e.freelancer_id = ANY($1)
         ORDER BY e.created_at DESC LIMIT $2 OFFSET $3`,
        [[uid, uidAlt], limit, offset]
      ),
      query(
        'SELECT COUNT(*) FROM escrows WHERE client_id = ANY($1) OR freelancer_id = ANY($1)',
        [[uid, uidAlt]]
      ),
    ]);
    res.json({ escrows: result.rows, total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
}

// ─── Payments ──────────────────────────────────────────────

// Resolve userId: JWT first, then pi_uid from metadata (for cases where JWT is not yet available).
// This allows the payment flow to work even if the JWT hasn't loaded yet — the Pi paymentId itself
// is unforgeable (issued by Pi per-user), so uid-from-metadata is safe as a fallback.
async function resolveUserId(req) {
  if (req.userId) return req.userId;
  // Frontend sends userId in various shapes depending on the flow
  const uid = req.body?.metadata?.uid
    || req.body?.metadata?.userId
    || req.body?.user?.id
    || req.body?.userId
    || req.body?.uid;
  if (!uid) return null;
  try {
    const row = await query('SELECT id FROM users WHERE pi_uid = $1 OR id = $1 LIMIT 1', [uid]);
    return row.rows[0]?.id || null;
  } catch (_) { return null; }
}

router.post('/api/payments/:paymentId/approve', softAuth, checkBlocked, async (req, res) => {
  const userId = await resolveUserId(req);
  await handlePaymentApprove(req.params.paymentId, req.body.metadata, userId, res, req.body.payments_enabled);
});

router.post('/api/payments/:paymentId/complete', softAuth, checkBlocked, async (req, res) => {
  const userId = await resolveUserId(req);
  await handlePaymentComplete(req.params.paymentId, req.body.txid, req.body.metadata, userId, res);
});

router.get('/api/payments', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query('SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM payments WHERE user_id = $1', [req.userId]);
    res.json({ payments: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

router.post('/api/payments/incomplete', auth, checkBlocked, async (req, res) => {
  const { paymentId } = req.body;
  if (!paymentId) return res.status(400).json({ error: 'paymentId required' });
  try {
    const paymentRecord = await query('SELECT * FROM payments WHERE id = $1 AND user_id = $2', [paymentId, req.userId]);
    if (!paymentRecord.rows.length) return res.status(403).json({ error: 'Payment not found or does not belong to you' });
    const piPayment = await piGetPayment(paymentId);
    if (piPayment.status && piPayment.status.developer_completed === false && piPayment.transaction) {
      await piCompletePayment(paymentId, piPayment.transaction.txid);
      const pgInc = await getPool().connect();
      try {
        await pgInc.query('BEGIN');
        const markDone = await pgInc.query(
          "UPDATE payments SET status='completed', txid=$1, updated_at=NOW() WHERE id=$2 AND status='approved' RETURNING *",
          [piPayment.transaction.txid, paymentId]
        );
        if (markDone.rows.length) {
          const meta = markDone.rows[0].metadata || {};
          const paymentOwner = markDone.rows[0].user_id || req.userId;
          if (meta.type === 'connects' && !meta.connects_credited) {
            const piAmountPaid = parseFloat(piPayment.amount || markDone.rows[0].amount || 0);
            const amount = resolveConnects(piAmountPaid);
            if (amount > 0) {
              await pgInc.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, paymentOwner]);
              await pgInc.query(`UPDATE payments SET metadata = metadata || '{"connects_credited":true}' WHERE id = $1`, [paymentId]);
            }
          } else if (meta.type === 'escrow' && meta.job_id && meta.freelancer_id) {
            const existingEscrow = await pgInc.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [paymentId]);
            if (!existingEscrow.rows.length) {
              const [jobCheck, freelancerCheck] = await Promise.all([
                pgInc.query('SELECT id FROM jobs WHERE id = $1 LIMIT 1', [meta.job_id]),
                pgInc.query('SELECT id FROM users WHERE id = $1 LIMIT 1', [meta.freelancer_id]),
              ]);
              if (jobCheck.rows.length && freelancerCheck.rows.length) {
                await pgInc.query(
                  'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (payment_id) DO NOTHING',
                  [meta.job_id, paymentOwner, meta.freelancer_id, parseFloat(piPayment.amount || markDone.rows[0].amount || 0), paymentId, 'funded']
                );
              }
            }
          }
        }
        await pgInc.query('COMMIT');
      } catch (txErr) { await pgInc.query('ROLLBACK').catch(() => {}); throw txErr; }
      finally { pgInc.release(); }
    }
    res.json({ success: true, payment: piPayment });
  } catch (err) { serverError(err, res); }
});

// Legacy flat-URL aliases — delegate to shared handlers
router.post('/api/payments/approve', auth, checkBlocked, async (req, res) => {
  const { payment_id, metadata } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
  await handlePaymentApprove(payment_id, metadata, req.userId, res, req.body.payments_enabled);
});

router.post('/api/payments/complete', auth, checkBlocked, async (req, res) => {
  const { payment_id, txid, metadata } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
  await handlePaymentComplete(payment_id, txid, metadata, req.userId, res);
});

// POST /api/payments/:paymentId/cancelled
router.post('/api/payments/:paymentId/cancelled', softAuth, async (req, res) => {
  try {
    // softAuth — called from onIncompletePaymentFound before JWT is available, so no strict auth.
    // Cancel by paymentId only; if userId known from JWT, also filter by it.
    if (req.userId) {
      await query(
        `UPDATE payments SET status = 'cancelled', updated_at = NOW() WHERE id = $1 AND user_id = $2`,
        [req.params.paymentId, req.userId]
      ).catch(() => {});
    } else {
      await query(
        `UPDATE payments SET status = 'cancelled', updated_at = NOW() WHERE id = $1`,
        [req.params.paymentId]
      ).catch(() => {});
    }
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

// POST /api/payments/:paymentId/resolve-incomplete — called from onIncompletePaymentFound.
// Tries to approve+complete (or just approve) the stuck payment via Pi API so Pi SDK unblocks.
//
// It cannot require `auth`: the Pi SDK fires onIncompletePaymentFound during
// Pi.authenticate(), before this backend has issued a JWT, and the SDK refuses
// to create new payments until the stale one is resolved. So it takes softAuth
// and enforces ownership only when it knows who is calling — but it no longer
// trusts *any* caller with the cancel path (see the tail of the handler).
router.post('/api/payments/:paymentId/resolve-incomplete', softAuth, checkBlocked, async (req, res) => {
  const paymentId = req.params.paymentId;
  const owner = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
  const ownerId = owner.rows[0]?.user_id;
  if (req.userId && ownerId && normalizeId(ownerId) !== normalizeId(req.userId)) {
    return res.status(403).json({ error: 'Payment does not belong to you' });
  }
  try {
    let piPayment = null;
    if (PI_API_KEY) {
      try { piPayment = await piGetPayment(paymentId); } catch (_) {}
      if (piPayment) {
        const st = piPayment.status || {};
        if (!st.developer_approved) {
          try { await piApprovePayment(paymentId); } catch (_) {}
        }
        const txid = piPayment.transaction?.txid;
        if (st.transaction_verified && txid && !st.developer_completed) {
          try { await piCompletePayment(paymentId, txid); } catch (_) {}
          // Credit connects if this was a connects payment. Locked in a
          // transaction: an unlocked read-then-write here let two concurrent
          // retries both see connects_credited=false and both credit.
          const pgRI = await getPool().connect();
          try {
            await pgRI.query('BEGIN');
            const row = await pgRI.query('SELECT * FROM payments WHERE id=$1 FOR UPDATE', [paymentId]);
            const pay = row.rows[0];
            const meta = pay?.metadata || {};
            if (pay && !meta.connects_credited && (meta.type === 'connects' || pay.type === 'connects')) {
              const amount = resolveConnects(parseFloat(piPayment.amount || pay.amount || 0));
              if (amount > 0 && pay.user_id) {
                await pgRI.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at=NOW() WHERE id=$2', [amount, pay.user_id]);
                await pgRI.query(`UPDATE payments SET metadata = metadata || '{"connects_credited":true}', status='completed', txid=$1, updated_at=NOW() WHERE id=$2`, [txid, paymentId]);
                await pgRI.query('COMMIT');
                return res.json({ success: true, credited: amount });
              }
            }
            await pgRI.query(`UPDATE payments SET status='completed', txid=$1, updated_at=NOW() WHERE id=$2`, [txid, paymentId]);
            await pgRI.query('COMMIT');
            return res.json({ success: true });
          } catch (txErr) {
            await pgRI.query('ROLLBACK').catch(() => {});
            throw txErr;
          } finally { pgRI.release(); }
        }
      }
    }
    // Only Pi gets to declare a payment dead. This used to cancel the row
    // unconditionally — including when the Pi lookup simply failed or
    // PI_API_KEY was unset — so a caller with someone else's payment id could
    // cancel a pending payment, and a transient Pi outage cancelled the user's
    // own payment out from under them.
    const cancelled = piPayment?.status?.cancelled || piPayment?.status?.user_cancelled;
    if (piPayment && cancelled) {
      await query(`UPDATE payments SET status='cancelled', updated_at=NOW() WHERE id=$1`, [paymentId]).catch(() => {});
      return res.json({ success: true, status: 'cancelled' });
    }
    // Nothing conclusive: leave the row alone. The hourly stuck-payments sweep
    // reconciles it later against Pi rather than guessing here.
    res.json({ success: true, status: 'unresolved' });
  } catch (err) { res.json({ success: true, status: 'unresolved' }); }
});

// POST /api/payments/clear-pending
router.post('/api/payments/clear-pending', auth, checkBlocked, async (req, res) => {
  try {
    await query(
      `UPDATE payments SET status = 'cancelled', updated_at = NOW() WHERE user_id = $1 AND status = 'pending' AND created_at < NOW() - INTERVAL '10 minutes'`,
      [req.userId]
    ).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

// POST /api/payments/:paymentId/resolve-complete
router.post('/api/payments/:paymentId/resolve-complete', auth, checkBlocked, async (req, res) => {
  const paymentId = req.params.paymentId;
  const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
  if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== req.userId) {
    return res.status(403).json({ error: 'Payment does not belong to you' });
  }
  try {
    let txid = null;
    if (PI_API_KEY) {
      const piRes = await fetch(`${PI_API_BASE}/v2/payments/${paymentId}`, {
        headers: { 'Authorization': `Key ${PI_API_KEY}` }
      }).catch(() => null);
      if (piRes && piRes.ok) {
        const piData = await piRes.json().catch(() => ({}));
        txid = piData.transaction?.txid || piData.txid || null;
        if (txid) {
          await fetch(`${PI_API_BASE}/v2/payments/${paymentId}/complete`, {
            method: 'POST',
            headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ txid })
          }).catch(() => {});
        }
      }
    }
    // Without a real txid from Pi's own GET response, nothing here has been
    // Pi-confirmed — proceeding anyway (as the code previously did) let this
    // route mark a payment 'completed' and credit connects/create an escrow
    // purely because our own /approve step had run, same gap as elsewhere.
    if (!txid && !process.env.SANDBOX_MODE) {
      return res.json({ success: true, resolved: false, reason: 'not confirmed by Pi yet' });
    }
    const pgRC = await getPool().connect();
    try {
      await pgRC.query('BEGIN');
      const markDoneRC = await pgRC.query(
        `UPDATE payments SET status = 'completed', txid = COALESCE($1, txid), updated_at = NOW() WHERE id = $2 AND status = 'approved' RETURNING *`,
        [txid, paymentId]
      );
      if (markDoneRC.rows.length) {
        const meta = markDoneRC.rows[0].metadata || {};
        const paymentOwner = markDoneRC.rows[0].user_id || req.userId;
        if (meta.type === 'connects' && !meta.connects_credited) {
          const piAmountPaid = parseFloat(markDoneRC.rows[0].amount || 0);
          const amount = resolveConnects(piAmountPaid);
          if (amount > 0) {
            await pgRC.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, paymentOwner]);
            await pgRC.query(`UPDATE payments SET metadata = metadata || '{"connects_credited":true}' WHERE id = $1`, [paymentId]);
          }
        } else if (meta.type === 'escrow' && meta.job_id && meta.freelancer_id) {
          const existingEscrowForPayment = await pgRC.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [paymentId]);
          if (!existingEscrowForPayment.rows.length) {
            const [jobCheck, freelancerCheck] = await Promise.all([
              pgRC.query('SELECT id FROM jobs WHERE id = $1 LIMIT 1', [meta.job_id]),
              pgRC.query('SELECT id FROM users WHERE id = $1 LIMIT 1', [meta.freelancer_id]),
            ]);
            if (jobCheck.rows.length && freelancerCheck.rows.length) {
              await pgRC.query(
                'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (payment_id) DO NOTHING',
                [meta.job_id, paymentOwner, meta.freelancer_id, parseFloat(markDoneRC.rows[0].amount || 0), paymentId, 'funded']
              );
            }
          }
        }
      }
      await pgRC.query('COMMIT');
    } catch (txErr) { await pgRC.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgRC.release(); }
    res.json({ success: true, resolved: true, txid });
  } catch (err) { res.json({ success: true, resolved: false }); }
});

// ─── Connects ──────────────────────────────────────────────

router.get('/api/connects/balance', auth, async (req, res) => {
  try {
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
    res.json({ balance: result.rows[0]?.balance_connects || 0 });
  } catch (err) { serverError(err, res); }
});

// POST /api/connects/purchase — credit connects after Pi payment (approved state)
router.post('/api/connects/purchase', auth, checkBlocked, async (req, res) => {
  const { payment_id } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
  try {
    const payRec = await query(
      "SELECT id, user_id, status, amount FROM payments WHERE id = $1",
      [payment_id]
    );
    if (!payRec.rows.length) return res.status(400).json({ error: 'Payment not found' });
    if (payRec.rows[0].user_id !== req.userId) return res.status(403).json({ error: 'Payment does not belong to you' });
    if (payRec.rows[0].status === 'completed') return res.status(400).json({ error: 'Payment already processed' });
    if (payRec.rows[0].status !== 'approved') return res.status(400).json({ error: 'Payment not approved by Pi yet' });

    // 'approved' only means our own server called Pi's /approve (which
    // unlocks the user's wallet to let them send funds) — handlePaymentApprove
    // sets it even when the Pi API call itself failed. It is NOT proof any
    // Pi transaction was ever broadcast or confirmed. Verify with Pi's own
    // API before crediting real value, same as /api/connects/buy does.
    let verifiedAmount = parseFloat(payRec.rows[0].amount || 0);
    if (PI_API_KEY) {
      let piPayment;
      try {
        piPayment = await piGetPayment(payment_id);
      } catch (piErr) {
        logger.error('[Connects] Pi verification failed:', piErr.message);
        return res.status(502).json({ error: 'Could not verify payment with Pi — please retry' });
      }
      const st = piPayment && piPayment.status;
      const verified = !!(st && (st.transaction_verified || st.developer_completed));
      if (!verified && !process.env.SANDBOX_MODE) {
        return res.status(502).json({ error: 'Pi payment not confirmed yet' });
      }
      verifiedAmount = parseFloat(piPayment.amount || verifiedAmount || 0);
    }

    const connectsAmount = resolveConnects(verifiedAmount);
    if (!(connectsAmount > 0)) {
      return res.status(400).json({ error: 'Payment amount too small to credit any connects' });
    }
    const pgClient2 = await getPool().connect();
    let newBalance;
    try {
      await pgClient2.query('BEGIN');
      // Same payment_id must not also have funded an escrow (or vice versa —
      // see the metadata.connects_credited check in escrow creation below).
      const escrowUsed = await pgClient2.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [payment_id]);
      if (escrowUsed.rows.length) {
        await pgClient2.query('ROLLBACK');
        return res.status(400).json({ error: 'Payment already used for an escrow' });
      }
      const updated = await pgClient2.query(
        "UPDATE payments SET status = 'completed', amount = $2, metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb, updated_at = NOW() WHERE id = $1 AND status = 'approved' RETURNING id",
        [payment_id, verifiedAmount, JSON.stringify({ type: 'connects', connects_credited: true, credited: connectsAmount })]
      );
      if (!updated.rows.length) {
        await pgClient2.query('ROLLBACK');
        return res.status(400).json({ error: 'Payment already processed' });
      }
      const balRes = await pgClient2.query(
        'UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2 RETURNING balance_connects',
        [connectsAmount, req.userId]
      );
      newBalance = balRes.rows[0]?.balance_connects || 0;
      await pgClient2.query('COMMIT');
    } catch (txErr) {
      await pgClient2.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally { pgClient2.release(); }
    await audit('connects_purchased', { user_id: req.userId, amount: connectsAmount, payment_id });
    res.json({ balance: newBalance, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/connects/buy — credit connects via Pi-verified payment (full flow)
// Different call pattern from /purchase — keeps both as per requirement #3
router.post('/api/connects/buy', auth, checkBlocked, async (req, res) => {
  // In production, require Pi payments to be enabled for this user
  if (!process.env.SANDBOX_MODE) {
    const userRow = await query('SELECT payments_enabled FROM users WHERE id = $1 LIMIT 1', [req.userId]).catch(() => ({ rows: [] }));
    if (userRow.rows[0]?.payments_enabled === false) {
      return res.status(403).json({ error: 'Pi payments are not enabled for your account. Complete Pi KYC first.' });
    }
  }
  const { payment_id, txid, amount, status, pi_amount, package_amount } = req.body;

  // Approval / pending step: record intent only. NEVER credit connects here.
  if (status === 'pending') {
    const pid = payment_id || ('connects_' + req.userId + '_' + Date.now());
    const quantity = parseInt(req.body.quantity || req.body.package_amount) || 0;
    await query(
      `INSERT INTO payments (id, user_id, payment_id, amount, status, metadata)
       VALUES ($1,$2,$3,$4,'pending',$5)
       ON CONFLICT (id) DO UPDATE SET status='pending', updated_at=NOW()`,
      [pid, req.userId, pid, amount || 0, JSON.stringify({ type: 'connects', quantity })]
    ).catch(() => {});
    return res.json({ success: true, status: 'pending' });
  }

  // Completion step: credit connects after a Pi payment.
  // NOTE: the frontend calls /api/payments/:id/complete (which marks the row
  // 'completed') and does NOT send a txid here, so we must not require txid nor
  // gate crediting on status. Idempotency is enforced via metadata.connects_credited.
  if (!payment_id) {
    return res.status(400).json({ error: 'payment_id required to credit connects' });
  }

  try {
    // Authoritative verification: ask Pi for the payment's real state + amount.
    // (best-effort approve/complete first in case the client never finished it).
    let piPayment = null;
    let verified = false;
    if (PI_API_KEY) {
      try {
        if (txid) {
          await piApprovePayment(payment_id).catch(() => {});
          await piCompletePayment(payment_id, txid).catch(() => {});
        }
        piPayment = await piGetPayment(payment_id);
        const st = piPayment && piPayment.status;
        verified = !!(st && (st.transaction_verified || st.developer_completed));
      } catch (piErr) {
        logger.error('[Connects] Pi verification failed:', piErr.message);
      }
    }

    const pgClient = await getPool().connect();
    let credited = 0;
    let balance = 0;
    try {
      await pgClient.query('BEGIN');
      // Lock the payment row (create a stub if the approve step never persisted it).
      let payRow = (await pgClient.query('SELECT * FROM payments WHERE id = $1 FOR UPDATE', [payment_id])).rows[0];
      if (!payRow) {
        await pgClient.query(
          `INSERT INTO payments (id, user_id, type, amount, status, txid, metadata)
           VALUES ($1,$2,'connects',$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING`,
          [payment_id, req.userId, parseFloat(pi_amount || amount || 0), verified ? 'completed' : 'pending', txid || null, JSON.stringify({ type: 'connects' })]
        );
        payRow = (await pgClient.query('SELECT * FROM payments WHERE id = $1 FOR UPDATE', [payment_id])).rows[0];
      }

      if (payRow.user_id && payRow.user_id !== req.userId) {
        await pgClient.query('ROLLBACK');
        return res.status(403).json({ error: 'Payment does not belong to you' });
      }

      // Same payment_id must not also have funded an escrow (see the mirrored
      // check in POST /api/escrow(s) and /api/connects/purchase above).
      const escrowUsedBuy = await pgClient.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [payment_id]);
      if (escrowUsedBuy.rows.length) {
        await pgClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Payment already used for an escrow' });
      }

      // 'approved' alone is not proof of a Pi-confirmed transaction — it's set
      // automatically by our own /approve step even when the underlying Pi API
      // call failed (see handlePaymentApprove). Only trust it when there's no
      // way to verify at all (no PI_API_KEY configured) or in sandbox, where
      // Pi doesn't issue real txids.
      const acceptableStatuses = ['completed'];
      if (!PI_API_KEY || process.env.SANDBOX_MODE) acceptableStatuses.push('approved', 'pending');
      if (!verified && !acceptableStatuses.includes(payRow.status)) {
        await pgClient.query('ROLLBACK');
        return res.status(502).json({ error: 'Pi payment not confirmed' });
      }

      const meta = payRow.metadata || {};
      // Idempotency: never credit the same payment twice (shared with /complete path).
      if (meta.connects_credited) {
        await pgClient.query('COMMIT');
        const cur = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
        balance = cur.rows[0]?.balance_connects || 0;
        return res.json({ success: true, credited: 0, alreadyCredited: true, balance, balance_connects: balance, new_balance: balance, remaining_connects: balance });
      }

      const verifiedAmount = parseFloat((piPayment && piPayment.amount) || payRow.amount || pi_amount || amount || 0);
      credited = resolveConnects(verifiedAmount);
      if (!(credited > 0)) {
        await pgClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Payment amount too small to credit any connects' });
      }

      const newMeta = Object.assign({}, meta, { type: 'connects', connects_credited: true, credited });
      await pgClient.query(
        `UPDATE payments SET status='completed', txid=COALESCE($2, txid), amount=$3, metadata=$4, updated_at=NOW() WHERE id=$1`,
        [payment_id, txid || null, verifiedAmount || payRow.amount || 0, JSON.stringify(newMeta)]
      );
      const balRes = await pgClient.query(
        'UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2 RETURNING balance_connects',
        [credited, req.userId]
      );
      balance = balRes.rows[0]?.balance_connects || 0;
      await pgClient.query('COMMIT');
      logger.info(`[Connects] COMMIT OK: user=${req.userId} +${credited} connects → balance=${balance} payment=${payment_id}`);
    } catch (txErr) {
      await pgClient.query('ROLLBACK').catch(() => {});
      logger.error(`[Connects] ROLLBACK: user=${req.userId} payment=${payment_id} err=${txErr.message}`);
      throw txErr;
    } finally { pgClient.release(); }

    await audit('connects_purchased', { user_id: req.userId, credited, payment_id, txid: txid || null });
    res.json({ success: true, credited, balance, balance_connects: balance, new_balance: balance, remaining_connects: balance });
  } catch (err) { serverError(err, res); }
});

// ─── Escrow ──────────────────────────────────────────────

// Bundle uses /api/escrows (plural) — both spellings handled
router.get('/api/escrow', auth, handleGetEscrow);
router.get('/api/escrows', auth, handleGetEscrow);

router.get(['/api/escrow/:id', '/api/escrows/:id'], auth, async (req, res) => {
  const id = req.params.id;
  const uid = req.userId;
  const uidAlt = uid.startsWith('pi_') ? uid.slice(3) : 'pi_' + uid;
  if (id === 'me') {
    const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    try {
      const result = await query(
        `SELECT e.*, j.title AS job_title FROM escrows e LEFT JOIN jobs j ON j.id = e.job_id
         WHERE e.client_id = ANY($1) OR e.freelancer_id = ANY($1)
         ORDER BY e.created_at DESC LIMIT $2 OFFSET $3`,
        [[uid, uidAlt], limit, offset]
      );
      return res.json({ escrows: result.rows, limit, offset });
    } catch (err) { return serverError(err, res); }
  }
  if (isNaN(parseInt(id))) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query(
      `SELECT e.*, j.title AS job_title FROM escrows e LEFT JOIN jobs j ON j.id = e.job_id
       WHERE e.id = $1 AND (e.client_id = ANY($2) OR e.freelancer_id = ANY($2))`,
      [id, [uid, uidAlt]]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const e = result.rows[0];
    res.json({ escrow: e });
  } catch (err) { serverError(err, res); }
});

router.post(['/api/escrow', '/api/escrows'], auth, checkBlocked, async (req, res) => {
  const { job_id, freelancer_id, payment_id } = req.body;
  if (!job_id || !freelancer_id || !payment_id) return res.status(400).json({ error: 'job_id, freelancer_id, payment_id required' });
  try {
    const pmtRec = await query('SELECT id, user_id, amount, status, metadata FROM payments WHERE id = $1', [payment_id]);
    if (!pmtRec.rows.length) return res.status(402).json({ error: 'Payment not found — complete Pi payment first' });
    if (pmtRec.rows[0].user_id !== req.userId) return res.status(403).json({ error: 'Payment does not belong to you' });
    if (pmtRec.rows[0].status !== 'completed') return res.status(402).json({ error: 'Payment not yet completed' });
    // A 'completed' status alone doesn't mean this payment is still spendable —
    // /api/connects/purchase and /api/connects/buy also flip status to
    // 'completed' when crediting connects from it. Without this check the same
    // Pi payment could fund both a connects purchase and a full escrow.
    if (pmtRec.rows[0].metadata && pmtRec.rows[0].metadata.connects_credited) {
      return res.status(400).json({ error: 'Payment was already used to purchase connects' });
    }
    const piVerifiedAmount = parseFloat(pmtRec.rows[0].amount || 0);
    const jobCheck = await query('SELECT posted_by, hired_freelancer_id FROM jobs WHERE id = $1', [job_id]);
    if (!jobCheck.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (normalizeId(jobCheck.rows[0].posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your job' });
    if (jobCheck.rows[0].hired_freelancer_id && jobCheck.rows[0].hired_freelancer_id !== freelancer_id) {
      return res.status(400).json({ error: 'freelancer_id does not match hired freelancer' });
    }
    const pgClientE = await getPool().connect();
    let escrowRow;
    try {
      await pgClientE.query('BEGIN');
      const existing = await pgClientE.query('SELECT id FROM escrows WHERE job_id = $1 AND status = ANY($2) FOR UPDATE', [job_id, ['pending', 'funded']]);
      if (existing.rows.length) { await pgClientE.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already exists for this job' }); }
      const payUsed = await pgClientE.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [payment_id]);
      if (payUsed.rows.length) { await pgClientE.query('ROLLBACK'); return res.status(400).json({ error: 'Payment already used for another escrow' }); }
      const result = await pgClientE.query(
        "INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1, $2, $3, $4, $5, 'funded') RETURNING *",
        [job_id, req.userId, freelancer_id, piVerifiedAmount, payment_id]
      );
      await pgClientE.query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['in_progress', job_id]);
      await pgClientE.query('COMMIT');
      escrowRow = result.rows[0];
    } catch (txErr) { await pgClientE.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClientE.release(); }
    await audit('escrow_created', { escrow_id: escrowRow.id, job_id, payment_id });
    const jobTitleRes = await query('SELECT title FROM jobs WHERE id = $1', [job_id]).catch(() => ({ rows: [] }));
    const jobTitle = jobTitleRes.rows[0]?.title || job_id;
    await notify(freelancer_id, 'hired', `Вас наняли на задачу "${jobTitle}"`,
      'Заказчик создал эскроу. Можете приступать к работе.', parseInt(job_id), null,
      { key: 'nHiredEscrowFunded', params: { job: jobTitle || '' } }).catch(() => {});
    const existRmEsc = await query('SELECT id FROM chat_rooms WHERE job_id=$1 AND client_id=$2 AND freelancer_id=$3',
      [job_id, req.userId, freelancer_id]).catch(() => ({ rows: [] }));
    if (!existRmEsc.rows.length) {
      const rmId = 'room_' + crypto.randomUUID();
      await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1,$2,$3,$4)',
        [rmId, req.userId, freelancer_id, job_id]).catch(() => {});
    }
    res.json({ escrow: escrowRow });
  } catch (err) { serverError(err, res); }
});

// Merged escrow release handler — serves BOTH /api/escrow/:id/release and /api/escrows/:id/release
router.post('/api/escrow/:id/release', auth, checkBlocked, handleEscrowRelease);
router.post('/api/escrows/:id/release', auth, checkBlocked, handleEscrowRelease);

// POST /api/escrows/:id/dispute/withdraw — either party calls off a dispute.
//
// Parties often sort it out between themselves in chat, which the admin cannot
// see. Without this the escrow stays 'disputed' forever, the money stays frozen,
// and an admin eventually rules on an argument that ended days ago.
router.post(['/api/escrows/:id/dispute/withdraw', '/api/escrow/:id/dispute/withdraw'], auth, checkBlocked, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    const isClient = normalizeId(escrow.client_id) === normalizeId(req.userId);
    const isFreelancer = normalizeId(escrow.freelancer_id) === normalizeId(req.userId);
    if (!isClient && !isFreelancer) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status !== 'disputed') {
      return res.status(400).json({ error: `No open dispute on this escrow (status: '${escrow.status}')` });
    }
    // Back to 'funded', which is where it was before the dispute — the normal
    // release, cancel and auto-release paths all work again from there.
    const updated = await query(
      "UPDATE escrows SET status='funded', dispute_reason=NULL, disputed_by=NULL, disputed_at=NULL, updated_at=NOW() WHERE id=$1 AND status='disputed' RETURNING id",
      [req.params.id]
    );
    if (!updated.rows.length) return res.status(409).json({ error: 'Dispute already resolved' });
    await audit('escrow_dispute_withdrawn', { escrow_id: req.params.id, by: req.userId });
    const otherParty = isClient ? escrow.freelancer_id : escrow.client_id;
    await notify(otherParty, 'escrow', 'Спор отозван', 'Спор по задаче отозван — можно продолжать работу.',
      escrow.job_id, null, { key: 'nDisputeWithdrawn', params: {} });
    res.json({ success: true, escrow: { ...escrow, status: 'funded' } });
  } catch (err) { serverError(err, res); }
});

router.post(['/api/escrows/:id/cancel', '/api/escrow/:id/cancel'], auth, checkBlocked, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (normalizeId(escrow.client_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your escrow' });
    if (!['pending', 'funded'].includes(escrow.status)) return res.status(400).json({ error: 'Escrow already settled' });
    // Work already delivered: cancelling here would let a client take the money
    // back after receiving the work, with the freelancer having no recourse.
    // Submission is recorded on the job, not the escrow, so this has to be
    // checked explicitly — disagreement after delivery goes through a dispute.
    const jobRow = await query('SELECT status FROM jobs WHERE id = $1', [escrow.job_id]);
    if (jobRow.rows[0]?.status === 'submitted') {
      return res.status(409).json({
        error: 'The freelancer has already submitted the work. Accept it or open a dispute.',
        code: 'work_submitted',
      });
    }
    const wasFunded = escrow.status === 'funded';
    const pgClient6 = await getPool().connect();
    try {
      await pgClient6.query('BEGIN');
      const updated = await pgClient6.query(
        "UPDATE escrows SET status='refunded', updated_at=NOW() WHERE id=$1 AND status = ANY($2) RETURNING id",
        [req.params.id, ['pending', 'funded']]
      );
      if (!updated.rows.length) { await pgClient6.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already settled' }); }
      await pgClient6.query("UPDATE escrow_milestones SET status='cancelled', updated_at=NOW() WHERE escrow_id=$1 AND status IN ('pending','requested')", [req.params.id]);
      await pgClient6.query('UPDATE jobs SET status = $1, hired_freelancer_id = NULL, hired_freelancer_name = NULL, updated_at = NOW() WHERE id = $2', ['open', escrow.job_id]);
      if (wasFunded) {
        await pgClient6.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, updated_at = NOW() WHERE id = $2', [escrow.amount, escrow.client_id]);
      }
      await pgClient6.query(
        "UPDATE applications SET status='rejected', updated_at=NOW() WHERE job_id=$1 AND status IN ('accepted')",
        [escrow.job_id]
      );
      await pgClient6.query('COMMIT');
    } catch (txErr) { await pgClient6.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient6.release(); }
    if (wasFunded) {
      await notify(escrow.freelancer_id, 'payment', 'Задача отменена заказчиком', `Эскроу по задаче отменён. Свяжитесь с заказчиком для уточнения деталей.`, escrow.job_id, null, { key: 'nJobCancelled', params: {} }).catch(() => {});
      await audit('escrow_cancelled_refunded', { escrow_id: req.params.id, amount: escrow.amount, client_id: escrow.client_id });
    }
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

router.post('/api/escrow/:id/refund', auth, checkBlocked, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (normalizeId(escrow.client_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your escrow' });
    if (!['pending', 'funded'].includes(escrow.status)) return res.status(400).json({ error: 'Cannot refund escrow with status: ' + escrow.status });
    const wasFunded = escrow.status === 'funded';
    const pgClient7 = await getPool().connect();
    try {
      await pgClient7.query('BEGIN');
      const updated = await pgClient7.query(
        "UPDATE escrows SET status='refunded', updated_at=NOW() WHERE id=$1 AND status = ANY($2) RETURNING id",
        [req.params.id, ['pending', 'funded']]
      );
      if (!updated.rows.length) { await pgClient7.query('ROLLBACK'); return res.status(400).json({ error: 'Already processed' }); }
      await pgClient7.query("UPDATE escrow_milestones SET status='cancelled', updated_at=NOW() WHERE escrow_id=$1 AND status IN ('pending','requested')", [req.params.id]);
      await pgClient7.query('UPDATE jobs SET status = $1, hired_freelancer_id = NULL, hired_freelancer_name = NULL, updated_at = NOW() WHERE id = $2', ['open', escrow.job_id]);
      if (wasFunded) {
        await pgClient7.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, updated_at = NOW() WHERE id = $2', [escrow.amount, escrow.client_id]);
      }
      await pgClient7.query("UPDATE applications SET status='rejected', updated_at=NOW() WHERE job_id=$1 AND status='accepted'", [escrow.job_id]);
      await pgClient7.query('COMMIT');
    } catch (txErr) { await pgClient7.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient7.release(); }
    if (wasFunded) {
      await notify(escrow.client_id, 'payment', 'Возврат средств', `${escrow.amount}π возвращено на ваш счёт.`, escrow.job_id, null, { key: 'nRefund', params: { amount: escrow.amount } });
    }
    await audit('escrow_refunded', { escrow_id: req.params.id, status_was: escrow.status, amount: escrow.amount });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

router.post('/api/escrows/:id/fund', auth, checkBlocked, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  const { payment_id, txid } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required — provide the Pi payment identifier' });
  try {
    const preCheck = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!preCheck.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    if (normalizeId(preCheck.rows[0].client_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your escrow' });
    const pmtCheck = await query('SELECT id, amount, metadata FROM payments WHERE payment_id = $1 AND status = $2 LIMIT 1', [payment_id, 'completed']);
    if (!pmtCheck.rows.length) return res.status(402).json({ error: 'Payment not verified — complete Pi payment first' });
    if (pmtCheck.rows[0].metadata && pmtCheck.rows[0].metadata.connects_credited) {
      return res.status(400).json({ error: 'Payment was already used to purchase connects' });
    }
    let escrow;
    const pgFund = await getPool().connect();
    try {
      await pgFund.query('BEGIN');
      const locked = await pgFund.query('SELECT * FROM escrows WHERE id = $1 FOR UPDATE', [req.params.id]);
      if (!locked.rows.length) { await pgFund.query('ROLLBACK'); return res.status(404).json({ error: 'Escrow not found' }); }
      escrow = locked.rows[0];
      if (escrow.status !== 'pending') { await pgFund.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already funded or settled' }); }
      const paymentUsedFund = await pgFund.query('SELECT id FROM escrows WHERE payment_id = $1 AND id != $2 LIMIT 1', [payment_id, req.params.id]);
      if (paymentUsedFund.rows.length) { await pgFund.query('ROLLBACK'); return res.status(400).json({ error: 'Payment already used for another escrow' }); }
      await pgFund.query('UPDATE escrows SET status = $1, payment_id = $2, amount = COALESCE($3, amount), updated_at = NOW() WHERE id = $4',
        ['funded', payment_id, pmtCheck.rows[0].amount, req.params.id]);
      await pgFund.query('COMMIT');
    } catch (txErr) { await pgFund.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgFund.release(); }
    await audit('escrow_funded', { escrow_id: req.params.id, payment_id, txid });
    res.json({ escrow: { ...escrow, status: 'funded' }, success: true });
  } catch (err) { serverError(err, res); }
});

router.post('/api/escrows/:id/dispute', auth, checkBlocked, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  const reason = String(req.body?.reason || '').trim();
  // A dispute freezes someone's money until an admin rules on it, and the admin
  // cannot read the parties' chat. Without a stated reason there is nothing to
  // rule on — "a dispute was opened" tells them nothing about who is right.
  if (reason.length < 20) {
    return res.status(400).json({
      error: 'Describe the problem in at least 20 characters — the administrator cannot see your chat.',
      code: 'reason_required',
    });
  }
  if (reason.length > 1000) return res.status(400).json({ error: 'Reason too long (max 1000 chars)' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (normalizeId(escrow.client_id) !== normalizeId(req.userId) && normalizeId(escrow.freelancer_id) !== normalizeId(req.userId)) {
      return res.status(403).json({ error: 'Not your escrow' });
    }
    if (escrow.status !== 'funded') {
      return res.status(400).json({ error: `Can only dispute a funded escrow (current status: '${escrow.status}')` });
    }
    await query('UPDATE escrows SET status = $1, dispute_reason = $2, disputed_by = $3, disputed_at = NOW(), updated_at = NOW() WHERE id = $4', ['disputed', reason, req.userId, req.params.id]);
    await audit('escrow_disputed', { escrow_id: req.params.id, reason, user_id: req.userId });
    const otherParty = normalizeId(req.userId) === normalizeId(escrow.client_id) ? escrow.freelancer_id : escrow.client_id;
    await notify(otherParty, 'dispute', 'Открыт спор по задаче',
      reason, escrow.job_id, null,
      { key: 'nDisputeOpened', params: { reason } });
    res.json({ escrow: { ...escrow, status: 'disputed' }, success: true });
  } catch (err) { serverError(err, res); }
});

router.get('/api/escrows/:id/room', auth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const escResult = await query('SELECT * FROM escrows WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!escResult.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = escResult.rows[0];
    const roomResult = await query(
      `SELECT * FROM chat_rooms WHERE job_id = $3 AND ((client_id = $1 AND freelancer_id = $2) OR (client_id = $2 AND freelancer_id = $1)) LIMIT 1`,
      [escrow.client_id, escrow.freelancer_id, escrow.job_id]
    );
    if (roomResult.rows.length) {
      return res.json({ room: roomResult.rows[0], room_id: roomResult.rows[0].id });
    }
    const roomId = 'room_' + crypto.randomUUID();
    const newRoom = await query(
      'INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [roomId, escrow.client_id, escrow.freelancer_id, escrow.job_id]
    );
    res.json({ room: newRoom.rows[0], room_id: newRoom.rows[0].id });
  } catch (err) { serverError(err, res); }
});

// GET /api/escrows/user/:userId
router.get('/api/escrows/user/:userId', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const paramUserId = req.params.userId === 'cherry19899' ? 'pi_cherry19899' : req.params.userId;
    if (paramUserId !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const userId = req.userId;
    const result = await query(
      `SELECT e.*, j.title as job_title,
              c.username as client_name, f.username as freelancer_name
       FROM escrows e
       LEFT JOIN jobs j ON j.id = e.job_id
       LEFT JOIN users c ON c.id = e.client_id
       LEFT JOIN users f ON f.id = e.freelancer_id
       WHERE e.client_id = $1 OR e.freelancer_id = $1
       ORDER BY e.created_at DESC LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    res.json({ escrows: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// ─── Offers ──────────────────────────────────────────────

router.post('/api/offers', auth, checkBlocked, async (req, res) => {
  const { to_user_id, job_id, amount, message } = req.body;
  if (!to_user_id || !job_id) return res.status(400).json({ error: 'to_user_id and job_id required' });
  if (message && message.length > 2000) return res.status(400).json({ error: 'Message too long (max 2000)' });
  if (amount !== undefined) {
    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0 || amountNum > 100000) return res.status(400).json({ error: 'amount must be a positive number (max 100000)' });
  }
  try {
    const jobRes = await query('SELECT * FROM jobs WHERE id = $1', [job_id]);
    if (!jobRes.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobRes.rows[0];
    if (normalizeId(job.posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Can only send offers for open jobs' });
    // normalizeId, not ===: a strict check here fails open, so a client could
    // send themselves a direct offer by varying the casing of their own id and
    // accept it — hiring themselves onto their own job.
    if (normalizeId(to_user_id) === normalizeId(req.userId)) return res.status(400).json({ error: 'Cannot send offer to yourself' });
    const freelancerRes = await query('SELECT id, username FROM users WHERE id = $1', [to_user_id]);
    if (!freelancerRes.rows.length) return res.status(404).json({ error: 'Freelancer not found' });
    const freelancer = freelancerRes.rows[0];
    const callerRes = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const callerName = callerRes.rows[0]?.username || req.userId;
    const anyApp = await query(
      `SELECT id, status FROM applications WHERE job_id=$1 AND freelancer_id=$2 LIMIT 1`,
      [job_id, to_user_id]
    );
    let result;
    if (anyApp.rows.length) {
      const existing = anyApp.rows[0];
      if (['accepted', 'in_progress'].includes(existing.status)) {
        return res.status(400).json({ error: 'Freelancer is already working on this job' });
      }
      result = await query(
        `UPDATE applications SET status='offer', message=$1, bid_amount=$2, updated_at=NOW() WHERE id=$3 RETURNING *`,
        [message || '', amount || job.budget, existing.id]
      );
    } else {
      result = await query(
        `INSERT INTO applications (job_id, job_title, freelancer_id, freelancer_name, message, bid_amount, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'offer', NOW()) RETURNING *`,
        [job_id, job.title, to_user_id, freelancer.username, message || '', amount || job.budget]
      );
    }
    await notify(to_user_id, 'offer', `Вам отправлено предложение по задаче "${job.title}"`,
      `${callerName} предлагает вам работу. Сумма: ${amount || job.budget} π`, job_id, null,
      { key: 'nOfferReceived', params: { job: job.title, name: callerName, amount: amount || job.budget } });
    res.json({ offer: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

router.get('/api/offers', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query(
      `SELECT a.*, j.title as job_title, j.budget, j.status as job_status,
              u.username as client_username
       FROM applications a
       JOIN jobs j ON a.job_id = j.id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.freelancer_id = $1 AND a.status = 'offer'
       ORDER BY a.created_at DESC LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    res.json({ offers: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

router.get('/api/offers/:id', auth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Offer not found' });
  try {
    const result = await query(
      `SELECT a.*, j.title as job_title, j.budget, u.username as client_username
       FROM applications a
       JOIN jobs j ON a.job_id = j.id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.id = $1 AND a.freelancer_id = $2`,
      [req.params.id, req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Offer not found' });
    res.json({ offer: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

router.post('/api/offers/:id/accept', auth, checkBlocked, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Offer not found' });
  try {
    const offerRes = await query(
      `SELECT a.*, j.posted_by, j.budget AS job_budget, j.title AS job_title, j.apply_cost
       FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1 AND a.freelancer_id = $2`,
      [req.params.id, req.userId]
    );
    if (!offerRes.rows.length) return res.status(404).json({ error: 'Offer not found' });
    const offer = offerRes.rows[0];
    if (offer.status !== 'offer') return res.status(400).json({ error: `Offer cannot be accepted (current status: ${offer.status})` });
    const pgOffer = await getPool().connect();
    let acceptedOffer;
    try {
      await pgOffer.query('BEGIN');
      const upd = await pgOffer.query(
        "UPDATE applications SET status='accepted', updated_at=NOW() WHERE id=$1 AND status='offer' RETURNING *",
        [req.params.id]
      );
      if (!upd.rows.length) { await pgOffer.query('ROLLBACK'); return res.status(409).json({ error: 'Offer already processed' }); }
      acceptedOffer = upd.rows[0];
      const toRej = await pgOffer.query(
        "SELECT freelancer_id FROM applications WHERE job_id=$1 AND id!=$2 AND status='pending'",
        [offer.job_id, req.params.id]
      );
      if (toRej.rows.length) {
        await pgOffer.query("UPDATE applications SET status='rejected', updated_at=NOW() WHERE job_id=$1 AND id!=$2 AND status='pending'", [offer.job_id, req.params.id]);
        for (const r of toRej.rows) {
          await pgOffer.query('UPDATE users SET balance_connects=balance_connects+$1, updated_at=NOW() WHERE id=$2', [offer.apply_cost || 1, r.freelancer_id]);
        }
      }
      const escrowAmt = offer.bid_amount || offer.job_budget || 0;
      const existEsc = await pgOffer.query("SELECT id FROM escrows WHERE job_id=$1 AND status=ANY($2) FOR UPDATE", [offer.job_id, ['pending', 'funded']]);
      if (!existEsc.rows.length) {
        await pgOffer.query("INSERT INTO escrows (job_id, client_id, freelancer_id, amount, status) VALUES ($1,$2,$3,$4,'pending')",
          [offer.job_id, offer.posted_by, req.userId, escrowAmt]);
      }
      const jobUpd = await pgOffer.query(
        "UPDATE jobs SET status='in_progress', hired_freelancer_id=$1, hired_freelancer_name=$2, updated_at=NOW() WHERE id=$3 AND status='open' RETURNING id",
        [req.userId, acceptedOffer.freelancer_name, offer.job_id]
      );
      if (!jobUpd.rows.length) {
        // Job was already hired out from under this offer (another accept won
        // the race) — don't report success on an application that isn't
        // actually the one working the job.
        await pgOffer.query('ROLLBACK');
        return res.status(409).json({ error: 'Job is no longer open — already hired' });
      }
      await pgOffer.query('COMMIT');
    } catch (txErr) { await pgOffer.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgOffer.release(); }
    await notify(offer.posted_by, 'hired', `Фрилансер принял ваше предложение по задаче "${offer.job_title}"`,
      'Пополните эскроу, чтобы начать работу.', parseInt(offer.job_id), null,
      { key: 'nOfferAccepted', params: { job: offer.job_title || '' } }).catch(() => {});
    const existRmOffer = await query('SELECT id FROM chat_rooms WHERE job_id=$1 AND client_id=$2 AND freelancer_id=$3',
      [offer.job_id, offer.posted_by, req.userId]).catch(() => ({ rows: [] }));
    if (!existRmOffer.rows.length) {
      const rmId = 'room_' + crypto.randomUUID();
      await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1,$2,$3,$4)',
        [rmId, offer.posted_by, req.userId, offer.job_id]).catch(() => {});
    }
    res.json({ application: acceptedOffer, success: true });
  } catch (err) { serverError(err, res); }
});

router.post('/api/offers/:id/decline', auth, checkBlocked, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Offer not found' });
  try {
    const result = await query("UPDATE applications SET status = $1, updated_at = NOW() WHERE id = $2 AND freelancer_id = $3 AND status = 'offer' RETURNING *", ['rejected', req.params.id, req.userId]);
    if (!result.rows.length) {
      const exists = await query('SELECT status FROM applications WHERE id = $1 AND freelancer_id = $2', [req.params.id, req.userId]);
      if (!exists.rows.length) return res.status(404).json({ error: 'Offer not found' });
      return res.status(400).json({ error: `Offer cannot be declined (current status: ${exists.rows[0].status})` });
    }
    const app_ = result.rows[0];
    const jobRow = await query('SELECT posted_by, title FROM jobs WHERE id = $1', [app_.job_id]).catch(() => ({ rows: [] }));
    if (jobRow.rows.length) {
      await notify(jobRow.rows[0].posted_by, 'offer', `Предложение отклонено`,
        `Фрилансер отклонил ваше предложение по задаче "${jobRow.rows[0].title}"`, app_.job_id, null,
        { key: 'nOfferDeclined', params: { job: jobRow.rows[0].title || '' } }).catch(() => {});
    }
    res.json({ application: app_, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/payments/webhook — Pi Platform callback, update payment status
router.post('/api/payments/webhook', async (req, res) => {
  try {
    const { payment_id, txid, status } = req.body;
    if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
    const validStatuses = ['completed', 'cancelled', 'failed'];
    if (status && !validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });
    // Verify with Pi API before trusting the webhook.
    //
    // This endpoint is unauthenticated and there is no signature to check, so
    // Pi's own answer is the only thing that may decide the status. The old
    // code fell back to `status || 'completed'` whenever the lookup came back
    // empty — and the lookup comes back empty on any network blip, or if
    // PI_API_KEY is unset — which let an anonymous POST of
    // {payment_id, status:'completed', txid:'…'} mark any payment paid.
    let piPayment = null;
    if (PI_API_KEY) {
      try { piPayment = await piGetPayment(payment_id); } catch (_) {}
    }
    if (!piPayment) {
      await audit('webhook_payment_unverified', { payment_id, claimed_status: status });
      return res.status(502).json({ error: 'Could not verify payment with Pi — not applied' });
    }
    const resolvedStatus = resolveWebhookStatus(piPayment);
    if (!resolvedStatus) {
      return res.json({ success: true, payment_id, status: 'pending', applied: false });
    }
    // Only Pi's txid is trusted — the request body's is attacker-controlled.
    const verifiedTxid = piPayment.transaction?.txid || null;
    await query(
      `UPDATE payments SET status = $1, txid = COALESCE($2, txid), updated_at = NOW() WHERE id = $3`,
      [resolvedStatus, verifiedTxid, payment_id]
    );
    await audit('webhook_payment_update', { payment_id, status: resolvedStatus, txid: verifiedTxid });
    res.json({ success: true, payment_id, status: resolvedStatus });
  } catch (err) { serverError(err, res); }
});

// ─── Escrow Milestones ────────────────────────────────────────────────────────

// GET /api/escrows/:id/milestones
router.get('/api/escrows/:id/milestones', auth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  const escrowId = parseInt(req.params.id);
  try {
    const esc = await query('SELECT * FROM escrows WHERE id=$1', [escrowId]);
    if (!esc.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const e = esc.rows[0];
    if (normalizeId(e.client_id) !== normalizeId(req.userId) && normalizeId(e.freelancer_id) !== normalizeId(req.userId)) {
      return res.status(403).json({ error: 'Not your escrow' });
    }
    const [milestones, txns] = await Promise.all([
      query('SELECT * FROM escrow_milestones WHERE escrow_id=$1 ORDER BY milestone_index', [escrowId]),
      query('SELECT * FROM escrow_transactions WHERE escrow_id=$1 ORDER BY created_at', [escrowId]),
    ]);
    res.json({ escrow: e, milestones: milestones.rows, transactions: txns.rows });
  } catch (err) { serverError(err, res); }
});

// POST /api/escrows/:id/milestones — create milestones (on fund, auto-created)
router.post('/api/escrows/:id/milestones', auth, checkBlocked, async (req, res) => {
  // This route deletes the escrow's pending milestones and writes new ones, so
  // parseInt's prefix parsing let `/escrows/5abc/milestones` rewrite the
  // milestones of escrow 5.
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  const escrowId = parseInt(req.params.id);
  const { milestones } = req.body; // [{ title, percent }]
  if (!milestones || !Array.isArray(milestones)) return res.status(400).json({ error: 'milestones array required' });
  const totalPct = milestones.reduce((s, m) => s + (parseInt(m.percent) || 0), 0);
  if (totalPct !== 100) return res.status(400).json({ error: 'Milestone percents must sum to 100' });
  // Summing to 100 alone allows e.g. {130, -30} — a negative-percent milestone
  // gets a negative amount, and approving it *reduces* the freelancer's
  // balance_pi with no floor (see the approve route below). Each slice must
  // be a genuine positive share of the escrow.
  if (milestones.some(m => !(parseInt(m.percent) > 0))) return res.status(400).json({ error: 'Each milestone percent must be greater than 0' });
  if (milestones.length < 1 || milestones.length > 10) return res.status(400).json({ error: '1-10 milestones allowed' });
  try {
    const esc = await query('SELECT * FROM escrows WHERE id=$1', [escrowId]);
    if (!esc.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const e = esc.rows[0];
    if (normalizeId(e.client_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Only client can set milestones' });
    if (!['funded', 'active'].includes(e.status)) return res.status(400).json({ error: 'Escrow must be funded first' });
    // Delete existing pending milestones
    await query('DELETE FROM escrow_milestones WHERE escrow_id=$1 AND status=$2', [escrowId, 'pending']);
    const totalAmt = parseFloat(e.amount);
    const created = [];
    for (let i = 0; i < milestones.length; i++) {
      const m = milestones[i];
      const pct = parseInt(m.percent);
      const amt = parseFloat((totalAmt * pct / 100).toFixed(2));
      const r = await query(
        `INSERT INTO escrow_milestones (escrow_id, milestone_index, title, percent, amount)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [escrowId, i, m.title || `Milestone ${i + 1}`, pct, amt]
      );
      created.push(r.rows[0]);
    }
    await query('UPDATE escrows SET milestone_count=$1, updated_at=NOW() WHERE id=$2', [milestones.length, escrowId]);
    res.json({ milestones: created, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/escrows/:id/milestone/:milestoneId/request — freelancer requests release
router.post('/api/escrows/:id/milestone/:milestoneId/request', auth, checkBlocked, async (req, res) => {
  // parseInt('abc') is NaN, which pg sends as the literal 'NaN' and Postgres
  // rejects — a 500 for what is simply a URL naming no milestone.
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  if (!isIdParam(req.params.milestoneId)) return res.status(404).json({ error: 'Milestone not found' });
  const escrowId = parseInt(req.params.id);
  const milestoneId = parseInt(req.params.milestoneId);
  try {
    const esc = await query('SELECT * FROM escrows WHERE id=$1', [escrowId]);
    if (!esc.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const e = esc.rows[0];
    if (normalizeId(e.freelancer_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Only freelancer can request release' });
    if (!['funded', 'active'].includes(e.status)) return res.status(400).json({ error: 'Escrow not active' });
    const ms = await query('SELECT * FROM escrow_milestones WHERE id=$1 AND escrow_id=$2', [milestoneId, escrowId]);
    if (!ms.rows.length) return res.status(404).json({ error: 'Milestone not found' });
    const m = ms.rows[0];
    if (m.status !== 'pending') return res.status(400).json({ error: 'Milestone already processed' });
    // Auto-release in 14 days if client doesn't respond
    const autoReleaseAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);
    await query(
      "UPDATE escrow_milestones SET status='requested', freelancer_requested=TRUE, requested_at=NOW(), auto_release_at=$1 WHERE id=$2",
      [autoReleaseAt, milestoneId]
    );
    // Notify client
    notify(e.client_id, 'milestone_requested', 'Запрошена выплата этапа',
      `Фрилансер запросил выплату этапа ${m.milestone_index + 1}`, e.job_id, null,
      { key: 'nMilestoneRequested', params: { n: m.milestone_index + 1 } }).catch(() => {});
    res.json({ success: true, auto_release_at: autoReleaseAt });
  } catch (err) { serverError(err, res); }
});

// POST /api/escrows/:id/milestone/:milestoneId/approve — client approves, releases funds
router.post('/api/escrows/:id/milestone/:milestoneId/approve', auth, checkBlocked, async (req, res) => {
  // Checked before a connection is taken from the pool: this route holds one
  // for a whole transaction, and a bad id should not cost one.
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  if (!isIdParam(req.params.milestoneId)) return res.status(404).json({ error: 'Milestone not found' });
  const escrowId = parseInt(req.params.id);
  const milestoneId = parseInt(req.params.milestoneId);
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const escRow = await client.query('SELECT * FROM escrows WHERE id=$1 FOR UPDATE', [escrowId]);
    if (!escRow.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Escrow not found' }); }
    const e = escRow.rows[0];
    if (normalizeId(e.client_id) !== normalizeId(req.userId)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Only client can approve' }); }
    // A refunded/cancelled escrow already paid the client back in full — its
    // milestones must not still be individually payable out of it, or the
    // freelancer gets paid twice (once from the refund reversal never
    // happening on milestones, once here).
    if (!['funded', 'active'].includes(e.status)) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow is not funded — cannot approve milestones' }); }
    const msRow = await client.query('SELECT * FROM escrow_milestones WHERE id=$1 AND escrow_id=$2 FOR UPDATE', [milestoneId, escrowId]);
    if (!msRow.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Milestone not found' }); }
    const m = msRow.rows[0];
    if (!['pending', 'requested'].includes(m.status)) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Already processed' }); }

    const releaseAmt = parseFloat(m.amount);
    const fee = await getPlatformFee();
    const platformFee = parseFloat((releaseAmt * fee).toFixed(2));
    const freelancerAmt = parseFloat((releaseAmt - platformFee).toFixed(2));

    // Update milestone
    await client.query('UPDATE escrow_milestones SET status=$1, client_approved=TRUE, approved_at=NOW() WHERE id=$2',
      ['released', milestoneId]);
    // Credit freelancer balance
    await client.query('UPDATE users SET balance_pi=balance_pi+$1, total_earned=total_earned+$1, updated_at=NOW() WHERE id=$2',
      [freelancerAmt, e.freelancer_id]);
    // Record transaction
    await client.query('INSERT INTO escrow_transactions (escrow_id, milestone_id, type, amount, note) VALUES ($1,$2,$3,$4,$5)',
      [escrowId, milestoneId, 'release', releaseAmt, `Milestone ${m.milestone_index + 1} approved`]);
    await client.query('INSERT INTO escrow_transactions (escrow_id, milestone_id, type, amount, note) VALUES ($1,$2,$3,$4,$5)',
      [escrowId, milestoneId, 'fee', platformFee, 'Platform fee']);
    // Check if all milestones completed
    const remaining = await client.query("SELECT COUNT(*) FROM escrow_milestones WHERE escrow_id=$1 AND status IN ('pending','requested')", [escrowId]);
    const allDone = parseInt(remaining.rows[0].count) === 0;
    if (allDone) {
      await client.query("UPDATE escrows SET status='completed', updated_at=NOW() WHERE id=$1", [escrowId]);
      if (e.job_id) {
        await client.query("UPDATE jobs SET status='completed', updated_at=NOW() WHERE id=$1", [e.job_id]);
      }
    }
    await client.query('COMMIT');
    // Real wallet payout via A2U, same as full release: on success deduct the
    // just-credited balance_pi; on failure the debt stays retryable.
    let payoutTxid = null;
    if (a2uEnabled()) {
      try {
        const { txid } = await sendA2U(e.freelancer_id, freelancerAmt, 'WorkPro milestone payment',
          { type: 'milestone_release', escrow_id: escrowId, milestone_id: milestoneId });
        payoutTxid = txid;
        await query('UPDATE users SET balance_pi = GREATEST(COALESCE(balance_pi,0) - $1, 0), updated_at = NOW() WHERE id = $2', [freelancerAmt, e.freelancer_id]).catch(() => {});
        await audit('milestone_payout_a2u', { escrow_id: escrowId, milestone_id: milestoneId, freelancer_id: e.freelancer_id, net_paid: freelancerAmt, txid });
      } catch (a2uErr) {
        logger.error(`[a2u] milestone payout failed for escrow ${escrowId}/${milestoneId}: ${a2uErr.message} — kept as balance_pi`);
      }
    }
    // Notify freelancer
    notify(e.freelancer_id, 'milestone_approved', 'Этап оплачен',
      payoutTxid ? `${freelancerAmt}π за этап ${m.milestone_index + 1} отправлено на ваш Pi-кошелёк.` : `${freelancerAmt}π зачислено за этап ${m.milestone_index + 1}.`,
      e.job_id, null,
      { key: payoutTxid ? 'nMilestonePaidWallet' : 'nMilestonePaidBalance',
        params: { amount: freelancerAmt, n: m.milestone_index + 1 } }).catch(() => {});
    res.json({ success: true, released: freelancerAmt, fee: platformFee, all_completed: allDone, payout_txid: payoutTxid });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    serverError(err, res);
  } finally { client.release(); }
});

// ─── Saved searches: daily alert check (called by cron) ──────────────────────
// POST /api/saved-searches/check-alerts (internal — requires admin key)
router.post('/api/saved-searches/check-alerts', async (req, res) => {
  const key = req.headers['x-admin-key'] || '';
  const { ADMIN_API_KEY, timingSafeStrEqual } = require('../src/middleware');
  // `!==` on secrets leaks length and prefix through timing; use the same
  // constant-time compare the admin middleware uses.
  if (!timingSafeStrEqual(key, ADMIN_API_KEY)) return res.status(403).json({ error: 'Forbidden' });
  try {
    const { checkSavedSearchAlerts } = require('../src/saved-search-alerts');
    res.json(await checkSavedSearchAlerts());
  } catch (err) { serverError(err, res); }
});

// ─── Full-text search endpoint ────────────────────────────────────────────────
router.get('/api/jobs/search/fulltext', async (req, res) => {
  const { q, category, min_budget, max_budget, urgent, sort = 'relevance', page = 1, limit: lim = 20 } = req.query;
  const pageNum = Math.max(1, parseInt(page));
  const limitNum = Math.max(1, Math.min(50, parseInt(lim)));
  const offset = (pageNum - 1) * limitNum;
  try {
    const conditions = ["j.status='open'"];
    const params = [];
    let idx = 1;
    if (q && q.trim()) {
      conditions.push(`(j.search_vector @@ plainto_tsquery('english',$${idx}) OR j.title ILIKE $${idx+1})`);
      params.push(q.trim(), `%${q.trim()}%`);
      idx += 2;
    }
    if (category && category !== 'all') { conditions.push(`j.category ILIKE $${idx++}`); params.push(category); }
    if (min_budget) { conditions.push(`j.budget >= $${idx++}`); params.push(parseFloat(min_budget)); }
    if (max_budget) { conditions.push(`j.budget <= $${idx++}`); params.push(parseFloat(max_budget)); }
    if (urgent === 'true') { conditions.push('j.is_urgent = TRUE'); }
    const orderBy = {
      relevance: q ? `ts_rank(j.search_vector, plainto_tsquery('english', '${q.replace(/'/g,"''")}')) DESC, j.created_at DESC` : 'j.created_at DESC',
      newest: 'j.created_at DESC',
      budget_high: 'j.budget DESC',
      budget_low: 'j.budget ASC',
      popular: 'j.applications DESC',
    }[sort] || 'j.created_at DESC';
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const [rows, total] = await Promise.all([
      query(`SELECT j.*, u.username AS posted_by_name, u.rating AS client_rating FROM jobs j LEFT JOIN users u ON u.id=j.posted_by ${where} ORDER BY ${orderBy} LIMIT $${idx} OFFSET $${idx+1}`, [...params, limitNum, offset]),
      query(`SELECT COUNT(*) FROM jobs j ${where}`, params),
    ]);
    res.json({ jobs: rows.rows, total: parseInt(total.rows[0].count), page: pageNum, limit: limitNum });
  } catch (err) { serverError(err, res); }
});

module.exports = router;

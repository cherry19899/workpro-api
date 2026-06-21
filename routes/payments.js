/**
 * routes/payments.js — /api/payments/*, /api/connects/*, /api/escrows/*, /api/escrow/*, /api/offers/*
 */
const router = require('express').Router();
const fetch = require('node-fetch');
const { query, getPool } = require('../src/db');
const { piApprovePayment, piCompletePayment, piGetPayment, notify, audit, serverError, PI_API_KEY } = require('../src/helpers');
const { auth, softAuth, checkBlocked } = require('../src/middleware');

const PLATFORM_FEE = Math.min(Math.max(parseFloat(process.env.PLATFORM_FEE_PERCENT || '2') / 100, 0), 0.5);

// ─── Shared Pi payment handlers ────────────────────────────────────────────
// handlePaymentApprove and handlePaymentComplete: shared by RESTful /:id/approve|complete
// and legacy flat /approve|complete routes.

async function handlePaymentApprove(paymentId, metadata, userId, res, paymentsEnabled) {
  // payments_enabled is set by the Pi SDK on the frontend and passed through metadata.
  // In sandbox/testnet it may be absent — block only on mainnet (when PI_API_KEY is production).
  if (PI_API_KEY && paymentsEnabled === false) {
    return res.status(403).json({ error: 'Pi payments not enabled for this account. Complete KYC on Pi App first.' });
  }
  try {
    const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
    if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'Payment does not belong to you' });
    }
    let piPayment = { amount: 0 };
    if (PI_API_KEY) {
      try {
        piPayment = await piApprovePayment(paymentId);
      } catch (piErr) {
        console.error('[Payment] Pi approval failed:', piErr.message);
        return res.status(502).json({ error: 'Pi payment verification failed' });
      }
    }
    await query(
      `INSERT INTO payments (id, user_id, type, amount, metadata, status, payment_id)
       VALUES ($1,$2,$3,$4,$5,'approved',$1)
       ON CONFLICT (id) DO UPDATE SET status='approved', amount=EXCLUDED.amount, updated_at=NOW()`,
      [paymentId, userId, metadata?.type || 'payment', piPayment.amount || 0, JSON.stringify(metadata || {})]
    ).catch(() => {});
    await audit('payment_approved', { payment_id: paymentId, user_id: userId, amount: piPayment.amount });
    res.json({ success: true, payment: piPayment });
  } catch (err) {
    console.error('[Payment] Approve error:', err.message);
    serverError(err, res);
  }
}

async function handlePaymentComplete(paymentId, txid, metadata, userId, res) {
  if (!txid) return res.status(400).json({ error: 'txid required' });
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
        // Pi API failure (wrong key, network, sandbox quirk) — log but continue:
        // the Pi blockchain confirmed the payment (client received txid), so we
        // still mark it completed on our side and credit connects. /api/connects/buy
        // will do additional idempotency check.
        console.error('[Payment] Pi complete failed (continuing):', piErr.message);
      }
    }
    const pgPmtC = await getPool().connect();
    try {
      await pgPmtC.query('BEGIN');
      let markRes = await pgPmtC.query(
        "UPDATE payments SET status='completed', txid=$1, updated_at=NOW() WHERE id=$2 AND status='approved' RETURNING *",
        [txid, paymentId]
      );
      if (!markRes.rows.length) {
        // No approved row — check if already completed (idempotent) or never approved (approve step failed).
        const existingRow = await pgPmtC.query('SELECT * FROM payments WHERE id = $1', [paymentId]);
        if (existingRow.rows.length && existingRow.rows[0].status === 'completed') {
          // Already completed by a previous call — idempotent success.
          await pgPmtC.query('ROLLBACK');
          return res.json({ success: true, payment: piPayment });
        }
        // Approve step was skipped (e.g. cold-start 502) — upsert as completed so connects can be credited.
        await pgPmtC.query(
          `INSERT INTO payments (id, user_id, type, amount, status, txid, metadata)
           VALUES ($1,$2,'connects',$3,'completed',$4,$5)
           ON CONFLICT (id) DO UPDATE SET status='completed', txid=EXCLUDED.txid, updated_at=NOW()`,
          [paymentId, userId, parseFloat(piPayment.amount || 0), txid, JSON.stringify({ type: 'connects' })]
        );
        markRes = await pgPmtC.query('SELECT * FROM payments WHERE id = $1', [paymentId]);
        if (!markRes.rows.length) { await pgPmtC.query('ROLLBACK'); return res.json({ success: true, payment: piPayment }); }
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
          console.error(`[Payment] Amount mismatch: Pi returned ${piAmountPaid}, DB stored ${storedAmount}`);
          return res.status(400).json({ error: 'Payment amount mismatch — contact support' });
        }
        // Use package_amount if provided and pi-formula gives less (bonus packages like 50 for 4π)
        const formulaAmount = Math.floor(piAmountPaid * 10);
        const pkgAmount = parseInt(meta.quantity || meta.package_amount || 0);
        const amount = pkgAmount > formulaAmount ? pkgAmount : formulaAmount;
        if (amount <= 0) { await pgPmtC.query('ROLLBACK'); return res.status(400).json({ error: 'Payment amount too small to credit connects' }); }
        await pgPmtC.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, paymentOwner]);
        await pgPmtC.query("UPDATE payments SET metadata = jsonb_set(COALESCE(metadata,'{}'::jsonb), '{connects_credited}', 'true') WHERE id = $1", [paymentId]);
        const newBal = await pgPmtC.query('SELECT balance_connects FROM users WHERE id = $1', [paymentOwner]);
        console.log(`[Payment] COMMIT connects +${amount} → user ${paymentOwner} new balance=${newBal.rows[0]?.balance_connects}`);
      } else if (meta.type === 'escrow' && meta.job_id && meta.freelancer_id) {
        const existingEscrow = await pgPmtC.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [paymentId]);
        if (!existingEscrow.rows.length) {
          const [jobCheck, freelancerCheck] = await Promise.all([
            pgPmtC.query('SELECT id FROM jobs WHERE id = $1 LIMIT 1', [meta.job_id]),
            pgPmtC.query('SELECT id FROM users WHERE id = $1 LIMIT 1', [meta.freelancer_id]),
          ]);
          if (jobCheck.rows.length && freelancerCheck.rows.length) {
            await pgPmtC.query(
              'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (payment_id) DO NOTHING',
              [meta.job_id, paymentOwner, meta.freelancer_id, parseFloat(piPayment.amount || markDone.amount || 0), paymentId, 'funded']
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
    console.error('[Payment] Complete error:', err.message);
    serverError(err, res);
  }
}

// ─── Escrow release (merged from singular /api/escrow/:id/release + plural /api/escrows/:id/release) ───
// The plural version (line 2059 in original) is newer — has .catch(()=>{}) on notify and returns { success: true }.
// The singular version (line 1389) returns { escrow: {..., status:'released'}, success: true }.
// Merged: returns { success: true, escrow: { ...escrow, status: 'released' } } (both response formats).
async function handleEscrowRelease(req, res) {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status !== 'funded') return res.status(400).json({ error: 'Escrow is not funded' });
    const net = parseFloat((escrow.amount * (1 - PLATFORM_FEE)).toFixed(8)); // platform commission
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
    await notify(escrow.freelancer_id, 'payment', 'Оплата получена', `${net}π зачислено на ваш счёт после завершения задачи.`, escrow.job_id, null).catch(() => {});
    await audit('escrow_released', { escrow_id: req.params.id, freelancer_id: escrow.freelancer_id, amount: escrow.amount, net_paid: net });
    res.json({ success: true, escrow: { ...escrow, status: 'released' } });
  } catch (err) { serverError(err, res); }
}

// ─── Escrow GET handler (shared by /api/escrow and /api/escrows) ──────────────
async function handleGetEscrow(req, res) {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const [result, totalRes] = await Promise.all([
      query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]),
      query('SELECT COUNT(*) FROM escrows WHERE client_id = $1 OR freelancer_id = $1', [req.userId]),
    ]);
    res.json({ escrows: result.rows, total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
}

// ─── Payments ──────────────────────────────────────────────

// approve/complete now require a verified JWT (was softAuth with a client-controlled
// req.body.user_id fallback that let an attacker pass the ownership check by spoofing the id).
// Frontend sends Authorization: Bearer on both payment flows (bundle _wpAuthHdr + index.html wrapper).
router.post('/api/payments/:paymentId/approve', auth, async (req, res) => {
  await handlePaymentApprove(req.params.paymentId, req.body.metadata, req.userId, res, req.body.payments_enabled);
});

router.post('/api/payments/:paymentId/complete', auth, async (req, res) => {
  await handlePaymentComplete(req.params.paymentId, req.body.txid, req.body.metadata, req.userId, res);
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

router.post('/api/payments/incomplete', auth, async (req, res) => {
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
          if (meta.type === 'connects') {
            const piAmountPaid = parseFloat(piPayment.amount || markDone.rows[0].amount || 0);
            const amount = Math.floor(piAmountPaid * 10);
            if (amount > 0) {
              await pgInc.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, paymentOwner]);
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
router.post('/api/payments/approve', auth, async (req, res) => {
  const { payment_id, metadata } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
  await handlePaymentApprove(payment_id, metadata, req.userId, res);
});

router.post('/api/payments/complete', auth, async (req, res) => {
  const { payment_id, txid, metadata } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
  await handlePaymentComplete(payment_id, txid, metadata, req.userId, res);
});

// POST /api/payments/:paymentId/cancelled
router.post('/api/payments/:paymentId/cancelled', auth, async (req, res) => {
  try {
    await query(
      `UPDATE payments SET status = 'cancelled', updated_at = NOW() WHERE id = $1 AND user_id = $2`,
      [req.params.paymentId, req.userId]
    ).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

// POST /api/payments/clear-pending
router.post('/api/payments/clear-pending', auth, async (req, res) => {
  try {
    await query(
      `UPDATE payments SET status = 'cancelled', updated_at = NOW() WHERE user_id = $1 AND status = 'pending' AND created_at < NOW() - INTERVAL '10 minutes'`,
      [req.userId]
    ).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

// POST /api/payments/:paymentId/resolve-complete
router.post('/api/payments/:paymentId/resolve-complete', auth, async (req, res) => {
  const paymentId = req.params.paymentId;
  const ownerCheck = await query('SELECT user_id FROM payments WHERE id = $1', [paymentId]).catch(() => ({ rows: [] }));
  if (ownerCheck.rows.length && ownerCheck.rows[0].user_id && ownerCheck.rows[0].user_id !== req.userId) {
    return res.status(403).json({ error: 'Payment does not belong to you' });
  }
  try {
    let txid = null;
    if (PI_API_KEY) {
      const piRes = await fetch(`https://api.minepi.com/v2/payments/${paymentId}`, {
        headers: { 'Authorization': `Key ${PI_API_KEY}` }
      }).catch(() => null);
      if (piRes && piRes.ok) {
        const piData = await piRes.json().catch(() => ({}));
        txid = piData.transaction?.txid || piData.txid || null;
        if (txid) {
          await fetch(`https://api.minepi.com/v2/payments/${paymentId}/complete`, {
            method: 'POST',
            headers: { 'Authorization': `Key ${PI_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ txid })
          }).catch(() => {});
        }
      }
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
        if (meta.type === 'connects') {
          const piAmountPaid = parseFloat(markDoneRC.rows[0].amount || 0);
          const amount = Math.floor(piAmountPaid * 10);
          if (amount > 0) {
            await pgRC.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, paymentOwner]);
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
    const piAmount = parseFloat(payRec.rows[0].amount || 0);
    const connectsAmount = Math.floor(piAmount * 10);
    if (!(connectsAmount > 0)) {
      return res.status(400).json({ error: 'Payment amount too small to credit any connects' });
    }
    const pgClient2 = await getPool().connect();
    let newBalance;
    try {
      await pgClient2.query('BEGIN');
      const updated = await pgClient2.query(
        "UPDATE payments SET status = 'completed', updated_at = NOW() WHERE id = $1 AND status = 'approved' RETURNING id",
        [payment_id]
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
        console.error('[Connects] Pi verification failed:', piErr.message);
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

      // Accept if Pi confirmed it, server already completed it, OR payment is approved
      // (approved = Pi blockchain confirmed but our /complete step may have failed to reach Pi API).
      const acceptableStatuses = ['completed', 'approved'];
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

      // Credit connects: use package_amount from frontend when it's larger than the Pi formula
      // (bonus packages: e.g. 50 connects for 4π = more than 4*10=40 by formula).
      // Base rate: 10 connects per 1 Pi.
      const verifiedAmount = parseFloat((piPayment && piPayment.amount) || payRow.amount || pi_amount || amount || 0);
      const formulaCredited = Math.floor(verifiedAmount * 10);
      const pkgCredited = parseInt(package_amount || req.body.quantity || payRow.metadata?.quantity || 0);
      credited = pkgCredited > formulaCredited ? pkgCredited : formulaCredited;
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
      console.log(`[Connects] COMMIT OK: user=${req.userId} +${credited} connects → balance=${balance} payment=${payment_id}`);
    } catch (txErr) {
      await pgClient.query('ROLLBACK').catch(() => {});
      console.error(`[Connects] ROLLBACK: user=${req.userId} payment=${payment_id} err=${txErr.message}`);
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
  if (id === 'me') {
    const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    try {
      const result = await query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]);
      return res.json({ escrows: result.rows, limit, offset });
    } catch (err) { return serverError(err, res); }
  }
  if (isNaN(parseInt(id))) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [id, req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    res.json({ escrow: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

router.post(['/api/escrow', '/api/escrows'], auth, checkBlocked, async (req, res) => {
  const { job_id, freelancer_id, payment_id } = req.body;
  if (!job_id || !freelancer_id || !payment_id) return res.status(400).json({ error: 'job_id, freelancer_id, payment_id required' });
  try {
    const pmtRec = await query('SELECT id, user_id, amount, status FROM payments WHERE id = $1', [payment_id]);
    if (!pmtRec.rows.length) return res.status(402).json({ error: 'Payment not found — complete Pi payment first' });
    if (pmtRec.rows[0].user_id !== req.userId) return res.status(403).json({ error: 'Payment does not belong to you' });
    if (pmtRec.rows[0].status !== 'completed') return res.status(402).json({ error: 'Payment not yet completed' });
    const piVerifiedAmount = parseFloat(pmtRec.rows[0].amount || 0);
    const jobCheck = await query('SELECT posted_by, hired_freelancer_id FROM jobs WHERE id = $1', [job_id]);
    if (!jobCheck.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (jobCheck.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
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
      'Заказчик создал эскроу. Можете приступать к работе.', parseInt(job_id), null).catch(() => {});
    const existRmEsc = await query('SELECT id FROM chat_rooms WHERE job_id=$1 AND client_id=$2 AND freelancer_id=$3',
      [job_id, req.userId, freelancer_id]).catch(() => ({ rows: [] }));
    if (!existRmEsc.rows.length) {
      const rmId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
      await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1,$2,$3,$4)',
        [rmId, req.userId, freelancer_id, job_id]).catch(() => {});
    }
    res.json({ escrow: escrowRow });
  } catch (err) { serverError(err, res); }
});

// Merged escrow release handler — serves BOTH /api/escrow/:id/release and /api/escrows/:id/release
router.post('/api/escrow/:id/release', auth, checkBlocked, handleEscrowRelease);
router.post('/api/escrows/:id/release', auth, checkBlocked, handleEscrowRelease);

router.post(['/api/escrows/:id/cancel', '/api/escrow/:id/cancel'], auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (!['pending', 'funded'].includes(escrow.status)) return res.status(400).json({ error: 'Escrow already settled' });
    const wasFunded = escrow.status === 'funded';
    const pgClient6 = await getPool().connect();
    try {
      await pgClient6.query('BEGIN');
      const updated = await pgClient6.query(
        "UPDATE escrows SET status='refunded', updated_at=NOW() WHERE id=$1 AND status = ANY($2) RETURNING id",
        [req.params.id, ['pending', 'funded']]
      );
      if (!updated.rows.length) { await pgClient6.query('ROLLBACK'); return res.status(400).json({ error: 'Escrow already settled' }); }
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
      await notify(escrow.freelancer_id, 'payment', 'Задача отменена заказчиком', `Эскроу по задаче отменён. Свяжитесь с заказчиком для уточнения деталей.`, escrow.job_id, null).catch(() => {});
      await audit('escrow_cancelled_refunded', { escrow_id: req.params.id, amount: escrow.amount, client_id: escrow.client_id });
    }
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

router.post('/api/escrow/:id/refund', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Escrow not found' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
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
      await pgClient7.query('UPDATE jobs SET status = $1, hired_freelancer_id = NULL, hired_freelancer_name = NULL, updated_at = NOW() WHERE id = $2', ['open', escrow.job_id]);
      if (wasFunded) {
        await pgClient7.query('UPDATE users SET balance_pi = COALESCE(balance_pi, 0) + $1, updated_at = NOW() WHERE id = $2', [escrow.amount, escrow.client_id]);
      }
      await pgClient7.query("UPDATE applications SET status='rejected', updated_at=NOW() WHERE job_id=$1 AND status='accepted'", [escrow.job_id]);
      await pgClient7.query('COMMIT');
    } catch (txErr) { await pgClient7.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient7.release(); }
    if (wasFunded) {
      await notify(escrow.client_id, 'payment', 'Возврат средств', `${escrow.amount}π возвращено на ваш счёт.`, escrow.job_id, null);
    }
    await audit('escrow_refunded', { escrow_id: req.params.id, status_was: escrow.status, amount: escrow.amount });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

router.post('/api/escrows/:id/fund', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Escrow not found' });
  const { payment_id, txid } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required — provide the Pi payment identifier' });
  try {
    const preCheck = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!preCheck.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    if (preCheck.rows[0].client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    const pmtCheck = await query('SELECT id, amount FROM payments WHERE payment_id = $1 AND status = $2 LIMIT 1', [payment_id, 'completed']);
    if (!pmtCheck.rows.length) return res.status(402).json({ error: 'Payment not verified — complete Pi payment first' });
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
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Escrow not found' });
  const { reason } = req.body;
  if (reason && reason.length > 1000) return res.status(400).json({ error: 'Reason too long (max 1000 chars)' });
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId && escrow.freelancer_id !== req.userId) {
      return res.status(403).json({ error: 'Not your escrow' });
    }
    if (escrow.status !== 'funded') {
      return res.status(400).json({ error: `Can only dispute a funded escrow (current status: '${escrow.status}')` });
    }
    await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['disputed', req.params.id]);
    await audit('escrow_disputed', { escrow_id: req.params.id, reason, user_id: req.userId });
    const otherParty = req.userId === escrow.client_id ? escrow.freelancer_id : escrow.client_id;
    await notify(otherParty, 'dispute', 'Открыт спор по задаче',
      reason || 'Одна из сторон открыла спор. Пожалуйста, свяжитесь с поддержкой.', escrow.job_id, null);
    res.json({ escrow: { ...escrow, status: 'disputed' }, success: true });
  } catch (err) { serverError(err, res); }
});

router.get('/api/escrows/:id/room', auth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Escrow not found' });
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
    const roomId = `room_${escrow.client_id}-${escrow.freelancer_id}-${Date.now()}`;
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
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Can only send offers for open jobs' });
    if (to_user_id === req.userId) return res.status(400).json({ error: 'Cannot send offer to yourself' });
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
      `${callerName} предлагает вам работу. Сумма: ${amount || job.budget} π`, job_id, null);
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
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Offer not found' });
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
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Offer not found' });
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
      await pgOffer.query(
        "UPDATE jobs SET status='in_progress', hired_freelancer_id=$1, hired_freelancer_name=$2, updated_at=NOW() WHERE id=$3 AND status='open'",
        [req.userId, acceptedOffer.freelancer_name, offer.job_id]
      );
      await pgOffer.query('COMMIT');
    } catch (txErr) { await pgOffer.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgOffer.release(); }
    await notify(offer.posted_by, 'hired', `Фрилансер принял ваше предложение по задаче "${offer.job_title}"`,
      'Пополните эскроу, чтобы начать работу.', parseInt(offer.job_id), null).catch(() => {});
    const existRmOffer = await query('SELECT id FROM chat_rooms WHERE job_id=$1 AND client_id=$2 AND freelancer_id=$3',
      [offer.job_id, offer.posted_by, req.userId]).catch(() => ({ rows: [] }));
    if (!existRmOffer.rows.length) {
      const rmId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
      await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1,$2,$3,$4)',
        [rmId, offer.posted_by, req.userId, offer.job_id]).catch(() => {});
    }
    res.json({ application: acceptedOffer, success: true });
  } catch (err) { serverError(err, res); }
});

router.post('/api/offers/:id/decline', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Offer not found' });
  try {
    const result = await query("UPDATE applications SET status = $1, updated_at = NOW() WHERE id = $2 AND freelancer_id = $3 AND status = 'offer' RETURNING *", ['rejected', req.params.id, req.userId]);
    if (!result.rows.length) {
      const exists = await query('SELECT status FROM applications WHERE id = $1 AND freelancer_id = $2', [req.params.id, req.userId]);
      if (!exists.rows.length) return res.status(404).json({ error: 'Offer not found' });
      return res.status(400).json({ error: `Offer cannot be declined (current status: ${exists.rows[0].status})` });
    }
    res.json({ application: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

module.exports = router;

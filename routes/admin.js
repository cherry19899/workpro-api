const logger = require('../src/logger');
/**
 * routes/admin.js — /api/admin/*
 */
const router = require('express').Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { query, getPool } = require('../src/db');
const { isOwnerId, OWNER_UIDS, isIdParam, notify, audit, serverError, getPlatformFee, getDeveloperFee, invalidatePlatformFeeCache, invalidateConnectsEconomyCache, invalidateSupportUrlCache, FEE_MAX, DEV_FEE_MAX } = require('../src/helpers');
const { adminAuth, twinId, JWT_SECRET, ADMIN_API_KEY, timingSafeStrEqual, _rlBlocks } = require('../src/middleware');
const { a2uEnabled, sendA2U } = require('../src/pi-a2u');

// In-memory cache for stats (5-minute TTL)
let _statsCache = null;
let _statsCacheTs = 0;
const STATS_TTL = 5 * 60 * 1000;

// Computes the full stats object directly from the DB (no cache).
async function computeStats() {
  const fee = await getPlatformFee();
  const devFee = await getDeveloperFee();
  const [users, jobs, applications, escrows, activeEscrows, payments, escrowRevBase, ratings, chats, disputes] = await Promise.all([
    query('SELECT COUNT(*) FROM users'),
    query('SELECT COUNT(*) FROM jobs'),
    query('SELECT COUNT(*) FROM applications'),
    query('SELECT COUNT(*) FROM escrows'),
    query("SELECT COUNT(*) FROM escrows WHERE status IN ('pending','funded')"),
    query('SELECT COUNT(*) FROM payments'),
    query("SELECT COALESCE(SUM(amount),0) AS total FROM escrows WHERE status='released'"),
    query('SELECT COUNT(*) FROM ratings'),
    query('SELECT COUNT(*) FROM chat_rooms'),
    query("SELECT COUNT(*) FROM escrows WHERE status='disputed'"),
  ]);
  const u = parseInt(users.rows[0].count);
  const j = parseInt(jobs.rows[0].count);
  const a = parseInt(applications.rows[0].count);
  const e = parseInt(escrows.rows[0].count);
  const ae = parseInt(activeEscrows.rows[0].count);
  const rev = parseFloat(escrowRevBase.rows[0].total) * fee;
  return {
    total_users: u, users: u,
    total_jobs: j, jobs: j,
    total_applications: a, applications: a,
    total_escrows: e, escrows: e,
    active_escrows: ae,
    total_revenue: rev,
    payments: parseInt(payments.rows[0].count),
    ratings: parseInt(ratings.rows[0].count),
    chats: parseInt(chats.rows[0].count),
    pending_moderation: parseInt(disputes.rows[0].count),
    platformFeePercent: parseFloat((fee * 100).toFixed(4)),
    developerFeePercent: parseFloat((devFee * 100).toFixed(4)),
  };
}

// Pre-warm the stats cache at server startup so the very first admin load is
// instant (no cold-start timeout → no empty Statistics tab on Render free tier).
async function warmStats() {
  try {
    const data = await computeStats();
    _statsCache = data;
    _statsCacheTs = Date.now();
    logger.info('[admin/stats] cache warmed on startup');
  } catch (err) {
    logger.error('[admin/stats] warm failed:', err.message);
  }
}

// GET /api/admin/stats
router.get('/api/admin/stats', adminAuth, async (req, res) => {
  const now = Date.now();
  if (_statsCache && (now - _statsCacheTs) < STATS_TTL) {
    return res.json({ ..._statsCache, cached: true });
  }
  // 8-second timeout fallback — return stale/empty rather than error.
  const timeout = new Promise(resolve => setTimeout(() => resolve(null), 8000));
  const work = computeStats().catch(err => { logger.error('[admin/stats]', err.message); return null; });
  const data = await Promise.race([work, timeout]);
  if (data) {
    _statsCache = data;
    _statsCacheTs = Date.now();
    return res.json(data);
  }
  if (_statsCache) return res.json({ ..._statsCache, cached: true, _stale: true });
  return res.json({ status: 'loading', retry_after: 5 });
});

// GET /api/admin/users
router.get('/api/admin/users', adminAuth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 200, 500));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  // Exclude heavy fields (avatar/bio) on list to keep payload small
  const safeFields = 'id, username, role, rating, total_jobs_posted, total_jobs_completed, balance_connects, balance_pi, is_blocked, status, created_at, updated_at';
  try {
    const search = (req.query.search || '').slice(0, 200);
    const timeout = new Promise(resolve => setTimeout(() => resolve(null), 12000));
    const work = (async () => {
      let sql, params = [];
      if (search) {
        sql = `SELECT ${safeFields} FROM users WHERE username ILIKE $1 OR id ILIKE $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`;
        params = [`%${search}%`, limit, offset];
      } else {
        sql = `SELECT ${safeFields} FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`;
        params = [limit, offset];
      }
      const [result, total] = await Promise.all([
        query(sql, params),
        query(search ? 'SELECT COUNT(*) FROM users WHERE username ILIKE $1 OR id ILIKE $1' : 'SELECT COUNT(*) FROM users', search ? [`%${search}%`] : []),
      ]);
      return { users: result.rows, count: result.rows.length, total: parseInt(total.rows[0].count), limit, offset };
    })();
    const data = await Promise.race([work, timeout]);
    if (data) return res.json(data);
    return res.json({ users: [], count: 0, total: 0, limit, offset, _timeout: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/block
router.post('/api/admin/users/:id/block', adminAuth, async (req, res) => {
  try {
    const twin = twinId(req.params.id);
    // Guard the owner under EVERY id form and any username casing. The real Pi Browser
    // owner account is id 'pi_a2b617f7-…' username 'Cherry19899' (capital C) — the old
    // guard only matched lowercase 'cherry19899' and missed it, so the owner kept getting
    // blocked by automated callers. Mirror the owner identities used in middleware adminAuth.
    const target = await query('SELECT username, role FROM users WHERE id IN ($1, $2)', [req.params.id, twin]);
    // Uid only. The old `|| username === 'cherry19899'` fallback meant anyone who
    // took that name became permanently un-blockable and un-demotable — an abuser
    // could immunise themselves against moderation by renaming. OWNER_IDS already
    // covers the real owner, so the fallback was redundant as well as exploitable.
    const isOwner = isOwnerId(req.params.id) || isOwnerId(twin);
    if (isOwner) {
      return res.status(403).json({ error: 'Cannot block owner' });
    }
    if (target.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    // Block both duplicate-account twins so the block can't be bypassed by logging
    // in as the unblocked twin (same person, "pi_" prefix mismatch).
    await query('UPDATE users SET is_blocked = true, status = $1, updated_at = NOW() WHERE id IN ($2, $3)', ['blocked', req.params.id, twin]);
    await audit('user_blocked', { user_id: req.params.id, by: req.userId, ip: req.headers['x-forwarded-for'] || req.ip });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/unblock
router.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  try {
    const twin = twinId(req.params.id);
    const result = await query('UPDATE users SET is_blocked = false, status = $1, updated_at = NOW() WHERE id IN ($2, $3)', ['active', req.params.id, twin]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    await audit('user_unblocked', { user_id: req.params.id, by: req.userId, ip: req.headers['x-forwarded-for'] || req.ip });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/make-admin
router.post('/api/admin/users/:id/make-admin', adminAuth, async (req, res) => {
  try {
    const result = await query("UPDATE users SET role = 'admin', updated_at = NOW() WHERE id = $1", [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    await audit('user_made_admin', { user_id: req.params.id, by: req.userId });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/remove-admin
router.post('/api/admin/users/:id/remove-admin', adminAuth, async (req, res) => {
  try {
    // Same owner identities as the block route: the real owner logs in as
    // 'pi_a2b617f7-…' username 'Cherry19899' (capital C) — the old
    // case-sensitive, twin-blind check here missed both the uuid id form and
    // that casing, so the owner's admin role could be stripped by an id or
    // username this check didn't recognize as the owner.
    const twin = twinId(req.params.id);
    const target = await query('SELECT username, role FROM users WHERE id IN ($1, $2)', [req.params.id, twin]);
    // Uid only. The old `|| username === 'cherry19899'` fallback meant anyone who
    // took that name became permanently un-blockable and un-demotable — an abuser
    // could immunise themselves against moderation by renaming. OWNER_IDS already
    // covers the real owner, so the fallback was redundant as well as exploitable.
    const isOwner = isOwnerId(req.params.id) || isOwnerId(twin);
    if (isOwner) {
      return res.status(403).json({ error: 'Cannot remove owner admin' });
    }
    if (target.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    await query("UPDATE users SET role = 'freelancer', updated_at = NOW() WHERE id = $1", [req.params.id]);
    await audit('user_removed_admin', { user_id: req.params.id, by: req.userId });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/grant-connects
router.post('/api/admin/users/:id/grant-connects', adminAuth, async (req, res) => {
  const { amount } = req.body;
  const qty = Math.max(1, Math.min(10000, parseInt(amount || 50) || 50));
  try {
    const upd = await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [qty, req.params.id]);
    if (upd.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.params.id]);
    await audit('admin_grant_connects', { user_id: req.params.id, amount: qty, granted_by: req.userId });
    res.json({ success: true, balance: result.rows[0]?.balance_connects || 0 });
  } catch (err) { serverError(err, res); }
});

const JOB_LIST_FIELDS = 'j.id, j.title, j.status, j.budget, j.category, j.posted_by, j.hired_freelancer_id, j.apply_cost, j.created_at, j.updated_at, u.username as posted_by_name';

// GET /api/admin/jobs
router.get('/api/admin/jobs', adminAuth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 100, 500));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const timeout = new Promise(resolve => setTimeout(() => resolve(null), 12000));
    const work = Promise.all([
      query(`SELECT ${JOB_LIST_FIELDS} FROM jobs j LEFT JOIN users u ON u.id = j.posted_by ORDER BY j.created_at DESC LIMIT $1 OFFSET $2`, [limit, offset]),
      query('SELECT COUNT(*) FROM jobs'),
    ]).then(([r, t]) => ({ jobs: r.rows, total: parseInt(t.rows[0].count), limit, offset }));
    const data = await Promise.race([work, timeout]);
    if (data) return res.json(data);
    return res.json({ jobs: [], total: 0, limit, offset, _timeout: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/jobs/all
router.get('/api/admin/jobs/all', adminAuth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 200, 500));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const timeout = new Promise(resolve => setTimeout(() => resolve(null), 12000));
    const work = Promise.all([
      query(`SELECT ${JOB_LIST_FIELDS} FROM jobs j LEFT JOIN users u ON u.id = j.posted_by ORDER BY j.created_at DESC LIMIT $1 OFFSET $2`, [limit, offset]),
      query('SELECT COUNT(*) FROM jobs'),
    ]).then(([r, t]) => ({ jobs: r.rows, total: parseInt(t.rows[0].count), limit, offset }));
    const data = await Promise.race([work, timeout]);
    if (data) return res.json(data);
    return res.json({ jobs: [], total: 0, limit, offset, _timeout: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/debug/schema — \d users equivalent (column list + types)
router.get('/api/admin/debug/schema', adminAuth, async (req, res) => {
  try {
    const result = await query(`
      SELECT column_name, data_type, column_default, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'users' AND table_schema = 'public'
      ORDER BY ordinal_position`);
    res.json({ table: 'users', columns: result.rows });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/debug/integrity — verify mainnet-prep migrations actually applied
router.get('/api/admin/debug/integrity', adminAuth, async (req, res) => {
  try {
    const [fks, nullUpd, roomIds] = await Promise.all([
      query(`SELECT constraint_name, table_name FROM information_schema.table_constraints
             WHERE constraint_type = 'FOREIGN KEY' AND table_schema = 'public'
               AND constraint_name IN ('fk_applications_job_id','fk_escrows_job_id','fk_chat_messages_room_id')
             ORDER BY constraint_name`),
      query(`SELECT COUNT(*)::int AS n FROM applications WHERE updated_at IS NULL`),
      query(`SELECT COUNT(*)::int AS legacy FROM chat_rooms WHERE id LIKE 'room_%' AND id NOT SIMILAR TO 'room_[0-9a-f-]{36}'`),
    ]);
    res.json({
      foreign_keys: fks.rows,
      applications_null_updated_at: nullUpd.rows[0].n,
      legacy_format_room_ids: roomIds.rows[0].legacy,
    });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/debug/connects/:userId — raw DB data for diagnosing connects balance issues
router.get('/api/admin/debug/connects/:userId', adminAuth, async (req, res) => {
  const userId = req.params.userId;
  try {
    const [userRow, payments, auditRows] = await Promise.all([
      query('SELECT id, username, balance_connects, balance_pi, role, status, updated_at FROM users WHERE id = $1', [userId]),
      query(`SELECT id, status, amount, type, metadata, txid, created_at, updated_at
             FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`, [userId]),
      query(`SELECT id, action, data, created_at FROM audit_logs
             WHERE data::text ILIKE $1 ORDER BY created_at DESC LIMIT 20`, [`%${userId}%`]),
    ]);
    if (!userRow.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({
      user: userRow.rows[0],
      payments: payments.rows,
      audit_logs: auditRows.rows,
    });
  } catch (err) { serverError(err, res); }
});

// PATCH /api/admin/jobs/:id/images — used by the image migration script to swap
// base64 payloads for static file URLs without touching any other job fields.
router.patch('/api/admin/jobs/:id/images', adminAuth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Job not found' });
  const { images } = req.body;
  if (!Array.isArray(images)) return res.status(400).json({ error: 'images must be an array' });
  try {
    const serialized = images.length > 0 ? JSON.stringify(images) : null;
    const r = await query('UPDATE jobs SET images = $1, updated_at = NOW() WHERE id = $2 RETURNING id', [serialized, req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Job not found' });
    res.json({ success: true, id: req.params.id, images });
  } catch (err) { serverError(err, res); }
});

// PATCH /api/admin/jobs/:id — update featured flag (and other admin-level job fields)
router.patch('/api/admin/jobs/:id', adminAuth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Job not found' });
  const { featured } = req.body;
  if (typeof featured !== 'boolean') return res.status(400).json({ error: 'featured (boolean) required' });
  try {
    const r = await query('UPDATE jobs SET featured = $1, updated_at = NOW() WHERE id = $2 RETURNING id, featured', [featured, req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Job not found' });
    await audit('job_featured_updated', { job_id: req.params.id, featured, by: req.userId });
    res.json({ success: true, job: r.rows[0] });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/admin/jobs/:id
router.delete('/api/admin/jobs/:id', adminAuth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Job not found' });
  try {
    // escrows.job_id → jobs(id) is ON DELETE CASCADE, so the DELETE FROM jobs
    // below erases any escrow row for this job regardless of status. A
    // 'disputed' escrow still holds the client's Pi exactly like a 'funded'
    // one — only checking 'funded' here silently destroyed that money on
    // delete with no refund and no trace beyond the audit log's job_id.
    const fundedEscrow = await query("SELECT * FROM escrows WHERE job_id = $1 AND status IN ('funded','disputed') LIMIT 1", [req.params.id]);
    const jobMeta = await query('SELECT apply_cost, posted_by FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobMeta.rows.length) return res.status(404).json({ error: 'Job not found' });
    const applyRefundCost = jobMeta.rows[0]?.apply_cost || 1;
    const jobPoster = jobMeta.rows[0]?.posted_by;
    const applicants = await query("SELECT DISTINCT freelancer_id FROM applications WHERE job_id = $1 AND status = 'pending'", [req.params.id]);
    const pgAdm = await getPool().connect();
    try {
      await pgAdm.query('BEGIN');
      if (fundedEscrow.rows.length) {
        const esc = fundedEscrow.rows[0];
        await pgAdm.query("UPDATE escrows SET status='refunded', updated_at=NOW() WHERE id=$1", [esc.id]);
        await pgAdm.query('UPDATE users SET balance_pi = COALESCE(balance_pi,0) + $1, updated_at=NOW() WHERE id=$2', [esc.amount, esc.client_id]);
      }
      if (jobPoster) {
        await pgAdm.query('UPDATE users SET balance_connects = balance_connects + 1, updated_at=NOW() WHERE id=$1', [jobPoster]);
      }
      for (const row of applicants.rows) {
        await pgAdm.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at=NOW() WHERE id=$2', [applyRefundCost, row.freelancer_id]);
      }
      await pgAdm.query('DELETE FROM applications WHERE job_id = $1', [req.params.id]);
      await pgAdm.query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
      await pgAdm.query('COMMIT');
    } catch (txErr) { await pgAdm.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgAdm.release(); }
    if (fundedEscrow.rows.length) {
      const esc = fundedEscrow.rows[0];
      await notify(esc.client_id, 'payment', 'Задача удалена администратором', 'Средства эскроу возвращены на ваш баланс.', parseInt(req.params.id), null, { key: 'nJobDeletedAdminClient', params: {} }).catch(() => {});
      if (esc.freelancer_id) {
        await notify(esc.freelancer_id, 'info', 'Задача удалена администратором', 'Задача, над которой вы работали, была удалена администратором.', parseInt(req.params.id), null, { key: 'nJobDeletedAdminFreelancer', params: {} }).catch(() => {});
      }
    }
    await audit('admin_job_deleted', { job_id: req.params.id, by: req.userId, escrow_refunded: fundedEscrow.rows.length > 0, connects_refunded: applicants.rows.length });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/escrows
router.get('/api/admin/escrows', adminAuth, async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 100, 500));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const result = await query(`
      SELECT e.*,
        uc.username AS client_name,
        uf.username AS freelancer_name,
        j.title AS job_title,
        j.status AS job_status,
        ud.username AS disputed_by_name,
        -- Which side raised it. The admin cannot read their chat, so knowing who
        -- is complaining is most of the context available.
        CASE
          WHEN e.disputed_by IS NULL THEN NULL
          WHEN lower(regexp_replace(e.disputed_by, '^pi_', '')) = lower(regexp_replace(e.client_id, '^pi_', '')) THEN 'client'
          ELSE 'freelancer'
        END AS disputed_by_side
      FROM escrows e
      LEFT JOIN users uc ON uc.id = e.client_id
      LEFT JOIN users uf ON uf.id = e.freelancer_id
      LEFT JOIN users ud ON ud.id = e.disputed_by
      LEFT JOIN jobs j ON j.id = e.job_id
      ORDER BY e.created_at DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM escrows');
    res.json({ escrows: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/escrows/:id/resolve
router.post('/api/admin/escrows/:id/resolve', adminAuth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Escrow not found' });
  const { action, reason } = req.body;
  if (!['release_to_freelancer', 'refund_to_client'].includes(action)) {
    return res.status(400).json({ error: 'action must be release_to_freelancer or refund_to_client' });
  }
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    // Admin can resolve both disputed escrows AND funded ones (the admin panel shows
    // Release/Refund on funded escrows too). Reject only already-settled/pending ones.
    if (!['disputed', 'funded'].includes(escrow.status)) {
      return res.status(400).json({ error: `Escrow cannot be resolved (status: ${escrow.status})` });
    }
    // Declared outside the transaction block so it's still in scope for the A2U
    // payout below (a block-scoped `let net` inside try threw "net is not defined").
    let net = null;
    const pgC = await getPool().connect();
    try {
      await pgC.query('BEGIN');
      const guard = await pgC.query(
        "UPDATE escrows SET status=$1, updated_at=NOW() WHERE id=$2 AND status = ANY($3) RETURNING id",
        [action === 'release_to_freelancer' ? 'released' : 'refunded', req.params.id, ['disputed', 'funded']]
      );
      if (!guard.rows.length) { await pgC.query('ROLLBACK'); return res.status(409).json({ error: 'Escrow already settled' }); }
      if (action === 'release_to_freelancer') {
        const fee = await getPlatformFee();
        net = parseFloat((escrow.amount * (1 - fee)).toFixed(8));
        await pgC.query('UPDATE users SET balance_pi = COALESCE(balance_pi,0) + $1, total_jobs_completed = total_jobs_completed + 1, updated_at=NOW() WHERE id=$2', [net, escrow.freelancer_id]);
        await pgC.query("UPDATE jobs SET status='completed', updated_at=NOW() WHERE id=$1", [escrow.job_id]);
      } else {
        await pgC.query('UPDATE users SET balance_pi = COALESCE(balance_pi,0) + $1, updated_at=NOW() WHERE id=$2', [escrow.amount, escrow.client_id]);
        await pgC.query("UPDATE jobs SET status='open', hired_freelancer_id=NULL, hired_freelancer_name=NULL, updated_at=NOW() WHERE id=$1", [escrow.job_id]);
        // The other two refund paths (client cancel, client refund in
        // payments.js) do this and this one did not: the job reopened with
        // nobody hired while the application still read 'accepted'. The direct
        // offer route reads that status, so the client was told "Freelancer is
        // already working on this job" and could not re-hire the person whose
        // dispute had just been settled, with no way to clear it from the UI.
        await pgC.query("UPDATE applications SET status='rejected', updated_at=NOW() WHERE job_id=$1 AND status='accepted'", [escrow.job_id]);
      }
      await pgC.query('COMMIT');
    } catch (txErr) { await pgC.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgC.release(); }
    // Real A2U payout when the dispute is resolved in the freelancer's favor.
    let payoutTxid = null;
    if (action === 'release_to_freelancer' && net > 0 && a2uEnabled()) {
      try {
        const r = await sendA2U(escrow.freelancer_id, net, 'WorkPro dispute resolution', { type: 'dispute_release', escrow_id: escrow.id, job_id: escrow.job_id });
        payoutTxid = r.txid;
        // balance_pi is what /api/admin/users/:id/payout-owed pays out. The Pi
        // has already left the wallet at this point, so if this deduction is
        // swallowed the freelancer is still owed `net` on paper and a later
        // payout-owed sends it a second time. Nothing here can undo the
        // transfer, so the failure is logged with everything needed to
        // reconcile by hand rather than discarded.
        await query('UPDATE users SET balance_pi = GREATEST(COALESCE(balance_pi,0) - $1, 0), updated_at = NOW() WHERE id = $2', [net, escrow.freelancer_id])
          .catch((e) => logger.error(`[a2u] PAID BUT NOT DEDUCTED — escrow ${escrow.id}, user ${escrow.freelancer_id}, ${net}π, txid ${payoutTxid}: ${e.message}`));
        await query('UPDATE escrows SET payout_txid = $1, updated_at = NOW() WHERE id = $2', [payoutTxid, escrow.id])
          .catch((e) => logger.error(`[a2u] payout_txid not recorded for escrow ${escrow.id} (txid ${payoutTxid}): ${e.message}`));
      } catch (e) { logger.error(`[a2u] dispute payout failed for escrow ${escrow.id}: ${e.message}`); }
    }
    await audit(escrow.status === 'disputed' ? 'admin_dispute_resolved' : 'admin_escrow_resolved', { escrow_id: req.params.id, action, reason: reason || null, by: req.userId, payout_txid: payoutTxid });
    const notifTitle = escrow.status === 'disputed' ? 'Спор разрешён администратором'
      : (action === 'release_to_freelancer' ? 'Средства выплачены фрилансеру' : 'Средства возвращены заказчику');
    const notifKey = escrow.status === 'disputed' ? 'nDisputeResolved'
      : (action === 'release_to_freelancer' ? 'nEscrowReleasedAdmin' : 'nEscrowRefundedAdmin');
    const notifBody = reason || (action === 'release_to_freelancer' ? 'Эскроу выплачен.' : 'Эскроу возвращён заказчику.');
    await notify(escrow.client_id, 'escrow', notifTitle, notifBody, escrow.job_id, null,
      { key: notifKey, params: { reason: reason || '' } }).catch(() => {});
    await notify(escrow.freelancer_id, 'escrow', notifTitle, notifBody, escrow.job_id, null,
      { key: notifKey, params: { reason: reason || '' } }).catch(() => {});
    res.json({ success: true, action, payout_txid: payoutTxid });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/payout-owed — send the user's accumulated balance_pi
// (amounts owed from releases where the real A2U transfer failed) as one real
// A2U payment, then deduct it.
router.post('/api/admin/users/:id/payout-owed', adminAuth, async (req, res) => {
  try {
    if (!a2uEnabled()) return res.status(400).json({ error: 'A2U is not configured (PI_WALLET_PRIVATE_SEED missing)' });
    const userRes = await query('SELECT id, username, balance_pi FROM users WHERE id = $1', [req.params.id]);
    if (!userRes.rows.length) return res.status(404).json({ error: 'User not found' });
    const owed = parseFloat(userRes.rows[0].balance_pi || 0);
    if (!(owed > 0)) return res.status(400).json({ error: 'Nothing to pay out (balance_pi is 0)' });
    // Reserve (deduct) the exact amount just read BEFORE sending it, guarded by
    // the balance still being at least that much. Without this, two overlapping
    // calls (double-click, retry-on-timeout, two admin tabs) both read the same
    // starting balance, both send the full amount via sendA2U — a real,
    // irreversible transfer — and only then both deduct, paying the user twice.
    const reserved = await query(
      'UPDATE users SET balance_pi = GREATEST(COALESCE(balance_pi,0) - $1, 0), updated_at = NOW() WHERE id = $2 AND COALESCE(balance_pi,0) >= $1 RETURNING id',
      [owed, req.params.id]
    );
    if (!reserved.rows.length) return res.status(409).json({ error: 'Balance changed — retry' });
    let txid, paymentId;
    try {
      ({ txid, paymentId } = await sendA2U(req.params.id, owed, 'WorkPro payout', { type: 'owed_payout', by: req.userId }));
    } catch (a2uErr) {
      // Nothing was sent — give the reservation back so the amount isn't lost.
      await query('UPDATE users SET balance_pi = COALESCE(balance_pi,0) + $1, updated_at = NOW() WHERE id = $2', [owed, req.params.id])
        .catch((e) => logger.error(`[a2u] RESERVED BUT NOT REFUNDED — user ${req.params.id}, ${owed}π: ${e.message}`));
      throw a2uErr;
    }
    await audit('admin_owed_payout', { user_id: req.params.id, amount: owed, txid, payment_id: paymentId, by: req.userId });
    await notify(req.params.id, 'payment', 'Выплата получена', `${owed}π отправлено на ваш Pi-кошелёк.`, null, null, { key: 'nPayoutSent', params: { amount: owed } }).catch(() => {});
    res.json({ success: true, paid: owed, txid });
  } catch (err) {
    // Surface the real A2U error to the admin instead of a generic 500.
    const msg = (err && (err.response?.data?.error_message || err.message)) || 'Payout failed';
    logger.error(`[a2u] owed payout failed for ${req.params.id}: ${msg}`);
    res.status(502).json({ error: `A2U payout failed: ${msg}` });
  }
});

// GET /api/admin/earnings
router.get('/api/admin/earnings', adminAuth, async (req, res) => {
  const timeout = new Promise(resolve => setTimeout(() => resolve(null), 12000));
  const work = (async () => {
    try {
      const fee = await getPlatformFee();
      const freelancerShare = parseFloat((1 - fee).toFixed(4));
      // Single combined query instead of 4 separate ones
      const [summary, recentPayments] = await Promise.all([
        query(`SELECT
          (SELECT COALESCE(SUM(amount),0) FROM escrows WHERE status='released') AS escrow_total,
          (SELECT COUNT(*) FROM payments) AS tx_count,
          (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='approved') AS pending_vol
        `),
        query(`SELECT p.id, p.user_id, p.type, p.amount, p.status, p.created_at, u.username AS client_name
               FROM payments p LEFT JOIN users u ON u.id = p.user_id
               ORDER BY p.created_at DESC LIMIT 30`),
      ]);
      const baseTotal = parseFloat(summary.rows[0].escrow_total);
      const total_earnings = parseFloat((baseTotal * fee).toFixed(8));
      const txCount = parseInt(summary.rows[0].tx_count);
      const payments = recentPayments.rows.map(p => ({
        ...p,
        freelancer_amount: parseFloat((parseFloat(p.amount || 0) * freelancerShare).toFixed(4)),
        developer_fee:     parseFloat((parseFloat(p.amount || 0) * fee).toFixed(4)),
      }));
      return {
        total_earnings, transactions: txCount, payments, history: payments,
        summary: {
          total_earnings, collected: total_earnings,
          total_transactions: txCount,
          pending_volume: parseFloat(summary.rows[0].pending_vol),
          average_transaction: txCount > 0 ? Math.round(total_earnings / txCount * 100) / 100 : 0,
        }
      };
    } catch (err) { logger.error('[admin/earnings]', err.message); return null; }
  })();
  const data = await Promise.race([work, timeout]);
  if (data) return res.json(data);
  return res.json({ total_earnings: 0, transactions: 0, payments: [], history: [], summary: { total_earnings:0, collected:0, total_transactions:0, pending_volume:0, average_transaction:0 }, _timeout: true });
});

// ─── Developer fee ──────────────────────────────────────────────
// GET /api/admin/developer-fee
router.get('/api/admin/developer-fee', adminAuth, async (req, res) => {
  try {
    const r = await query("SELECT value FROM platform_settings WHERE key = 'developer_fee_percent' LIMIT 1");
    const current = r.rows.length ? parseFloat(r.rows[0].value) : 0;
    res.json({ developerFeePercent: current, maxPercent: DEV_FEE_MAX * 100 });
  } catch (err) { serverError(err, res); }
});

// PATCH /api/admin/developer-fee
router.patch('/api/admin/developer-fee', adminAuth, async (req, res) => {
  const pct = parseFloat(req.body.percent);
  if (isNaN(pct) || pct < 0 || pct > DEV_FEE_MAX * 100) {
    return res.status(400).json({ error: `percent must be between 0 and ${DEV_FEE_MAX * 100}` });
  }
  try {
    await query(
      `INSERT INTO platform_settings (key, value, updated_at)
       VALUES ('developer_fee_percent', $1, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
      [String(pct)]
    );
    invalidatePlatformFeeCache();
    _statsCache = null;   // stats carry developerFeePercent — see PATCH /api/admin/settings
    _statsCacheTs = 0;
    await audit('admin_developer_fee_updated', { percent: pct, by: req.userId });
    res.json({ success: true, developerFeePercent: pct });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/audit-logs
router.get('/api/admin/audit-logs', adminAuth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 200, 1000));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const [result, total] = await Promise.all([
      query('SELECT id, action, data, created_at FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]),
      query('SELECT COUNT(*) FROM audit_logs'),
    ]);
    res.json({ logs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/verify — check if current credentials are valid admin
router.get('/api/admin/verify', async (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const rawKey = req.headers['x-admin-key'] || req.query.admin_key || '';
  let token = rawKey || (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader);
  const keyValid = timingSafeStrEqual(token, ADMIN_API_KEY);
  if (keyValid) return res.json({ valid: true });
  if (authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
      const jwtId = decoded.id || '';

      // Keyed on the JWT's *id*, never its username. Ids come from the
      // Pi-verified uid; the username claim was settable from the login request
      // body, and a signature only proves we issued the token. The old code also
      // promoted every row named 'cherry19899' from here, which handed a
      // permanent admin role to any impostor row and re-opened the hole that
      // middleware adminAuth had just been fixed to close.
      if (isOwnerId(jwtId)) {
        // Self-heal this row only — never a name-wide promote.
        query("UPDATE users SET role = 'admin' WHERE id = $1 AND role != 'admin'", [jwtId]).catch(() => {});
        return res.json({ valid: true });
      }

      const userRow = await query(
        'SELECT id, role FROM users WHERE id = $1 OR id = $2 LIMIT 1',
        [jwtId, 'pi_' + jwtId]
      );
      const ur = userRow.rows[0];
      if (!ur) return res.json({ valid: false });
      const isOwner = isOwnerId(ur.id);
      if (ur.role === 'admin' || isOwner) {
        if (ur.role !== 'admin' && isOwner) {
          await query("UPDATE users SET role = 'admin' WHERE id = $1", [ur.id]).catch(() => {});
        }
        return res.json({ valid: true });
      }
    } catch (_) {}
  }
  res.json({ valid: false });
});

// POST /api/admin/bootstrap-owner — one-time: grant admin to the owner's uid.
// Only promotes, never demotes; does nothing if already admin; idempotent.
// Targets the uid allowlist, NOT the username: usernames are not unique and were
// settable, so "promote everyone called cherry19899" handed admin to impostors.
router.post('/api/admin/bootstrap-owner', adminAuth, async (req, res) => {
  try {
    const result = await query(
      `UPDATE users SET role = 'admin', updated_at = NOW()
       WHERE id = ANY($1) AND role != 'admin'
       RETURNING id, username, role`,
      [OWNER_UIDS]
    );
    if (result.rows.length === 0) {
      const already = await query('SELECT id, username, role FROM users WHERE id = ANY($1)', [OWNER_UIDS]);
      return res.json({ message: 'Already admin or user not found', rows: already.rows });
    }
    res.json({ message: 'Owner promoted to admin', updated: result.rows });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/merge-users — merge duplicate user accounts (from_id → to_id)
router.post('/api/admin/merge-users', adminAuth, async (req, res) => {
  const { from_id, to_id } = req.body;
  if (!from_id || !to_id) return res.status(400).json({ error: 'from_id and to_id required' });
  if (from_id === to_id) return res.status(400).json({ error: 'Cannot merge user with itself' });
  try {
    const [fromRow, toRow] = await Promise.all([
      query('SELECT * FROM users WHERE id = $1', [from_id]),
      query('SELECT * FROM users WHERE id = $1', [to_id]),
    ]);
    if (!fromRow.rows.length) return res.status(404).json({ error: `User ${from_id} not found` });
    if (!toRow.rows.length) return res.status(404).json({ error: `User ${to_id} not found` });
    const from = fromRow.rows[0];
    const to = toRow.rows[0];
    const pgM = await getPool().connect();
    try {
      await pgM.query('BEGIN');
      // Transfer connects and pi balance
      await pgM.query(
        'UPDATE users SET balance_connects = balance_connects + $1, balance_pi = COALESCE(balance_pi,0) + $2, total_jobs_posted = total_jobs_posted + $3, total_jobs_completed = total_jobs_completed + $4, updated_at = NOW() WHERE id = $5',
        [from.balance_connects || 0, parseFloat(from.balance_pi || 0), from.total_jobs_posted || 0, from.total_jobs_completed || 0, to_id]
      );
      // Safe per-statement update: a SAVEPOINT lets us swallow a failure
      // (e.g. unique-index violation) without aborting the whole transaction.
      // A plain .catch() does NOT do this — once any statement errors, Postgres
      // marks the tx aborted and every later query + COMMIT fails.
      const safeUpdate = async (tbl, col) => {
        await pgM.query('SAVEPOINT sp');
        try {
          await pgM.query(`UPDATE ${tbl} SET ${col} = $1 WHERE ${col} = $2`, [to_id, from_id]);
          await pgM.query('RELEASE SAVEPOINT sp');
        } catch (e) {
          await pgM.query('ROLLBACK TO SAVEPOINT sp');
          // This savepoint exists to swallow the one expected failure — a
          // unique-index collision (chat_rooms etc). Anything else (a
          // dropped connection, a locked row) is a real failure that would
          // otherwise leave from_id's rows silently un-repointed while
          // from_id gets deleted a few statements later, orphaning them.
          if (e.code !== '23505') throw e;
        }
      };
      // Re-point straightforward FK references first
      const tables = [
        ['jobs', 'posted_by'], ['jobs', 'hired_freelancer_id'],
        ['applications', 'freelancer_id'], ['applications', 'client_id'],
        ['escrows', 'client_id'], ['escrows', 'freelancer_id'], ['payments', 'user_id'],
        ['ratings', 'from_user_id'], ['ratings', 'to_user_id'], ['notifications', 'user_id'],
        ['chat_messages', 'sender_id'], ['portfolio_items', 'user_id'],
      ];
      for (const [tbl, col] of tables) {
        await safeUpdate(tbl, col);
      }
      // chat_rooms needs collision-aware merge: the partial unique indexes on
      // (client_id, freelancer_id, job_id) mean renaming from_id → to_id can
      // duplicate an existing room. For each from_id room, if a matching to_id
      // room already exists, move its messages there and drop the dup; otherwise
      // just re-point the column.
      const mergeRoomsForCol = async (col, otherCol) => {
        const rooms = await pgM.query(
          `SELECT id, client_id, freelancer_id, job_id FROM chat_rooms WHERE ${col} = $1`,
          [from_id]
        );
        for (const room of rooms.rows) {
          const newClient = col === 'client_id' ? to_id : room.client_id;
          const newFreelancer = col === 'freelancer_id' ? to_id : room.freelancer_id;
          // Find an existing surviving room with the same identity tuple
          const survivor = await pgM.query(
            `SELECT id FROM chat_rooms
             WHERE client_id = $1 AND freelancer_id = $2
               AND ((job_id IS NULL AND $3::int IS NULL) OR job_id = $3)
               AND id <> $4
             LIMIT 1`,
            [newClient, newFreelancer, room.job_id, room.id]
          );
          await pgM.query('SAVEPOINT sp');
          try {
            if (survivor.rows.length) {
              const keepId = survivor.rows[0].id;
              await pgM.query('UPDATE chat_messages SET room_id = $1 WHERE room_id = $2', [keepId, room.id]);
              await pgM.query('DELETE FROM chat_rooms WHERE id = $1', [room.id]);
            } else {
              await pgM.query(`UPDATE chat_rooms SET ${col} = $1 WHERE id = $2`, [to_id, room.id]);
            }
            await pgM.query('RELEASE SAVEPOINT sp');
          } catch (e) {
            await pgM.query('ROLLBACK TO SAVEPOINT sp');
            if (e.code !== '23505') throw e;
          }
        }
      };
      await mergeRoomsForCol('client_id', 'freelancer_id');
      await mergeRoomsForCol('freelancer_id', 'client_id');
      // Sweep any leftover rooms/messages still pointing at from_id
      await safeUpdate('chat_rooms', 'client_id');
      await safeUpdate('chat_rooms', 'freelancer_id');
      // Merge portfolio (one row per user — keep primary's, fill blanks from secondary's)
      await pgM.query('SAVEPOINT sp');
      try {
        const fromPortfolio = await pgM.query('SELECT * FROM portfolios WHERE user_id = $1', [from_id]);
        if (fromPortfolio.rows.length) {
          const fp = fromPortfolio.rows[0];
          await pgM.query(
            `INSERT INTO portfolios (user_id, headline, summary, experience_years, website, github, linkedin)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (user_id) DO UPDATE SET
               headline       = COALESCE(NULLIF(portfolios.headline,''), EXCLUDED.headline),
               summary        = COALESCE(NULLIF(portfolios.summary,''), EXCLUDED.summary),
               experience_years = CASE WHEN portfolios.experience_years = 0 THEN EXCLUDED.experience_years ELSE portfolios.experience_years END,
               website        = COALESCE(NULLIF(portfolios.website,''), EXCLUDED.website),
               github         = COALESCE(NULLIF(portfolios.github,''), EXCLUDED.github),
               linkedin       = COALESCE(NULLIF(portfolios.linkedin,''), EXCLUDED.linkedin),
               updated_at     = NOW()`,
            [to_id, fp.headline||'', fp.summary||'', fp.experience_years||0, fp.website||'', fp.github||'', fp.linkedin||'']
          );
          await pgM.query('DELETE FROM portfolios WHERE user_id = $1', [from_id]);
        }
        await pgM.query('RELEASE SAVEPOINT sp');
      } catch (e) {
        // The INSERT already handles the one expected collision via
        // ON CONFLICT, so there is nothing legitimate left for this to
        // swallow — anything reaching here is a real failure and merge-users
        // is about to delete from_id, which would silently lose their
        // portfolio data if this were absorbed instead of raised.
        await pgM.query('ROLLBACK TO SAVEPOINT sp');
        throw e;
      }

      // If from was admin, promote to
      if (from.role === 'admin') {
        await pgM.query("UPDATE users SET role = 'admin' WHERE id = $1", [to_id]);
      }
      await pgM.query('DELETE FROM users WHERE id = $1', [from_id]);
      await pgM.query('COMMIT');
    } catch (e) { await pgM.query('ROLLBACK').catch(() => {}); throw e; }
    finally { pgM.release(); }
    res.json({ success: true, merged: from_id, into: to_id });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/settings — returns all platform settings
router.get('/api/admin/settings', adminAuth, async (req, res) => {
  try {
    const result = await query('SELECT key, value, updated_at, updated_by FROM platform_settings ORDER BY key');
    // Also return the current effective fee so the UI can show it immediately
    const fee = await getPlatformFee();
    res.json({
      settings: result.rows,
      effective: { platform_fee_percent: parseFloat((fee * 100).toFixed(4)) },
    });
  } catch (err) { serverError(err, res); }
});

// PATCH /api/admin/settings — update a platform setting (whitelisted keys only)
const SETTINGS_WHITELIST = {
  platform_fee_percent:   { min: 0, max: FEE_MAX * 100,     label: 'Platform fee %' },
  developer_fee_percent:  { min: 0, max: DEV_FEE_MAX * 100, label: 'Developer fee %' },
  connect_price_base:     { min: 0.001, max: 10,            label: 'Connect price base (Pi)' },
  min_job_budget:         { min: 0.1,   max: 1000,          label: 'Minimum job budget (Pi)' },
  max_job_budget:         { min: 100,   max: 1000000,        label: 'Maximum job budget (Pi)' },
  // Applying costs 1 connect per this many Pi of budget, minimum 1. Lowering it
  // makes applying more expensive, which is the lever against spray-and-pray
  // applications.
  apply_cost_divisor:     { min: 1,     max: 1000,           label: 'Pi of budget per connect to apply' },
  post_job_cost:          { min: 0,     max: 50,             label: 'Connects to post a job' },
};

// Settings that hold text rather than a number. Kept separate because the
// numeric path parses with parseFloat and would turn any URL into NaN.
const TEXT_SETTINGS = {
  support_url: {
    label: 'Support site URL',
    maxLength: 300,
    // Only http(s). A javascript: or data: URL here would be handed straight to
    // every user's browser from a screen they trust.
    validate: (v) => v === '' || /^https?:\/\/[^\s]+$/i.test(v),
    hint: 'must start with http:// or https://',
  },
};
router.patch('/api/admin/settings', adminAuth, async (req, res) => {
  const { key, value } = req.body;
  if (!key || value === undefined || value === null) {
    return res.status(400).json({ error: 'key and value required' });
  }
  const textRule = TEXT_SETTINGS[key];
  if (textRule) {
    const raw = String(value).trim();
    if (raw.length > textRule.maxLength) {
      return res.status(400).json({ error: `${textRule.label} is too long (max ${textRule.maxLength})` });
    }
    if (!textRule.validate(raw)) {
      return res.status(400).json({ error: `${textRule.label} ${textRule.hint}` });
    }
    try {
      await query(
        `INSERT INTO platform_settings (key, value, updated_at, updated_by)
         VALUES ($1, $2, NOW(), $3)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
        [key, raw, req.userId || 'admin']
      );
      invalidateSupportUrlCache();
      await audit('admin_setting_changed', { key, new_value: raw, by: req.userId });
      return res.json({ success: true, key, value: raw });
    } catch (err) { return serverError(err, res); }
  }

  const rule = SETTINGS_WHITELIST[key];
  if (!rule) {
    const allowed = [...Object.keys(SETTINGS_WHITELIST), ...Object.keys(TEXT_SETTINGS)].join(', ');
    return res.status(400).json({ error: `Unknown setting key. Allowed: ${allowed}` });
  }
  const num = parseFloat(value);
  if (isNaN(num) || num < rule.min || num > rule.max) {
    return res.status(400).json({ error: `${rule.label} must be between ${rule.min} and ${rule.max}` });
  }
  const strVal = num.toString();
  try {
    const old = await query("SELECT value FROM platform_settings WHERE key = $1", [key]);
    const oldVal = old.rows[0]?.value ?? null;
    await query(
      `INSERT INTO platform_settings (key, value, updated_at, updated_by)
       VALUES ($1, $2, NOW(), $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
      [key, strVal, req.userId || 'admin']
    );
    invalidatePlatformFeeCache();
    invalidateConnectsEconomyCache();
    // The stats payload carries platformFeePercent and is cached for 5 minutes.
    // Without dropping it here the admin saves a new fee, reloads Stats, and is
    // served the old percentage — indistinguishable from the save having failed.
    _statsCache = null;
    _statsCacheTs = 0;
    await audit('admin_setting_changed', { key, old_value: oldVal, new_value: strVal, by: req.userId });
    const fee = await getPlatformFee();
    const devFee = await getDeveloperFee();
    res.json({
      success: true,
      key,
      value: strVal,
      effective: {
        platform_fee_percent: parseFloat((fee * 100).toFixed(4)),
        developer_fee_percent: parseFloat((devFee * 100).toFixed(4)),
      },
    });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/twin-pairs — list all duplicate account pairs sharing the same canonical uid
// canonical uid = 'pi_' + regexp_replace(id, '^(pi_)+', '')
// e.g.: cherry19899 → pi_cherry19899; pi_pi_X → pi_X
router.get('/api/admin/twin-pairs', adminAuth, async (req, res) => {
  try {
    const result = await query(`
      WITH canonical AS (
        SELECT id, username, balance_connects, bio,
               'pi_' || regexp_replace(id, '^(pi_)+', '') AS cid
        FROM users
      )
      SELECT c1.id AS canonical_id, c1.username AS canonical_username,
             c1.balance_connects AS canonical_connects, c1.bio AS canonical_bio,
             c2.id AS twin_id, c2.username AS twin_username,
             c2.balance_connects AS twin_connects, c2.bio AS twin_bio
      FROM canonical c1
      JOIN canonical c2 ON c1.cid = c2.cid AND c1.id <> c2.id
      WHERE c1.id = c1.cid   -- c1 IS the canonical form
        AND c2.id <> c2.cid  -- c2 is NOT canonical
      ORDER BY c1.id
    `);
    res.json({ pairs: result.rows, count: result.rows.length });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/auto-merge-twins — merge all duplicate pairs into their canonical uid
// Uses same canonical logic: 'pi_' + regexp_replace(id, '^(pi_)+', '')
router.post('/api/admin/auto-merge-twins', adminAuth, async (req, res) => {
  try {
    const pairs = await query(`
      WITH canonical AS (
        SELECT id, 'pi_' || regexp_replace(id, '^(pi_)+', '') AS cid
        FROM users
      )
      SELECT c1.id AS canonical_id, c2.id AS twin_id
      FROM canonical c1
      JOIN canonical c2 ON c1.cid = c2.cid AND c1.id <> c2.id
      WHERE c1.id = c1.cid
        AND c2.id <> c2.cid
      ORDER BY c1.id
    `);
    if (!pairs.rows.length) return res.json({ success: true, merged: 0, pairs: [] });

    const results = [];
    for (const { canonical_id, twin_id } of pairs.rows) {
      try {
        const [fromRow, toRow] = await Promise.all([
          query('SELECT * FROM users WHERE id = $1', [twin_id]),
          query('SELECT * FROM users WHERE id = $1', [canonical_id]),
        ]);
        if (!fromRow.rows.length || !toRow.rows.length) {
          results.push({ canonical_id, twin_id, status: 'skipped_not_found' });
          continue;
        }
        const from = fromRow.rows[0];
        const pgM = await getPool().connect();
        try {
          await pgM.query('BEGIN');
          await pgM.query(
            `UPDATE users SET
               balance_connects     = balance_connects + $1,
               balance_pi           = COALESCE(balance_pi,0) + $2,
               total_jobs_posted    = total_jobs_posted + $3,
               total_jobs_completed = total_jobs_completed + $4,
               bio     = COALESCE(NULLIF(bio,''), $5),
               skills  = COALESCE(NULLIF(skills,''), $6),
               avatar  = COALESCE(NULLIF(avatar,''), $7),
               rating  = CASE WHEN rating = 0 THEN $8 ELSE rating END,
               kyc_verified = (kyc_verified OR $9),
               updated_at = NOW()
             WHERE id = $10`,
            [from.balance_connects||0, parseFloat(from.balance_pi||0),
             from.total_jobs_posted||0, from.total_jobs_completed||0,
             from.bio||'', from.skills||'', from.avatar||'',
             parseFloat(from.rating||0), from.kyc_verified||false, canonical_id]
          );
          const safeUpd = async (tbl, col) => {
            await pgM.query('SAVEPOINT sp');
            try {
              await pgM.query(`UPDATE ${tbl} SET ${col} = $1 WHERE ${col} = $2`, [canonical_id, twin_id]);
              await pgM.query('RELEASE SAVEPOINT sp');
            } catch (e) {
              await pgM.query('ROLLBACK TO SAVEPOINT sp');
              // Only a unique-index collision is expected here; anything else
              // is a real failure and the outer per-pair catch below already
              // rolls back and reports it instead of deleting twin_id with
              // this table's rows left un-repointed.
              if (e.code !== '23505') throw e;
            }
          };
          const fkCols = [
            ['jobs', 'posted_by'], ['jobs', 'hired_freelancer_id'],
            ['applications', 'freelancer_id'], ['applications', 'client_id'],
            ['escrows', 'client_id'], ['escrows', 'freelancer_id'],
            ['payments', 'user_id'], ['ratings', 'from_user_id'], ['ratings', 'to_user_id'],
            ['notifications', 'user_id'], ['chat_messages', 'sender_id'],
            ['chat_rooms', 'client_id'], ['chat_rooms', 'freelancer_id'],
            ['portfolio_items', 'user_id'],
          ];
          for (const [tbl, col] of fkCols) await safeUpd(tbl, col);

          // Portfolio merge
          await pgM.query('SAVEPOINT sp');
          try {
            const fp = await pgM.query('SELECT * FROM portfolios WHERE user_id = $1', [twin_id]);
            if (fp.rows.length) {
              const p = fp.rows[0];
              await pgM.query(
                `INSERT INTO portfolios (user_id, headline, summary, experience_years, website, github, linkedin)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)
                 ON CONFLICT (user_id) DO UPDATE SET
                   headline=COALESCE(NULLIF(portfolios.headline,''),EXCLUDED.headline),
                   summary=COALESCE(NULLIF(portfolios.summary,''),EXCLUDED.summary),
                   experience_years=CASE WHEN portfolios.experience_years=0 THEN EXCLUDED.experience_years ELSE portfolios.experience_years END,
                   website=COALESCE(NULLIF(portfolios.website,''),EXCLUDED.website),
                   github=COALESCE(NULLIF(portfolios.github,''),EXCLUDED.github),
                   linkedin=COALESCE(NULLIF(portfolios.linkedin,''),EXCLUDED.linkedin),
                   updated_at=NOW()`,
                [canonical_id, p.headline||'', p.summary||'', p.experience_years||0, p.website||'', p.github||'', p.linkedin||'']
              );
              await pgM.query('DELETE FROM portfolios WHERE user_id=$1', [twin_id]);
            }
            await pgM.query('RELEASE SAVEPOINT sp');
          } catch (e) {
            await pgM.query('ROLLBACK TO SAVEPOINT sp');
            throw e;
          }

          if (from.role === 'admin') await pgM.query("UPDATE users SET role='admin' WHERE id=$1", [canonical_id]);
          await pgM.query('DELETE FROM users WHERE id = $1', [twin_id]);
          await pgM.query('COMMIT');
          results.push({ canonical_id, twin_id, status: 'merged', connects_moved: from.balance_connects||0 });
        } catch (e) {
          await pgM.query('ROLLBACK').catch(() => {});
          results.push({ canonical_id, twin_id, status: 'error', error: e.message });
        } finally { pgM.release(); }
      } catch (e) {
        results.push({ canonical_id, twin_id: twin_id||'?', status: 'error', error: e.message });
      }
    }
    await audit('auto_merge_twins', { results });
    res.json({ success: true, merged: results.filter(r => r.status === 'merged').length, pairs: results });
  } catch (err) { serverError(err, res); }
});

// In-memory cache for analytics (1-hour TTL)
let _analyticsCache = null;
let _analyticsCacheTs = 0;
const ANALYTICS_TTL = 60 * 60 * 1000;

// GET /api/admin/analytics — daily active users, job stats, revenue, top categories
router.get('/api/admin/analytics', adminAuth, async (req, res) => {
  const now = Date.now();
  if (_analyticsCache && (now - _analyticsCacheTs) < ANALYTICS_TTL) {
    return res.json({ ..._analyticsCache, cached: true });
  }
  const timeout = new Promise(resolve => setTimeout(() => resolve(null), 12000));
  const work = (async () => {
    try {
      const fee = await getPlatformFee();
      // 7 separate simple queries — no GROUP BY DISTINCT, no complex joins
      const days = [0,1,2,3,4,5,6].map(d =>
        query(`SELECT COUNT(*) AS count FROM jobs WHERE created_at::date = (NOW() - INTERVAL '${d} days')::date`)
          .then(r => ({ day: d, jobs: parseInt(r.rows[0].count) }))
      );
      const [
        jobStats, revenueRow, topCategories, newUsers7d, newJobs7d,
        ...dailyJobsArr
      ] = await Promise.all([
        query(`SELECT status, COUNT(*) AS count FROM jobs GROUP BY status ORDER BY count DESC`),
        query(`SELECT COALESCE(SUM(amount),0) AS total FROM escrows WHERE status='released'`),
        query(`SELECT category, COUNT(*) AS count FROM jobs WHERE category IS NOT NULL AND category <> '' GROUP BY category ORDER BY count DESC LIMIT 10`),
        query(`SELECT COUNT(*) AS count FROM users WHERE created_at >= NOW() - INTERVAL '7 days'`),
        query(`SELECT COUNT(*) AS count FROM jobs WHERE created_at >= NOW() - INTERVAL '7 days'`),
        ...days,
      ]);
      const totalRevenue = parseFloat(revenueRow.rows[0].total);
      return {
        daily_active_users: dailyJobsArr.map(d => ({ day: d.day, active_users: d.jobs })),
        job_stats: jobStats.rows,
        revenue: {
          total_escrow_released: totalRevenue,
          platform_fee_percent: parseFloat((fee * 100).toFixed(4)),
          platform_earnings: parseFloat((totalRevenue * fee).toFixed(8)),
        },
        top_categories: topCategories.rows,
        last_7_days: {
          new_users: parseInt(newUsers7d.rows[0].count),
          new_jobs: parseInt(newJobs7d.rows[0].count),
        },
      };
    } catch (err) { logger.error('[admin/analytics]', err.message); return null; }
  })();
  const data = await Promise.race([work, timeout]);
  if (data) {
    _analyticsCache = data;
    _analyticsCacheTs = Date.now();
    return res.json(data);
  }
  if (_analyticsCache) return res.json({ ..._analyticsCache, cached: true, _stale: true });
  return res.json({ status: 'loading', retry_after: 5 });
});

// POST /api/admin/backup/trigger — run a DB backup now (for external cron-job.org trigger)
router.post('/api/admin/backup/trigger', adminAuth, async (req, res) => {
  try {
    const { run } = require('../scripts/backup');
    const result = await run();
    await audit('backup_triggered', { ...result, by: req.userId });
    res.json({ success: true, ...result });
  } catch (err) {
    logger.error('[backup] trigger error:', err.message);
    await audit('backup_failed', { error: err.message, by: req.userId }).catch(() => {});
    res.status(500).json({ error: 'Backup failed', detail: err.message });
  }
});

// POST /api/admin/payments/sweep-stuck — reconcile pending payments against Pi now,
// instead of waiting for the hourly sweep.
router.post('/api/admin/payments/sweep-stuck', adminAuth, async (req, res) => {
  try {
    const { sweepStuckPayments } = require('../src/stuck-payments');
    const result = await sweepStuckPayments(logger);
    await audit('stuck_payments_swept', { ...result, by: req.userId });
    res.json({ success: true, ...result });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/payments/stuck — list pending payments the sweep would look at
router.get('/api/admin/payments/stuck', adminAuth, async (req, res) => {
  try {
    const r = await query(
      `SELECT p.id, p.user_id, u.username, p.type, p.amount, p.created_at,
              ROUND(EXTRACT(EPOCH FROM (NOW() - p.created_at)) / 3600, 1) AS age_hours
         FROM payments p
         LEFT JOIN users u ON u.id = p.user_id
        WHERE p.status = 'pending'
          AND p.created_at < NOW() - INTERVAL '15 minutes'
        ORDER BY p.created_at ASC
        LIMIT 200`
    );
    res.json({ stuck: r.rows, count: r.rows.length });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/rate-limits — list IPs currently tracked as blocked
router.get('/api/admin/rate-limits', adminAuth, (req, res) => {
  const blocks = [];
  for (const [ip, info] of _rlBlocks.entries()) {
    blocks.push({ ip, ...info });
  }
  blocks.sort((a, b) => b.count - a.count);
  res.json({ blocks, total: blocks.length });
});

// POST /api/admin/rate-limits/unblock — clear a blocked IP from the tracker
router.post('/api/admin/rate-limits/unblock', adminAuth, async (req, res) => {
  const { ip } = req.body;
  if (!ip || typeof ip !== 'string') return res.status(400).json({ error: 'ip required' });
  const had = _rlBlocks.has(ip);
  _rlBlocks.delete(ip);
  await audit('rate_limit_unblock', { ip, by: req.userId });
  res.json({ success: true, was_blocked: had });
});

// GET /api/admin/payments — paginated list of all payments with optional status filter
router.get('/api/admin/payments', adminAuth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  const status = req.query.status;
  try {
    const where = status ? 'WHERE status = $3' : '';
    const params = status ? [limit, offset, status] : [limit, offset];
    const rows = await query(
      `SELECT p.*, u.username FROM payments p LEFT JOIN users u ON p.user_id = u.id ${where} ORDER BY p.created_at DESC LIMIT $1 OFFSET $2`,
      params
    );
    const total = await query(
      `SELECT COUNT(*) FROM payments${status ? ' WHERE status = $1' : ''}`,
      status ? [status] : []
    );
    res.json({ payments: rows.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/bulk-block
router.post('/api/admin/users/bulk-block', adminAuth, async (req, res) => {
  const { user_ids } = req.body;
  if (!Array.isArray(user_ids) || user_ids.length === 0) return res.status(400).json({ error: 'user_ids array required' });
  if (user_ids.length > 100) return res.status(400).json({ error: 'Max 100 users per request' });
  // isOwnerId, not a local copy of the list: the copies drifted apart and one
  // went stale, which is how two of the owner's real uids ended up outside every
  // owner check in the codebase.
  const safe = user_ids.filter(id => !isOwnerId(id));
  const skipped = user_ids.length - safe.length;
  if (safe.length === 0) return res.status(403).json({ error: 'Cannot block owner account(s)' });
  // The single-user block route also blocks the id's "pi_" twin (same person,
  // duplicate account) — bulk-block skipped that, so a bulk-blocked user could
  // just log in as their unblocked twin and keep going, since /api/auth/login
  // checks is_blocked on the exact login uid only, not twin-aware.
  const ids = [...new Set(safe.flatMap(id => [id, twinId(id)]))];
  try {
    await query(
      `UPDATE users SET is_blocked = true, status = 'blocked', updated_at = NOW() WHERE id = ANY($1::text[])`,
      [ids]
    );
    await audit('bulk_user_blocked', { user_ids: safe, count: safe.length, skipped_owner: skipped, by: req.userId });
    res.json({ success: true, blocked: safe.length, skipped_owner: skipped });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/bulk-unblock
router.post('/api/admin/users/bulk-unblock', adminAuth, async (req, res) => {
  const { user_ids } = req.body;
  if (!Array.isArray(user_ids) || user_ids.length === 0) return res.status(400).json({ error: 'user_ids array required' });
  if (user_ids.length > 100) return res.status(400).json({ error: 'Max 100 users per request' });
  // Mirror bulk-block's twin handling — otherwise an admin unblocks a user,
  // sees success, but the "pi_" twin (blocked by bulk-block above) is still
  // blocked and the user still can't log in under that id.
  const ids = [...new Set(user_ids.flatMap(id => [id, twinId(id)]))];
  try {
    await query(
      `UPDATE users SET is_blocked = false, status = 'active', updated_at = NOW() WHERE id = ANY($1::text[])`,
      [ids]
    );
    await audit('bulk_user_unblocked', { user_ids, count: user_ids.length, by: req.userId });
    res.json({ success: true, unblocked: user_ids.length });
  } catch (err) { serverError(err, res); }
});

// ─── Analytics: daily signups / revenue / jobs over time ─────────────────────

// GET /api/admin/analytics/signups?days=30
router.get('/api/admin/analytics/signups', adminAuth, async (req, res) => {
  const days = Math.min(365, Math.max(7, parseInt(req.query.days) || 30));
  try {
    const r = await query(`
      SELECT DATE(created_at) AS date, COUNT(*) AS count
      FROM users
      WHERE created_at >= NOW() - INTERVAL '${days} days'
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `);
    res.json({ data: r.rows, days });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/analytics/revenue?days=30
router.get('/api/admin/analytics/revenue', adminAuth, async (req, res) => {
  const days = Math.min(365, Math.max(7, parseInt(req.query.days) || 30));
  try {
    const [daily, byCategory] = await Promise.all([
      query(`
        SELECT DATE(created_at) AS date, COALESCE(SUM(amount),0) AS amount, COUNT(*) AS count
        FROM payments WHERE status='completed' AND created_at >= NOW() - INTERVAL '${days} days'
        GROUP BY DATE(created_at) ORDER BY date ASC
      `),
      query(`
        SELECT j.category, COUNT(e.id) AS count, COALESCE(SUM(e.amount),0) AS volume
        FROM escrows e LEFT JOIN jobs j ON j.id=e.job_id
        WHERE e.status IN ('released','completed')
        GROUP BY j.category ORDER BY volume DESC
      `),
    ]);
    res.json({ daily: daily.rows, by_category: byCategory.rows, days });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/analytics/jobs?days=30
router.get('/api/admin/analytics/jobs', adminAuth, async (req, res) => {
  const days = Math.min(365, Math.max(7, parseInt(req.query.days) || 30));
  try {
    const [daily, byCategory, funnel] = await Promise.all([
      query(`SELECT DATE(created_at) AS date, COUNT(*) AS count FROM jobs WHERE created_at >= NOW() - INTERVAL '${days} days' GROUP BY DATE(created_at) ORDER BY date ASC`),
      query(`SELECT category, COUNT(*) AS count FROM jobs GROUP BY category ORDER BY count DESC`),
      query(`
        SELECT
          (SELECT COUNT(*) FROM users) AS total_users,
          (SELECT COUNT(*) FROM jobs) AS total_jobs,
          (SELECT COUNT(*) FROM applications) AS total_applications,
          (SELECT COUNT(*) FROM escrows WHERE status != 'pending') AS total_hires,
          (SELECT COUNT(*) FROM escrows WHERE status IN ('released','completed')) AS total_completed,
          (SELECT COUNT(*) FROM ratings) AS total_reviews
      `),
    ]);
    res.json({ daily: daily.rows, by_category: byCategory.rows, funnel: funnel.rows[0], days });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/analytics/retention
router.get('/api/admin/analytics/retention', adminAuth, async (req, res) => {
  try {
    const r = await query(`
      SELECT
        COUNT(CASE WHEN last_active >= NOW()-INTERVAL '1 day'  THEN 1 END)  AS dau,
        COUNT(CASE WHEN last_active >= NOW()-INTERVAL '7 days' THEN 1 END)  AS wau,
        COUNT(CASE WHEN last_active >= NOW()-INTERVAL '30 days' THEN 1 END) AS mau,
        COUNT(CASE WHEN last_active < NOW()-INTERVAL '30 days' THEN 1 END)  AS churned,
        COUNT(*) AS total
      FROM users WHERE status != 'deleted'
    `);
    res.json(r.rows[0] || {});
  } catch (err) { serverError(err, res); }
});

// ─── CSV Export ───────────────────────────────────────────────────────────────

function toCSV(rows) {
  if (!rows || !rows.length) return '';
  const headers = Object.keys(rows[0]);
  const escape = v => {
    if (v == null) return '';
    let s = String(v);
    // A username/category/etc starting with =, +, -, @ (or a tab/CR) is
    // interpreted as a formula by Excel/Sheets when the export is opened —
    // prefix with a quote to defuse it (standard CSV-injection mitigation).
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    s = s.replace(/"/g, '""');
    return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s}"` : s;
  };
  return [
    headers.join(','),
    ...rows.map(r => headers.map(h => escape(r[h])).join(',')),
  ].join('\n');
}

// GET /api/admin/export/:table — CSV export
router.get('/api/admin/export/:table', adminAuth, async (req, res) => {
  const ALLOWED = { users: 'users', jobs: 'jobs', escrows: 'escrows', payments: 'payments', reviews: 'ratings', applications: 'applications' };
  const table = ALLOWED[req.params.table];
  if (!table) return res.status(400).json({ error: `Unknown table. Allowed: ${Object.keys(ALLOWED).join(', ')}` });
  try {
    // parseInt('-1') is truthy, so without a floor here ?limit=-1 reaches
    // Postgres as `LIMIT -1`, which errors ("LIMIT must not be negative")
    // and isn't in CLIENT_DATA_ERRORS, surfacing as a raw 500 instead of 400.
    const limit = Math.min(10000, Math.max(1, parseInt(req.query.limit) || 1000));
    const r = await query(`SELECT * FROM ${table} ORDER BY created_at DESC LIMIT $1`, [limit]);
    const csv = toCSV(r.rows);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${table}_export_${new Date().toISOString().slice(0,10)}.csv"`);
    res.send(csv);
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/realtime — live counts for dashboard WebSocket (polling fallback)
router.get('/api/admin/realtime', adminAuth, async (req, res) => {
  try {
    const r = await query(`
      SELECT
        (SELECT COUNT(*) FROM users WHERE last_active >= NOW()-INTERVAL '5 minutes') AS online_now,
        (SELECT COUNT(*) FROM jobs WHERE created_at >= NOW()-INTERVAL '1 hour') AS jobs_last_hour,
        (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='completed' AND created_at >= NOW()-INTERVAL '24 hours') AS revenue_24h,
        (SELECT COUNT(*) FROM escrows WHERE status IN ('funded','active')) AS active_escrows
    `);
    res.json(r.rows[0]);
  } catch (err) { serverError(err, res); }
});

router.warmStats = warmStats;
module.exports = router;

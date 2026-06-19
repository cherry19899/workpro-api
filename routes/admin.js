/**
 * routes/admin.js — /api/admin/*
 */
const router = require('express').Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { query, getPool } = require('../src/db');
const { notify, audit, serverError } = require('../src/helpers');
const { adminAuth, JWT_SECRET, ADMIN_API_KEY } = require('../src/middleware');

const PLATFORM_FEE = Math.min(Math.max(parseFloat(process.env.PLATFORM_FEE_PERCENT || '2') / 100, 0), 0.5);

// GET /api/admin/stats
router.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [users, jobs, applications, escrows, activeEscrows, payments, revenue, ratings, chats, disputes] = await Promise.all([
      query('SELECT COUNT(*) FROM users'),
      query('SELECT COUNT(*) FROM jobs'),
      query('SELECT COUNT(*) FROM applications'),
      query('SELECT COUNT(*) FROM escrows'),
      query("SELECT COUNT(*) FROM escrows WHERE status IN ('pending','funded')"),
      query('SELECT COUNT(*) FROM payments'),
      query(`SELECT COALESCE(SUM(amount*${PLATFORM_FEE}),0) AS total FROM escrows WHERE status='released'`),
      query('SELECT COUNT(*) FROM ratings'),
      query('SELECT COUNT(*) FROM chat_rooms'),
      query("SELECT COUNT(*) FROM escrows WHERE status='disputed'"),
    ]);
    const u = parseInt(users.rows[0].count);
    const j = parseInt(jobs.rows[0].count);
    const a = parseInt(applications.rows[0].count);
    const e = parseInt(escrows.rows[0].count);
    const ae = parseInt(activeEscrows.rows[0].count);
    const rev = parseFloat(revenue.rows[0].total);
    res.json({
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
    });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/users
router.get('/api/admin/users', adminAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 500, 2000);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const search = req.query.search || '';
    if (search.length > 200) return res.status(400).json({ error: 'Search query too long (max 200 chars)' });
    const safeFields = 'id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at';
    let sql, params = [];
    if (search) {
      sql = `SELECT ${safeFields} FROM users WHERE username ILIKE $1 OR id ILIKE $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`;
      params = [`%${search}%`, limit, offset];
    } else {
      sql = `SELECT ${safeFields} FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`;
      params = [limit, offset];
    }
    const result = await query(sql, params);
    const totalSql = search
      ? 'SELECT COUNT(*) FROM users WHERE username ILIKE $1 OR id ILIKE $1'
      : 'SELECT COUNT(*) FROM users';
    const total = await query(totalSql, search ? [`%${search}%`] : []);
    res.json({ users: result.rows, count: result.rows.length, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/block
router.post('/api/admin/users/:id/block', adminAuth, async (req, res) => {
  try {
    const target = await query('SELECT username FROM users WHERE id = $1', [req.params.id]);
    if (['cherry19899', 'pi_cherry19899'].includes(req.params.id) || target.rows[0]?.username === 'cherry19899') {
      return res.status(403).json({ error: 'Cannot block owner' });
    }
    await query('UPDATE users SET is_blocked = true, status = $1, updated_at = NOW() WHERE id = $2', ['blocked', req.params.id]);
    await audit('user_blocked', { user_id: req.params.id });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/unblock
router.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  try {
    await query('UPDATE users SET is_blocked = false, status = $1, updated_at = NOW() WHERE id = $2', ['active', req.params.id]);
    await audit('user_unblocked', { user_id: req.params.id });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/make-admin
router.post('/api/admin/users/:id/make-admin', adminAuth, async (req, res) => {
  try {
    await query("UPDATE users SET role = 'admin', updated_at = NOW() WHERE id = $1", [req.params.id]);
    await audit('user_made_admin', { user_id: req.params.id, by: req.userId });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/remove-admin
router.post('/api/admin/users/:id/remove-admin', adminAuth, async (req, res) => {
  try {
    const target = await query('SELECT username FROM users WHERE id = $1', [req.params.id]);
    if (req.params.id === 'cherry19899' || req.params.id === 'pi_cherry19899' || target.rows[0]?.username === 'cherry19899') {
      return res.status(403).json({ error: 'Cannot remove owner admin' });
    }
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
    await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [qty, req.params.id]);
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.params.id]);
    await audit('admin_grant_connects', { user_id: req.params.id, amount: qty, granted_by: req.userId });
    res.json({ success: true, balance: result.rows[0]?.balance_connects || 0 });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/jobs
router.get('/api/admin/jobs', adminAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM jobs ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM jobs');
    res.json({ jobs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/jobs/all
router.get('/api/admin/jobs/all', adminAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
    const offset = parseInt(req.query.offset) || 0;
    const result = await query('SELECT j.*, u.username as posted_by_name FROM jobs j LEFT JOIN users u ON u.id = j.posted_by ORDER BY j.created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM jobs');
    res.json({ jobs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/admin/jobs/:id
router.delete('/api/admin/jobs/:id', adminAuth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  try {
    const fundedEscrow = await query("SELECT * FROM escrows WHERE job_id = $1 AND status = 'funded' LIMIT 1", [req.params.id]);
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
      await notify(esc.client_id, 'payment', 'Задача удалена администратором', 'Средства эскроу возвращены на ваш баланс.', parseInt(req.params.id), null).catch(() => {});
      if (esc.freelancer_id) {
        await notify(esc.freelancer_id, 'info', 'Задача удалена администратором', 'Задача, над которой вы работали, была удалена администратором.', parseInt(req.params.id), null).catch(() => {});
      }
    }
    await audit('admin_job_deleted', { job_id: req.params.id, by: req.userId, escrow_refunded: fundedEscrow.rows.length > 0, connects_refunded: applicants.rows.length });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/escrows
router.get('/api/admin/escrows', adminAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    const result = await query(`
      SELECT e.*,
        uc.username AS client_name,
        uf.username AS freelancer_name,
        j.title AS job_title
      FROM escrows e
      LEFT JOIN users uc ON uc.id = e.client_id
      LEFT JOIN users uf ON uf.id = e.freelancer_id
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
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Escrow not found' });
  const { action, reason } = req.body;
  if (!['release_to_freelancer', 'refund_to_client'].includes(action)) {
    return res.status(400).json({ error: 'action must be release_to_freelancer or refund_to_client' });
  }
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.status !== 'disputed') return res.status(400).json({ error: `Escrow is not disputed (status: ${escrow.status})` });
    const pgC = await getPool().connect();
    try {
      await pgC.query('BEGIN');
      const guard = await pgC.query(
        "UPDATE escrows SET status=$1, updated_at=NOW() WHERE id=$2 AND status='disputed' RETURNING id",
        [action === 'release_to_freelancer' ? 'released' : 'refunded', req.params.id]
      );
      if (!guard.rows.length) { await pgC.query('ROLLBACK'); return res.status(409).json({ error: 'Escrow no longer disputed' }); }
      if (action === 'release_to_freelancer') {
        const net = parseFloat((escrow.amount * (1 - PLATFORM_FEE)).toFixed(8));
        await pgC.query('UPDATE users SET balance_pi = COALESCE(balance_pi,0) + $1, total_jobs_completed = total_jobs_completed + 1, updated_at=NOW() WHERE id=$2', [net, escrow.freelancer_id]);
        await pgC.query("UPDATE jobs SET status='completed', updated_at=NOW() WHERE id=$1", [escrow.job_id]);
      } else {
        await pgC.query('UPDATE users SET balance_pi = COALESCE(balance_pi,0) + $1, updated_at=NOW() WHERE id=$2', [escrow.amount, escrow.client_id]);
        await pgC.query("UPDATE jobs SET status='open', hired_freelancer_id=NULL, hired_freelancer_name=NULL, updated_at=NOW() WHERE id=$1", [escrow.job_id]);
      }
      await pgC.query('COMMIT');
    } catch (txErr) { await pgC.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgC.release(); }
    await audit('admin_dispute_resolved', { escrow_id: req.params.id, action, reason: reason || null, by: req.userId });
    await notify(escrow.client_id, 'dispute', 'Спор разрешён администратором', reason || `Решение: ${action}`, escrow.job_id, null).catch(() => {});
    await notify(escrow.freelancer_id, 'dispute', 'Спор разрешён администратором', reason || `Решение: ${action}`, escrow.job_id, null).catch(() => {});
    res.json({ success: true, action });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/earnings
router.get('/api/admin/earnings', adminAuth, async (req, res) => {
  try {
    const [result, transactions, pending, recentPayments] = await Promise.all([
      query(`SELECT COALESCE(SUM(amount*${PLATFORM_FEE}), 0) as total FROM escrows WHERE status = 'released'`),
      query('SELECT COUNT(*) FROM payments'),
      query("SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'approved'"),
      query(`
        SELECT p.*,
          u.username AS client_name,
          p.amount AS job_amount,
          CAST(ROUND(CAST(p.amount AS numeric) * ${(1 - PLATFORM_FEE).toFixed(4)}, 4) AS float) AS freelancer_amount,
          CAST(ROUND(CAST(p.amount AS numeric) * ${PLATFORM_FEE.toFixed(4)}, 4) AS float) AS developer_fee
        FROM payments p
        LEFT JOIN users u ON u.id = p.user_id
        ORDER BY p.created_at DESC LIMIT 50
      `),
    ]);
    const total_earnings = parseFloat(result.rows[0].total);
    const txCount = parseInt(transactions.rows[0].count);
    res.json({
      total_earnings,
      transactions: txCount,
      payments: recentPayments.rows,
      history: recentPayments.rows,
      summary: {
        total_earnings,
        collected: total_earnings,
        total_transactions: txCount,
        pending_volume: parseFloat(pending.rows[0].total),
        average_transaction: txCount > 0 ? Math.round(total_earnings / txCount * 100) / 100 : 0,
      }
    });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/audit-logs
router.get('/api/admin/audit-logs', adminAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM audit_logs');
    res.json({ logs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/verify — check if current credentials are valid admin
router.get('/api/admin/verify', async (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const rawKey = req.headers['x-admin-key'] || req.query.admin_key || '';
  let token = rawKey || (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader);
  const keyValid = token.length > 0 && token.length === ADMIN_API_KEY.length &&
    crypto.timingSafeEqual(Buffer.from(token), Buffer.from(ADMIN_API_KEY));
  if (keyValid) return res.json({ valid: true });
  if (authHeader.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(authHeader.slice(7), JWT_SECRET);
      const userRow = await query("SELECT id FROM users WHERE id = $1 AND role = 'admin' LIMIT 1", [decoded.id]);
      if (userRow.rows.length) return res.json({ valid: true });
    } catch (_) {}
  }
  res.json({ valid: false });
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
      // Re-point all FK references from old to new
      const tables = [
        ['jobs', 'posted_by'], ['applications', 'freelancer_id'], ['applications', 'client_id'],
        ['escrows', 'client_id'], ['escrows', 'freelancer_id'], ['payments', 'user_id'],
        ['ratings', 'from_user_id'], ['ratings', 'to_user_id'], ['notifications', 'user_id'],
        ['chat_rooms', 'client_id'], ['chat_rooms', 'freelancer_id'], ['chat_messages', 'sender_id'],
      ];
      for (const [tbl, col] of tables) {
        await pgM.query(`UPDATE ${tbl} SET ${col} = $1 WHERE ${col} = $2`, [to_id, from_id]).catch(() => {});
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

module.exports = router;

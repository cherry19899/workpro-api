/**
 * routes/admin.js — /api/admin/*
 */
const router = require('express').Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { query, getPool } = require('../src/db');
const { notify, audit, serverError } = require('../src/helpers');
const { adminAuth, twinId, JWT_SECRET, ADMIN_API_KEY } = require('../src/middleware');

const PLATFORM_FEE = Math.min(Math.max(parseFloat(process.env.PLATFORM_FEE_PERCENT || '2') / 100, 0), 0.1);

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
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 500, 2000));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
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
    const twin = twinId(req.params.id);
    // Guard the owner under either id form (with/without pi_ prefix).
    const target = await query('SELECT username FROM users WHERE id IN ($1, $2)', [req.params.id, twin]);
    const isOwner = ['cherry19899', 'pi_cherry19899'].includes(req.params.id) ||
      target.rows.some(r => r.username === 'cherry19899');
    if (isOwner) {
      return res.status(403).json({ error: 'Cannot block owner' });
    }
    // Block both duplicate-account twins so the block can't be bypassed by logging
    // in as the unblocked twin (same person, "pi_" prefix mismatch).
    await query('UPDATE users SET is_blocked = true, status = $1, updated_at = NOW() WHERE id IN ($2, $3)', ['blocked', req.params.id, twin]);
    await audit('user_blocked', { user_id: req.params.id });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/admin/users/:id/unblock
router.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  try {
    const twin = twinId(req.params.id);
    await query('UPDATE users SET is_blocked = false, status = $1, updated_at = NOW() WHERE id IN ($2, $3)', ['active', req.params.id, twin]);
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
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 100, 500));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query('SELECT * FROM jobs ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM jobs');
    res.json({ jobs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/admin/jobs/all
router.get('/api/admin/jobs/all', adminAuth, async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 200, 1000));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const result = await query('SELECT j.*, u.username as posted_by_name FROM jobs j LEFT JOIN users u ON u.id = j.posted_by ORDER BY j.created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const total = await query('SELECT COUNT(*) FROM jobs');
    res.json({ jobs: result.rows, total: parseInt(total.rows[0].count), limit, offset });
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
    const [userRow, payments, audit] = await Promise.all([
      query('SELECT id, username, balance_connects, updated_at FROM users WHERE id = $1', [userId]),
      query(`SELECT id, status, amount, type, metadata, txid, created_at, updated_at
             FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`, [userId]),
      query(`SELECT action, data, created_at FROM audit_logs
             WHERE data::text ILIKE $1 ORDER BY created_at DESC LIMIT 20`, [`%${userId}%`]),
    ]);
    if (!userRow.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({
      user: userRow.rows[0],
      payments: payments.rows,
      audit_logs: audit.rows,
    });
  } catch (err) { serverError(err, res); }
});

// PATCH /api/admin/jobs/:id/images — used by the image migration script to swap
// base64 payloads for static file URLs without touching any other job fields.
router.patch('/api/admin/jobs/:id/images', adminAuth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  const { images } = req.body;
  if (!Array.isArray(images)) return res.status(400).json({ error: 'images must be an array' });
  try {
    const serialized = images.length > 0 ? JSON.stringify(images) : null;
    const r = await query('UPDATE jobs SET images = $1, updated_at = NOW() WHERE id = $2 RETURNING id', [serialized, req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Job not found' });
    res.json({ success: true, id: req.params.id, images });
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
    const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 100, 500));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
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
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 200, 1000));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
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

// POST /api/admin/bootstrap-owner — one-time: grant admin to cherry19899 (any case, any uid).
// Safe: only promotes, never demotes; does nothing if already admin; idempotent.
router.post('/api/admin/bootstrap-owner', async (req, res) => {
  try {
    const result = await query(
      `UPDATE users SET role = 'admin', updated_at = NOW()
       WHERE LOWER(username) = 'cherry19899' AND role != 'admin'
       RETURNING id, username, role`
    );
    if (result.rows.length === 0) {
      const already = await query(`SELECT id, username, role FROM users WHERE LOWER(username) = 'cherry19899' LIMIT 3`);
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
      } catch { await pgM.query('ROLLBACK TO SAVEPOINT sp'); }

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
            } catch { await pgM.query('ROLLBACK TO SAVEPOINT sp'); }
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
          } catch { await pgM.query('ROLLBACK TO SAVEPOINT sp'); }

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

module.exports = router;

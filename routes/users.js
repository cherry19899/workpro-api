/**
 * routes/users.js — /api/users/:id, ratings, level, portfolio, availability, connects, /api/reviews/*
 */
const router = require('express').Router();
const { query } = require('../src/db');
const { notify, serverError } = require('../src/helpers');
const { auth, softAuth, checkBlocked } = require('../src/middleware');

const normalizeId = (id) => (id || '').toString().toLowerCase().replace(/^pi_/, '');

// ─── Level helper ──────────────────────────────────────────────
function computeLevel(completedJobs, rating) {
  const r = parseFloat(rating) || 0;
  const j = parseInt(completedJobs) || 0;
  if (j >= 50 && r >= 4.7) return { level: 5, title: 'Легенда', emoji: '🏆', nextJobs: null, nextRating: null };
  if (j >= 25 && r >= 4.5) return { level: 4, title: 'Эксперт', emoji: '💎', nextJobs: 50, nextRating: 4.7 };
  if (j >= 10 && r >= 4.3) return { level: 3, title: 'Профи', emoji: '🥇', nextJobs: 25, nextRating: 4.5 };
  if (j >= 3 && r >= 4.0) return { level: 2, title: 'Восходящий талант', emoji: '⭐', nextJobs: 10, nextRating: 4.3 };
  return { level: 1, title: 'Новичок', emoji: '🌱', nextJobs: 3, nextRating: 4.0 };
}

// GET /api/users — list users
router.get('/api/users', softAuth, async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const result = await query(
      "SELECT id, username, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, created_at FROM users WHERE status != 'deleted' ORDER BY created_at DESC LIMIT $1 OFFSET $2",
      [limit, offset]
    );
    const total = await query("SELECT COUNT(*) FROM users WHERE status != 'deleted'");
    const users = result.rows.map(u => {
      if (!Array.isArray(u.skills)) {
        u.skills = (typeof u.skills === 'string' && u.skills && u.skills !== '{}')
          ? u.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
      }
      return u;
    });
    res.json({ users, count: users.length, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/users/:id — view a user profile
router.get('/api/users/:id', softAuth, async (req, res) => {
  const callerId = req.userId || null;
  const userId = req.params.id === 'me' ? (callerId || '') : req.params.id;
  if (!userId) return res.status(401).json({ error: 'User ID required' });
  try {
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at FROM users WHERE id = $1', [userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    if (!Array.isArray(u.skills)) {
      u.skills = (typeof u.skills === 'string' && u.skills && u.skills !== '{}')
        ? u.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
    }
    const isOwner = callerId === u.id;
    if (!isOwner && u.status === 'deleted') return res.status(404).json({ error: 'User not found' });
    if (!isOwner) {
      delete u.balance_connects;
      delete u.balance_pi;
      delete u.is_blocked;
      delete u.status;
    }
    const is_admin = u.role === 'admin';
    delete u.role;
    res.json({ ...u, uid: u.id, is_admin });
  } catch (err) { serverError(err, res); }
});

// POST /api/users/:id — update profile (by owner)
router.post('/api/users/:id', auth, checkBlocked, async (req, res) => {
  if (req.userId !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
  const { username, email, bio, skills, availability, avatar } = req.body;
  if (username && username.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
  if (bio && bio.length > 1000) return res.status(400).json({ error: 'Bio too long (max 1000)' });
  const skillsStr = skills !== undefined ? (Array.isArray(skills) ? skills.join(',') : (skills || null)) : undefined;
  if (skillsStr && skillsStr.length > 300) return res.status(400).json({ error: 'Skills too long (max 300)' });
  if (email && (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).json({ error: 'Invalid email address' });
  const ALLOWED_AVAILABILITY = ['available', 'busy', 'away', 'unavailable'];
  if (availability && !ALLOWED_AVAILABILITY.includes(availability)) return res.status(400).json({ error: 'Invalid availability value' });
  if (avatar && avatar.length > 2 * 1024 * 1024 * 1.37) {
    return res.status(400).json({ error: 'Фото слишком большое (макс. 2MB)' });
  }
  try {
    const result = await query(
      'UPDATE users SET username = COALESCE($1, username), email = COALESCE($2, email), bio = COALESCE($3, bio), skills = COALESCE($4, skills), availability = COALESCE($5, availability), avatar = COALESCE($6, avatar), updated_at = NOW() WHERE id = $7 RETURNING id, username, email, role, bio, skills, avatar, availability, balance_connects, rating, kyc_verified',
      [username, email, bio, skillsStr !== undefined ? skillsStr : skills, availability, avatar, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u2 = result.rows[0];
    if (!Array.isArray(u2.skills)) {
      u2.skills = (typeof u2.skills === 'string' && u2.skills && u2.skills !== '{}')
        ? u2.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
    }
    res.json(u2);
  } catch (err) { serverError(err, res); }
});

// GET /api/users/:id/ratings
router.get('/api/users/:id/ratings', async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query('SELECT * FROM ratings WHERE to_user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.params.id, limit, offset]);
    const totalRes = await query('SELECT COUNT(*), AVG(rating) FROM ratings WHERE to_user_id = $1', [req.params.id]);
    const avg = parseFloat(totalRes.rows[0].avg) || 0;
    res.json({ ratings: result.rows, average: Math.round(avg * 10) / 10, count: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/users/:id/level
router.get('/api/users/:id/level', async (req, res) => {
  try {
    const result = await query('SELECT total_jobs_completed, rating FROM users WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    const levelInfo = computeLevel(u.total_jobs_completed, u.rating);
    res.json({ ...levelInfo, completed_jobs: u.total_jobs_completed, rating: u.rating });
  } catch (err) { serverError(err, res); }
});

// GET /api/users/:id/portfolio
router.get('/api/users/:id/portfolio', async (req, res) => {
  try {
    const userResult = await query('SELECT id, username, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar FROM users WHERE id = $1', [req.params.id]);
    if (!userResult.rows.length) return res.status(404).json({ error: 'User not found' });
    const portfolioResult = await query('SELECT * FROM portfolios WHERE user_id = $1', [req.params.id]).catch(() => ({ rows: [] }));
    const itemsResult = await query('SELECT * FROM portfolio_items WHERE user_id = $1 ORDER BY created_at DESC', [req.params.id]).catch(() => ({ rows: [] }));
    const owner = userResult.rows[0];
    res.json({
      owner,
      portfolio: portfolioResult.rows[0] || {},
      items: itemsResult.rows,
      stats: { jobs_posted: owner.total_jobs_posted, jobs_completed: owner.total_jobs_completed, rating: owner.rating }
    });
  } catch (err) { serverError(err, res); }
});

// POST + PUT /api/users/:id/availability
async function handleAvailability(req, res) {
  const { available, availability } = req.body;
  // Always operate on the authenticated user (from the JWT). Never trust the
  // client-supplied :id for a self-mutation — the stored user object can desync
  // from the JWT after account migrations (e.g. cherry19899 -> pi_cherry19899),
  // which previously caused a spurious 403 "Forbidden" -> "Failed to update".
  const ALLOWED_AVAILABILITY = ['available', 'busy', 'away', 'unavailable'];
  let newStatus;
  if (availability !== undefined) {
    if (!ALLOWED_AVAILABILITY.includes(availability)) return res.status(400).json({ error: `Invalid availability. Valid: ${ALLOWED_AVAILABILITY.join(', ')}` });
    newStatus = availability;
  } else {
    newStatus = available ? 'available' : 'unavailable';
  }
  const targetId = req.userId;
  try {
    await query(`UPDATE users SET availability = $1, updated_at = NOW() WHERE id = $2`, [newStatus, targetId]);
    const result = await query(
      'SELECT id, username, role, rating, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, status, updated_at FROM users WHERE id = $1',
      [targetId]
    );
    const u = result.rows[0] || {};
    if (!Array.isArray(u.skills)) {
      u.skills = (typeof u.skills === 'string' && u.skills && u.skills !== '{}')
        ? u.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
    }
    res.json({ ...u, uid: u.id, is_admin: u?.role === 'admin', success: true });
  } catch (err) { serverError(err, res); }
}
router.put('/api/users/:id/availability', auth, handleAvailability);
router.post('/api/users/:id/availability', auth, handleAvailability);

// GET /api/users/:id/connects
router.get('/api/users/:id/connects', auth, async (req, res) => {
  if (req.params.id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  try {
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.params.id]);
    res.json({ balance: result.rows[0]?.balance_connects || 0, connects: result.rows[0]?.balance_connects || 0 });
  } catch (err) { res.json({ balance: 0, connects: 0 }); }
});

// ─── Reviews (= ratings alias) ──────────────────────────────────────────────

// POST /api/ratings — submit a rating
router.post('/api/ratings', auth, checkBlocked, async (req, res) => {
  const { to_user_id, job_id, rating, comment } = req.body;
  if (!to_user_id || rating === undefined || rating === null || rating === '') return res.status(400).json({ error: 'to_user_id and rating required' });
  if (job_id !== undefined && job_id !== null && isNaN(parseInt(job_id))) return res.status(400).json({ error: 'Invalid job_id' });
  const ratingNum = parseInt(rating);
  if (isNaN(ratingNum) || ratingNum < 1 || ratingNum > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
  if (to_user_id === req.userId) return res.status(400).json({ error: 'Cannot rate yourself' });
  if (comment && comment.length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000)' });
  try {
    if (job_id) {
      const jobCheck = await query('SELECT posted_by, hired_freelancer_id, status FROM jobs WHERE id = $1', [job_id]);
      if (jobCheck.rows.length) {
        const job = jobCheck.rows[0];
        const isParticipant = normalizeId(job.posted_by) === normalizeId(req.userId) || normalizeId(job.hired_freelancer_id) === normalizeId(req.userId);
        if (!isParticipant) return res.status(403).json({ error: 'You were not a participant in this job' });
        if (job.status !== 'completed') return res.status(400).json({ error: 'Job must be completed before rating' });
        const expectedTarget = normalizeId(job.posted_by) === normalizeId(req.userId) ? job.hired_freelancer_id : job.posted_by;
        if (to_user_id !== expectedTarget) return res.status(403).json({ error: 'You can only rate the other participant of this job' });
      }
    } else {
      const sharedJob = await query(
        `SELECT id FROM jobs WHERE status='completed' AND (
          (posted_by=$1 AND hired_freelancer_id=$2) OR (posted_by=$2 AND hired_freelancer_id=$1)
        ) LIMIT 1`,
        [req.userId, to_user_id]
      );
      if (!sharedJob.rows.length) return res.status(403).json({ error: 'You have no completed job with this user' });
    }
    const existing = await query(
      'SELECT id FROM ratings WHERE from_user_id = $1 AND to_user_id = $2 AND job_id IS NOT DISTINCT FROM $3',
      [req.userId, to_user_id, job_id || null]
    );
    if (existing.rows.length) return res.status(400).json({ error: 'Already rated this job' });
    const result = await query(
      'INSERT INTO ratings (from_user_id, to_user_id, job_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.userId, to_user_id, job_id || null, ratingNum, comment || '']
    );
    const avgResult = await query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [to_user_id]);
    const newAvg = Math.round(parseFloat(avgResult.rows[0].avg) * 10) / 10;
    await query('UPDATE users SET rating = $1, updated_at = NOW() WHERE id = $2', [newAvg, to_user_id]);
    await notify(to_user_id, 'rating', 'Новый отзыв', `Вы получили оценку ${rating}/5. Средний рейтинг: ${newAvg}`, job_id || null, null);
    res.json({ rating: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/reviews — alias for /api/ratings (bundle sends target_id/text variants)
router.post('/api/reviews', auth, checkBlocked, async (req, res) => {
  const { to_user_id, target_id, job_id, rating, comment, text } = req.body;
  const toId = to_user_id || target_id;
  const reviewComment = comment || text || '';
  if (!toId || rating === undefined || rating === null || rating === '') return res.status(400).json({ error: 'to_user_id and rating required' });
  if (job_id !== undefined && job_id !== null && isNaN(parseInt(job_id))) return res.status(400).json({ error: 'Invalid job_id' });
  const ratingNumR = parseInt(rating);
  if (isNaN(ratingNumR) || ratingNumR < 1 || ratingNumR > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
  if (toId === req.userId) return res.status(400).json({ error: 'Cannot rate yourself' });
  if (reviewComment.length > 1000) return res.status(400).json({ error: 'Comment too long (max 1000)' });
  try {
    if (job_id) {
      const jobCheck = await query('SELECT posted_by, hired_freelancer_id, status FROM jobs WHERE id = $1', [job_id]);
      if (jobCheck.rows.length) {
        const job = jobCheck.rows[0];
        const isParticipant = normalizeId(job.posted_by) === normalizeId(req.userId) || normalizeId(job.hired_freelancer_id) === normalizeId(req.userId);
        if (!isParticipant) return res.status(403).json({ error: 'You were not a participant in this job' });
        if (job.status !== 'completed') return res.status(400).json({ error: 'Job must be completed before rating' });
        const expectedTargetR = normalizeId(job.posted_by) === normalizeId(req.userId) ? job.hired_freelancer_id : job.posted_by;
        if (toId !== expectedTargetR) return res.status(403).json({ error: 'You can only rate the other participant of this job' });
      }
    } else {
      const sharedJob = await query(
        `SELECT id FROM jobs WHERE status='completed' AND (
          (posted_by=$1 AND hired_freelancer_id=$2) OR (posted_by=$2 AND hired_freelancer_id=$1)
        ) LIMIT 1`,
        [req.userId, toId]
      );
      if (!sharedJob.rows.length) return res.status(403).json({ error: 'You have no completed job with this user' });
    }
    const existing = await query(
      'SELECT id FROM ratings WHERE from_user_id = $1 AND to_user_id = $2 AND job_id IS NOT DISTINCT FROM $3',
      [req.userId, toId, job_id || null]
    );
    if (existing.rows.length) return res.status(400).json({ error: 'Already rated this job' });
    const result = await query('INSERT INTO ratings (from_user_id, to_user_id, job_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *', [req.userId, toId, job_id || null, ratingNumR, reviewComment]);
    const avgResult = await query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [toId]);
    const newAvg = Math.round(parseFloat(avgResult.rows[0].avg) * 10) / 10;
    await query('UPDATE users SET rating = $1, updated_at = NOW() WHERE id = $2', [newAvg, toId]);
    res.json({ review: result.rows[0], rating: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews/stats — review stats for logged-in user
router.get('/api/reviews/stats', auth, async (req, res) => {
  try {
    const userId = req.query.user_id || req.userId;
    const [totalResult, avgResult, distResult] = await Promise.all([
      query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [userId]),
      query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [userId]),
      query('SELECT rating, COUNT(*) as count FROM ratings WHERE to_user_id = $1 GROUP BY rating ORDER BY rating DESC', [userId]),
    ]);
    const total = parseInt(totalResult.rows[0].count);
    const avg = parseFloat(avgResult.rows[0].avg || 0).toFixed(1);
    const distribution = {};
    distResult.rows.forEach(r => { distribution[r.rating] = parseInt(r.count); });
    res.json({ total, avg: parseFloat(avg), distribution, rating: parseFloat(avg) });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews/stats/:userId — review stats for a specific user (MUST be before /:id)
router.get('/api/reviews/stats/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const [totalResult, avgResult, distResult] = await Promise.all([
      query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [userId]),
      query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [userId]),
      query('SELECT rating, COUNT(*) as count FROM ratings WHERE to_user_id = $1 GROUP BY rating ORDER BY rating DESC', [userId]),
    ]);
    const total = parseInt(totalResult.rows[0].count);
    const avg = parseFloat(avgResult.rows[0].avg || 0).toFixed(1);
    const distribution = {};
    distResult.rows.forEach(r => { distribution[r.rating] = parseInt(r.count); });
    res.json({ total, avg: parseFloat(avg), distribution, rating: parseFloat(avg) });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews/user/:userId
router.get('/api/reviews/user/:userId', async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query('SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC LIMIT $2 OFFSET $3', [req.params.userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [req.params.userId]);
    res.json({ reviews: result.rows, ratings: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews — alias used by some frontend pages (?user_id=xxx)
router.get('/api/reviews', async (req, res) => {
  const userId = req.query.user_id;
  if (!userId) return res.json({ reviews: [], ratings: [] });
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query('SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC LIMIT $2 OFFSET $3', [userId, limit, offset]);
    const total = await query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [userId]);
    res.json({ reviews: result.rows, ratings: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/reviews/:id — by numeric ID OR non-numeric userId
router.get('/api/reviews/:id', async (req, res) => {
  const id = req.params.id;
  const isNumeric = /^\d+$/.test(id);
  try {
    if (isNumeric) {
      const result = await query(
        'SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.id = $1',
        [id]
      );
      if (!result.rows.length) return res.status(404).json({ error: 'Review not found' });
      res.json({ review: result.rows[0] });
    } else {
      const limit2 = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
      const offset2 = Math.max(0, parseInt(req.query.offset) || 0);
      const result = await query(
        'SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC LIMIT $2 OFFSET $3',
        [id, limit2, offset2]
      );
      res.json({ reviews: result.rows, ratings: result.rows, limit: limit2, offset: offset2 });
    }
  } catch (err) { serverError(err, res); }
});

// PUT /api/reviews/:id/reply — reviewed user replies once
router.put('/api/reviews/:id/reply', auth, checkBlocked, async (req, res) => {
  const { reply } = req.body;
  if (!reply || !reply.trim()) return res.status(400).json({ error: 'reply required' });
  if (reply.length > 1000) return res.status(400).json({ error: 'Reply too long (max 1000 chars)' });
  const id = req.params.id;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid review id' });
  try {
    const result = await query('SELECT * FROM ratings WHERE id=$1', [id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Review not found' });
    const rev = result.rows[0];
    if (rev.to_user_id !== req.userId) return res.status(403).json({ error: 'Only the reviewed user can reply' });
    if (rev.reply) return res.status(400).json({ error: 'Reply already submitted' });
    const updated = await query('UPDATE ratings SET reply=$1, replied_at=NOW() WHERE id=$2 RETURNING *', [reply.trim(), id]);
    res.json({ review: updated.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/ratings/:id/reply — alias
router.post('/api/ratings/:id/reply', auth, checkBlocked, async (req, res) => {
  const { reply } = req.body;
  if (!reply || !reply.trim()) return res.status(400).json({ error: 'reply required' });
  if (reply.length > 1000) return res.status(400).json({ error: 'Reply too long (max 1000 chars)' });
  const id = req.params.id;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid review id' });
  try {
    const result = await query('SELECT * FROM ratings WHERE id=$1', [id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Review not found' });
    const rev = result.rows[0];
    if (rev.to_user_id !== req.userId) return res.status(403).json({ error: 'Only the reviewed user can reply' });
    if (rev.reply) return res.status(400).json({ error: 'Reply already submitted' });
    const updated = await query('UPDATE ratings SET reply=$1, replied_at=NOW() WHERE id=$2 RETURNING *', [reply.trim(), id]);
    res.json({ review: updated.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

module.exports = router;

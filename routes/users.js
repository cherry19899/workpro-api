const logger = require('../src/logger');
/**
 * routes/users.js — /api/users/:id, ratings, level, portfolio, availability, connects, /api/reviews/*
 */
const router = require('express').Router();
const { query } = require('../src/db');
const { notify, serverError, safeHttpUrl, MAX_URL_LEN, isOwnerUid, OWNER_USERNAME, ratingTarget, parseJobId, isIdParam } = require('../src/helpers');
const { auth, softAuth, checkBlocked, adminAuth } = require('../src/middleware');
const { FEEDBACK_FOR_USER, weightFor } = require('../src/feedback');

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
    return res.status(400).json({ error: 'Photo too large (max 2MB)' });
  }
  try {
    // A username is an identity here — several places grant admin by matching
    // one, chat and job cards show it as who you are dealing with — yet this
    // endpoint used to write whatever the body said. Anyone could take the
    // owner's name (and with it, the role) or pose as another freelancer.
    let uname = username;
    if (username !== undefined) {
      uname = String(username).trim();
      if (!uname) return res.status(400).json({ error: 'Username cannot be empty' });
      if (uname.toLowerCase() === OWNER_USERNAME && !isOwnerUid(req.params.id)) {
        return res.status(409).json({ error: 'That username is reserved' });
      }
      const taken = await query(
        'SELECT id FROM users WHERE LOWER(username) = LOWER($1) AND id <> $2 LIMIT 1',
        [uname, req.params.id]
      );
      if (taken.rows.length) return res.status(409).json({ error: 'That username is already taken' });
    }
    const result = await query(
      'UPDATE users SET username = COALESCE($1, username), email = COALESCE($2, email), bio = COALESCE($3, bio), skills = COALESCE($4, skills), availability = COALESCE($5, availability), avatar = COALESCE($6, avatar), updated_at = NOW() WHERE id = $7 RETURNING id, username, email, role, bio, skills, avatar, availability, balance_connects, rating, kyc_verified',
      [uname, email, bio, skillsStr !== undefined ? skillsStr : skills, availability, avatar, req.params.id]
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
    // Reads the same union as everything else. It used to read `ratings`
    // alone, which no longer receives new rows — so this route would have gone
    // on answering with history while quietly omitting every review written
    // from today onwards.
    const result = await query(
      `SELECT * FROM (${FEEDBACK_FOR_USER}) f ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [req.params.id, limit, offset]);
    const totalRes = await query(
      `SELECT COUNT(*), AVG(rating) FROM (${FEEDBACK_FOR_USER}) f`, [req.params.id]);
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
    // This is the page a client lands on when sizing up a freelancer, so it
    // carries the whole public picture: verification, review count, badges,
    // whether they are open to work and how long they have been around.
    const userResult = await query('SELECT id, username, rating, total_reviews, badges, kyc_verified, availability, total_jobs_posted, total_jobs_completed, bio, skills, avatar, created_at FROM users WHERE id = $1', [req.params.id]);
    if (!userResult.rows.length) return res.status(404).json({ error: 'User not found' });
    // No .catch(() => ({rows: []})) here: both tables are created at boot, so
    // a failure is a real one, and swallowing it rendered the owner's
    // portfolio as empty — indistinguishable from never having written one.
    const portfolioResult = await query('SELECT * FROM portfolios WHERE user_id = $1', [req.params.id]);
    const itemsResult = await query('SELECT * FROM portfolio_items WHERE user_id = $1 ORDER BY created_at DESC', [req.params.id]);
    const owner = userResult.rows[0];
    res.json({
      owner,
      portfolio: portfolioResult.rows[0] || {},
      items: itemsResult.rows,
      stats: { jobs_posted: owner.total_jobs_posted, jobs_completed: owner.total_jobs_completed, rating: owner.rating }
    });
  } catch (err) { serverError(err, res); }
});

// PUT /api/users/me/portfolio — upsert own portfolio header (headline/summary/links)
router.put('/api/users/me/portfolio', auth, checkBlocked, async (req, res) => {
  const { headline = '', summary = '', experience_years = 0, website = '', github = '', linkedin = '' } = req.body || {};
  if (String(headline).length > 200) return res.status(400).json({ error: 'Headline too long (max 200)' });
  if (String(summary).length > 2000) return res.status(400).json({ error: 'Summary too long (max 2000)' });
  const years = parseInt(experience_years) || 0;
  if (years < 0 || years > 80) return res.status(400).json({ error: 'Invalid experience_years' });
  // These three end up as clickable hrefs on a page other users open, so a
  // non-http(s) scheme is refused rather than stored. See safeHttpUrl.
  const links = {};
  for (const [field, raw] of Object.entries({ website, github, linkedin })) {
    const url = safeHttpUrl(raw);
    if (url === null) {
      return res.status(400).json({ error: `Invalid ${field} link — use a full http(s) URL (max ${MAX_URL_LEN} characters)` });
    }
    links[field] = url;
  }
  try {
    const result = await query(
      `INSERT INTO portfolios (user_id, headline, summary, experience_years, website, github, linkedin)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (user_id) DO UPDATE SET
         headline=$2, summary=$3, experience_years=$4, website=$5, github=$6, linkedin=$7, updated_at=NOW()
       RETURNING *`,
      [req.userId, headline, summary, years, links.website, links.github, links.linkedin]
    );
    res.json({ portfolio: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/users/me/portfolio/items — add a work item
router.post('/api/users/me/portfolio/items', auth, checkBlocked, async (req, res) => {
  const { title, description = '', image_url = '', category = '', tags = '' } = req.body || {};
  if (!title || !String(title).trim()) return res.status(400).json({ error: 'Title required' });
  if (String(title).length > 500) return res.status(400).json({ error: 'Title too long (max 500)' });
  if (String(description).length > 3000) return res.status(400).json({ error: 'Description too long (max 3000)' });
  if (String(category).length > 50) return res.status(400).json({ error: 'Category too long (max 50)' });
  if (String(tags).length > 300) return res.status(400).json({ error: 'Tags too long (max 300)' });
  const image = safeHttpUrl(image_url);
  if (image === null) return res.status(400).json({ error: `Invalid image link — use a full http(s) URL (max ${MAX_URL_LEN} characters)` });
  try {
    // The count and the insert used to be a separate round trip apiece, wide
    // enough for two near-simultaneous taps of "add" to both read 19 and both
    // insert. One statement closes that window; a soft display cap doesn't
    // need the row locking that would make it airtight under true concurrency.
    const result = await query(
      `INSERT INTO portfolio_items (user_id, title, description, image_url, category, tags)
       SELECT $1,$2,$3,$4,$5,$6
       WHERE (SELECT COUNT(*) FROM portfolio_items WHERE user_id = $1) < 20
       RETURNING *`,
      [req.userId, String(title).trim(), description, image, category, tags]
    );
    if (!result.rows.length) return res.status(400).json({ error: 'Portfolio limit reached (max 20 items)' });
    res.json({ item: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/users/me/portfolio/items/:itemId — remove own work item
router.delete('/api/users/me/portfolio/items/:itemId', auth, async (req, res) => {
  // Not isNaN(parseInt(...)): parseInt stops at the first non-digit, so
  // `/items/5abc` passed that check and then deleted item 5 — a different
  // item than the URL named — and reported success for it.
  if (!isIdParam(req.params.itemId)) return res.status(404).json({ error: 'Item not found' });
  const itemId = parseInt(req.params.itemId);
  try {
    const result = await query('DELETE FROM portfolio_items WHERE id = $1 AND user_id = $2 RETURNING id', [itemId, req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Item not found' });
    res.json({ success: true });
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
    // Was `res.json({ balance: 0, connects: 0 })`: a failed query was served as a
    // 200 with a zero balance and logged nothing, so someone who owned connects
    // was told they had none and sent off to buy more.
  } catch (err) { serverError(err, res); }
});

// ─── Reviews (= ratings alias) ──────────────────────────────────────────────

// POST /api/ratings — the original route, kept for clients still on an older
// bundle. A thin adapter now: names in, shape out, rules shared.
router.post('/api/ratings', auth, checkBlocked, async (req, res) => {
  const r = await submitFeedback({
    reviewerId: req.userId,
    revieweeId: req.body.to_user_id,
    jobId: req.body.job_id,
    rating: req.body.rating,
    text: req.body.comment,
    maxText: 1000,
  }).catch((err) => ({ thrown: err }));
  if (r.thrown) return serverError(r.thrown, res);
  if (r.error) return _rej(res, r.code, r.error);
  res.json({ rating: r.row, success: true });
});

// POST /api/reviews — the same thing under another name, accepting the field
// spellings an older bundle sent (target_id / text).
router.post('/api/reviews', auth, checkBlocked, async (req, res) => {
  const r = await submitFeedback({
    reviewerId: req.userId,
    revieweeId: req.body.to_user_id || req.body.target_id,
    jobId: req.body.job_id,
    rating: req.body.rating,
    text: req.body.comment || req.body.text,
    maxText: 1000,
  }).catch((err) => ({ thrown: err }));
  if (r.thrown) return serverError(r.thrown, res);
  if (r.error) return _rej(res, r.code, r.error);
  res.json({ review: r.row, rating: r.row, success: true });
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
    // normalizeId, not ===: ids are compared case- and pi_-insensitively
    // everywhere else, so a reviewed user whose id is stored with different
    // casing than their token carries was refused a reply to their own review.
    if (normalizeId(rev.to_user_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Only the reviewed user can reply' });
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
    // normalizeId, not ===: ids are compared case- and pi_-insensitively
    // everywhere else, so a reviewed user whose id is stored with different
    // casing than their token carries was refused a reply to their own review.
    if (normalizeId(rev.to_user_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Only the reviewed user can reply' });
    if (rev.reply) return res.status(400).json({ error: 'Reply already submitted' });
    const updated = await query('UPDATE ratings SET reply=$1, replied_at=NOW() WHERE id=$2 RETURNING *', [reply.trim(), id]);
    res.json({ review: updated.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// ─── GDPR — anonymize all user data ──────────────────────────────────────────
router.delete('/api/me/gdpr', auth, async (req, res) => {
  const uid = req.userId;
  try {
    const anon = `deleted_user_${Date.now()}`;
    // Anonymize user record (keep row for FK integrity)
    await query(`UPDATE users SET
      username=$1, email=NULL, bio=NULL, skills=NULL, avatar=NULL,
      balance_connects=0, balance_pi=0, kyc_verified=FALSE,
      availability='unavailable', is_blocked=TRUE, status='deleted',
      title=NULL, hourly_rate=NULL, location=NULL, website=NULL,
      updated_at=NOW()
      WHERE id=$2`, [anon, uid]);
    // Anonymize chat messages
    await query(`UPDATE chat_messages SET message='[deleted]', sender_name=$1 WHERE sender_id=$2`, [anon, uid]);
    // Anonymize reviews/ratings
    await query(`UPDATE ratings SET comment='[deleted]' WHERE from_user_id=$1`, [uid]);
    await query(`UPDATE reviews SET text='[deleted]' WHERE reviewer_id=$1`, [uid]);
    // The portfolio is free text the user wrote about themselves and it stays
    // publicly readable by user id — leaving it behind meant an erasure
    // request erased the profile and left the biography.
    await query(`DELETE FROM portfolio_items WHERE user_id=$1`, [uid]);
    await query(`DELETE FROM portfolios WHERE user_id=$1`, [uid]);
    // Files the user uploaded into chat — the message text was blanked above
    // but the attachment bytes (photos, documents) were not touched.
    await query(`DELETE FROM chat_attachments WHERE uploader_id=$1`, [uid]);
    // Delete notifications
    await query(`DELETE FROM notifications WHERE user_id=$1`, [uid]);
    // The push endpoint is a live channel to the person's device. Deleting the
    // notification rows without it left them still receiving push after asking
    // to be deleted.
    await query(`DELETE FROM push_subscriptions WHERE user_id=$1`, [uid]);
    // Delete saved searches
    await query(`DELETE FROM saved_searches WHERE user_id=$1`, [uid]);
    // Revoke all JWTs by noting deletion (JWT blacklist via timestamp)
    res.json({ success: true, message: 'Account anonymized per GDPR request' });
  } catch (err) { serverError(err, res); }
});

// ─── Badges — compute and update user badges ──────────────────────────────────
async function computeBadges(userId) {
  try {
    const [user, reviews] = await Promise.all([
      // kyc_verified was missing from this list, so `u.kyc_verified` below was
      // always undefined and the 'verified' badge could never be awarded to
      // anyone, no matter how many times badges were recomputed.
      query('SELECT total_jobs_completed, rating, total_reviews, repeat_client_count, kyc_verified FROM users WHERE id=$1', [userId]),
      // Both tables, deduped — see src/feedback.js. Reading `ratings`
      // alone made the rating depend on a mirror insert whose failure is
      // swallowed, so a review could exist and never count.
      query(`SELECT rating, created_at FROM (${FEEDBACK_FOR_USER}) f`, [userId]),
    ]);
    if (!user.rows.length) return;
    const u = user.rows[0];
    const completed = parseInt(u.total_jobs_completed) || 0;
    // Count what is actually on record, not the column being recomputed. The
    // old `u.total_reviews || rows.length`, written back through Math.max,
    // was a ratchet: it could only ever climb, so a stored value that had
    // drifted (or was seeded by the non-v2 rating routes, which never touch
    // total_reviews at all) pinned the count forever. Production ended up with
    // users showing rating 5.0 against total_reviews 0.
    const totalReviews = reviews.rows.length;
    const repeatClients = parseInt(u.repeat_client_count) || 0;

    // Weighted avg: last 6 months weight 1.5x, older 1.0x
    let weightedSum = 0, weightedCount = 0;
    for (const r of reviews.rows) {
      const w = weightFor(r.created_at);
      weightedSum += parseFloat(r.rating) * w;
      weightedCount += w;
    }
    const avgRating = weightedCount > 0 ? weightedSum / weightedCount : 0;

    const badges = [];
    if (totalReviews >= 5 && avgRating >= 4.5) badges.push('rising_talent');
    if (totalReviews >= 20 && avgRating >= 4.8 && completed >= 15) badges.push('top_rated');
    if (totalReviews >= 50 && avgRating >= 4.9) badges.push('top_rated_plus');
    if (u.kyc_verified) badges.push('verified');
    if (totalReviews > 0 && repeatClients / Math.max(totalReviews, 1) >= 0.5) badges.push('repeat_magnet');
    if (completed >= 100) badges.push('expert_level');

    await query(`UPDATE users SET badges=$1, rating=$2, total_reviews=$3, updated_at=NOW() WHERE id=$4`,
      [badges, avgRating.toFixed(2), totalReviews, userId]);
    // Returned so the rating routes can quote the new average in their
    // notification instead of computing a second, differently-rounded one.
    return { rating: Math.round(avgRating * 10) / 10, totalReviews, badges };
  } catch (err) {
    logger.error('[badges] compute error:', err.message);
    return null;
  }
}

// GET /api/users/:id/badges
router.get('/api/users/:id/badges', async (req, res) => {
  try {
    const r = await query('SELECT badges, rating, total_reviews FROM users WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ badges: r.rows[0].badges || [], rating: r.rows[0].rating, total_reviews: r.rows[0].total_reviews });
  } catch (err) { serverError(err, res); }
});

// POST /api/reviews — create a review (enhanced with badges trigger)
let _lastReviewReject = null;
// adminAuth, not open. This returned recent reviews *and* escrow rows —
// client_id, freelancer_id and amount — to anyone on the internet, so the whole
// payment graph (who paid whom, how much) could be enumerated without logging
// in. It exists only to inspect _lastReviewReject while debugging.
router.get('/api/reviews/v2/_diag', adminAuth, async (req, res) => {
  const recent = await query('SELECT id, reviewer_id, reviewee_id, job_id, rating, created_at FROM reviews ORDER BY id DESC LIMIT 5').catch(() => ({ rows: [] }));
  const escrows = await query('SELECT id, job_id, status, client_id, freelancer_id, amount, created_at, updated_at FROM escrows ORDER BY id DESC LIMIT 6').catch(() => ({ rows: [] }));
  res.json({ last_reject: _lastReviewReject, recent: recent.rows, escrows: escrows.rows });
});
const _rej = (res, code, error) => { _lastReviewReject = { code, error, at: new Date().toISOString() }; return res.status(code).json({ error }); };

// ─── One implementation behind all three rating routes ──────────────────────
// /api/ratings, /api/reviews and /api/reviews/v2 were three near-copies of the
// same forty lines. They drifted, as copies do: only one of them notified the
// reviewee, and they disagreed on how the average was computed. Everything
// they genuinely differ in — the field names they accept, the text limits, the
// shape of the reply — now lives in the thin handlers below; the rules live
// here, once.
//
// All three write to `reviews`. `ratings` keeps its historical rows and is
// still read (see src/feedback.js) but no longer grows, which is what makes it
// possible to retire it later.
async function submitFeedback({ reviewerId, revieweeId, jobId, text, rating, minText = 0, maxText = 2000 }) {
  if (!revieweeId || rating === undefined || rating === null || rating === '') {
    return { code: 400, error: 'to_user_id and rating required' };
  }
  const num = parseInt(rating, 10);
  // The range test alone lets anything non-numeric through: 'abc' < 1 and
  // 'abc' > 5 are both false, so the value reached the INSERT and Postgres
  // answered 500 where this belongs.
  if (isNaN(num) || num < 1 || num > 5) return { code: 400, error: 'Rating must be 1-5' };
  if (normalizeId(revieweeId) === normalizeId(reviewerId)) return { code: 400, error: 'Cannot review yourself' };

  const body = typeof text === 'string' ? text : '';
  if (body && minText && body.length < minText) {
    return { code: 400, error: `Review text must be at least ${minText} characters` };
  }
  if (body.length > maxText) return { code: 400, error: `Review too long (max ${maxText} chars)` };

  const jid = parseJobId(jobId);
  if (Number.isNaN(jid)) return { code: 400, error: 'Invalid job_id' };

  // Only the two sides of a completed job may review each other. When a job
  // vouches for the pair, ratingTarget hands back the spelling the job row
  // holds, so a differently-cased body value cannot open a second identity for
  // the same person.
  let target = revieweeId;
  if (jid) {
    const job = await query('SELECT posted_by, hired_freelancer_id, status FROM jobs WHERE id = $1', [jid]);
    const verdict = ratingTarget(job.rows[0] || null, reviewerId, revieweeId);
    if (verdict.error) return { code: verdict.code, error: verdict.error };
    target = verdict.targetId;
  } else {
    const shared = await query(
      `SELECT id FROM jobs WHERE status='completed' AND (
         (posted_by=$1 AND hired_freelancer_id=$2) OR (posted_by=$2 AND hired_freelancer_id=$1)
       ) LIMIT 1`, [reviewerId, revieweeId]);
    if (!shared.rows.length) return { code: 403, error: 'You have no completed job with this user' };
  }

  // Both tables, because the older routes left rows in `ratings` and one
  // opinion per pair per job has to mean one across the two of them — checking
  // only `reviews` would let the same person rate twice through two doors.
  const dup = await query(
    `SELECT 1 FROM reviews WHERE job_id IS NOT DISTINCT FROM $1 AND reviewer_id=$2 AND reviewee_id=$3
     UNION ALL
     SELECT 1 FROM ratings WHERE job_id IS NOT DISTINCT FROM $1 AND from_user_id=$2 AND to_user_id=$3
     LIMIT 1`, [jid, reviewerId, target]);
  if (dup.rows.length) return { code: 409, error: 'You already reviewed this person for this job' };

  const { sanitizeText } = require('../src/sanitize');
  const safeText = body ? sanitizeText(body, maxText) : null;
  const row = await query(
    'INSERT INTO reviews (job_id, reviewer_id, reviewee_id, rating, text) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [jid, reviewerId, target, num, safeText]);

  // Awaited, not fire-and-forget: this is what writes users.rating and
  // total_reviews, so letting it race meant the response could describe a
  // rating the profile had not been given yet.
  const stats = await computeBadges(target);
  const avg = stats ? stats.rating : num;
  await notify(target, 'rating', 'Новый отзыв',
    `Вы получили оценку ${num}/5. Средний рейтинг: ${avg}`, jid, null,
    { key: 'nRating', params: { rating: num, avg } });

  return { row: row.rows[0] };
}

router.post('/api/reviews/v2', auth, checkBlocked, async (req, res) => {
  // The route the app actually calls. It alone asks for a minimum text length,
  // because its dialog offers a text box and ten characters is the line
  // between a review and a slip of the thumb.
  const r = await submitFeedback({
    reviewerId: req.userId,
    revieweeId: req.body.reviewee_id,
    jobId: req.body.job_id,
    rating: req.body.rating,
    text: req.body.text,
    minText: 10, maxText: 2000,
  }).catch((err) => ({ thrown: err }));
  if (r.thrown) return serverError(r.thrown, res);
  if (r.error) return _rej(res, r.code, r.error);
  res.json({ review: r.row, success: true });
});

// GET /api/reviews/v2/user/:userId — paginated reviews with weighted stats
router.get('/api/reviews/v2/user/:userId', async (req, res) => {
  const { userId } = req.params;
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(50, parseInt(req.query.limit) || 20);
  const offset = (page - 1) * limit;
  try {
    // One definition of the set, shared with computeBadges and the resync
    // sweep, so the count can never describe a different list than it shows.
    const LIST = `SELECT f.*, u.username AS reviewer_username, u.avatar AS reviewer_avatar
                    FROM (${FEEDBACK_FOR_USER}) f LEFT JOIN users u ON u.id = f.reviewer_id`;
    const [reviews, total, user] = await Promise.all([
      query(`${LIST} ORDER BY created_at DESC LIMIT $2 OFFSET $3`, [userId, limit, offset]),
      query(`SELECT COUNT(*) FROM (${LIST}) AS all_feedback`, [userId]),
      query('SELECT badges, rating, total_reviews FROM users WHERE id=$1', [userId]),
    ]);
    res.json({
      reviews: reviews.rows,
      total: parseInt(total.rows[0].count),
      page, limit,
      badges: user.rows[0]?.badges || [],
      weighted_rating: user.rows[0]?.rating,
    });
  } catch (err) { serverError(err, res); }
});

// GET /api/saved-searches — list user's saved searches
router.get('/api/saved-searches', auth, async (req, res) => {
  try {
    const r = await query('SELECT * FROM saved_searches WHERE user_id=$1 ORDER BY created_at DESC', [req.userId]);
    res.json({ saved_searches: r.rows });
  } catch (err) { serverError(err, res); }
});

// POST /api/saved-searches — save a search
router.post('/api/saved-searches', auth, checkBlocked, async (req, res) => {
  const { name, query_params, alert_enabled } = req.body;
  if (!query_params) return res.status(400).json({ error: 'query_params required' });
  // name is VARCHAR(255): a longer one was refused by Postgres, which reaches
  // the caller as a 500 rather than as this message.
  const searchName = String(name || '').trim() || 'Search ' + Date.now();
  if (searchName.length > 200) return res.status(400).json({ error: 'Name too long (max 200)' });
  // query_params is JSONB with no size of its own, and 20 of them per user is
  // only a cap on the count. It is also read back by the hourly alert sweep,
  // so it has to be a plain object rather than whatever the body sent.
  if (typeof query_params !== 'object' || Array.isArray(query_params)) {
    return res.status(400).json({ error: 'query_params must be an object' });
  }
  const paramsJson = JSON.stringify(query_params);
  if (paramsJson.length > 4000) return res.status(400).json({ error: 'Search is too large (max 4000 characters)' });
  try {
    const count = await query('SELECT COUNT(*) FROM saved_searches WHERE user_id=$1', [req.userId]);
    if (parseInt(count.rows[0].count) >= 20) return res.status(400).json({ error: 'Max 20 saved searches' });
    const r = await query(
      'INSERT INTO saved_searches (user_id, name, query_params, alert_enabled) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.userId, searchName, paramsJson, !!alert_enabled]
    );
    res.json({ saved_search: r.rows[0] });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/saved-searches/:id
router.delete('/api/saved-searches/:id', auth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Saved search not found' });
  try {
    await query('DELETE FROM saved_searches WHERE id=$1 AND user_id=$2', [req.params.id, req.userId]);
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

module.exports = { router, computeBadges };

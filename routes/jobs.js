/**
 * routes/jobs.js — /api/jobs/*, /api/applications/*
 */
const router = require('express').Router();
const crypto = require('crypto');
const { query, getPool } = require('../src/db');
const { notify, audit, serverError, getPlatformFee } = require('../src/helpers');
const { auth, softAuth, checkBlocked, jobPostLimiter } = require('../src/middleware');
const { processJobImages } = require('../src/github-images');

const normalizeId = (id) => (id || '').toString().toLowerCase().replace(/^pi_/, '');

// ─── Image helpers ──────────────────────────────────────────────
function serializeImages(images) {
  if (!images) return null;
  if (typeof images === 'string') {
    const s = images.trim();
    if (!s || s === '{}' || s === '[]' || s === 'null') return null;
    return s;
  }
  if (Array.isArray(images)) return images.length > 0 ? JSON.stringify(images) : null;
  if (typeof images === 'object') {
    const keys = Object.keys(images);
    return keys.length > 0 ? JSON.stringify(images) : null;
  }
  return null;
}

function parseImages(images) {
  if (!images || images === '[object Object]') return null;
  if (typeof images === 'string') {
    try { return JSON.parse(images); } catch (e) { return null; }
  }
  return images;
}

function parseJobRow(job, { stripBase64 = false } = {}) {
  if (!job) return job;
  let imgs = parseImages(job.images);
  if (stripBase64 && Array.isArray(imgs)) {
    // In list responses, drop base64 blobs — they haven't been migrated yet.
    // Single-job GET still returns them (callers pass stripBase64:false).
    imgs = imgs.map(i => (typeof i === 'string' && i.startsWith('data:')) ? null : i).filter(Boolean);
    if (imgs.length === 0) imgs = null;
  }
  return { ...job, images: imgs };
}

// ─── Jobs ──────────────────────────────────────────────

// GET /api/jobs/search/autocomplete?q=<text>
// Uses pg_trgm similarity when available, falls back to ILIKE.
router.get('/api/jobs/search/autocomplete', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q || q.length > 100) return res.json({ suggestions: [] });
  try {
    const result = await query(
      `SELECT DISTINCT title FROM jobs
       WHERE status = 'open' AND title ILIKE $1
       ORDER BY title LIMIT 10`,
      [`%${q}%`]
    );
    res.json({ suggestions: result.rows.map(r => r.title) });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs
router.get('/api/jobs', async (req, res) => {
  const { status, category, posted_by, client_uid, search, min_budget, max_budget, urgent, sort, cursor } = req.query;
  if (search && search.length > 200) return res.status(400).json({ error: 'Search query too long (max 200 chars)' });
  if (min_budget !== undefined && isNaN(parseFloat(min_budget))) return res.status(400).json({ error: 'Invalid min_budget' });
  if (max_budget !== undefined && isNaN(parseFloat(max_budget))) return res.status(400).json({ error: 'Invalid max_budget' });
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 20, 200));
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const ownerFilter = posted_by || client_uid;
  // Cursor-based pagination is only supported for the default created_at DESC sort.
  const orderMap = {
    'newest': 'created_at DESC', 'oldest': 'created_at ASC',
    'budget_asc': 'budget ASC', 'budget_desc': 'budget DESC',
    'budget-asc': 'budget ASC', 'budget-desc': 'budget DESC',
    'budget_low': 'budget ASC', 'budget_high': 'budget DESC',
    'popular': 'applications DESC, created_at DESC',
  };
  const orderBy = orderMap[sort] || 'created_at DESC';
  const useCursor = cursor && !sort; // cursor mode only when using default sort
  try {
    let conditions = [];
    const params = [];
    let idx = 1;
    if (status) { conditions.push(`status = $${idx++}`); params.push(status); }
    else { conditions.push(`status = 'open'`); }
    if (category && category !== 'all' && category !== 'All') { conditions.push(`LOWER(category) = LOWER($${idx++})`); params.push(category); }
    if (ownerFilter) { conditions.push(`posted_by = $${idx++}`); params.push(ownerFilter); }
    else {
      // Hide jobs posted by blocked accounts — they can't post new ones, existing ones shouldn't be visible either.
      conditions.push(`posted_by NOT IN (SELECT id FROM users WHERE is_blocked = true)`);
    }
    if (search) { conditions.push(`(title ILIKE $${idx} OR description ILIKE $${idx})`); params.push(`%${search}%`); idx++; }
    if (min_budget) { conditions.push(`budget >= $${idx++}`); params.push(parseFloat(min_budget)); }
    if (max_budget) { conditions.push(`budget <= $${idx++}`); params.push(parseFloat(max_budget)); }
    if (urgent === '1' || urgent === 'true') { conditions.push(`is_urgent = TRUE`); }
    if (req.query.featured === 'true') { conditions.push(`featured = true`); }

    // Decode cursor and add keyset condition (created_at DESC: fetch rows older than cursor)
    let cursorData = null;
    if (useCursor) {
      try { cursorData = JSON.parse(Buffer.from(cursor, 'base64url').toString()); } catch (_) {}
    }
    if (cursorData && cursorData.created_at && cursorData.id) {
      conditions.push(`(created_at, id) < ($${idx++}, $${idx++})`);
      params.push(cursorData.created_at, cursorData.id);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    let total = null;
    let total_pages = null;
    if (!useCursor) {
      const countResult = await query(`SELECT COUNT(*) FROM jobs ${where}`, params);
      total = parseInt(countResult.rows[0].count);
      total_pages = Math.ceil(total / limit);
    }

    const offset = useCursor ? 0 : (page - 1) * limit;
    const dataResult = await query(
      `SELECT * FROM jobs ${where} ORDER BY ${orderBy} LIMIT $${idx}${useCursor ? '' : ` OFFSET $${idx + 1}`}`,
      useCursor ? [...params, limit + 1] : [...params, limit, offset] // fetch +1 to detect next page
    );

    let rows = dataResult.rows;
    let next_cursor = null;
    if (useCursor) {
      const hasMore = rows.length > limit;
      if (hasMore) rows = rows.slice(0, limit);
      if (hasMore) {
        const last = rows[rows.length - 1];
        next_cursor = Buffer.from(JSON.stringify({ created_at: last.created_at, id: last.id })).toString('base64url');
      }
    }

    // Use posted_by_name as posted_by so bundle's own-job filter (posted_by !== username) works
    // correctly with case-sensitive Pi SDK username (e.g. 'Cherry19899' not 'pi_cherry19899').
    // _open:true marks open jobs so the frontend fetch interceptor can remap status for the bundle.
    const jobs = rows.map(r => parseJobRow(r, { stripBase64: true })).map(function(j) {
      const normalized = Object.assign({}, j, {
        posted_by: j.posted_by_name || (j.posted_by ? j.posted_by.replace(/^pi_/, '') : j.posted_by),
      });
      if (normalized.status === 'open') return Object.assign({}, normalized, { _open: true });
      return normalized;
    });

    const resp = { jobs, limit };
    if (useCursor) {
      resp.next_cursor = next_cursor;
    } else {
      resp.total = total;
      resp.page = page;
      resp.total_pages = total_pages;
    }
    res.json(resp);
  } catch (err) { serverError(err, res); }
});

// POST /api/jobs
router.post('/api/jobs', auth, checkBlocked, jobPostLimiter, async (req, res) => {
  const { title, description, category, budget, skills, deadline, images } = req.body;
  if (!title || !description || budget === undefined || budget === null || budget === '') {
    return res.status(400).json({ error: 'Title, description, and budget are required' });
  }
  const budgetNum = parseFloat(budget);
  if (isNaN(budgetNum) || budgetNum < 1) return res.status(400).json({ error: 'Budget must be at least 1 Pi' });
  if (budgetNum > 10000) return res.status(400).json({ error: 'Budget cannot exceed 10000 Pi' });
  if (String(title).length > 200) return res.status(400).json({ error: 'Title too long (max 200 chars)' });
  if (String(description).length > 5000) return res.status(400).json({ error: 'Description too long (max 5000 chars)' });
  if (images && Array.isArray(images) && images.length > 10) return res.status(400).json({ error: 'Too many images (max 10)' });
  if (skills && String(skills).length > 500) return res.status(400).json({ error: 'Skills too long (max 500)' });
  const VALID_CATEGORIES = ['development','design','writing','marketing','data','support','translation','va','other'];
  if (category && !VALID_CATEGORIES.includes(category.toLowerCase())) {
    return res.status(400).json({ error: `Invalid category. Valid: ${VALID_CATEGORIES.join(', ')}` });
  }
  if (deadline) {
    const dl = new Date(deadline);
    if (isNaN(dl.getTime())) return res.status(400).json({ error: 'Invalid deadline date' });
    if (dl < new Date()) return res.status(400).json({ error: 'Deadline must be in the future' });
  }
  const applyCost = (req.body.connects_required !== undefined && !isNaN(parseInt(req.body.connects_required)) && parseInt(req.body.connects_required) >= 1 && parseInt(req.body.connects_required) <= 200)
  ? parseInt(req.body.connects_required)
  : Math.ceil(budgetNum / 50);
  const POST_COST = 1;
  try {
    const userRes = await query('SELECT username, balance_connects FROM users WHERE id = $1', [req.userId]);
    const userRow = userRes.rows[0];
    const username = userRow?.username || req.userId;
    if ((userRow?.balance_connects || 0) < POST_COST) {
      return res.status(400).json({ error: 'Not enough connects to post a job (costs 1 connect)', required: POST_COST, current: userRow?.balance_connects || 0 });
    }
    const pgClientPost = await getPool().connect();
    let newJob;
    try {
      await pgClientPost.query('BEGIN');
      const deduct = await pgClientPost.query(
        'UPDATE users SET balance_connects = balance_connects - $1, updated_at = NOW() WHERE id = $2 AND balance_connects >= $1 RETURNING id',
        [POST_COST, req.userId]
      );
      if (!deduct.rows.length) {
        await pgClientPost.query('ROLLBACK');
        return res.status(400).json({ error: 'Not enough connects to post a job (costs 1 connect)' });
      }
      const isUrgent = req.body.is_urgent === true || req.body.is_urgent === 'true';
      const jobRes = await pgClientPost.query(
        'INSERT INTO jobs (title, description, category, budget, skills, images, deadline, posted_by, posted_by_name, apply_cost, connects_spent, is_urgent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11) RETURNING *',
        [title, description, (category || 'other').toLowerCase(), budgetNum, skills || null, serializeImages(images), deadline || null, req.userId, username, applyCost, isUrgent]
      );
      await pgClientPost.query('UPDATE users SET total_jobs_posted = total_jobs_posted + 1, updated_at = NOW() WHERE id = $1', [req.userId]);
      await pgClientPost.query('COMMIT');
      newJob = jobRes.rows[0];
    } catch (txErr) {
      await pgClientPost.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally { pgClientPost.release(); }
    // If any image is still base64 (GITHUB_TOKEN set), upload to GitHub Pages now
    // that we have the job id for a stable filename.
    if (Array.isArray(images) && images.some(i => typeof i === 'string' && i.startsWith('data:'))) {
      const { images: uploadedImgs, upload_failed } = await processJobImages(images, newJob.id);
      const anyUploaded = uploadedImgs.some((u, i) => u !== images[i]);
      if (anyUploaded || upload_failed) {
        const meta = newJob.metadata ? (typeof newJob.metadata === 'string' ? JSON.parse(newJob.metadata) : newJob.metadata) : {};
        if (upload_failed) meta.upload_failed = true;
        await query('UPDATE jobs SET images = $1, metadata = $2, updated_at = NOW() WHERE id = $3',
          [serializeImages(uploadedImgs), JSON.stringify(meta), newJob.id]).catch(() => {});
        newJob.images = serializeImages(uploadedImgs);
      }
    }
    await audit('job_created', { job_id: newJob.id, user_id: req.userId, post_cost: POST_COST });
    res.json({ job: parseJobRow(newJob), success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs/user/:userId — jobs posted by a specific user (MUST be before /:id)
router.get('/api/jobs/user/:userId', async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const userId = req.params.userId;
    const [result, totalRes] = await Promise.all([
      query(
        `SELECT j.*, u.username as client_username FROM jobs j LEFT JOIN users u ON u.id = j.posted_by WHERE j.posted_by = $1 OR LOWER(u.username) = LOWER($1) ORDER BY j.created_at DESC LIMIT $2 OFFSET $3`,
        [userId, limit, offset]
      ),
      query(`SELECT COUNT(*) FROM jobs j LEFT JOIN users u ON u.id = j.posted_by WHERE j.posted_by = $1 OR LOWER(u.username) = LOWER($1)`, [userId]),
    ]);
    res.json({ jobs: result.rows.map(parseJobRow), total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs/as-freelancer — jobs where current user is the hired freelancer
router.get('/api/jobs/as-freelancer', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const [result, totalRes] = await Promise.all([
      query(`SELECT j.*, u.username as client_username FROM jobs j LEFT JOIN users u ON u.id = j.posted_by WHERE j.hired_freelancer_id = $1 ORDER BY j.updated_at DESC LIMIT $2 OFFSET $3`, [req.userId, limit, offset]),
      query('SELECT COUNT(*) FROM jobs WHERE hired_freelancer_id = $1', [req.userId]),
    ]);
    res.json({ jobs: result.rows.map(parseJobRow), total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs/my — client's own posted jobs (must be before /:id)
router.get('/api/jobs/my', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const [result, totalRes] = await Promise.all([
      query('SELECT j.*, u.username as client_username FROM jobs j LEFT JOIN users u ON u.id = j.posted_by WHERE j.posted_by = $1 ORDER BY j.created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]),
      query('SELECT COUNT(*) FROM jobs WHERE posted_by = $1', [req.userId]),
    ]);
    res.json({ jobs: result.rows.map(parseJobRow), total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs/:id
router.get('/api/jobs/:id', softAuth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job_row = jobResult.rows[0];
    const callerId = req.userId || null;
    let applications = [];
    if (callerId && callerId === job_row.posted_by) {
      const appsResult = await query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC LIMIT 200', [req.params.id]);
      applications = appsResult.rows;
    }
    let roomId = null;
    if (callerId) {
      const roomResult = await query(
        'SELECT id FROM chat_rooms WHERE job_id = $1 AND (client_id = $2 OR freelancer_id = $2) LIMIT 1',
        [req.params.id, callerId]
      );
      roomId = roomResult.rows[0]?.id || null;
    }
    const job = parseJobRow({ ...job_row, room_id: roomId });
    res.json({ job, applications });
  } catch (err) { serverError(err, res); }
});

// PATCH /api/jobs/:id — freelancer submits work
router.patch('/api/jobs/:id', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    const { status } = req.body;
    const isHiredFreelancer = normalizeId(job.hired_freelancer_id) === normalizeId(req.userId);
    if (!(isHiredFreelancer && status === 'submitted')) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (job.status !== 'in_progress') return res.status(400).json({ error: 'Job is not in progress' });
    // Don't let the freelancer submit work until the client has actually funded the escrow.
    const unfundedSubmit = await query("SELECT id FROM escrows WHERE job_id = $1 AND status = 'pending' LIMIT 1", [req.params.id]);
    if (unfundedSubmit.rows.length) return res.status(400).json({ error: 'Дождитесь, пока заказчик пополнит эскроу, прежде чем сдавать работу' });
    const result = await query("UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2 AND status = 'in_progress' RETURNING *", [status, req.params.id]);
    if (!result.rows.length) return res.status(409).json({ error: 'Job status changed concurrently — try again' });
    if (status === 'submitted' && isHiredFreelancer) {
      await notify(job.posted_by, 'submitted', `Фрилансер сдал работу по задаче "${job.title}"`,
        'Проверьте результат и примите работу или откройте спор.', parseInt(req.params.id), null);
    }
    res.json({ job: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// PUT /api/jobs/:id — update job (open jobs only)
router.put('/api/jobs/:id', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  const { title, description, category, budget, skills, deadline, images } = req.body;
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (normalizeId(job.posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Can only edit open jobs' });
    const fields = [], vals = [];
    let i = 1;
    if (title !== undefined) {
      if (String(title).length > 200) return res.status(400).json({ error: 'Title too long (max 200)' });
      fields.push(`title=$${i++}`); vals.push(title);
    }
    if (description !== undefined) {
      if (String(description).length > 5000) return res.status(400).json({ error: 'Description too long (max 5000)' });
      fields.push(`description=$${i++}`); vals.push(description);
    }
    if (category !== undefined) { fields.push(`category=$${i++}`); vals.push(category ? category.toLowerCase() : category); }
    if (budget !== undefined) {
      const b = parseFloat(budget);
      if (isNaN(b) || b < 1) return res.status(400).json({ error: 'Budget must be at least 1 Pi' });
      if (b > 10000) return res.status(400).json({ error: 'Budget cannot exceed 10000 Pi' });
      if (b !== job.budget) {
        const pendingApps = await query("SELECT COUNT(*) FROM applications WHERE job_id=$1 AND status='pending'", [req.params.id]);
        if (parseInt(pendingApps.rows[0].count) > 0) {
          return res.status(400).json({ error: 'Cannot change budget while there are pending applications (applicants paid the current apply cost and must be refunded correctly)' });
        }
      }
      fields.push(`budget=$${i++}`); vals.push(b);
      const newCost = Math.ceil(b / 50);
      fields.push(`apply_cost=$${i++}`); vals.push(newCost);
      fields.push(`connects_spent=$${i++}`); vals.push(newCost);
    }
    if (skills !== undefined) {
      if (skills && String(skills).length > 500) return res.status(400).json({ error: 'Skills too long (max 500)' });
      fields.push(`skills=$${i++}`); vals.push(skills);
    }
    if (deadline !== undefined) {
      if (deadline) {
        const dl = new Date(deadline);
        if (isNaN(dl.getTime())) return res.status(400).json({ error: 'Invalid deadline date' });
        if (dl < new Date()) return res.status(400).json({ error: 'Deadline must be in the future' });
      }
      fields.push(`deadline=$${i++}`); vals.push(deadline || null);
    }
    if (images !== undefined) {
      if (Array.isArray(images) && images.length > 10) return res.status(400).json({ error: 'Too many images (max 10)' });
      // Upload any base64 to GitHub Pages before storing
      let finalImgs = images;
      if (Array.isArray(images) && images.some(x => typeof x === 'string' && x.startsWith('data:'))) {
        const { images: uploaded, upload_failed } = await processJobImages(images, req.params.id);
        finalImgs = uploaded;
        if (upload_failed) {
          fields.push(`metadata=jsonb_set(COALESCE(metadata,'{}'), '{upload_failed}', 'true')`);
        }
      }
      fields.push(`images=$${i++}`); vals.push(serializeImages(finalImgs));
    }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    fields.push(`updated_at=NOW()`);
    vals.push(req.params.id);
    const result = await query(`UPDATE jobs SET ${fields.join(',')} WHERE id=$${i} AND status='open' RETURNING *`, vals);
    if (!result.rows.length) return res.status(400).json({ error: 'Job is no longer open and cannot be edited' });
    res.json({ job: parseJobRow(result.rows[0]), success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs/:id/check-applied
router.get('/api/jobs/:id/check-applied', auth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  try {
    const result = await query(
      "SELECT id, status FROM applications WHERE job_id = $1 AND freelancer_id = $2 AND status NOT IN ('withdrawn','rejected','offer','declined') LIMIT 1",
      [req.params.id, req.userId]
    );
    res.json({ applied: result.rows.length > 0, application_id: result.rows[0]?.id || null, status: result.rows[0]?.status || null });
  } catch (err) { serverError(err, res); }
});

// POST /api/jobs/:id/apply
router.post('/api/jobs/:id/apply', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  if (req.body.message && req.body.message.length > 2000) {
    return res.status(400).json({ error: 'Cover letter too long (max 2000 chars)' });
  }
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (normalizeId(job.posted_by) === normalizeId(req.userId)) return res.status(400).json({ error: 'Cannot apply to own job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });
    const existingApp = await query('SELECT id, status FROM applications WHERE job_id = $1 AND freelancer_id = $2', [req.params.id, req.userId]);
    if (existingApp.rows.length && !['withdrawn', 'rejected', 'offer', 'declined'].includes(existingApp.rows[0].status)) {
      return res.status(409).json({ error: 'Already applied', alreadyApplied: true });
    }
    const userResult = await query('SELECT id, username, balance_connects, is_blocked FROM users WHERE id = $1', [req.userId]);
    const user = userResult.rows[0];
    const cost = job.apply_cost || 1;
    if (!user || user.balance_connects < cost) {
      return res.status(400).json({ error: 'Not enough connects', required: cost, current: user?.balance_connects || 0 });
    }
    let appResult;
    let lockedCost = cost;
    const pgClient = await getPool().connect();
    try {
      await pgClient.query('BEGIN');
      // Re-check job status inside transaction (prevents race: job closed between outer check and INSERT)
      const jobLock = await pgClient.query('SELECT status, apply_cost FROM jobs WHERE id = $1 FOR UPDATE', [req.params.id]);
      if (!jobLock.rows.length || jobLock.rows[0].status !== 'open') {
        await pgClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Job is not open' });
      }
      lockedCost = jobLock.rows[0].apply_cost || 1;
      // Lock user row to prevent concurrent double-spend of connects
      await pgClient.query('SELECT balance_connects FROM users WHERE id = $1 FOR UPDATE', [req.userId]);
      const deductResult = await pgClient.query(
        'UPDATE users SET balance_connects = balance_connects - $1, updated_at = NOW() WHERE id = $2 AND balance_connects >= $1 RETURNING id',
        [lockedCost, req.userId]
      );
      if (!deductResult.rows.length) {
        await pgClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Not enough connects', required: lockedCost });
      }
      const prevApp = await pgClient.query(
        `SELECT id FROM applications WHERE job_id=$1 AND freelancer_id=$2 AND status IN ('withdrawn','rejected','offer','declined') LIMIT 1`,
        [req.params.id, req.userId]
      );
      let isNewApp = false;
      if (prevApp.rows.length) {
        appResult = await pgClient.query(
          `UPDATE applications SET status='pending', message=$1, updated_at=NOW() WHERE id=$2 RETURNING *`,
          [req.body.message || '', prevApp.rows[0].id]
        );
      } else {
        appResult = await pgClient.query(
          `INSERT INTO applications (job_id, job_title, freelancer_id, freelancer_name, message) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
          [req.params.id, job.title, req.userId, user.username || req.userId, req.body.message || '']
        );
        isNewApp = true;
      }
      if (!appResult.rows.length) {
        await pgClient.query('ROLLBACK');
        return res.status(400).json({ error: 'Already applied' });
      }
      if (isNewApp) {
        await pgClient.query('UPDATE jobs SET applications = applications + 1, updated_at = NOW() WHERE id = $1', [req.params.id]);
      }
      await pgClient.query('COMMIT');
    } catch (txErr) {
      await pgClient.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally { pgClient.release(); }

    // ── Create chat room and send proposal as first message ──
    let roomId = null;
    try {
      const existingRoom = await query(
        'SELECT id FROM chat_rooms WHERE job_id = $1 AND ((client_id = $2 AND freelancer_id = $3) OR (client_id = $3 AND freelancer_id = $2))',
        [req.params.id, job.posted_by, req.userId]
      );
      if (existingRoom.rows.length) {
        roomId = existingRoom.rows[0].id;
      } else {
        roomId = 'room_' + crypto.randomUUID();
        await query(
          'INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4)',
          [roomId, job.posted_by, req.userId, req.params.id]
        );
      }
      // Send proposal as first message in chat
      const proposalMsg = req.body.message || '';
      if (proposalMsg.trim()) {
        await query(
          'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4)',
          [roomId, req.userId, user.username || req.userId, proposalMsg.trim()]
        );
        await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [roomId]);
      }
    } catch (chatErr) {
      // Non-fatal: chat creation failure should not break the apply flow
      console.error('[Apply] Chat creation failed:', chatErr.message);
    }

    await audit('job_applied', { job_id: req.params.id, user_id: req.userId });
    await notify(job.posted_by, 'application', `Новый отклик на задачу "${job.title}"`,
      `${user.username || 'Фрилансер'} откликнулся на вашу задачу`, parseInt(req.params.id), roomId).catch(() => {});
    const newBalance = (user.balance_connects || 0) - lockedCost;
    res.json({ application: appResult.rows[0], success: true, remaining_connects: newBalance, new_balance: newBalance, room_id: roomId });
  } catch (err) { serverError(err, res); }
});

// POST /api/jobs/:id/hire
router.post('/api/jobs/:id/hire', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  const { application_id, freelancer_id, payment_id } = req.body;
  if (!application_id || !freelancer_id || !payment_id) return res.status(400).json({ error: 'application_id, freelancer_id, and payment_id required' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (normalizeId(job.posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });
    // Verify the client has Pi payments enabled before creating escrow
    if (!process.env.SANDBOX_MODE) {
      const clientRow = await query('SELECT payments_enabled FROM users WHERE id = $1 LIMIT 1', [req.userId]);
      if (clientRow.rows[0]?.payments_enabled === false) {
        return res.status(403).json({ error: 'Pi payments are not enabled for your account. Complete Pi KYC to hire freelancers.' });
      }
    }
    const pmtRec = await query('SELECT id, user_id, amount, status FROM payments WHERE id = $1', [payment_id]);
    if (!pmtRec.rows.length) return res.status(402).json({ error: 'Payment not found — complete Pi payment first' });
    if (pmtRec.rows[0].user_id !== req.userId) return res.status(403).json({ error: 'Payment does not belong to you' });
    if (pmtRec.rows[0].status !== 'completed') return res.status(402).json({ error: 'Payment not yet completed' });
    const appResult = await query('SELECT * FROM applications WHERE id = $1 AND job_id = $2 AND status = $3', [application_id, req.params.id, 'pending']);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found or not in pending status' });
    const app = appResult.rows[0];
    if (app.freelancer_id !== freelancer_id) return res.status(400).json({ error: 'freelancer_id does not match application' });
    const freelancerRes = await query('SELECT username FROM users WHERE id = $1', [freelancer_id]);
    const freelancerName = freelancerRes.rows[0]?.username || freelancer_id;
    const pgClientJ = await getPool().connect();
    let roomId, escrowRow;
    try {
      await pgClientJ.query('BEGIN');
      // Lock job row first to prevent concurrent hire races (two requests both reading status='open')
      const jobLockJ = await pgClientJ.query('SELECT status FROM jobs WHERE id = $1 FOR UPDATE', [req.params.id]);
      if (!jobLockJ.rows.length || jobLockJ.rows[0].status !== 'open') {
        await pgClientJ.query('ROLLBACK');
        return res.status(400).json({ error: 'Job is not open' });
      }
      // Re-verify application is still pending inside the transaction
      const appLockJ = await pgClientJ.query('SELECT id FROM applications WHERE id = $1 AND status = $2 FOR UPDATE', [application_id, 'pending']);
      if (!appLockJ.rows.length) {
        await pgClientJ.query('ROLLBACK');
        return res.status(409).json({ error: 'Application is no longer pending — it may have already been accepted' });
      }
      const existingEsc = await pgClientJ.query("SELECT * FROM escrows WHERE job_id = $1 AND status = ANY($2) FOR UPDATE", [req.params.id, ['pending', 'funded']]);
      const payUsed = await pgClientJ.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [payment_id]);
      if (payUsed.rows.length && (!existingEsc.rows.length || existingEsc.rows[0].payment_id !== payment_id)) {
        await pgClientJ.query('ROLLBACK');
        return res.status(400).json({ error: 'Payment already used for another escrow' });
      }
      await pgClientJ.query('UPDATE applications SET status = $1, updated_at = NOW() WHERE id = $2', ['accepted', application_id]);
      const toRejectJ = await pgClientJ.query('SELECT freelancer_id FROM applications WHERE job_id = $1 AND id != $2 AND status = $3', [req.params.id, application_id, 'pending']);
      await pgClientJ.query('UPDATE applications SET status = $1, updated_at = NOW() WHERE job_id = $2 AND id != $3 AND status = $4', ['rejected', req.params.id, application_id, 'pending']);
      const refundCostJ = job.apply_cost || 1;
      for (const r of toRejectJ.rows) {
        /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
      }
      if (!existingEsc.rows.length) {
        const escRes = await pgClientJ.query(
          "INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1,$2,$3,$4,$5,'funded') RETURNING *",
          [req.params.id, req.userId, freelancer_id, parseFloat(pmtRec.rows[0].amount || 0), payment_id]
        );
        escrowRow = escRes.rows[0];
      } else {
        escrowRow = existingEsc.rows[0];
      }
      await pgClientJ.query(
        'UPDATE jobs SET status=$1, hired_freelancer_id=$2, hired_freelancer_name=$3, updated_at=NOW() WHERE id=$4',
        ['in_progress', freelancer_id, freelancerName, req.params.id]
      );
      await pgClientJ.query('COMMIT');
    } catch (txErr) { await pgClientJ.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClientJ.release(); }
    const existingRoom = await query('SELECT id FROM chat_rooms WHERE job_id = $1 AND client_id = $2 AND freelancer_id = $3', [req.params.id, req.userId, freelancer_id]);
    if (existingRoom.rows.length) {
      roomId = existingRoom.rows[0].id;
    } else {
      roomId = 'room_' + crypto.randomUUID();
      await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4)', [roomId, req.userId, freelancer_id, req.params.id]);
    }
    await audit('job_hired', { job_id: req.params.id, freelancer_id, application_id, payment_id });
    await notify(freelancer_id, 'hired', `Вас наняли на задачу "${job.title}"`,
      'Заказчик выбрал вас и создал эскроу. Можете приступать к работе.', parseInt(req.params.id), roomId);
    res.json({ success: true, room_id: roomId, freelancer_name: freelancerName, escrow: escrowRow });
  } catch (err) { serverError(err, res); }
});

// POST /api/jobs/:id/complete
router.post('/api/jobs/:id/complete', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (normalizeId(job.posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your job' });
    if (!['in_progress', 'submitted'].includes(job.status)) return res.status(400).json({ error: 'Job is not in progress' });
    const disputedEscrow = await query("SELECT id FROM escrows WHERE job_id = $1 AND status = 'disputed' LIMIT 1", [req.params.id]);
    if (disputedEscrow.rows.length) return res.status(400).json({ error: 'Cannot complete job while escrow is under dispute — wait for admin resolution' });
    // Block completion until the escrow is funded — otherwise the freelancer is paid 0π for finished work.
    const unfundedComplete = await query("SELECT id FROM escrows WHERE job_id = $1 AND status = 'pending' LIMIT 1", [req.params.id]);
    if (unfundedComplete.rows.length) return res.status(400).json({ error: 'Пополните эскроу, прежде чем принимать работу и завершать задачу' });
    // Payment is handled exclusively by POST /api/escrow/:id/release (handleEscrowRelease).
    // job/complete only changes the job status — no escrow release or balance_pi credit here.
    const pgClient5 = await getPool().connect();
    try {
      await pgClient5.query('BEGIN');
      const jobUpdate = await pgClient5.query(
        "UPDATE jobs SET status='completed', updated_at=NOW() WHERE id=$1 AND status = ANY($2) RETURNING id",
        [req.params.id, ['in_progress', 'submitted']]
      );
      if (!jobUpdate.rows.length) { await pgClient5.query('ROLLBACK'); return res.status(400).json({ error: 'Job already completed or status changed' }); }
      if (job.hired_freelancer_id) {
        await pgClient5.query('UPDATE users SET total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $1', [job.hired_freelancer_id]);
      }
      await pgClient5.query('COMMIT');
    } catch (txErr) { await pgClient5.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient5.release(); }
    await audit('job_completed', { job_id: req.params.id });
    if (job.hired_freelancer_id) {
      await notify(job.hired_freelancer_id, 'completed', `Задача "${job.title}" принята`,
        'Заказчик принял работу.', parseInt(req.params.id), null);
    }
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/jobs/:id
router.delete('/api/jobs/:id', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (normalizeId(job.posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Not your job' });
    if (['in_progress', 'submitted'].includes(job.status)) return res.status(400).json({ error: 'Cannot delete a job that is in progress' });
    const applyRefundCost = job.apply_cost || 1;
    const applicants = await query("SELECT DISTINCT freelancer_id FROM applications WHERE job_id = $1 AND status = 'pending'", [req.params.id]);
    const pgClientDel = await getPool().connect();
    try {
      await pgClientDel.query('BEGIN');
      /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
      for (const row of applicants.rows) {
        /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
      }
      await pgClientDel.query('DELETE FROM applications WHERE job_id = $1', [req.params.id]);
      await pgClientDel.query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
      await pgClientDel.query('COMMIT');
    } catch (txErr) { await pgClientDel.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClientDel.release(); }
    res.json({ success: true, refunded: applicants.rows.length });
  } catch (err) { serverError(err, res); }
});

// GET /api/jobs/:id/applications
router.get('/api/jobs/:id/applications', auth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Job not found' });
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 100, 500));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const jobResult = await query('SELECT j.posted_by, j.posted_by_name, u.username FROM jobs j LEFT JOIN users u ON u.id = $1 WHERE j.id = $2', [req.userId, req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const { posted_by, posted_by_name, username: callerUsername } = jobResult.rows[0];
    const isOwner = normalizeId(posted_by) === normalizeId(req.userId)
      || (posted_by_name && callerUsername && posted_by_name.toLowerCase() === callerUsername.toLowerCase());
    if (!isOwner) return res.status(403).json({ error: 'Forbidden' });
    const [result, totalRes] = await Promise.all([
      query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.params.id, limit, offset]),
      query('SELECT COUNT(*) FROM applications WHERE job_id = $1', [req.params.id]),
    ]);
    res.json({ applications: result.rows, total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// ─── Applications ──────────────────────────────────────────────

// GET /api/applications — my applications as freelancer
router.get('/api/applications', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query(
      `SELECT a.*, j.posted_by_name as client_name, j.posted_by as client_id
       FROM applications a LEFT JOIN jobs j ON j.id = a.job_id
       WHERE a.freelancer_id = $1 ORDER BY a.created_at DESC LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    const total = await query('SELECT COUNT(*) FROM applications WHERE freelancer_id = $1', [req.userId]);
    res.json({ applications: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications — apply (frontend sends job_id in body, alias)
router.post('/api/applications', auth, checkBlocked, async (req, res) => {
  const { job_id, message } = req.body;
  if (!job_id) return res.status(400).json({ error: 'job_id required' });
  if (message && message.length > 2000) return res.status(400).json({ error: 'Cover letter too long (max 2000 chars)' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [job_id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (normalizeId(job.posted_by) === normalizeId(req.userId)) return res.status(400).json({ error: 'Cannot apply to own job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });
    const existing = await query('SELECT id, status FROM applications WHERE job_id = $1 AND freelancer_id = $2', [job_id, req.userId]);
    if (existing.rows.length && !['withdrawn', 'rejected', 'offer', 'declined'].includes(existing.rows[0].status)) {
      return res.status(409).json({ error: 'Already applied', alreadyApplied: true });
    }
    const userResult = await query('SELECT id, username, balance_connects, is_blocked FROM users WHERE id = $1', [req.userId]);
    const user = userResult.rows[0];
    const cost = job.apply_cost || 1;
    if (!user || user.balance_connects < cost) return res.status(400).json({ error: 'Not enough connects', required: cost, current: user?.balance_connects || 0 });
    let appResult;
    const pgClient = await getPool().connect();
    try {
      await pgClient.query('BEGIN');
      const deductResult2 = await pgClient.query(
        'UPDATE users SET balance_connects = balance_connects - $1, updated_at = NOW() WHERE id = $2 AND balance_connects >= $1 RETURNING id',
        [cost, req.userId]
      );
      if (!deductResult2.rows.length) { await pgClient.query('ROLLBACK'); return res.status(400).json({ error: 'Not enough connects', required: cost }); }
      const existingForAlias = await pgClient.query(
        `SELECT id FROM applications WHERE job_id=$1 AND freelancer_id=$2 AND status IN ('withdrawn','rejected','offer','declined') LIMIT 1`,
        [job_id, req.userId]
      );
      const isNewAlias = !existingForAlias.rows.length;
      if (existingForAlias.rows.length) {
        appResult = await pgClient.query(
          `UPDATE applications SET status='pending', message=$1, updated_at=NOW() WHERE id=$2 RETURNING *`,
          [message || '', existingForAlias.rows[0].id]
        );
      } else {
        appResult = await pgClient.query(
          `INSERT INTO applications (job_id, job_title, freelancer_id, freelancer_name, message) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
          [job_id, job.title, req.userId, user.username || req.userId, message || '']
        );
      }
      if (!appResult.rows.length) { await pgClient.query('ROLLBACK'); return res.status(400).json({ error: 'Already applied' }); }
      if (isNewAlias) {
        await pgClient.query('UPDATE jobs SET applications = applications + 1, updated_at = NOW() WHERE id = $1', [job_id]);
      }
      await pgClient.query('COMMIT');
    } catch (txErr) { await pgClient.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClient.release(); }
    await audit('job_applied', { job_id, user_id: req.userId });
    await notify(job.posted_by, 'application', `Новый отклик на задачу "${job.title}"`,
      `${user.username || 'Фрилансер'} откликнулся на вашу задачу`, parseInt(job_id), null);
    const newBal = (user.balance_connects || 0) - cost;
    res.json({ application: appResult.rows[0], success: true, remaining_connects: newBal, new_balance: newBal });
  } catch (err) { serverError(err, res); }
});

// GET /api/applications/my
router.get('/api/applications/my', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query(
      `SELECT a.*, j.posted_by_name as client_name, j.posted_by as client_id,
              COALESCE(u.username, j.posted_by_name) as client_username
       FROM applications a LEFT JOIN jobs j ON j.id = a.job_id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.freelancer_id = $1 ORDER BY a.created_at DESC LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    const total = await query('SELECT COUNT(*) FROM applications WHERE freelancer_id = $1', [req.userId]);
    res.json({ applications: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/applications/me
router.get('/api/applications/me', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const result = await query(
      `SELECT a.*, j.posted_by_name as client_name, j.posted_by as client_id,
              COALESCE(u.username, j.posted_by_name) as client_username
       FROM applications a LEFT JOIN jobs j ON j.id = a.job_id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.freelancer_id = $1 ORDER BY a.created_at DESC LIMIT $2 OFFSET $3`,
      [req.userId, limit, offset]
    );
    const total = await query('SELECT COUNT(*) FROM applications WHERE freelancer_id = $1', [req.userId]);
    res.json({ applications: result.rows, total: parseInt(total.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/applications/user/:userId
router.get('/api/applications/user/:userId', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const paramUserId = req.params.userId === 'cherry19899' ? 'pi_cherry19899' : req.params.userId;
    if (paramUserId !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const userId = req.userId;
    const result = await query(
      `SELECT a.*, j.title as job_title, j.budget, j.status as job_status,
              COALESCE(u.username, j.posted_by_name) as client_username,
              COALESCE(u.username, j.posted_by_name) as client_name
       FROM applications a
       JOIN jobs j ON a.job_id = j.id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.freelancer_id = $1
       ORDER BY a.created_at DESC LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    res.json({ applications: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// GET /api/applications/job/:jobId
router.get('/api/applications/job/:jobId', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const jobResult = await query('SELECT posted_by FROM jobs WHERE id = $1', [req.params.jobId]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (normalizeId(jobResult.rows[0].posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Forbidden' });
    const [result, totalRes] = await Promise.all([
      query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.params.jobId, limit, offset]),
      query('SELECT COUNT(*) FROM applications WHERE job_id = $1', [req.params.jobId]),
    ]);
    res.json({ applications: result.rows, total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// PATCH /api/applications/:id
router.patch('/api/applications/:id', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Application not found' });
  const { status } = req.body;
  const OWNER_ALLOWED = ['accepted', 'rejected'];
  if (!OWNER_ALLOWED.includes(status)) return res.status(400).json({ error: `Invalid status. Allowed: ${OWNER_ALLOWED.join(', ')}` });
  try {
    const appResult = await query('SELECT a.*, j.posted_by, j.apply_cost, j.budget AS job_budget, j.title AS job_title_full FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (normalizeId(appResult.rows[0].posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Forbidden' });
    const app_ = appResult.rows[0];
    let patchedApp;
    const pgPatch = await getPool().connect();
    try {
      await pgPatch.query('BEGIN');
      if (status === 'rejected' && app_.status === 'pending') {
        /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
      }
      const result = await pgPatch.query('UPDATE applications SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *', [status, req.params.id]);
      patchedApp = result.rows[0];
      if (status === 'accepted') {
        const toRejectPatch = await pgPatch.query(
          "SELECT freelancer_id FROM applications WHERE job_id = $1 AND id != $2 AND status = 'pending'",
          [app_.job_id, req.params.id]
        );
        if (toRejectPatch.rows.length) {
          await pgPatch.query("UPDATE applications SET status = 'rejected', updated_at = NOW() WHERE job_id = $1 AND id != $2 AND status = 'pending'", [app_.job_id, req.params.id]);
          for (const r of toRejectPatch.rows) {
            /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
          }
        }
        if (app_.freelancer_id) {
          const escrowAmt = app_.bid_amount || app_.job_budget || 0;
          const existingEscPatch = await pgPatch.query(
            "SELECT id FROM escrows WHERE job_id=$1 AND status=ANY($2) FOR UPDATE",
            [app_.job_id, ['pending', 'funded']]
          );
          if (!existingEscPatch.rows.length) {
            await pgPatch.query(
              "INSERT INTO escrows (job_id, client_id, freelancer_id, amount, status) VALUES ($1,$2,$3,$4,'pending')",
              [app_.job_id, req.userId, app_.freelancer_id, escrowAmt]
            );
          }
          await pgPatch.query(
            "UPDATE jobs SET status='in_progress', hired_freelancer_id=$1, hired_freelancer_name=$2, updated_at=NOW() WHERE id=$3 AND status='open'",
            [app_.freelancer_id, app_.freelancer_name, app_.job_id]
          );
        }
      }
      await pgPatch.query('COMMIT');
    } catch (txErr) { await pgPatch.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgPatch.release(); }
    if (status === 'accepted' && app_.freelancer_id) {
      await notify(app_.freelancer_id, 'hired', `Вас наняли на задачу "${app_.job_title_full || app_.job_title}"`,
        'Заказчик принял ваш отклик. Ожидайте финансирования эскроу.', parseInt(app_.job_id), null).catch(() => {});
      const existRmPatch = await query('SELECT id FROM chat_rooms WHERE job_id=$1 AND client_id=$2 AND freelancer_id=$3',
        [app_.job_id, req.userId, app_.freelancer_id]).catch(() => ({ rows: [] }));
      if (!existRmPatch.rows.length) {
        const rmId = 'room_' + crypto.randomUUID();
        await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1,$2,$3,$4)',
          [rmId, req.userId, app_.freelancer_id, app_.job_id]).catch(() => {});
      }
    }
    await audit('application_status_changed', { app_id: req.params.id, status });
    res.json({ application: patchedApp, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/accept
router.post('/api/applications/:id/accept', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Application not found' });
  try {
    const appResult = await query(
      'SELECT a.*, j.posted_by, j.budget, j.title FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1',
      [req.params.id]
    );
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = appResult.rows[0];
    if (normalizeId(app_.posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Forbidden' });
    const jobStatusCheck = await query('SELECT status FROM jobs WHERE id = $1', [app_.job_id]);
    if (!jobStatusCheck.rows.length || ['completed', 'cancelled'].includes(jobStatusCheck.rows[0].status)) {
      return res.status(400).json({ error: 'Cannot accept application — job is already completed or cancelled' });
    }
    const freelancerId = app_.freelancer_id;
    const escrowAmount = app_.bid_amount || app_.budget || 0;
    let escrow = null;
    let acceptedApp = null;
    const pgClientAccept = await getPool().connect();
    try {
      await pgClientAccept.query('BEGIN');
      const acceptRes = await pgClientAccept.query('UPDATE applications SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *', ['accepted', req.params.id]);
      acceptedApp = acceptRes.rows[0];
      const jobApplyCost = await pgClientAccept.query('SELECT apply_cost FROM jobs WHERE id = $1', [app_.job_id]);
      const refundCost = jobApplyCost.rows[0]?.apply_cost || 1;
      const toReject = await pgClientAccept.query(
        "SELECT freelancer_id FROM applications WHERE job_id = $1 AND id != $2 AND status = 'pending'",
        [app_.job_id, req.params.id]
      );
      if (toReject.rows.length) {
        await pgClientAccept.query("UPDATE applications SET status = 'rejected', updated_at = NOW() WHERE job_id = $1 AND id != $2 AND status = 'pending'", [app_.job_id, req.params.id]);
        for (const r of toReject.rows) {
          /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
        }
      }
      if (freelancerId) {
        const existing = await pgClientAccept.query(
          "SELECT * FROM escrows WHERE job_id = $1 AND status = ANY($2) FOR UPDATE",
          [app_.job_id, ['pending', 'funded']]
        );
        if (!existing.rows.length) {
          const escrowResult = await pgClientAccept.query(
            `INSERT INTO escrows (job_id, client_id, freelancer_id, amount, status) VALUES ($1,$2,$3,$4,'pending') RETURNING *`,
            [app_.job_id, req.userId, freelancerId, escrowAmount]
          );
          escrow = escrowResult.rows[0];
        } else {
          escrow = existing.rows[0];
        }
        await pgClientAccept.query("UPDATE jobs SET status='in_progress', hired_freelancer_id=$1, hired_freelancer_name=$2, updated_at=NOW() WHERE id=$3", [freelancerId, app_.freelancer_name, app_.job_id]);
      }
      await pgClientAccept.query('COMMIT');
    } catch (txErr) { await pgClientAccept.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClientAccept.release(); }
    if (freelancerId) {
      await notify(freelancerId, 'hired', `Вас наняли на задачу "${app_.title}"`,
        'Заказчик принял ваш отклик. Ожидайте финансирования эскроу.', parseInt(app_.job_id), null).catch(() => {});
    }
    if (freelancerId) {
      const existingRoom = await query(
        'SELECT id FROM chat_rooms WHERE job_id=$1 AND client_id=$2 AND freelancer_id=$3',
        [app_.job_id, req.userId, freelancerId]
      ).catch(() => ({ rows: [] }));
      if (!existingRoom.rows.length) {
        const newRoomId = 'room_' + crypto.randomUUID();
        await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1,$2,$3,$4)',
          [newRoomId, req.userId, freelancerId, app_.job_id]).catch(() => {});
      }
    }
    await audit('application_accepted', { app_id: req.params.id, job_id: app_.job_id, freelancer_id: freelancerId });
    res.json({ application: acceptedApp, escrow, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/reject
router.post('/api/applications/:id/reject', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Application not found' });
  try {
    const appResult = await query('SELECT a.*, j.posted_by, j.apply_cost FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (normalizeId(appResult.rows[0].posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Forbidden' });
    const app_ = appResult.rows[0];
    let rejectedApp;
    const pgRej = await getPool().connect();
    try {
      await pgRej.query('BEGIN');
      const rejRes = await pgRej.query("UPDATE applications SET status = 'rejected', updated_at = NOW() WHERE id = $1 AND status != 'rejected' RETURNING *", [req.params.id]);
      if (!rejRes.rows.length) {
        await pgRej.query('ROLLBACK');
        return res.status(400).json({ error: 'Application already rejected' });
      }
      if (app_.status === 'pending') {
        /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
      }
      await pgRej.query('COMMIT');
      rejectedApp = rejRes.rows[0];
    } catch (txErr) { await pgRej.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgRej.release(); }
    res.json({ application: rejectedApp, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/withdraw
router.post('/api/applications/:id/withdraw', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Application not found' });
  try {
    const appResult = await query('SELECT a.*, j.apply_cost FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = appResult.rows[0];
    if (normalizeId(app_.freelancer_id) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Forbidden' });
    if (app_.status !== 'pending') return res.status(400).json({ error: 'Can only withdraw pending applications' });
    let withdrawnApp;
    const pgWith = await getPool().connect();
    try {
      await pgWith.query('BEGIN');
      const wResult = await pgWith.query("UPDATE applications SET status = 'withdrawn', updated_at = NOW() WHERE id = $1 AND status = 'pending' RETURNING *", [req.params.id]);
      if (!wResult.rows.length) { await pgWith.query('ROLLBACK'); return res.status(400).json({ error: 'Can only withdraw pending applications' }); }
      await pgWith.query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [app_.apply_cost || 1, req.userId]);
      await pgWith.query('COMMIT');
      withdrawnApp = wResult.rows[0];
    } catch (txErr) { await pgWith.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgWith.release(); }
    res.json({ application: withdrawnApp, success: true });
  } catch (err) { serverError(err, res); }
});

// PUT /api/applications/:id/status
router.put('/api/applications/:id/status', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Application not found' });
  const { status } = req.body;
  const OWNER_ALLOWED = ['accepted', 'rejected'];
  if (!OWNER_ALLOWED.includes(status)) return res.status(400).json({ error: `Invalid status. Job owners may set: ${OWNER_ALLOWED.join(', ')}` });
  try {
    const appResult = await query('SELECT a.*, j.posted_by, j.apply_cost, j.budget AS job_budget, j.title AS job_title_full FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (normalizeId(appResult.rows[0].posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Forbidden' });
    const app_ = appResult.rows[0];
    let updatedApp;
    const pgStatusClient = await getPool().connect();
    try {
      await pgStatusClient.query('BEGIN');
      if (status === 'rejected' && app_.status === 'pending') {
        /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
      }
      const result = await pgStatusClient.query('UPDATE applications SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *', [status, req.params.id]);
      updatedApp = result.rows[0];
      if (status === 'accepted') {
        const toRejectStatus = await pgStatusClient.query(
          "SELECT freelancer_id FROM applications WHERE job_id = $1 AND id != $2 AND status = 'pending'",
          [app_.job_id, req.params.id]
        );
        if (toRejectStatus.rows.length) {
          await pgStatusClient.query("UPDATE applications SET status = 'rejected', updated_at = NOW() WHERE job_id = $1 AND id != $2 AND status = 'pending'", [app_.job_id, req.params.id]);
          for (const r of toRejectStatus.rows) {
            /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
          }
        }
        const escrowAmt = app_.bid_amount || app_.job_budget || 0;
        const existingSt = await pgStatusClient.query(
          "SELECT id FROM escrows WHERE job_id=$1 AND status=ANY($2) FOR UPDATE",
          [app_.job_id, ['pending', 'funded']]
        );
        if (!existingSt.rows.length && app_.freelancer_id) {
          await pgStatusClient.query(
            "INSERT INTO escrows (job_id, client_id, freelancer_id, amount, status) VALUES ($1,$2,$3,$4,'pending')",
            [app_.job_id, req.userId, app_.freelancer_id, escrowAmt]
          );
        }
        await pgStatusClient.query(
          "UPDATE jobs SET status='in_progress', hired_freelancer_id=$1, hired_freelancer_name=$2, updated_at=NOW() WHERE id=$3 AND status='open'",
          [app_.freelancer_id, app_.freelancer_name, app_.job_id]
        );
      }
      await pgStatusClient.query('COMMIT');
    } catch (txErr) { await pgStatusClient.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgStatusClient.release(); }
    if (status === 'accepted' && app_.freelancer_id) {
      await notify(app_.freelancer_id, 'hired', `Вас наняли на задачу`,
        'Заказчик принял ваш отклик. Ожидайте финансирования эскроу.', parseInt(app_.job_id), null).catch(() => {});
      const existRm = await query('SELECT id FROM chat_rooms WHERE job_id=$1 AND client_id=$2 AND freelancer_id=$3',
        [app_.job_id, req.userId, app_.freelancer_id]).catch(() => ({ rows: [] }));
      if (!existRm.rows.length) {
        const rmId = 'room_' + crypto.randomUUID();
        await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1,$2,$3,$4)',
          [rmId, req.userId, app_.freelancer_id, app_.job_id]).catch(() => {});
      }
    }
    res.json({ application: updatedApp, success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/hire — initiate Pi escrow for hired freelancer
router.post('/api/applications/:id/hire', auth, checkBlocked, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Application not found' });
  const { payment_id } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required — Pi payment must be completed before hiring' });
  try {
    const paymentCheck = await query(
      "SELECT * FROM payments WHERE id = $1 AND user_id = $2 AND status = 'completed'",
      [payment_id, req.userId]
    );
    if (!paymentCheck.rows.length) return res.status(402).json({ error: 'Valid completed payment required to hire' });
    const appResult = await query(
      'SELECT a.*, j.posted_by, j.budget, j.title as job_title, j.apply_cost FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1',
      [req.params.id]
    );
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = appResult.rows[0];
    if (normalizeId(app_.posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Forbidden' });
    const escrowAmount = parseFloat(paymentCheck.rows[0].amount || 0);
    const freelancerId = app_.freelancer_id;
    let escrowRow;
    const pgClientHire = await getPool().connect();
    try {
      await pgClientHire.query('BEGIN');
      await pgClientHire.query('UPDATE applications SET status = $1, updated_at = NOW() WHERE id = $2', ['accepted', req.params.id]);
      const existingEsc = await pgClientHire.query(
        "SELECT * FROM escrows WHERE job_id = $1 AND status = ANY($2) FOR UPDATE",
        [app_.job_id, ['pending', 'funded']]
      );
      const paymentUsed = await pgClientHire.query('SELECT id FROM escrows WHERE payment_id = $1 LIMIT 1', [payment_id]);
      if (paymentUsed.rows.length && (!existingEsc.rows.length || existingEsc.rows[0].payment_id !== payment_id)) {
        await pgClientHire.query('ROLLBACK');
        return res.status(400).json({ error: 'Payment already used for another escrow' });
      }
      if (existingEsc.rows.length) {
        escrowRow = existingEsc.rows[0];
      } else {
        const escrowResult = await pgClientHire.query(
          `INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1,$2,$3,$4,$5,'funded') RETURNING *`,
          [app_.job_id, req.userId, freelancerId, escrowAmount, payment_id]
        );
        escrowRow = escrowResult.rows[0];
      }
      const freelancerNameRes = await pgClientHire.query('SELECT username FROM users WHERE id = $1', [freelancerId]);
      const freelancerName = freelancerNameRes.rows[0]?.username || freelancerId;
      const toRejectHire = await pgClientHire.query(
        'SELECT freelancer_id FROM applications WHERE job_id = $1 AND id != $2 AND status = $3',
        [app_.job_id, req.params.id, 'pending']
      );
      await pgClientHire.query(
        'UPDATE applications SET status = $1, updated_at = NOW() WHERE job_id = $2 AND id != $3 AND status = $4',
        ['rejected', app_.job_id, req.params.id, 'pending']
      );
      const refundCostHire = app_.apply_cost || 1;
      for (const r of toRejectHire.rows) {
        /* connects are non-refundable — spent on apply/post, no refund on reject/delete */
      }
      await pgClientHire.query(
        "UPDATE jobs SET status='in_progress', hired_freelancer_id=$1, hired_freelancer_name=$2, updated_at=NOW() WHERE id=$3",
        [freelancerId, freelancerName, app_.job_id]
      );
      await pgClientHire.query('COMMIT');
    } catch (txErr) { await pgClientHire.query('ROLLBACK').catch(() => {}); throw txErr; }
    finally { pgClientHire.release(); }
    await notify(freelancerId, 'hired', `Вас наняли на задачу "${app_.job_title || app_.job_id}"`,
      'Заказчик выбрал вас и создал эскроу. Можете приступать к работе.', parseInt(app_.job_id), null);
    const existRmHire = await query('SELECT id FROM chat_rooms WHERE job_id=$1 AND client_id=$2 AND freelancer_id=$3',
      [app_.job_id, req.userId, freelancerId]).catch(() => ({ rows: [] }));
    if (!existRmHire.rows.length) {
      const rmIdHire = 'room_' + crypto.randomUUID();
      await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1,$2,$3,$4)',
        [rmIdHire, req.userId, freelancerId, app_.job_id]).catch(() => {});
    }
    await audit('hire_with_escrow', { app_id: req.params.id, job_id: app_.job_id, freelancer_id: freelancerId, amount: escrowAmount });
    res.json({ success: true, escrow: escrowRow || { job_id: app_.job_id, status: 'funded' } });
  } catch (err) { serverError(err, res); }
});

// POST /api/applications/:id/view
router.post('/api/applications/:id/view', auth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Application not found' });
  try {
    const appRes = await query(
      'SELECT j.posted_by FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1',
      [req.params.id]
    );
    if (!appRes.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (normalizeId(appRes.rows[0].posted_by) !== normalizeId(req.userId)) return res.status(403).json({ error: 'Forbidden' });
    await query('UPDATE applications SET viewed = true, viewed_at = NOW() WHERE id = $1', [req.params.id]).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

module.exports = router;

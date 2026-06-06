/**
 * WorkPro API v3.1.0
 * Pi Network Freelance Marketplace
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fetch = require('node-fetch');
const { query, initDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'admin-secret-key';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';
const PI_API_KEY = process.env.PI_API_KEY || '';
const PI_API_BASE = 'https://api.minepi.com';

// ─── Middleware ──────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: [FRONTEND_URL, 'https://cherry19899.github.io', 'http://localhost:3000', 'http://localhost:5173', 'http://localhost:3001'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-pi-token', 'x-admin-key'],
  credentials: true,
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  skip: (req) => req.path === '/api/health',
}));

// ─── Helpers ──────────────────────────────────────────────
function now() { return new Date().toISOString(); }
async function audit(action, data) {
  try {
    await query('INSERT INTO audit_logs (action, data) VALUES ($1, $2)', [action, JSON.stringify(data)]);
  } catch (_) {}
}

// ─── Pi Platform API ──────────────────────────────────────────────
async function piApiRequest(path, method = 'GET', body = null) {
  const opts = {
    method,
    headers: {
      'Authorization': `Key ${PI_API_KEY}`,
      'Content-Type': 'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${PI_API_BASE}${path}`, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_message || `Pi API error: ${res.status}`);
  return data;
}

async function piApprovePayment(paymentId) {
  return piApiRequest(`/v2/payments/${paymentId}/approve`, 'POST');
}

async function piCompletePayment(paymentId, txid) {
  return piApiRequest(`/v2/payments/${paymentId}/complete`, 'POST', { txid });
}

async function piGetPayment(paymentId) {
  return piApiRequest(`/v2/payments/${paymentId}`);
}

// ─── Auth Middleware ──────────────────────────────────────────────
async function auth(req, res, next) {
  // Accept user ID from: x-user-id header, x-pi-token header, or body user_id/reviewer_id
  const userId = req.headers['x-user-id']
    || req.headers['x-pi-token']
    || req.body?.user_id
    || req.body?.reviewer_id
    || req.body?.client_id;
  if (!userId) return res.status(401).json({ error: 'Access token required' });
  req.userId = userId;

  // Auto-register user in DB on first API call (Pi Network users aren't registered by bundle)
  try {
    const username = req.body?.username || req.headers['x-username'] || userId.replace(/^pi_/, '');
    await query(
      `INSERT INTO users (id, username, role, balance_connects, created_at, updated_at)
       VALUES ($1, $2, 'freelancer', 10, NOW(), NOW())
       ON CONFLICT (id) DO NOTHING`,
      [userId, username]
    );
  } catch (_) { /* ignore — user already exists or table error */ }

  next();
}

// softAuth — extracts userId but NEVER rejects (for endpoints where bundle sends no auth)
function softAuth(req, res, next) {
  req.userId = req.headers['x-user-id']
    || req.headers['x-pi-token']
    || req.body?.user_id
    || req.body?.reviewer_id
    || req.body?.client_id
    || null;
  next();
}

function adminAuth(req, res, next) {
  const userId = req.headers['x-user-id'];
  if (userId === 'cherry19899') {
    req.isAdmin = true;
    return next();
  }
  return res.status(403).json({ error: 'Admin access required' });
}

async function checkBlocked(req, res, next) {
  try {
    const result = await query('SELECT is_blocked FROM users WHERE id = $1', [req.userId]);
    if (result.rows[0]?.is_blocked) {
      return res.status(403).json({ error: 'Account blocked' });
    }
    next();
  } catch (_) { next(); }
}

// ─── Root & Pi Network verification ──────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ name: 'WorkPro API', version: '3.2.0', status: 'ok' });
});

// Pi Network calls this to verify backend ownership
app.get('/.well-known/pi-network', (req, res) => {
  res.json({ app: 'workpro', backend: true, version: '3.2.0' });
});

// ─── Health ──────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await query('SELECT 1');
    res.json({ status: 'ok', version: '3.2.0', database: 'connected', timestamp: now() });
  } catch (err) {
    res.status(500).json({ status: 'error', database: 'disconnected', error: err.message });
  }
});

// PUT /api/me — update profile (used by Profile.js)
app.put('/api/me', auth, async (req, res) => {
  const { username, bio, skills, display_name } = req.body;
  try {
    const uname = display_name || username;
    const skillsStr = Array.isArray(skills) ? skills.join(',') : (skills || null);
    await query(
      'UPDATE users SET username = COALESCE($1, username), bio = COALESCE($2, bio), skills = COALESCE($3, skills), updated_at = NOW() WHERE id = $4',
      [uname || null, bio || null, skillsStr, req.userId]
    );
    const result = await query('SELECT * FROM users WHERE id = $1', [req.userId]);
    const u = result.rows[0];
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/me — get current user profile (used by Profile.js)
app.get('/api/me', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(401).json({ error: 'x-user-id header required' });
  try {
    const result = await query('SELECT * FROM users WHERE id = $1', [userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/me — alias login endpoint used by Auth.js + bundle registration
app.post('/api/me', async (req, res) => {
  const { uid, username, accessToken } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid required' });
  try {
    const uname = username || uid.replace(/^pi_/, '') || uid;
    // UPSERT: create or update user
    await query(
      `INSERT INTO users (id, username, role, balance_connects, created_at, updated_at)
       VALUES ($1, $2, 'freelancer', 10, NOW(), NOW())
       ON CONFLICT (id) DO UPDATE SET username = $2, updated_at = NOW()`,
      [uid, uname]
    );
    const user = await query('SELECT * FROM users WHERE id = $1', [uid]);
    await audit('user_login', { user_id: uid });
    const u = user.rows[0];
    res.json({
      ...u,
      uid: u.id,                          // alias: frontend expects uid
      is_admin: u.role === 'admin',       // frontend checks is_admin
      token: 'pi-' + u.id,               // dummy token for compatibility
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Auth ──────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { userId, username, accessToken } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });

  try {
    // Verify with Pi Platform if accessToken provided
    let piUser = null;
    if (accessToken) {
      try {
        piUser = await piApiRequest('/v2/me', 'GET', null, accessToken);
      } catch (e) {
        // Non-fatal: proceed with provided data
      }
    }

    const uid = userId;
    const uname = (piUser && piUser.username) || username || uid;
    const paymentsEnabled = piUser ? piUser.payments_enabled === true : false;

    const existing = await query('SELECT * FROM users WHERE id = $1', [uid]);
    if (!existing.rows.length) {
      await query(
        'INSERT INTO users (id, username, role, balance_connects, created_at, updated_at) VALUES ($1, $2, $3, 10, NOW(), NOW())',
        [uid, uname, 'freelancer']
      );
    } else {
      await query('UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2', [uname, uid]);
    }

    const token = jwt.sign({ id: uid, username: uname }, JWT_SECRET, { expiresIn: '7d' });
    const user = await query('SELECT * FROM users WHERE id = $1', [uid]);
    await audit('user_login', { user_id: uid });
    res.json({ token, user: { ...user.rows[0], payments_enabled: paymentsEnabled } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM users WHERE id = $1', [req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Users ──────────────────────────────────────────────
app.get('/api/users', async (req, res) => {
  try {
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, created_at FROM users ORDER BY created_at DESC');
    res.json({ users: result.rows, count: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/users/:id', async (req, res) => {
  const userId = req.params.id === 'me' ? (req.headers['x-user-id'] || '') : req.params.id;
  if (!userId) return res.status(401).json({ error: 'User ID required' });
  try {
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at FROM users WHERE id = $1', [userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users/:id', auth, async (req, res) => {
  if (req.userId !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
  const { username, email, bio, skills, availability, avatar } = req.body;
  try {
    const result = await query(
      'UPDATE users SET username = COALESCE($1, username), email = COALESCE($2, email), bio = COALESCE($3, bio), skills = COALESCE($4, skills), availability = COALESCE($5, availability), avatar = COALESCE($6, avatar), updated_at = NOW() WHERE id = $7 RETURNING id, username, email, role, bio, skills, avatar, availability, balance_connects, rating, kyc_verified',
      [username, email, bio, skills, availability, avatar, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/users/:id/ratings', async (req, res) => {
  try {
    const result = await query('SELECT * FROM ratings WHERE to_user_id = $1 ORDER BY created_at DESC', [req.params.id]);
    const avg = result.rows.length ? result.rows.reduce((a, b) => a + parseInt(b.rating), 0) / result.rows.length : 0;
    res.json({ ratings: result.rows, average: Math.round(avg * 10) / 10, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Jobs ──────────────────────────────────────────────
app.get('/api/jobs', async (req, res) => {
  const { status, category, posted_by, client_uid, search, limit = 20, page = 1 } = req.query;
  const ownerFilter = posted_by || client_uid;
  try {
    let conditions = [];
    const params = [];
    let idx = 1;

    if (status) { conditions.push(`status = $${idx++}`); params.push(status); }
    if (category && category !== 'all' && category !== 'All') { conditions.push(`category = $${idx++}`); params.push(category); }
    if (ownerFilter) { conditions.push(`posted_by = $${idx++}`); params.push(ownerFilter); }
    if (search) { conditions.push(`(title ILIKE $${idx} OR description ILIKE $${idx})`); params.push(`%${search}%`); idx++; }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const countResult = await query(`SELECT COUNT(*) FROM jobs ${where}`, params);
    const total = parseInt(countResult.rows[0].count);

    const offset = (parseInt(page) - 1) * parseInt(limit);
    const dataResult = await query(
      `SELECT * FROM jobs ${where} ORDER BY created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...params, parseInt(limit), offset]
    );

    res.json({ jobs: dataResult.rows, total, page: parseInt(page), total_pages: Math.ceil(total / parseInt(limit)) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/jobs', auth, checkBlocked, async (req, res) => {
  const { title, description, category, budget, skills, deadline, images } = req.body;
  if (!title || !description || !budget) {
    return res.status(400).json({ error: 'Title, description, and budget are required' });
  }
  try {
    const userRes = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const username = userRes.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO jobs (title, description, category, budget, skills, images, deadline, posted_by, posted_by_name) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
      [title, description, category || 'Other', parseFloat(budget), skills || null, images || null, deadline || null, req.userId, username]
    );
    await query('UPDATE users SET total_jobs_posted = total_jobs_posted + 1, updated_at = NOW() WHERE id = $1', [req.userId]);
    await audit('job_created', { job_id: result.rows[0].id, user_id: req.userId });
    res.json({ job: result.rows[0], success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/jobs/my — client's own posted jobs (must be before /:id to avoid conflict)
app.get('/api/jobs/my', auth, async (req, res) => {
  try {
    const result = await query(
      'SELECT j.*, u.username as client_username FROM jobs j LEFT JOIN users u ON u.id = j.posted_by WHERE j.posted_by = $1 ORDER BY j.created_at DESC',
      [req.userId]
    );
    res.json({ jobs: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/jobs/:id', async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const appsResult = await query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC', [req.params.id]);
    res.json({ job: jobResult.rows[0], applications: appsResult.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/jobs/:id', auth, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (jobResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const { status } = req.body;
    const result = await query('UPDATE jobs SET status = COALESCE($1, status), updated_at = NOW() WHERE id = $2 RETURNING *', [status, req.params.id]);
    res.json({ job: result.rows[0], success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/jobs/:id/apply', auth, checkBlocked, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by === req.userId) return res.status(400).json({ error: 'Cannot apply to own job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });

    const existingApp = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2', [req.params.id, req.userId]);
    if (existingApp.rows.length) return res.status(400).json({ error: 'Already applied' });

    const userResult = await query('SELECT * FROM users WHERE id = $1', [req.userId]);
    const user = userResult.rows[0];
    const cost = job.apply_cost || 1;
    if (!user || user.balance_connects < cost) {
      return res.status(400).json({ error: 'Not enough connects', required: cost, current: user?.balance_connects || 0 });
    }

    await query('UPDATE users SET balance_connects = balance_connects - $1, updated_at = NOW() WHERE id = $2', [cost, req.userId]);
    const appResult = await query(
      'INSERT INTO applications (job_id, job_title, freelancer_id, freelancer_name, message) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.params.id, job.title, req.userId, user.username || req.userId, req.body.message || '']
    );
    await query('UPDATE jobs SET applications = applications + 1, updated_at = NOW() WHERE id = $1', [req.params.id]);
    await audit('job_applied', { job_id: req.params.id, user_id: req.userId });
    res.json({ application: appResult.rows[0], success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/jobs/:id/hire', auth, checkBlocked, async (req, res) => {
  const { application_id, freelancer_id } = req.body;
  if (!application_id || !freelancer_id) return res.status(400).json({ error: 'application_id and freelancer_id required' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });

    const appResult = await query('SELECT * FROM applications WHERE id = $1 AND job_id = $2', [application_id, req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app = appResult.rows[0];

    // Accept chosen application, reject all others
    await query('UPDATE applications SET status = $1 WHERE id = $2', ['accepted', application_id]);
    await query('UPDATE applications SET status = $1 WHERE job_id = $2 AND id != $3 AND status = $4', ['rejected', req.params.id, application_id, 'pending']);

    // Update job
    const freelancerRes = await query('SELECT username FROM users WHERE id = $1', [freelancer_id]);
    const freelancerName = freelancerRes.rows[0]?.username || freelancer_id;
    await query(
      'UPDATE jobs SET status = $1, hired_freelancer_id = $2, hired_freelancer_name = $3, updated_at = NOW() WHERE id = $4',
      ['in_progress', freelancer_id, freelancerName, req.params.id]
    );

    // Create or get chat room between client and freelancer
    const existingRoom = await query(
      'SELECT id FROM chat_rooms WHERE job_id = $1 AND client_id = $2 AND freelancer_id = $3',
      [req.params.id, req.userId, freelancer_id]
    );
    let roomId;
    if (existingRoom.rows.length) {
      roomId = existingRoom.rows[0].id;
    } else {
      roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
      await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4)', [roomId, req.userId, freelancer_id, req.params.id]);
    }

    await audit('job_hired', { job_id: req.params.id, freelancer_id, application_id });
    res.json({ success: true, room_id: roomId, freelancer_name: freelancerName });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/jobs/:id/complete', auth, checkBlocked, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    if (job.status !== 'in_progress') return res.status(400).json({ error: 'Job is not in progress' });

    const escrow = await query('SELECT * FROM escrows WHERE job_id = $1 AND status IN ($2, $3) LIMIT 1', [req.params.id, 'pending', 'funded']);
    if (escrow.rows.length) {
      const e = escrow.rows[0];
      await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['released', e.id]);
      await query('UPDATE users SET balance_pi = balance_pi + $1, total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $2', [e.amount, e.freelancer_id]);
    }
    await query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['completed', req.params.id]);
    if (job.hired_freelancer_id) {
      await query('UPDATE users SET total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $1', [job.hired_freelancer_id]);
    }
    await query('UPDATE users SET total_jobs_posted = total_jobs_posted + 1, updated_at = NOW() WHERE id = $1', [req.userId]);
    await audit('job_completed', { job_id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/jobs/:id', auth, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (jobResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    await query('DELETE FROM applications WHERE job_id = $1', [req.params.id]);
    await query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Applications ──────────────────────────────────────────────
app.get('/api/applications', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM applications WHERE freelancer_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json({ applications: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/applications/:id', auth, async (req, res) => {
  const { status } = req.body;
  try {
    const appResult = await query('SELECT a.*, j.posted_by FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (appResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 RETURNING *', [status, req.params.id]);
    await audit('application_status_changed', { app_id: req.params.id, status });
    res.json({ application: result.rows[0], success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Chat ──────────────────────────────────────────────
app.get('/api/chat/rooms', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT r.*,
        (SELECT message FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message,
        (SELECT created_at FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
        j.title as job_title,
        CASE WHEN r.client_id = $1 THEN r.freelancer_id ELSE r.client_id END as other_user_id,
        CASE WHEN r.client_id = $1 THEN uf.username ELSE uc.username END as other_user_name
       FROM chat_rooms r
       LEFT JOIN jobs j ON j.id = r.job_id
       LEFT JOIN users uc ON uc.id = r.client_id
       LEFT JOIN users uf ON uf.id = r.freelancer_id
       WHERE r.client_id = $1 OR r.freelancer_id = $1
       ORDER BY last_message_at DESC NULLS LAST`,
      [req.userId]
    );
    res.json({ rooms: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/chat/rooms', auth, checkBlocked, async (req, res) => {
  const { client_id, freelancer_id, job_id } = req.body;
  try {
    // Check if room already exists
    const existing = await query(
      'SELECT * FROM chat_rooms WHERE job_id = $1 AND ((client_id = $2 AND freelancer_id = $3) OR (client_id = $3 AND freelancer_id = $2))',
      [job_id, client_id, freelancer_id]
    );
    if (existing.rows.length) return res.json({ room: existing.rows[0] });

    const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
    const result = await query(
      'INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [roomId, client_id, freelancer_id, job_id]
    );
    res.json({ room: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/chat/rooms/:id/messages', auth, async (req, res) => {
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at ASC LIMIT 100', [req.params.id]);
    res.json({ messages: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/chat/rooms/:id/messages', auth, checkBlocked, async (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const userResult = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userResult.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.id, req.userId, senderName, message.trim()]
    );
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    res.json({ message: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Escrow ──────────────────────────────────────────────
app.get('/api/escrow', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json({ escrows: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/escrow', auth, checkBlocked, async (req, res) => {
  const { job_id, freelancer_id, amount, payment_id } = req.body;
  if (!job_id || !freelancer_id || !amount) return res.status(400).json({ error: 'job_id, freelancer_id, amount required' });
  try {
    const existing = await query('SELECT id FROM escrows WHERE job_id = $1 AND status IN ($2, $3)', [job_id, 'pending', 'funded']);
    if (existing.rows.length) return res.status(400).json({ error: 'Escrow already exists for this job' });
    const result = await query(
      'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [job_id, req.userId, freelancer_id, parseFloat(amount), payment_id || null]
    );
    await query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['in_progress', job_id]);
    await audit('escrow_created', { escrow_id: result.rows[0].id, job_id });
    res.json({ escrow: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// softAuth: bundle sends no auth header
app.post('/api/escrow/:id/release', softAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (req.userId && escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status === 'released') return res.status(400).json({ error: 'Already released' });

    await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['released', req.params.id]);
    await query('UPDATE users SET balance_pi = balance_pi + $1, total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $2', [escrow.amount, escrow.freelancer_id]);
    await query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['completed', escrow.job_id]);
    await audit('escrow_released', { escrow_id: req.params.id, freelancer_id: escrow.freelancer_id, amount: escrow.amount });
    res.json({ escrow: { ...escrow, status: 'released' }, success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Pi Payments ──────────────────────────────────────────────
app.post('/api/payments/:paymentId/approve', auth, async (req, res) => {
  const { paymentId } = req.params;
  const { metadata } = req.body;
  try {
    // Verify payment with Pi Platform
    const piPayment = await piApprovePayment(paymentId);

    // Store in DB
    const existing = await query('SELECT id FROM payments WHERE id = $1', [paymentId]);
    if (!existing.rows.length) {
      await query(
        'INSERT INTO payments (id, user_id, type, amount, metadata, status) VALUES ($1, $2, $3, $4, $5, $6)',
        [paymentId, req.userId, metadata?.type || 'payment', piPayment.amount || 0, JSON.stringify(metadata || {}), 'approved']
      );
    } else {
      await query('UPDATE payments SET status = $1, updated_at = NOW() WHERE id = $2', ['approved', paymentId]);
    }

    await audit('payment_approved', { payment_id: paymentId, user_id: req.userId, amount: piPayment.amount });
    res.json({ success: true, payment: piPayment });
  } catch (err) {
    console.error('[Payment] Approve error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/payments/:paymentId/complete', auth, async (req, res) => {
  const { paymentId } = req.params;
  const { txid, metadata } = req.body;
  if (!txid) return res.status(400).json({ error: 'txid required' });
  try {
    // Verify with Pi Platform
    const piPayment = await piCompletePayment(paymentId, txid);

    // Update payment record
    await query(
      'UPDATE payments SET status = $1, txid = $2, updated_at = NOW() WHERE id = $3',
      ['completed', txid, paymentId]
    );

    // Handle business logic based on payment type
    const paymentRecord = await query('SELECT * FROM payments WHERE id = $1', [paymentId]);
    if (paymentRecord.rows.length) {
      const meta = paymentRecord.rows[0].metadata || {};
      if (meta.type === 'connects') {
        const amount = parseInt(meta.connects_amount || 10);
        await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [amount, req.userId]);
      } else if (meta.type === 'escrow' && meta.job_id && meta.freelancer_id) {
        // Create escrow record
        await query(
          'INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING',
          [meta.job_id, req.userId, meta.freelancer_id, piPayment.amount, paymentId, 'funded']
        );
        await query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['in_progress', meta.job_id]);
      }
    }

    await audit('payment_completed', { payment_id: paymentId, txid, user_id: req.userId });
    res.json({ success: true, payment: piPayment });
  } catch (err) {
    console.error('[Payment] Complete error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/payments', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json({ payments: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/payments/incomplete', auth, async (req, res) => {
  // Called when Pi SDK finds an incomplete payment on app open
  const { paymentId } = req.body;
  if (!paymentId) return res.status(400).json({ error: 'paymentId required' });
  try {
    const piPayment = await piGetPayment(paymentId);
    // If payment is pending server completion, complete it
    if (piPayment.status && piPayment.status.developer_completed === false && piPayment.transaction) {
      await piCompletePayment(paymentId, piPayment.transaction.txid);
      await query('UPDATE payments SET status = $1, txid = $2, updated_at = NOW() WHERE id = $3',
        ['completed', piPayment.transaction.txid, paymentId]);
    }
    res.json({ success: true, payment: piPayment });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Connects ──────────────────────────────────────────────
app.get('/api/connects/balance', auth, async (req, res) => {
  try {
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
    res.json({ balance: result.rows[0]?.balance_connects || 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/connects/purchase', auth, checkBlocked, async (req, res) => {
  // Called after Pi payment is completed for connects
  const { amount, payment_id } = req.body;
  try {
    await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [parseInt(amount || 10), req.userId]);
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
    await audit('connects_purchased', { user_id: req.userId, amount, payment_id });
    res.json({ balance: result.rows[0].balance_connects, success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Ratings ──────────────────────────────────────────────
app.post('/api/ratings', auth, checkBlocked, async (req, res) => {
  const { to_user_id, job_id, rating, comment } = req.body;
  if (!to_user_id || !rating) return res.status(400).json({ error: 'to_user_id and rating required' });
  if (rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
  try {
    const existing = await query('SELECT id FROM ratings WHERE from_user_id = $1 AND job_id = $2', [req.userId, job_id]);
    if (existing.rows.length) return res.status(400).json({ error: 'Already rated this job' });

    const result = await query(
      'INSERT INTO ratings (from_user_id, to_user_id, job_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.userId, to_user_id, job_id, parseInt(rating), comment || '']
    );
    // Update user average rating
    const avgResult = await query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [to_user_id]);
    const newAvg = Math.round(parseFloat(avgResult.rows[0].avg) * 10) / 10;
    await query('UPDATE users SET rating = $1, updated_at = NOW() WHERE id = $2', [newAvg, to_user_id]);
    res.json({ rating: result.rows[0], success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin ──────────────────────────────────────────────
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [users, jobs, applications, escrows, payments, ratings, chats] = await Promise.all([
      query('SELECT COUNT(*) FROM users'),
      query('SELECT COUNT(*) FROM jobs'),
      query('SELECT COUNT(*) FROM applications'),
      query('SELECT COUNT(*) FROM escrows'),
      query('SELECT COUNT(*) FROM payments'),
      query('SELECT COUNT(*) FROM ratings'),
      query('SELECT COUNT(*) FROM chat_rooms'),
    ]);
    const u = parseInt(users.rows[0].count);
    const j = parseInt(jobs.rows[0].count);
    const a = parseInt(applications.rows[0].count);
    const e = parseInt(escrows.rows[0].count);
    res.json({
      total_users: u, users: u,
      total_jobs: j, jobs: j,
      total_applications: a, applications: a,
      total_escrows: e, escrows: e,
      payments: parseInt(payments.rows[0].count),
      ratings: parseInt(ratings.rows[0].count),
      chats: parseInt(chats.rows[0].count),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const search = req.query.search || '';
    let sql = 'SELECT * FROM users';
    const params = [];
    if (search) { sql += ' WHERE username ILIKE $1 OR id ILIKE $1'; params.push(`%${search}%`); }
    sql += ' ORDER BY created_at DESC';
    const result = await query(sql, params);
    res.json({ users: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/users/:id/block', adminAuth, async (req, res) => {
  if (req.params.id === 'cherry19899') return res.status(403).json({ error: 'Cannot block owner' });
  try {
    await query('UPDATE users SET is_blocked = true, status = $1, updated_at = NOW() WHERE id = $2', ['blocked', req.params.id]);
    await audit('user_blocked', { user_id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  try {
    await query('UPDATE users SET is_blocked = false, status = $1, updated_at = NOW() WHERE id = $2', ['active', req.params.id]);
    await audit('user_unblocked', { user_id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/jobs', adminAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM jobs ORDER BY created_at DESC LIMIT 100');
    res.json({ jobs: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/jobs/:id', adminAuth, async (req, res) => {
  try {
    await query('DELETE FROM applications WHERE job_id = $1', [req.params.id]);
    await query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/users/:id/grant-connects — admin grants connects to user
app.post('/api/admin/users/:id/grant-connects', adminAuth, async (req, res) => {
  const { amount } = req.body;
  const qty = parseInt(amount || 50);
  try {
    await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [qty, req.params.id]);
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.params.id]);
    await audit('admin_grant_connects', { user_id: req.params.id, amount: qty, granted_by: req.userId });
    res.json({ success: true, balance: result.rows[0]?.balance_connects || 0 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/escrows', adminAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows ORDER BY created_at DESC');
    res.json({ escrows: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/earnings', adminAuth, async (req, res) => {
  try {
    const result = await query("SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'completed'");
    const transactions = await query('SELECT COUNT(*) FROM payments');
    res.json({ total_earnings: parseFloat(result.rows[0].total), transactions: parseInt(transactions.rows[0].count) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/audit-logs', adminAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200');
    res.json({ logs: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/verify', async (req, res) => {
  const key = req.headers['x-admin-key'] || req.headers['authorization'] || req.query.admin_key;
  let token = key || '';
  if (token.startsWith('Bearer ')) token = token.substring(7);
  res.json({ valid: token === ADMIN_API_KEY, env_set: !!process.env.ADMIN_API_KEY });
});

// GET /api/jobs/:id/applications — used by JobDetail.js
app.get('/api/jobs/:id/applications', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC', [req.params.id]);
    res.json({ applications: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/jobs?client_uid=xxx — filter by owner (client_uid alias for posted_by)
// Handled in existing GET /api/jobs — patching it to support client_uid param
// (done below in the jobs section override)

// GET /api/applications/me — alias for /my
// (added below)

// GET /api/escrows + /api/escrows/me — alias for /api/escrow
app.get('/api/escrows', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json({ escrows: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/escrows/me', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json({ escrows: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
// softAuth: bundle sends no auth header for releaseEscrow
app.post('/api/escrows/:id/release', softAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    // Only enforce ownership if caller identified themselves
    if (req.userId && escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['released', req.params.id]);
    await query('UPDATE users SET balance_pi = balance_pi + $1, total_jobs_completed = total_jobs_completed + 1, updated_at = NOW() WHERE id = $2', [escrow.amount, escrow.freelancer_id]);
    await query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['completed', escrow.job_id]);
    await audit('escrow_released', { escrow_id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/escrows/:id/cancel', auth, checkBlocked, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['refunded', req.params.id]);
    await query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['open', escrow.job_id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/chat/start — start or get conversation
app.post('/api/chat/start', auth, checkBlocked, async (req, res) => {
  const { other_user_id, job_id } = req.body;
  if (!other_user_id) return res.status(400).json({ error: 'other_user_id required' });
  try {
    const jobId = job_id || 0;
    const existing = await query(
      'SELECT * FROM chat_rooms WHERE (client_id = $1 AND freelancer_id = $2) OR (client_id = $2 AND freelancer_id = $1)',
      [req.userId, other_user_id]
    );
    if (existing.rows.length) return res.json({ conversation: existing.rows[0], id: existing.rows[0].id });
    const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
    const result = await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *', [roomId, req.userId, other_user_id, jobId]);
    res.json({ conversation: result.rows[0], id: result.rows[0].id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Alias endpoints for cherry19899.github.io frontend ──────────────────
// POST /api/applications — apply to job (frontend sends job_id in body)
app.post('/api/applications', auth, checkBlocked, async (req, res) => {
  const { job_id, message } = req.body;
  if (!job_id) return res.status(400).json({ error: 'job_id required' });
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [job_id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by === req.userId) return res.status(400).json({ error: 'Cannot apply to own job' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job is not open' });
    const existing = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2', [job_id, req.userId]);
    if (existing.rows.length) return res.status(400).json({ error: 'Already applied' });
    const userResult = await query('SELECT * FROM users WHERE id = $1', [req.userId]);
    const user = userResult.rows[0];
    const cost = job.apply_cost || 1;
    if (!user || user.balance_connects < cost) return res.status(400).json({ error: 'Not enough connects', required: cost, current: user?.balance_connects || 0 });
    await query('UPDATE users SET balance_connects = balance_connects - $1, updated_at = NOW() WHERE id = $2', [cost, req.userId]);
    const appResult = await query(
      'INSERT INTO applications (job_id, job_title, freelancer_id, freelancer_name, message) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [job_id, job.title, req.userId, user.username || req.userId, message || '']
    );
    await query('UPDATE jobs SET applications = applications + 1, updated_at = NOW() WHERE id = $1', [job_id]);
    await audit('job_applied', { job_id, user_id: req.userId });
    res.json({ application: appResult.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/applications/my + /api/applications/me — my applications as freelancer
app.get('/api/applications/my', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM applications WHERE freelancer_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json({ applications: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/applications/me', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM applications WHERE freelancer_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json({ applications: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/applications/job/:jobId — applications for a specific job (owner only)
app.get('/api/applications/job/:jobId', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC', [req.params.jobId]);
    res.json({ applications: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/applications/:id/accept — accept application + create escrow record
// Uses softAuth: bundle sends no auth, ownership check is skipped when no userId
app.post('/api/applications/:id/accept', softAuth, async (req, res) => {
  try {
    const appResult = await query(
      'SELECT a.*, j.posted_by, j.budget, j.title FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1',
      [req.params.id]
    );
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = appResult.rows[0];
    // Only enforce ownership if caller identified themselves
    if (req.userId && app_.posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    // Set userId from job owner if not provided (bundle scenario)
    if (!req.userId) req.userId = app_.posted_by;

    // Accept the application
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 RETURNING *', ['accepted', req.params.id]);

    // Create escrow record (pending state — will be funded after Pi payment)
    const freelancerId = app_.freelancer_id;
    const escrowAmount = app_.bid_amount || app_.budget || 0;
    let escrow = null;
    if (freelancerId) {
      const existing = await query('SELECT * FROM escrows WHERE job_id = $1 AND status IN ($2, $3)', [app_.job_id, 'pending', 'funded']);
      if (!existing.rows.length) {
        const escrowResult = await query(
          `INSERT INTO escrows (job_id, client_id, freelancer_id, amount, status)
           VALUES ($1,$2,$3,$4,'pending') RETURNING *`,
          [app_.job_id, req.userId, freelancerId, escrowAmount]
        );
        escrow = escrowResult.rows[0];
      } else {
        escrow = existing.rows[0];
      }
      // Mark job as in-progress
      await query("UPDATE jobs SET status='in_progress', updated_at=NOW() WHERE id=$1", [app_.job_id]);
    }

    await audit('application_accepted', { app_id: req.params.id, job_id: app_.job_id, freelancer_id: freelancerId });
    res.json({ application: result.rows[0], escrow, success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/applications/:id/reject — alias used by JobDetail.js
app.post('/api/applications/:id/reject', auth, async (req, res) => {
  try {
    const appResult = await query('SELECT a.*, j.posted_by FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (appResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 RETURNING *', ['rejected', req.params.id]);
    res.json({ application: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/applications/:id/status — update application status
app.put('/api/applications/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  try {
    const appResult = await query('SELECT a.*, j.posted_by FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1', [req.params.id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    if (appResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 RETURNING *', [status, req.params.id]);
    res.json({ application: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/jobs/:id — update job
app.put('/api/jobs/:id', auth, async (req, res) => {
  const { title, description, category, budget, skills, deadline, status } = req.body;
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (jobResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    const fields = [], vals = [];
    let i = 1;
    if (title !== undefined) { fields.push(`title=$${i++}`); vals.push(title); }
    if (description !== undefined) { fields.push(`description=$${i++}`); vals.push(description); }
    if (category !== undefined) { fields.push(`category=$${i++}`); vals.push(category); }
    if (budget !== undefined) { fields.push(`budget=$${i++}`); vals.push(parseFloat(budget)); }
    if (skills !== undefined) { fields.push(`skills=$${i++}`); vals.push(skills); }
    if (deadline !== undefined) { fields.push(`deadline=$${i++}`); vals.push(deadline || null); }
    if (status !== undefined) { fields.push(`status=$${i++}`); vals.push(status); }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    fields.push(`updated_at=NOW()`);
    vals.push(req.params.id);
    const result = await query(`UPDATE jobs SET ${fields.join(',')} WHERE id=$${i} RETURNING *`, vals);
    res.json({ job: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/users/me — get current user profile
app.get('/api/users/me', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM users WHERE id = $1', [req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/users/me — update current user profile
app.put('/api/users/me', auth, async (req, res) => {
  const { username, bio, skills, availability, avatar, email } = req.body;
  try {
    const fields = [], vals = [];
    let i = 1;
    if (username) { fields.push(`username=$${i++}`); vals.push(username); }
    if (bio !== undefined) { fields.push(`bio=$${i++}`); vals.push(bio); }
    if (skills !== undefined) { fields.push(`skills=$${i++}`); vals.push(skills); }
    if (availability) { fields.push(`availability=$${i++}`); vals.push(availability); }
    if (avatar) { fields.push(`avatar=$${i++}`); vals.push(avatar); }
    if (email) { fields.push(`email=$${i++}`); vals.push(email); }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    fields.push(`updated_at=NOW()`);
    vals.push(req.userId);
    const result = await query(`UPDATE users SET ${fields.join(',')} WHERE id=$${i} RETURNING *`, vals);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Chat alias endpoints (conversations = rooms) ──────────────────
app.get('/api/chat/conversations', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT r.*,
        (SELECT message FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message,
        (SELECT created_at FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
        j.title as job_title,
        CASE WHEN r.client_id = $1 THEN r.freelancer_id ELSE r.client_id END as other_user_id,
        CASE WHEN r.client_id = $1 THEN uf.username ELSE uc.username END as other_user_name
       FROM chat_rooms r
       LEFT JOIN jobs j ON j.id = r.job_id
       LEFT JOIN users uc ON uc.id = r.client_id
       LEFT JOIN users uf ON uf.id = r.freelancer_id
       WHERE r.client_id = $1 OR r.freelancer_id = $1
       ORDER BY last_message_at DESC NULLS LAST`,
      [req.userId]
    );
    res.json({ conversations: result.rows, rooms: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/chat/conversations', auth, checkBlocked, async (req, res) => {
  const { client_id, freelancer_id, job_id, other_user_id } = req.body;
  const cId = client_id || req.userId;
  const fId = freelancer_id || other_user_id;
  if (!fId || !job_id) return res.status(400).json({ error: 'freelancer_id and job_id required' });
  try {
    const existing = await query('SELECT * FROM chat_rooms WHERE job_id = $1 AND ((client_id = $2 AND freelancer_id = $3) OR (client_id = $3 AND freelancer_id = $2))', [job_id, cId, fId]);
    if (existing.rows.length) return res.json({ conversation: existing.rows[0], room: existing.rows[0] });
    const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
    const result = await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *', [roomId, cId, fId, job_id]);
    res.json({ conversation: result.rows[0], room: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/chat/conversations/:id/messages', auth, async (req, res) => {
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const result = await query('SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at ASC LIMIT 200', [req.params.id]);
    res.json({ messages: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/chat/conversations/:id/messages', auth, checkBlocked, async (req, res) => {
  const msg = req.body.content || req.body.message;
  if (!msg || !msg.trim()) return res.status(400).json({ error: 'Message required' });
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const userResult = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userResult.rows[0]?.username || req.userId;
    const result = await query('INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *', [req.params.id, req.userId, senderName, msg.trim()]);
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    res.json({ message: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/chat/unread', auth, async (req, res) => {
  try {
    // Count messages in rooms where user is participant, not sent by user
    const result = await query(
      `SELECT COUNT(*) FROM chat_messages cm
       JOIN chat_rooms r ON r.id = cm.room_id
       WHERE (r.client_id = $1 OR r.freelancer_id = $1) AND cm.sender_id != $1
       AND cm.created_at > COALESCE((SELECT updated_at FROM users WHERE id = $1), NOW() - INTERVAL '30 days')`,
      [req.userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) { res.json({ count: 0 }); }
});

// ─── Reviews alias (= ratings) ──────────────────
// Bundle sends: {reviewer_id, reviewer_name, target_id, target_name, job_id, job_title, rating, text}
app.post('/api/reviews', auth, checkBlocked, async (req, res) => {
  const { to_user_id, target_id, job_id, rating, comment, text, reviewer_id } = req.body;
  const toId = to_user_id || target_id;  // bundle uses target_id
  const reviewComment = comment || text || '';
  if (!toId || !rating) return res.status(400).json({ error: 'to_user_id and rating required' });
  if (rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
  try {
    const existing = await query('SELECT id FROM ratings WHERE from_user_id = $1 AND job_id = $2', [req.userId, job_id]);
    if (existing.rows.length) return res.status(400).json({ error: 'Already rated this job' });
    const result = await query('INSERT INTO ratings (from_user_id, to_user_id, job_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *', [req.userId, toId, job_id || null, parseInt(rating), reviewComment]);
    const avgResult = await query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [toId]);
    const newAvg = Math.round(parseFloat(avgResult.rows[0].avg) * 10) / 10;
    await query('UPDATE users SET rating = $1, updated_at = NOW() WHERE id = $2', [newAvg, toId]);
    res.json({ review: result.rows[0], rating: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reviews/user/:userId', async (req, res) => {
  try {
    const result = await query('SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC', [req.params.userId]);
    res.json({ reviews: result.rows, ratings: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/reviews?user_id=xxx — alias used by some frontend pages
app.get('/api/reviews', async (req, res) => {
  const userId = req.query.user_id || req.headers['x-user-id'];
  if (!userId) return res.json({ reviews: [], ratings: [] });
  try {
    const result = await query('SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC', [userId]);
    res.json({ reviews: result.rows, ratings: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/jobs/all — alias for /api/admin/jobs
app.get('/api/admin/jobs/all', adminAuth, async (req, res) => {
  try {
    const result = await query('SELECT j.*, u.username as posted_by_name FROM jobs j LEFT JOIN users u ON u.id = j.posted_by ORDER BY j.created_at DESC');
    res.json({ jobs: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/connects/buy defined later (full version with package_amount + Pi payment support)

// ─── Escrow refund ──────────────────
app.post('/api/escrow/:id/refund', auth, checkBlocked, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    if (escrow.status === 'released' || escrow.status === 'refunded') return res.status(400).json({ error: 'Already processed' });
    await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['refunded', req.params.id]);
    await query('UPDATE jobs SET status = $1, updated_at = NOW() WHERE id = $2', ['open', escrow.job_id]);
    await audit('escrow_refunded', { escrow_id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Portfolio ──────────────────
app.get('/api/users/:id/portfolio', async (req, res) => {
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/me/portfolio', auth, async (req, res) => {
  const { headline, summary, experience_years, website, github, linkedin } = req.body;
  try {
    await query(`CREATE TABLE IF NOT EXISTS portfolios (
      id SERIAL PRIMARY KEY, user_id VARCHAR(255) UNIQUE, headline TEXT, summary TEXT,
      experience_years INTEGER DEFAULT 0, website TEXT, github TEXT, linkedin TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`).catch(() => {});
    await query(
      `INSERT INTO portfolios (user_id, headline, summary, experience_years, website, github, linkedin)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (user_id) DO UPDATE SET headline=$2, summary=$3, experience_years=$4, website=$5, github=$6, linkedin=$7, updated_at=NOW()`,
      [req.userId, headline || '', summary || '', parseInt(experience_years || 0), website || '', github || '', linkedin || '']
    );
    const result = await query('SELECT * FROM portfolios WHERE user_id = $1', [req.userId]);
    res.json({ portfolio: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users/me/portfolio/items', auth, async (req, res) => {
  const { title, description, image_url, category, tags } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });
  try {
    await query(`CREATE TABLE IF NOT EXISTS portfolio_items (
      id SERIAL PRIMARY KEY, user_id VARCHAR(255), title VARCHAR(500) NOT NULL,
      description TEXT, image_url TEXT, category VARCHAR(100), tags TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`).catch(() => {});
    const tagsStr = Array.isArray(tags) ? tags.join(',') : (tags || '');
    const result = await query(
      'INSERT INTO portfolio_items (user_id, title, description, image_url, category, tags) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.userId, title, description || '', image_url || '', category || 'Other', tagsStr]
    );
    res.json({ item: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/me/portfolio/items/:id', auth, async (req, res) => {
  try {
    await query('DELETE FROM portfolio_items WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Notifications ──────────────────────────────────────────────
// Simple notifications: unread chat messages count as notifications
app.get('/api/notifications/unread-count', auth, async (req, res) => {
  try {
    // Count recent messages in chat rooms where user is participant but not sender
    const result = await query(
      `SELECT COUNT(*) FROM chat_messages cm
       JOIN chat_rooms cr ON cr.id = cm.room_id
       WHERE (cr.client_id = $1 OR cr.freelancer_id = $1)
         AND cm.sender_id != $1
         AND cm.created_at > NOW() - INTERVAL '7 days'`,
      [req.userId]
    );
    const unread_count = parseInt(result.rows[0].count) || 0;
    res.json({ unread_count, count: unread_count });
  } catch (err) {
    res.json({ unread_count: 0, count: 0 });
  }
});

app.get('/api/notifications', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT cm.id, cm.message as message, cm.message as content, cm.created_at,
              u.username as from_username, cr.id as room_id
       FROM chat_messages cm
       JOIN chat_rooms cr ON cr.id = cm.room_id
       JOIN users u ON u.id = cm.sender_id
       WHERE (cr.client_id = $1 OR cr.freelancer_id = $1)
         AND cm.sender_id != $1
         AND cm.created_at > NOW() - INTERVAL '7 days'
       ORDER BY cm.created_at DESC LIMIT 50`,
      [req.userId]
    );
    res.json({ notifications: result.rows });
  } catch (err) {
    res.json({ notifications: [] });
  }
});

app.post('/api/notifications/mark-read', auth, async (req, res) => {
  // No read tracking in chat_messages table — just return success
  res.json({ success: true });
});

// ─── Hire with Pi payment (escrow) ──────────────────────────────────────────────
// POST /api/applications/:id/hire — initiate Pi escrow for hired freelancer
// Called from frontend after client decides to hire (Pi payment flow)
app.post('/api/applications/:id/hire', auth, checkBlocked, async (req, res) => {
  const { payment_id, txid, amount } = req.body;
  try {
    const appResult = await query(
      'SELECT a.*, j.posted_by, j.budget FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = $1',
      [req.params.id]
    );
    if (!appResult.rows.length) return res.status(404).json({ error: 'Application not found' });
    const app_ = appResult.rows[0];
    if (app_.posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });

    const escrowAmount = amount || app_.bid_amount || app_.budget;
    const freelancerId = app_.freelancer_id;

    // Accept application
    await query('UPDATE applications SET status = $1 WHERE id = $2', ['accepted', req.params.id]);
    // Create escrow
    const escrow = await query(
      `INSERT INTO escrows (job_id, client_id, freelancer_id, amount, payment_id, status)
       VALUES ($1,$2,$3,$4,$5,'funded') ON CONFLICT DO NOTHING RETURNING *`,
      [app_.job_id, req.userId, freelancerId, escrowAmount, payment_id || null]
    );
    // Mark job as in-progress
    await query("UPDATE jobs SET status='in_progress', updated_at=NOW() WHERE id=$1", [app_.job_id]);
    await audit('hire_with_escrow', { app_id: req.params.id, job_id: app_.job_id, freelancer_id: freelancerId, amount: escrowAmount });
    res.json({ success: true, escrow: escrow.rows[0] || { job_id: app_.job_id, status: 'funded' } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/payments/approve — Pi payment server-side approval
app.post('/api/payments/approve', auth, async (req, res) => {
  const { payment_id, metadata } = req.body;
  if (!payment_id) return res.status(400).json({ error: 'payment_id required' });
  try {
    // Call Pi Platform API to approve
    const approveRes = await fetch(`https://api.minepi.com/v2/payments/${payment_id}/approve`, {
      method: 'POST',
      headers: {
        'Authorization': `Key ${process.env.PI_API_KEY}`,
        'Content-Type': 'application/json',
      }
    });
    const approveData = await approveRes.json();
    // Record in DB
    await query(
      `INSERT INTO payments (user_id, payment_id, amount, status, metadata)
       VALUES ($1,$2,$3,'approved',$4)
       ON CONFLICT (payment_id) DO UPDATE SET status='approved', updated_at=NOW()`,
      [req.userId, payment_id, approveData.amount || 0, JSON.stringify(metadata || {})]
    ).catch(() => {});
    res.json({ success: true, payment: approveData });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/payments/complete — Pi payment server-side completion
app.post('/api/payments/complete', auth, async (req, res) => {
  const { payment_id, txid, metadata } = req.body;
  if (!payment_id || !txid) return res.status(400).json({ error: 'payment_id and txid required' });
  try {
    const completeRes = await fetch(`https://api.minepi.com/v2/payments/${payment_id}/complete`, {
      method: 'POST',
      headers: {
        'Authorization': `Key ${process.env.PI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ txid })
    });
    const completeData = await completeRes.json();
    await query(
      `UPDATE payments SET status='completed', txid=$1, updated_at=NOW() WHERE payment_id=$2`,
      [txid, payment_id]
    ).catch(() => {});
    res.json({ success: true, payment: completeData });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/connects/buy — alias for connects/purchase, called from Connects.js and bundle
app.post('/api/connects/buy', auth, checkBlocked, async (req, res) => {
  // Support both Connects.js format (quantity) and bundle format (package_amount)
  const quantity = req.body.quantity || req.body.package_amount;
  const { payment_id, txid, amount, status, pi_amount, user_id } = req.body;
  if (!quantity) return res.status(400).json({ error: 'quantity required' });

  // If this is a granted (admin/dev bonus) call, add directly
  if (status === 'granted') {
    try {
      // UPSERT to ensure user exists, then update balance
      const uname = req.body?.username || req.userId.replace(/^pi_/, '');
      await query(
        `INSERT INTO users (id, username, role, balance_connects, created_at, updated_at)
         VALUES ($1, $2, 'freelancer', $3, NOW(), NOW())
         ON CONFLICT (id) DO UPDATE SET balance_connects = users.balance_connects + $3, updated_at = NOW()`,
        [req.userId, uname, parseInt(quantity)]
      );
      const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
      return res.json({ success: true, balance: result.rows[0]?.balance_connects || 0 });
    } catch (err) { return res.status(500).json({ error: err.message }); }
  }

  // If this is a pending (approval) call, just record and return
  if (status === 'pending') {
    await query(
      `INSERT INTO payments (user_id, payment_id, amount, status, metadata)
       VALUES ($1,$2,$3,'pending',$4)
       ON CONFLICT (payment_id) DO UPDATE SET status='pending', updated_at=NOW()`,
      [req.userId, payment_id || 'manual', amount || 0, JSON.stringify({ type: 'connects', quantity })]
    ).catch(() => {});
    return res.json({ success: true, status: 'pending' });
  }

  // Completed — add connects
  try {
    if (payment_id && txid) {
      // Approve + complete with Pi
      await fetch(`https://api.minepi.com/v2/payments/${payment_id}/approve`, {
        method: 'POST',
        headers: { 'Authorization': `Key ${process.env.PI_API_KEY}` }
      }).catch(() => {});
      await fetch(`https://api.minepi.com/v2/payments/${payment_id}/complete`, {
        method: 'POST',
        headers: { 'Authorization': `Key ${process.env.PI_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ txid })
      }).catch(() => {});
    }
    await query(
      'UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2',
      [parseInt(quantity), req.userId]
    );
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
    const balance = result.rows[0]?.balance_connects || 0;
    await audit('connects_purchased', { user_id: req.userId, quantity, payment_id });
    res.json({ success: true, balance, balance_connects: balance });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// (jobs/my is defined above, before /jobs/:id)

// ─── Missing endpoint aliases found from bundle analysis ──────────────────────────────────────────────

// GET /api/applications/user/:userId — list applications for a user
app.get('/api/applications/user/:userId', auth, async (req, res) => {
  try {
    const userId = req.params.userId || req.userId;
    const result = await query(
      `SELECT a.*, j.title as job_title, j.budget, j.status as job_status,
              u.username as client_username
       FROM applications a
       JOIN jobs j ON a.job_id = j.id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.freelancer_id = $1
       ORDER BY a.created_at DESC`,
      [userId]
    );
    res.json({ applications: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/escrows/user/:userId — list escrows for a user
app.get('/api/escrows/user/:userId', auth, async (req, res) => {
  try {
    const userId = req.params.userId || req.userId;
    const result = await query(
      `SELECT e.*, j.title as job_title,
              c.username as client_username, f.username as freelancer_username
       FROM escrows e
       LEFT JOIN jobs j ON j.id = e.job_id
       LEFT JOIN users c ON c.id = e.client_id
       LEFT JOIN users f ON f.id = e.freelancer_id
       WHERE e.client_id = $1 OR e.freelancer_id = $1
       ORDER BY e.created_at DESC`,
      [userId]
    );
    res.json({ escrows: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/jobs/user/:userId — list jobs posted by a user (public)
app.get('/api/jobs/user/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const result = await query(
      `SELECT j.*, u.username as client_username
       FROM jobs j LEFT JOIN users u ON u.id = j.posted_by
       WHERE j.posted_by = $1
       ORDER BY j.created_at DESC`,
      [userId]
    );
    res.json({ jobs: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/offers — direct offers (job invitations) for freelancer
app.get('/api/offers', auth, async (req, res) => {
  try {
    // Offers are applications where the job posted_by invited the freelancer
    // For now, return applications with status 'offer' or all pending ones
    const result = await query(
      `SELECT a.*, j.title as job_title, j.budget, j.status as job_status,
              u.username as client_username
       FROM applications a
       JOIN jobs j ON a.job_id = j.id
       LEFT JOIN users u ON u.id = j.posted_by
       WHERE a.freelancer_id = $1
         AND a.status = 'offer'
       ORDER BY a.created_at DESC`,
      [req.userId]
    );
    res.json({ offers: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/reviews/stats — review statistics for logged-in user
app.get('/api/reviews/stats', auth, async (req, res) => {
  try {
    const userId = req.query.user_id || req.userId;
    const [totalResult, avgResult, distResult] = await Promise.all([
      query('SELECT COUNT(*) FROM ratings WHERE to_user_id = $1', [userId]),
      query('SELECT AVG(rating) as avg FROM ratings WHERE to_user_id = $1', [userId]),
      query(
        'SELECT rating, COUNT(*) as count FROM ratings WHERE to_user_id = $1 GROUP BY rating ORDER BY rating DESC',
        [userId]
      ),
    ]);
    const total = parseInt(totalResult.rows[0].count);
    const avg = parseFloat(avgResult.rows[0].avg || 0).toFixed(1);
    const distribution = {};
    distResult.rows.forEach(r => { distribution[r.rating] = parseInt(r.count); });
    res.json({ total, avg: parseFloat(avg), distribution, rating: parseFloat(avg) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Additional endpoints from bundle analysis ──────────────────────────────────────────────

// POST /api/chat/:roomId/messages — send message (alias for /chat/rooms/:id/messages)
app.post('/api/chat/:roomId/messages', auth, checkBlocked, async (req, res) => {
  const { content, message, text } = req.body;
  const msg = content || message || text || '';
  if (!msg.trim()) return res.status(400).json({ error: 'Message content required' });
  try {
    const roomCheck = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.roomId, req.userId]);
    if (!roomCheck.rows.length) return res.status(403).json({ error: 'Not in this room' });
    const userRes = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userRes.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.roomId, req.userId, senderName, msg]
    );
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.roomId]);
    res.json({ message: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/offers/:id — get a specific offer
app.get('/api/offers/:id', auth, async (req, res) => {
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/applications/:id/view — mark application as viewed
app.post('/api/applications/:id/view', auth, async (req, res) => {
  try {
    await query('UPDATE applications SET viewed = true, viewed_at = NOW() WHERE id = $1', [req.params.id]).catch(() => {
      // viewed column may not exist, ignore
    });
    res.json({ success: true });
  } catch (err) { res.json({ success: true }); }
});

// GET /api/chat/:roomId/messages — messages in a chat room (uses chat_messages table)
app.get('/api/chat/:roomId/messages', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT cm.*, u.username as sender_username,
              cm.message as content, cm.message as text
       FROM chat_messages cm
       LEFT JOIN users u ON u.id = cm.sender_id
       WHERE cm.room_id = $1
       ORDER BY cm.created_at ASC
       LIMIT 200`,
      [req.params.roomId]
    );
    res.json({ messages: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/chat/rooms/:id — specific chat room details
app.get('/api/chat/rooms/:id', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT cr.*,
              u1.username as client_username, u2.username as freelancer_username
       FROM chat_rooms cr
       LEFT JOIN users u1 ON u1.id = cr.client_id
       LEFT JOIN users u2 ON u2.id = cr.freelancer_id
       WHERE cr.id = $1 AND (cr.client_id = $2 OR cr.freelancer_id = $2)`,
      [req.params.id, req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Room not found' });
    res.json({ room: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/escrows/:id/fund — fund an escrow after Pi payment
// softAuth: bundle sends no auth header
app.post('/api/escrows/:id/fund', softAuth, async (req, res) => {
  const { payment_id, txid } = req.body;
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    // Only enforce ownership if caller identified themselves
    if (req.userId && escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    await query('UPDATE escrows SET status = $1, payment_id = $2, updated_at = NOW() WHERE id = $3', ['funded', payment_id || escrow.payment_id, req.params.id]);
    await audit('escrow_funded', { escrow_id: req.params.id, payment_id, txid });
    res.json({ escrow: { ...escrow, status: 'funded' }, success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/escrows/:id/dispute — open a dispute
// softAuth: bundle sends no auth header
app.post('/api/escrows/:id/dispute', softAuth, async (req, res) => {
  const { reason } = req.body;
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = result.rows[0];
    // Only enforce ownership if caller identified themselves
    if (req.userId && escrow.client_id !== req.userId && escrow.freelancer_id !== req.userId) {
      return res.status(403).json({ error: 'Not your escrow' });
    }
    await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['disputed', req.params.id]);
    await audit('escrow_disputed', { escrow_id: req.params.id, reason, user_id: req.userId });
    res.json({ escrow: { ...escrow, status: 'disputed' }, success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/escrows/:id/room — chat room for an escrow
app.get('/api/escrows/:id/room', auth, async (req, res) => {
  try {
    const escResult = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!escResult.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    const escrow = escResult.rows[0];
    // Find or create chat room between client and freelancer
    const roomResult = await query(
      `SELECT * FROM chat_rooms WHERE (client_id = $1 AND freelancer_id = $2) OR (client_id = $2 AND freelancer_id = $1) LIMIT 1`,
      [escrow.client_id, escrow.freelancer_id]
    );
    if (roomResult.rows.length) {
      return res.json({ room: roomResult.rows[0], room_id: roomResult.rows[0].id });
    }
    // Create room if not exists
    const roomId = `room_${escrow.client_id}-${escrow.freelancer_id}-${Date.now()}`;
    const newRoom = await query(
      'INSERT INTO chat_rooms (id, client_id, freelancer_id) VALUES ($1, $2, $3) RETURNING *',
      [roomId, escrow.client_id, escrow.freelancer_id]
    );
    res.json({ room: newRoom.rows[0], room_id: newRoom.rows[0].id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/jobs/:id/apply — apply to a job (alternative endpoint to /api/applications)
app.post('/api/jobs/:id/apply', auth, checkBlocked, async (req, res) => {
  const { message, cover_letter, bid_amount, proposed_budget, username } = req.body;
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobResult.rows[0];
    if (job.posted_by === req.userId) return res.status(400).json({ error: 'Cannot apply to your own job' });

    // Check connects
    const userResult = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
    const connectsNeeded = job.connects_required || 1;
    if ((userResult.rows[0]?.balance_connects || 0) < connectsNeeded) {
      return res.status(400).json({ error: `Insufficient connects. Need ${connectsNeeded}.` });
    }

    // Deduct connects
    await query('UPDATE users SET balance_connects = balance_connects - $1 WHERE id = $2', [connectsNeeded, req.userId]);

    const coverLetter = message || cover_letter || '';
    const bidAmount = parseFloat(bid_amount || proposed_budget) || job.budget;
    const result = await query(
      `INSERT INTO applications (job_id, freelancer_id, cover_letter, bid_amount, status)
       VALUES ($1,$2,$3,$4,'pending') RETURNING *`,
      [parseInt(req.params.id), req.userId, coverLetter, bidAmount]
    );
    res.json({ application: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/offers/:id/accept — accept a job offer
app.post('/api/offers/:id/accept', auth, async (req, res) => {
  try {
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 AND freelancer_id = $3 RETURNING *', ['accepted', req.params.id, req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Offer not found' });
    res.json({ application: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/offers/:id/decline — decline a job offer
app.post('/api/offers/:id/decline', auth, async (req, res) => {
  try {
    const result = await query('UPDATE applications SET status = $1 WHERE id = $2 AND freelancer_id = $3 RETURNING *', ['declined', req.params.id, req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Offer not found' });
    res.json({ application: result.rows[0], success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/reviews/stats/:userId — review stats for a specific user (path param, MUST be before /:id)
app.get('/api/reviews/stats/:userId', async (req, res) => {
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/reviews/:id — get review by ID, OR if id is non-integer, treat as user ID
app.get('/api/reviews/:id', async (req, res) => {
  const id = req.params.id;
  const isNumeric = /^\d+$/.test(id);
  try {
    if (isNumeric) {
      // Get specific review by integer ID
      const result = await query(
        'SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.id = $1',
        [id]
      );
      if (!result.rows.length) return res.status(404).json({ error: 'Review not found' });
      res.json({ review: result.rows[0] });
    } else {
      // Treat as user ID — return all reviews for this user
      const result = await query(
        'SELECT r.*, u.username as from_username FROM ratings r LEFT JOIN users u ON u.id = r.from_user_id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC',
        [id]
      );
      res.json({ reviews: result.rows, ratings: result.rows });
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST + PUT /api/users/:id/availability — update user availability status
// Bundle sends POST (not PUT), so we handle both
async function handleAvailability(req, res) {
  const { available, availability } = req.body;
  // Only enforce identity check if caller identified themselves
  if (req.userId && req.params.id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  const targetId = req.params.id;
  try {
    const isAvailable = available !== undefined ? available : (availability === 'available');
    // Update availability column (try both availability string and is_available bool)
    await query(
      `UPDATE users SET availability = $1, updated_at = NOW() WHERE id = $2`,
      [isAvailable ? 'available' : 'unavailable', targetId]
    ).catch(async () => {
      await query('UPDATE users SET updated_at = NOW() WHERE id = $1', [targetId]).catch(() => {});
    });
    const result = await query('SELECT * FROM users WHERE id = $1', [targetId]);
    const u = result.rows[0] || {};
    res.json({ ...u, uid: u.id, is_admin: u?.role === 'admin', success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
}
app.put('/api/users/:id/availability', softAuth, handleAvailability);
app.post('/api/users/:id/availability', softAuth, handleAvailability);

// ─── 404 ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ─── Error handler ──────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ──────────────────────────────────────────────
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`[WorkPro API] v3.1.0 on port ${PORT} (${NODE_ENV})`);
  });
}).catch(err => {
  console.error('[Server] Failed to start:', err);
  process.exit(1);
});

module.exports = app;

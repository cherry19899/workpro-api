/**
 * WorkPro API - PostgreSQL Version
 * v3.0.0 - Replaces JSON file storage with PostgreSQL
 * 
 * Environment variables needed:
 * - DATABASE_URL=postgresql://user:pass@host:port/dbname
 * - JWT_SECRET=random_string
 * - ADMIN_API_KEY=secret_for_admin
 * - FRONTEND_URL=https://cherry19899.github.io
 * - NODE_ENV=production
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { query, initDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'admin-secret-key';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';

// ─── Middleware ──────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: [FRONTEND_URL, 'https://cherry19899.github.io', 'http://localhost:5173', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-pi-token', 'x-admin-key']
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health'
}));

// ─── Auth ──────────────────────────────────────────────
function auth(req, res, next) {
  const userId = req.headers['x-user-id'] || req.headers['x-pi-token'];
  if (!userId) return res.status(401).json({ error: 'Access token required' });
  req.userId = userId;
  next();
}

function adminAuth(req, res, next) {
  const userId = req.headers['x-user-id'];
  if (userId === 'cherry19899' || userId === 'admin') {
    req.isAdmin = true;
    return next();
  }
  const apiKey = req.headers['x-admin-key'] || req.headers['authorization'] || req.query.admin_key;
  if (!apiKey) return res.status(403).json({ error: 'Admin access required' });
  let token = apiKey;
  if (apiKey.startsWith('Bearer ')) token = apiKey.substring(7);
  if (token !== ADMIN_API_KEY) return res.status(403).json({ error: 'Admin access required' });
  req.isAdmin = true;
  next();
}

// ─── Block Check ──────────────────────────────────────────────
async function checkBlocked(req, res, next) {
  const userId = req.userId || req.headers['x-user-id'];
  if (!userId) return next();
  try {
    const result = await query('SELECT is_blocked FROM users WHERE id = $1', [userId]);
    if (result.rows[0]?.is_blocked) {
      return res.status(403).json({ error: 'Account blocked', message: 'Your account has been blocked. Contact support.' });
    }
    next();
  } catch (err) {
    next();
  }
}

// ─── Helpers ──────────────────────────────────────────────
function now() { return new Date().toISOString(); }
async function audit(action, data) {
  await query('INSERT INTO audit_logs (action, data) VALUES ($1, $2)', [action, JSON.stringify(data)]);
}

// ─── Health ──────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await query('SELECT 1');
    res.json({ status: 'ok', database: 'connected', storage: 'postgresql', timestamp: now() });
  } catch (err) {
    res.status(500).json({ status: 'error', database: 'disconnected', error: err.message });
  }
});

// ─── Auth ──────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { userId, username, role } = req.body;
  const uid = userId || 'user_' + Math.random().toString(36).substring(2, 10);
  const uname = username || uid;
  const urole = role || 'freelancer';
  
  try {
    const existing = await query('SELECT * FROM users WHERE id = $1', [uid]);
    if (!existing.rows.length) {
      await query(
        'INSERT INTO users (id, username, role, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())',
        [uid, uname, urole]
      );
    }
    const token = jwt.sign({ id: uid, username: uname, role: urole }, JWT_SECRET, { expiresIn: '7d' });
    const user = await query('SELECT * FROM users WHERE id = $1', [uid]);
    res.json({ token, user: user.rows[0] });
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
    const result = await query('SELECT * FROM users ORDER BY created_at DESC');
    res.json({ users: result.rows, count: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const result = await query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users/:id', auth, async (req, res) => {
  const { username, email, bio, skills, availability, avatar } = req.body;
  try {
    const result = await query(
      'UPDATE users SET username = COALESCE($1, username), email = COALESCE($2, email), bio = COALESCE($3, bio), skills = COALESCE($4, skills), availability = COALESCE($5, availability), avatar = COALESCE($6, avatar), updated_at = NOW() WHERE id = $7 RETURNING *',
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
    const result = await query('SELECT * FROM ratings WHERE to_user_id = $1', [req.params.id]);
    const avg = result.rows.length ? result.rows.reduce((a, b) => a + parseInt(b.rating), 0) / result.rows.length : 0;
    res.json({ ratings: result.rows, average: avg, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Jobs ──────────────────────────────────────────────
app.get('/api/jobs', async (req, res) => {
  const { status, category, posted_by, search, limit = 20, page = 1 } = req.query;
  try {
    let sql = 'SELECT * FROM jobs WHERE 1=1';
    const params = [];
    let idx = 1;
    if (status) { sql += ` AND status = $${idx}`; params.push(status); idx++; }
    if (category && category !== 'all') { sql += ` AND category = $${idx}`; params.push(category); idx++; }
    if (posted_by) { sql += ` AND posted_by = $${idx}`; params.push(posted_by); idx++; }
    if (search) { sql += ` AND (title ILIKE $${idx} OR description ILIKE $${idx})`; params.push(`%${search}%`); idx++; }
    sql += ' ORDER BY created_at DESC';
    const countResult = await query(sql.replace('SELECT *', 'SELECT COUNT(*)'), params);
    const total = parseInt(countResult.rows[0].count);
    const offset = (page - 1) * limit;
    sql += ` LIMIT $${idx} OFFSET $${idx + 1}`;
    params.push(limit, offset);
    const result = await query(sql, params);
    res.json({ jobs: result.rows, total, page: parseInt(page), total_pages: Math.ceil(total / limit), limit: parseInt(limit) });
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
    const result = await query(
      'INSERT INTO jobs (title, description, category, budget, skills, images, deadline, posted_by, posted_by_name) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
      [title, description, category || 'Other', budget, skills || null, images || null, deadline || null, req.userId, req.userId]
    );
    await query('UPDATE users SET total_jobs_posted = total_jobs_posted + 1, updated_at = NOW() WHERE id = $1', [req.userId]);
    await audit('job_created', { job_id: result.rows[0].id, user_id: req.userId });
    res.json({ job: result.rows[0], success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/jobs/:id', async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    const appsResult = await query('SELECT * FROM applications WHERE job_id = $1', [req.params.id]);
    res.json({ job: jobResult.rows[0], applications: appsResult.rows });
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

app.delete('/api/jobs/:id', auth, async (req, res) => {
  try {
    const jobResult = await query('SELECT * FROM jobs WHERE id = $1', [req.params.id]);
    if (!jobResult.rows.length) return res.status(404).json({ error: 'Job not found' });
    if (jobResult.rows[0].posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
    await query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Chat ──────────────────────────────────────────────
app.get('/api/chat/rooms', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM chat_rooms WHERE client_id = $1 OR freelancer_id = $1', [req.userId]);
    res.json({ rooms: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/chat/rooms', auth, checkBlocked, async (req, res) => {
  const { client_id, freelancer_id, job_id } = req.body;
  const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
  try {
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
    const result = await query('SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at ASC', [req.params.id]);
    res.json({ messages: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/chat/rooms/:id/messages', auth, checkBlocked, async (req, res) => {
  try {
    const userResult = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userResult.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.id, req.userId, senderName, req.body.message]
    );
    res.json({ message: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Escrow ──────────────────────────────────────────────
app.get('/api/escrow', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1', [req.userId]);
    res.json({ escrows: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/escrow', auth, checkBlocked, async (req, res) => {
  const { job_id, freelancer_id, amount } = req.body;
  try {
    const result = await query(
      'INSERT INTO escrows (job_id, client_id, freelancer_id, amount) VALUES ($1, $2, $3, $4) RETURNING *',
      [job_id, req.userId, freelancer_id, amount]
    );
    res.json({ escrow: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/escrow/:id/release', auth, checkBlocked, async (req, res) => {
  try {
    const result = await query('SELECT * FROM escrows WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Escrow not found' });
    if (result.rows[0].client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
    await query('UPDATE escrows SET status = $1, updated_at = NOW() WHERE id = $2', ['released', req.params.id]);
    res.json({ escrow: { ...result.rows[0], status: 'released' }, success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Payments ──────────────────────────────────────────────
app.get('/api/payments', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM payments WHERE user_id = $1', [req.userId]);
    res.json({ payments: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/payments', auth, async (req, res) => {
  const { type, amount, metadata } = req.body;
  const paymentId = 'pay_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
  try {
    const result = await query(
      'INSERT INTO payments (id, user_id, type, amount, metadata) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [paymentId, req.userId, type, amount, JSON.stringify(metadata || {})]
    );
    res.json({ payment: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/payments/:id/complete', auth, async (req, res) => {
  try {
    await query('UPDATE payments SET status = $1, updated_at = NOW() WHERE id = $2', ['completed', req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/payments/incomplete', auth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM payments WHERE user_id = $1 AND status = $2', [req.userId, 'pending']);
    res.json({ payments: result.rows, count: result.rows.length });
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
  try {
    await query('UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2', [parseInt(req.body.amount || 0), req.userId]);
    const result = await query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]);
    res.json({ balance: result.rows[0].balance_connects, success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Ratings ──────────────────────────────────────────────
app.post('/api/ratings', auth, checkBlocked, async (req, res) => {
  const { to_user_id, job_id, rating, comment } = req.body;
  try {
    const result = await query(
      'INSERT INTO ratings (from_user_id, to_user_id, job_id, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.userId, to_user_id, job_id, rating, comment || '']
    );
    res.json({ rating: result.rows[0], success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/ratings', async (req, res) => {
  try {
    const result = await query('SELECT * FROM ratings');
    res.json({ ratings: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin ──────────────────────────────────────────────
app.get('/api/admin/verify', async (req, res) => {
  const key = req.headers['x-admin-key'] || req.headers['authorization'] || req.query.admin_key;
  res.json({
    provided: key ? 'yes' : 'no',
    valid: key === `Bearer ${ADMIN_API_KEY}` || key === ADMIN_API_KEY,
    env_set: !!process.env.ADMIN_API_KEY
  });
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const users = await query('SELECT COUNT(*) FROM users');
    const jobs = await query('SELECT COUNT(*) FROM jobs');
    const applications = await query('SELECT COUNT(*) FROM applications');
    const escrows = await query('SELECT COUNT(*) FROM escrows');
    const payments = await query('SELECT COUNT(*) FROM payments');
    const ratings = await query('SELECT COUNT(*) FROM ratings');
    const chats = await query('SELECT COUNT(*) FROM chat_rooms');
    res.json({
      users: parseInt(users.rows[0].count),
      jobs: parseInt(jobs.rows[0].count),
      applications: parseInt(applications.rows[0].count),
      escrows: parseInt(escrows.rows[0].count),
      payments: parseInt(payments.rows[0].count),
      ratings: parseInt(ratings.rows[0].count),
      chats: parseInt(chats.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const search = (req.query.search || '').toLowerCase();
    let sql = 'SELECT * FROM users';
    const params = [];
    if (search) {
      sql += ' WHERE username ILIKE $1 OR id ILIKE $1';
      params.push(`%${search}%`);
    }
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
    await audit('user_blocked', { user_id: req.params.id, by: req.headers['x-user-id'] || 'admin' });
    res.json({ success: true, message: 'User blocked', user_id: req.params.id, is_blocked: 1 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  try {
    await query('UPDATE users SET is_blocked = false, status = $1, updated_at = NOW() WHERE id = $2', ['active', req.params.id]);
    await audit('user_unblocked', { user_id: req.params.id });
    res.json({ success: true, message: 'User unblocked', user_id: req.params.id, is_blocked: 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/jobs', adminAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM jobs ORDER BY created_at DESC');
    res.json({ jobs: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/jobs/:id', adminAuth, async (req, res) => {
  try {
    await query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    const result = await query('SELECT SUM(amount) as total FROM payments WHERE status = $1', ['completed']);
    const transactions = await query('SELECT COUNT(*) FROM payments');
    res.json({ total_earnings: parseFloat(result.rows[0].total || 0), transactions: parseInt(transactions.rows[0].count) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/audit-logs', adminAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100');
    res.json({ logs: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ──────────────────────────────────────────────
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`[Server] v3.0.0 running on port ${PORT} (${NODE_ENV})`);
    console.log(`[Storage] PostgreSQL connected`);
  });
}).catch(err => {
  console.error('[Server] Failed to start:', err);
  process.exit(1);
});

module.exports = app;

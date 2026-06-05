/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  Work Pro - Pi Network Freelance Marketplace                              ║
 * ║  v2.2.0 — JSON File Storage, x-user-id Auth, User Blocking               ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const fetch = require('node-fetch');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const PI_API_KEY = process.env.PI_API_KEY || 'workpro-dev-key';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || process.env.WORKPRO_API_ACCESS || 'admin-secret-key';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';

// ─── JSON Storage ──────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

let db = {
  users: {},
  jobs: {},
  applications: {},
  escrows: {},
  payments: {},
  ratings: {},
  chatRooms: {},
  chatMessages: {},
  auditLogs: [],
  counters: { jobs: 0, users: 0, applications: 0, escrows: 0, payments: 0, ratings: 0, chatRooms: 0, chatMessages: 0 }
};

async function loadDb() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const data = await fs.readFile(DB_FILE, 'utf8');
    db = JSON.parse(data);
    console.log('[DB] Loaded from JSON file');
  } catch (e) {
    console.log('[DB] Starting fresh (no file found)');
    await saveDb();
  }
}

async function saveDb() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(DB_FILE, JSON.stringify(db, null, 2));
  } catch (e) {
    console.error('[DB] Save error:', e.message);
  }
}

// Auto-save every 30 seconds
setInterval(saveDb, 30000);

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
  req.user = db.users[userId] || null;
  next();
}

function adminAuth(req, res, next) {
  // v2.2: Allow cherry19899 owner access via x-user-id (Pi Browser auth)
  const userId = req.headers['x-user-id'];
  if (userId === 'cherry19899' || userId === 'admin' || userId === 'pi_a2b617f7-f510-4502-a046-805facedcc29') {
    req.isAdmin = true;
    return next();
  }

  const apiKey = req.headers['x-admin-key'] || req.headers['authorization'] || req.query.admin_key;
  
  if (!apiKey) return res.status(403).json({ error: 'Admin access required' });

  // Extract Bearer token if present
  let token = apiKey;
  if (apiKey.startsWith('Bearer ')) {
    token = apiKey.substring(7);
  }

  if (token !== ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  req.isAdmin = true;
  next();
}

// ─── Block Check Middleware ──────────────────────────────
function checkBlocked(req, res, next) {
  const userId = req.userId || req.headers['x-user-id'];
  if (!userId) return next();
  const user = db.users[userId];
  if (user && user.is_blocked) {
    return res.status(403).json({ error: 'Account blocked', message: 'Your account has been blocked. Contact support.' });
  }
  next();
}

// ─── Helpers ──────────────────────────────────────────────
function now() { return new Date().toISOString(); }
function id() { return ++db.counters.jobs + '_' + Math.random().toString(36).substring(2, 8); }
function audit(action, data) {
  db.auditLogs.push({ id: db.auditLogs.length + 1, action, data, timestamp: now() });
  if (db.auditLogs.length > 1000) db.auditLogs = db.auditLogs.slice(-500);
}

// ─── Health ──────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  res.json({ status: 'ok', database: 'connected', storage: 'json', timestamp: now() });
});

// ─── Auth ──────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { userId, username, role } = req.body;
  const uid = userId || 'user_' + Math.random().toString(36).substring(2, 10);
  const uname = username || uid;
  const urole = role || 'freelancer';

  if (!db.users[uid]) {
    db.users[uid] = {
      id: uid, username: uname, email: null, role: urole,
      balance_connects: 0, balance_pi: 0, rating: 0,
      total_jobs_posted: 0, total_jobs_completed: 0,
      bio: null, skills: null, kyc_verified: false,
      availability: 'available', created_at: now(), updated_at: now()
    };
    await saveDb();
  }

  const token = require('jsonwebtoken').sign(
    { id: uid, username: uname, role: urole },
    JWT_SECRET, { expiresIn: '7d' }
  );

  res.json({ token, user: db.users[uid] });
});

app.get('/api/auth/me', auth, async (req, res) => {
  if (!req.user) return res.status(404).json({ error: 'User not found' });
  res.json(req.user);
});

// ─── Users ──────────────────────────────────────────────
app.get('/api/users', async (req, res) => {
  const users = Object.values(db.users);
  res.json({ users, count: users.length });
});

app.get('/api/users/:id', async (req, res) => {
  const user = db.users[req.params.id];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.post('/api/users/:id', auth, async (req, res) => {
  const user = db.users[req.params.id];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { username, email, bio, skills, availability, avatar } = req.body;
  if (username) user.username = username;
  if (email !== undefined) user.email = email;
  if (bio !== undefined) user.bio = bio;
  if (skills !== undefined) user.skills = skills;
  if (availability) user.availability = availability;
  if (avatar !== undefined) user.avatar = avatar;
  user.updated_at = now();
  await saveDb();
  res.json(user);
});

app.post('/api/users/:id/avatar', auth, checkBlocked, async (req, res) => {
  const user = db.users[req.params.id];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { avatar } = req.body;
  if (!avatar) return res.status(400).json({ error: 'Avatar data required' });
  user.avatar = avatar;
  user.updated_at = now();
  await saveDb();
  res.json({ user, success: true });
});

app.get('/api/users/:id/ratings', async (req, res) => {
  const ratings = Object.values(db.ratings).filter(r => r.to_user_id === req.params.id);
  res.json({ ratings, average: ratings.length ? ratings.reduce((a, b) => a + b.rating, 0) / ratings.length : 0, count: ratings.length });
});

// ─── Jobs ──────────────────────────────────────────────
app.get('/api/jobs', async (req, res) => {
  const { status, category, posted_by, search, limit = 20, page = 1 } = req.query;
  let jobs = Object.values(db.jobs);
  if (status) jobs = jobs.filter(j => j.status === status);
  if (category && category !== 'all') jobs = jobs.filter(j => j.category === category);
  if (posted_by) jobs = jobs.filter(j => j.posted_by === posted_by);
  if (search) jobs = jobs.filter(j => j.title.toLowerCase().includes(search.toLowerCase()));
  jobs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const total = jobs.length;
  const totalPages = Math.ceil(total / limit);
  const start = (page - 1) * limit;
  jobs = jobs.slice(start, start + parseInt(limit));
  res.json({ jobs, total, page: parseInt(page), total_pages: totalPages, limit: parseInt(limit) });
});

app.post('/api/jobs', auth, checkBlocked, async (req, res) => {
  const { title, description, category, budget, skills, deadline, images } = req.body;
  if (!title || !description || !budget) {
    return res.status(400).json({ error: 'Title, description, and budget are required' });
  }
  const id = ++db.counters.jobs;
  const job = {
    id, title, description, category: category || 'Other',
    budget: parseFloat(budget), skills: skills || [],
    images: images || null, deadline: deadline || null,
    status: 'open', posted_by: req.userId,
    posted_by_name: req.user?.username || req.userId,
    applications: 0, connects_spent: 1, apply_cost: 1,
    created_at: now(), updated_at: now()
  };
  db.jobs[id] = job;
  if (req.user) { req.user.total_jobs_posted++; req.user.updated_at = now(); }
  await saveDb();
  audit('job_created', { job_id: id, user_id: req.userId });
  res.json({ job, success: true });
});

app.get('/api/jobs/:id', async (req, res) => {
  const job = db.jobs[req.params.id];
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const applications = Object.values(db.applications).filter(a => a.job_id === parseInt(req.params.id));
  res.json({ job, applications });
});

app.post('/api/jobs/:id/apply', auth, checkBlocked, async (req, res) => {
  const job = db.jobs[req.params.id];
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.posted_by === req.userId) return res.status(400).json({ error: 'Cannot apply to own job' });
  const cost = job.apply_cost || 1;
  if (!req.user || req.user.balance_connects < cost) {
    return res.status(400).json({ error: 'Not enough connects', required: cost, current: req.user?.balance_connects || 0 });
  }
  req.user.balance_connects -= cost;
  req.user.updated_at = now();
  const appId = ++db.counters.applications;
  db.applications[appId] = {
    id: appId, job_id: parseInt(req.params.id), job_title: job.title,
    freelancer_id: req.userId, freelancer_name: req.user?.username || req.userId,
    message: req.body.message || '', status: 'pending', created_at: now()
  };
  job.applications++;
  job.updated_at = now();
  await saveDb();
  audit('job_applied', { job_id: job.id, user_id: req.userId });
  res.json({ application: db.applications[appId], success: true });
});

app.get('/api/jobs/:id/applications', auth, async (req, res) => {
  const apps = Object.values(db.applications).filter(a => a.job_id === parseInt(req.params.id));
  res.json({ applications: apps, count: apps.length });
});

app.delete('/api/jobs/:id', auth, async (req, res) => {
  const job = db.jobs[req.params.id];
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Not your job' });
  delete db.jobs[req.params.id];
  await saveDb();
  res.json({ success: true });
});

app.get('/api/applications/my', auth, async (req, res) => {
  const apps = Object.values(db.applications).filter(a => a.freelancer_id === req.userId);
  res.json({ applications: apps });
});

// ─── Chat ──────────────────────────────────────────────
app.get('/api/chat/rooms', auth, async (req, res) => {
  const rooms = Object.values(db.chatRooms).filter(r =>
    r.client_id === req.userId || r.freelancer_id === req.userId
  );
  res.json({ rooms });
});

app.post('/api/chat/rooms', auth, checkBlocked, async (req, res) => {
  const { client_id, freelancer_id, job_id } = req.body;
  const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
  db.chatRooms[roomId] = {
    id: roomId, client_id, freelancer_id, job_id,
    created_at: now(), updated_at: now()
  };
  await saveDb();
  res.json({ room: db.chatRooms[roomId] });
});

app.get('/api/chat/rooms/:id/messages', auth, async (req, res) => {
  const room = db.chatRooms[req.params.id];
  if (!room) return res.status(404).json({ error: 'Room not found' });
  const messages = Object.values(db.chatMessages).filter(m => m.room_id === req.params.id);
  res.json({ messages });
});

app.post('/api/chat/rooms/:id/messages', auth, checkBlocked, async (req, res) => {
  const room = db.chatRooms[req.params.id];
  if (!room) return res.status(404).json({ error: 'Room not found' });
  const msgId = ++db.counters.chatMessages;
  db.chatMessages[msgId] = {
    id: msgId, room_id: req.params.id,
    sender_id: req.userId, sender_name: req.user?.username || req.userId,
    message: req.body.message, created_at: now()
  };
  await saveDb();
  res.json({ message: db.chatMessages[msgId] });
});

// ─── Escrow ──────────────────────────────────────────────
app.get('/api/escrow', auth, async (req, res) => {
  const escrows = Object.values(db.escrows).filter(e =>
    e.client_id === req.userId || e.freelancer_id === req.userId
  );
  res.json({ escrows });
});

app.post('/api/escrow', auth, checkBlocked, async (req, res) => {
  const { job_id, freelancer_id, amount } = req.body;
  const escrowId = ++db.counters.escrows;
  db.escrows[escrowId] = {
    id: escrowId, job_id, client_id: req.userId, freelancer_id,
    amount: parseFloat(amount), status: 'pending', created_at: now(), updated_at: now()
  };
  await saveDb();
  res.json({ escrow: db.escrows[escrowId] });
});

app.post('/api/escrow/:id/release', auth, checkBlocked, async (req, res) => {
  const escrow = db.escrows[req.params.id];
  if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
  if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Not your escrow' });
  escrow.status = 'released';
  escrow.updated_at = now();
  await saveDb();
  res.json({ escrow, success: true });
});

// ─── Payments ──────────────────────────────────────────────
app.get('/api/payments', auth, async (req, res) => {
  const payments = Object.values(db.payments).filter(p => p.user_id === req.userId);
  res.json({ payments });
});

app.post('/api/payments', auth, async (req, res) => {
  const { type, amount, metadata } = req.body;
  const paymentId = 'pay_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
  db.payments[paymentId] = {
    id: paymentId, user_id: req.userId, type, amount: parseFloat(amount),
    status: 'pending', metadata: metadata || {}, created_at: now()
  };
  await saveDb();
  res.json({ payment: db.payments[paymentId] });
});

app.post('/api/payments/:id/complete', auth, async (req, res) => {
  const payment = db.payments[req.params.id];
  if (!payment) return res.status(404).json({ error: 'Payment not found' });
  payment.status = 'completed';
  payment.updated_at = now();
  await saveDb();
  res.json({ payment, success: true });
});

app.post('/api/payments/:id/cancelled', auth, checkBlocked, async (req, res) => {
  const payment = db.payments[req.params.id];
  if (!payment) return res.status(404).json({ error: 'Payment not found' });
  payment.status = 'cancelled';
  payment.updated_at = now();
  await saveDb();
  res.json({ payment, success: true });
});

app.get('/api/payments/incomplete', auth, async (req, res) => {
  const payments = Object.values(db.payments).filter(p =>
    p.user_id === req.userId && p.status === 'pending'
  );
  res.json({ payments, count: payments.length });
});

// ─── Connects ──────────────────────────────────────────────
app.get('/api/connects/balance', auth, async (req, res) => {
  if (!req.user) return res.status(404).json({ error: 'User not found' });
  res.json({ balance: req.user.balance_connects || 0 });
});

app.post('/api/connects/purchase', auth, checkBlocked, async (req, res) => {
  const { amount } = req.body;
  if (!req.user) return res.status(404).json({ error: 'User not found' });
  req.user.balance_connects = (req.user.balance_connects || 0) + parseInt(amount || 0);
  req.user.updated_at = now();
  await saveDb();
  res.json({ balance: req.user.balance_connects, success: true });
});

// ─── Ratings ──────────────────────────────────────────────
app.post('/api/ratings', auth, checkBlocked, async (req, res) => {
  const { to_user_id, job_id, rating, comment } = req.body;
  const ratingId = ++db.counters.ratings;
  db.ratings[ratingId] = {
    id: ratingId, from_user_id: req.userId, to_user_id,
    job_id: parseInt(job_id), rating: parseInt(rating), comment: comment || '',
    created_at: now()
  };
  await saveDb();
  res.json({ rating: db.ratings[ratingId], success: true });
});

app.get('/api/ratings', async (req, res) => {
  const ratings = Object.values(db.ratings);
  res.json({ ratings, count: ratings.length });
});

app.get('/api/admin/verify', async (req, res) => {
  const key = req.headers['x-admin-key'] || req.headers['authorization'] || req.query.admin_key;
  res.json({
    provided: key ? 'yes' : 'no',
    valid: key === `Bearer ${ADMIN_API_KEY}` || key === ADMIN_API_KEY,
    env_set: !!process.env.ADMIN_API_KEY || !!process.env.WORKPRO_API_ACCESS
  });
});
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  res.json({
    users: Object.values(db.users).length,
    jobs: Object.values(db.jobs).length,
    applications: Object.values(db.applications).length,
    escrows: Object.values(db.escrows).length,
    payments: Object.values(db.payments).length,
    ratings: Object.values(db.ratings).length,
    chats: Object.values(db.chatRooms).length
  });
});

app.get('/api/status', async (req, res) => {
  res.json({ status: 'ok', database: 'connected', storage: 'json', timestamp: now() });
});

// ─── Check blocked middleware ──────────────────────────────────────────────
function checkBlocked(req, res, next) {
  const userId = req.headers['x-user-id'];
  if (userId && db.users[userId] && db.users[userId].blocked) {
    return res.status(403).json({ error: 'User is blocked', blocked: true });
  }
  next();
}

// ─── Admin Block/Unblock ──────────────────────────────────────────────
app.post('/api/admin/users/:id/block', adminAuth, async (req, res) => {
  const user = db.users[req.params.id];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (req.params.id === 'cherry19899') return res.status(403).json({ error: 'Cannot block admin' });
  user.blocked = true;
  user.updated_at = now();
  await saveDb();
  audit('user_blocked', { user_id: req.params.id, by: req.headers['x-user-id'] || 'admin' });
  res.json({ success: true, user: { id: user.id, username: user.username, blocked: true } });
});

app.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  const user = db.users[req.params.id];
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.blocked = false;
  user.updated_at = now();
  await saveDb();
  audit('user_unblocked', { user_id: req.params.id, by: req.headers['x-user-id'] || 'admin' });
  res.json({ success: true, user: { id: user.id, username: user.username, blocked: false } });
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  // v2.2: Add search support
  let users = Object.values(db.users);
  const search = (req.query.search || '').toLowerCase();
  if (search) {
    users = users.filter(u =>
      (u.username || '').toLowerCase().includes(search) ||
      (u.id || '').toLowerCase().includes(search)
    );
  }
  res.json({ users, count: users.length });
});

// v2.2: Block/unblock endpoints
app.post('/api/admin/users/:id/block', adminAuth, async (req, res) => {
  const targetId = req.params.id;
  const adminId = req.headers['x-user-id'] || 'admin';
  if (targetId === adminId) return res.status(403).json({ error: 'Cannot block yourself' });
  if (targetId === 'cherry19899') return res.status(403).json({ error: 'Cannot block the owner account' });
  const user = db.users[targetId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.is_blocked = true;
  user.status = 'blocked';
  await saveDb();
  console.log('[Admin] Blocked user:', targetId, 'by:', adminId);
  res.json({ success: true, message: 'User blocked', user_id: targetId, is_blocked: 1 });
});

app.post('/api/admin/users/:id/unblock', adminAuth, async (req, res) => {
  const targetId = req.params.id;
  const user = db.users[targetId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.is_blocked = false;
  user.status = 'active';
  await saveDb();
  console.log('[Admin] Unblocked user:', targetId);
  res.json({ success: true, message: 'User unblocked', user_id: targetId, is_blocked: 0 });
});

app.get('/api/admin/jobs', adminAuth, async (req, res) => {
  res.json({ jobs: Object.values(db.jobs) });
});

app.get('/api/admin/escrows', adminAuth, async (req, res) => {
  res.json({ escrows: Object.values(db.escrows) });
});

app.get('/api/admin/earnings', adminAuth, async (req, res) => {
  const total = Object.values(db.payments).reduce((a, p) => a + (p.amount || 0), 0);
  res.json({ total_earnings: total, transactions: Object.values(db.payments).length });
});

app.get('/api/admin/audit-logs', adminAuth, async (req, res) => {
  res.json({ logs: db.auditLogs.slice(-100) });
});

app.delete('/api/admin/jobs/:id', adminAuth, async (req, res) => {
  delete db.jobs[req.params.id];
  await saveDb();
  res.json({ success: true });
});

// ─── Pi SDK Compatible ──────────────────────────────────────────────
// v2.2: Global block check for all write endpoints
app.use((req, res, next) => {
  const userId = req.headers['x-user-id'];
  const method = req.method;
  const isWrite = method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH';
  if (!isWrite || !userId || req.path.startsWith('/api/admin')) return next();
  const user = db.users[userId];
  if (user && user.is_blocked) {
    return res.status(403).json({ error: 'Account blocked', message: 'Your account has been blocked. Contact support.' });
  }
  next();
});

app.post('/api/payments/verify', auth, async (req, res) => {
  res.json({ verified: true, payment: req.body });
});

app.post('/api/payments/approve', auth, async (req, res) => {
  res.json({ approved: true });
});

app.post('/api/payments/complete', auth, async (req, res) => {
  res.json({ completed: true });
});

// ─── Start ──────────────────────────────────────────────
loadDb().then(() => {
  app.listen(PORT, () => {
    console.log(`[Server] v2.2.0 running on port ${PORT} (${NODE_ENV})`);
    console.log(`[Storage] JSON file at ${DB_FILE}`);
  });
});

module.exports = app;

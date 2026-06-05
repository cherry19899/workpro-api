require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const fetch = require('node-fetch');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const PI_API_KEY = process.env.PI_API_KEY;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'dev';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';
const DATA_DIR = process.env.DATA_DIR || './data';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const TABLES = ['users', 'jobs', 'applications', 'chat_rooms', 'chat_messages', 'escrows', 'payments', 'ratings', 'connects_transactions', 'audit_logs'];

function loadTable(name) {
  const file = path.join(DATA_DIR, `${name}.json`);
  if (!fs.existsSync(file)) return [];
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return []; }
}
function saveTable(name, data) {
  fs.writeFileSync(path.join(DATA_DIR, `${name}.json`), JSON.stringify(data, null, 2));
}
function loadAll() {
  const db = {};
  TABLES.forEach(t => db[t] = loadTable(t));
  return db;
}
function saveAll(db) {
  TABLES.forEach(t => saveTable(t, db[t]));
}

let db = loadAll();

function getNextId(table) {
  const items = db[table];
  if (!items.length) return 1;
  return Math.max(...items.map(i => parseInt(i.id) || 0)) + 1;
}
function generateId(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function initDb() {
  if (!db.users.length) {
    // JSON database initialized
  }
}
initDb();

app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const corsOrigins = NODE_ENV === 'production'
  ? [FRONTEND_URL, 'https://cherry19899.github.io']
  : [FRONTEND_URL, 'https://cherry19899.github.io', 'http://localhost:5173', 'http://localhost:3000'];

app.use(cors({
  origin: corsOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-api-key'],
  credentials: true
}));

const generalLimiter = rateLimit({
  windowMs: 60 * 1000, max: 100,
  message: { error: 'Too many requests' },
  standardHeaders: true, legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { error: 'Too many auth attempts' },
});
const paymentLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  message: { error: 'Too many payment requests' },
});
app.use(generalLimiter);

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user; req.userId = user.id; next();
  });
}
function requireAdmin(req, res, next) {
  if (req.headers['x-api-key'] === ADMIN_API_KEY || req.user?.role === 'admin') return next();
  return res.status(403).json({ error: 'Admin access required' });
}

async function verifyPiToken(accessToken) {
  try {
    const res = await fetch('https://api.minepi.com/v2/me', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

async function logAudit(userId, action, details, req) {
  const ip = req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown';
  db.audit_logs.unshift({ id: getNextId('audit_logs'), user_id: userId, action, details: JSON.stringify(details), ip_address: ip, created_at: new Date().toISOString() });
  if (db.audit_logs.length > 10000) db.audit_logs = db.audit_logs.slice(0, 10000);
  saveTable('audit_logs', db.audit_logs);
}

app.get('/api/health', async (req, res) => {
  res.json({ status: 'ok', database: 'connected', storage: 'json', timestamp: new Date().toISOString() });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { accessToken, userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  let piUser = null;
  if (accessToken) piUser = await verifyPiToken(accessToken);
  let user = db.users.find(u => u.id === userId);
  if (!user) {
    const username = piUser?.username || userId;
    user = { id: userId, username, email: null, role: 'freelancer', balance_connects: 0, balance_pi: 0, rating: 0, total_jobs_posted: 0, total_jobs_completed: 0, bio: null, skills: null, kyc_verified: false, availability: 'available', created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    db.users.push(user);
    saveTable('users', db.users);
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  await logAudit(user.id, 'login', { method: accessToken ? 'pi' : 'direct' }, req);
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, rating: user.rating, balance_connects: user.balance_connects, balance_pi: user.balance_pi } });
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password_hash, ...safe } = user;
  res.json(safe);
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.userId !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { username, email, bio, skills, availability } = req.body;
  if (username !== undefined) user.username = username;
  if (email !== undefined) user.email = email;
  if (bio !== undefined) user.bio = bio;
  if (skills !== undefined) user.skills = skills;
  if (availability !== undefined) user.availability = availability;
  user.updated_at = new Date().toISOString();
  saveTable('users', db.users);
  res.json({ success: true });
});

app.post('/api/jobs', authenticateToken, async (req, res) => {
  const { title, description, category, budget, skills, images, deadline, connects_spent } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (connects_spent > 0 && user.balance_connects < connects_spent) return res.status(400).json({ error: 'Insufficient connects' });
  const job = {
    id: getNextId('jobs'), title, description, category: category || 'other', budget: budget || 0,
    connects_spent: connects_spent || 0, skills, images, deadline, status: 'open',
    posted_by: req.userId, posted_by_name: user.username, applications: 0,
    created_at: new Date().toISOString(), updated_at: new Date().toISOString()
  };
  db.jobs.push(job);
  if (connects_spent > 0) {
    user.balance_connects -= connects_spent;
    user.total_jobs_posted += 1;
    db.connects_transactions.unshift({ id: getNextId('connects_transactions'), user_id: req.userId, amount: -connects_spent, type: 'spend', description: `Posted job: ${title}`, created_at: new Date().toISOString() });
  } else {
    user.total_jobs_posted += 1;
  }
  saveTable('jobs', db.jobs);
  saveTable('users', db.users);
  saveTable('connects_transactions', db.connects_transactions);
  await logAudit(req.userId, 'job_posted', { job_id: job.id }, req);
  res.json({ job });
});

app.get('/api/jobs', async (req, res) => {
  const { status, category, posted_by, limit = 50, offset = 0 } = req.query;
  let jobs = db.jobs.slice();
  if (status) jobs = jobs.filter(j => j.status === status);
  if (category) jobs = jobs.filter(j => j.category === category);
  if (posted_by) jobs = jobs.filter(j => j.posted_by === posted_by);
  jobs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const total = jobs.length;
  jobs = jobs.slice(parseInt(offset), parseInt(offset) + parseInt(limit));
  res.json({ jobs, count: jobs.length, total });
});

app.get('/api/jobs/:id', async (req, res) => {
  const job = db.jobs.find(j => j.id == req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json({ job });
});

app.post('/api/jobs/:id/apply', authenticateToken, async (req, res) => {
  const { message, bid_amount } = req.body;
  const job = db.jobs.find(j => j.id == req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.status !== 'open') return res.status(400).json({ error: 'Job not open' });
  if (job.posted_by === req.userId) return res.status(400).json({ error: 'Cannot apply to own job' });
  const existing = db.applications.find(a => a.job_id == req.params.id && a.user_id === req.userId);
  if (existing) return res.status(409).json({ error: 'Already applied' });
  const user = db.users.find(u => u.id === req.userId);
  const application = {
    id: getNextId('applications'), job_id: parseInt(req.params.id), user_id: req.userId,
    username: user?.username, message, bid_amount, status: 'pending',
    created_at: new Date().toISOString()
  };
  db.applications.push(application);
  job.applications += 1;
  saveTable('applications', db.applications);
  saveTable('jobs', db.jobs);
  res.json({ application });
});

app.get('/api/jobs/:id/applications', authenticateToken, async (req, res) => {
  const job = db.jobs.find(j => j.id == req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  const apps = db.applications.filter(a => a.job_id == req.params.id).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ applications: apps });
});

app.post('/api/chat/rooms', authenticateToken, async (req, res) => {
  const { job_id, other_user_id } = req.body;
  const roomId = generateId('room');
  db.chat_rooms.push({ id: roomId, job_id, user1_id: req.userId, user2_id: other_user_id, created_at: new Date().toISOString() });
  saveTable('chat_rooms', db.chat_rooms);
  res.json({ room_id: roomId });
});

app.post('/api/chat/rooms/:id/messages', authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'Message required' });
  const room = db.chat_rooms.find(r => r.id === req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (room.user1_id !== req.userId && room.user2_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  const user = db.users.find(u => u.id === req.userId);
  const msg = {
    id: getNextId('chat_messages'), room_id: req.params.id, sender_id: req.userId,
    sender_name: user?.username, message: message.trim(), created_at: new Date().toISOString()
  };
  db.chat_messages.push(msg);
  saveTable('chat_messages', db.chat_messages);
  res.json({ message: msg });
});

app.get('/api/chat/rooms/:id/messages', authenticateToken, async (req, res) => {
  const room = db.chat_rooms.find(r => r.id === req.params.id);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (room.user1_id !== req.userId && room.user2_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  const messages = db.chat_messages.filter(m => m.room_id === req.params.id).sort((a, b) => new Date(a.created_at) - new Date(b.created_at)).slice(-100);
  res.json({ messages });
});

app.post('/api/escrows', authenticateToken, paymentLimiter, async (req, res) => {
  const { job_id, freelancer_id, amount_pi, amount_usd } = req.body;
  const job = db.jobs.find(j => j.id == job_id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  const escrowId = generateId('esc');
  db.escrows.push({
    id: escrowId, job_id, client_id: req.userId, freelancer_id, amount_pi: amount_pi || 0, amount_usd: amount_usd || 0,
    status: 'pending', payment_id: null, txid: null, created_at: new Date().toISOString(), released_at: null, completed_at: null
  });
  job.status = 'in_progress';
  saveTable('escrows', db.escrows);
  saveTable('jobs', db.jobs);
  res.json({ escrow_id: escrowId });
});

app.get('/api/escrows', authenticateToken, async (req, res) => {
  const escrows = db.escrows.filter(e => e.client_id === req.userId || e.freelancer_id === req.userId).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ escrows });
});

app.post('/api/escrows/:id/release', authenticateToken, paymentLimiter, async (req, res) => {
  const escrow = db.escrows.find(e => e.id === req.params.id);
  if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
  if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  if (escrow.status !== 'pending') return res.status(400).json({ error: 'Escrow already processed' });
  escrow.status = 'released';
  escrow.released_at = new Date().toISOString();
  const freelancer = db.users.find(u => u.id === escrow.freelancer_id);
  if (freelancer) {
    freelancer.balance_pi += escrow.amount_pi;
    freelancer.total_jobs_completed += 1;
  }
  saveTable('escrows', db.escrows);
  saveTable('users', db.users);
  res.json({ success: true });
});

app.post('/api/payments', authenticateToken, paymentLimiter, async (req, res) => {
  const { escrow_id, amount_pi, amount_usd, pi_payment_id } = req.body;
  const escrow = db.escrows.find(e => e.id === escrow_id);
  if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
  const paymentId = generateId('pay');
  db.payments.push({
    id: paymentId, escrow_id, payer_id: req.userId, payee_id: escrow.freelancer_id,
    amount_pi, amount_usd, status: 'pending', txid: null, pi_payment_id,
    created_at: new Date().toISOString(), completed_at: null
  });
  saveTable('payments', db.payments);
  res.json({ payment_id: paymentId, status: 'pending' });
});

app.get('/api/payments/:id', authenticateToken, async (req, res) => {
  const payment = db.payments.find(p => p.id === req.params.id);
  if (!payment) return res.status(404).json({ error: 'Payment not found' });
  res.json({ payment });
});

app.post('/api/payments/:id/complete', authenticateToken, paymentLimiter, async (req, res) => {
  const { txid } = req.body;
  const payment = db.payments.find(p => p.id === req.params.id);
  if (!payment) return res.status(404).json({ error: 'Payment not found' });
  if (payment.payer_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
  payment.status = 'completed';
  payment.txid = txid;
  payment.completed_at = new Date().toISOString();
  const escrow = db.escrows.find(e => e.id === payment.escrow_id);
  if (escrow) {
    escrow.status = 'completed';
    escrow.completed_at = new Date().toISOString();
  }
  saveTable('payments', db.payments);
  saveTable('escrows', db.escrows);
  res.json({ success: true });
});

app.post('/api/ratings', authenticateToken, async (req, res) => {
  const { to_user_id, job_id, rating, comment } = req.body;
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating 1-5 required' });
  db.ratings.unshift({ id: getNextId('ratings'), from_user_id: req.userId, to_user_id, job_id, rating, comment, created_at: new Date().toISOString() });
  const userRatings = db.ratings.filter(r => r.to_user_id === to_user_id);
  const avg = userRatings.length ? (userRatings.reduce((s, r) => s + r.rating, 0) / userRatings.length).toFixed(2) : 0;
  const user = db.users.find(u => u.id === to_user_id);
  if (user) user.rating = parseFloat(avg);
  saveTable('ratings', db.ratings);
  saveTable('users', db.users);
  res.json({ success: true });
});

app.get('/api/users/:id/ratings', async (req, res) => {
  const ratings = db.ratings.filter(r => r.to_user_id === req.params.id).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ ratings });
});

app.post('/api/connects/purchase', authenticateToken, paymentLimiter, async (req, res) => {
  const { amount } = req.body;
  const user = db.users.find(u => u.id === req.userId);
  if (user) user.balance_connects += amount;
  db.connects_transactions.unshift({ id: getNextId('connects_transactions'), user_id: req.userId, amount, type: 'purchase', description: `Purchased ${amount} connects`, created_at: new Date().toISOString() });
  saveTable('users', db.users);
  saveTable('connects_transactions', db.connects_transactions);
  res.json({ success: true });
});

app.get('/api/connects/balance', authenticateToken, async (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  res.json({ balance: user?.balance_connects || 0 });
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  const totalRevenue = db.payments.filter(p => p.status === 'completed').reduce((s, p) => s + (p.amount_pi || 0), 0);
  res.json({
    total_users: db.users.length,
    total_jobs: db.jobs.length,
    total_applications: db.applications.length,
    total_escrows: db.escrows.length,
    total_revenue: totalRevenue,
    active_escrows: db.escrows.filter(e => e.status === 'pending').length,
    total_completed: db.jobs.filter(j => j.status === 'completed').length,
  });
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  const users = db.users.map(u => {
    const { password_hash, ...safe } = u;
    return safe;
  }).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ users, count: users.length });
});

app.get('/api/admin/jobs', authenticateToken, requireAdmin, async (req, res) => {
  const jobs = db.jobs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ jobs, count: jobs.length });
});

app.get('/api/admin/escrows', authenticateToken, requireAdmin, async (req, res) => {
  const escrows = db.escrows.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ escrows, count: escrows.length });
});

app.get('/api/admin/earnings', authenticateToken, requireAdmin, async (req, res) => {
  const payments = db.payments.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ payments, count: payments.length });
});

app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
  const { limit = 100 } = req.query;
  const logs = db.audit_logs.slice(0, parseInt(limit));
  res.json({ logs, count: logs.length });
});

app.post('/api/payments/complete', authenticateToken, paymentLimiter, async (req, res) => {
  const { txid, payment_id } = req.body;
  const payment = db.payments.find(p => p.id === payment_id || p.pi_payment_id === payment_id);
  if (!payment) return res.status(404).json({ error: 'Payment not found' });
  payment.status = 'completed';
  payment.txid = txid;
  payment.completed_at = new Date().toISOString();
  const escrow = db.escrows.find(e => e.id === payment.escrow_id);
  if (escrow) {
    escrow.status = 'completed';
    escrow.completed_at = new Date().toISOString();
  }
  saveTable('payments', db.payments);
  saveTable('escrows', db.escrows);
  res.json({ success: true });
});

app.use((err, req, res, next) => {
  res.status(500).json({ error: 'Internal server error', message: NODE_ENV === 'development' ? err.message : 'Something went wrong' });
});
app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.path }));

app.listen(PORT, () => {
  // Server started
});

module.exports = app;

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
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
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;

// ─── Database Layer (PostgreSQL or SQLite) ──────────────────
let pool;
let db;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });
} else {
  console.log('DATABASE_URL not set, using SQLite fallback');
  const sqlite3 = require('sqlite3').verbose();
  db = new sqlite3.Database('./workpro.db');
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA busy_timeout = 15000');
  
  // SQLite wrapper that mimics pg Pool
  pool = {
    query: async (sql, params = []) => {
      const lower = sql.trim().toLowerCase();
      if (lower === 'begin' || lower === 'commit' || lower === 'rollback') {
        return new Promise((resolve, reject) => {
          db.run(sql, (err) => {
            if (err) reject(err);
            else resolve({ rows: [] });
          });
        });
      }
      const sqliteSql = sql.replace(/\$(\d+)/g, '?');
      return new Promise((resolve, reject) => {
        const isSelect = sqliteSql.trim().toLowerCase().startsWith('select');
        if (isSelect) {
          db.all(sqliteSql, params, (err, rows) => {
            if (err) reject(err);
            else resolve({ rows });
          });
        } else {
          db.run(sqliteSql, params, function(err) {
            if (err) reject(err);
            else resolve({ rows: [], lastID: this.lastID, changes: this.changes });
          });
        }
      });
    },
    connect: async () => {
      return {
        query: async (sql, params = []) => {
          const lower = sql.trim().toLowerCase();
          if (lower === 'begin' || lower === 'commit' || lower === 'rollback') {
            return new Promise((resolve, reject) => {
              db.run(sql, (err) => {
                if (err) reject(err);
                else resolve({ rows: [] });
              });
            });
          }
          // Convert PostgreSQL $1, $2 to SQLite ?
          const sqliteSql = sql.replace(/\$(\d+)/g, '?');
          return new Promise((resolve, reject) => {
            const isSelect = sqliteSql.trim().toLowerCase().startsWith('select');
            if (isSelect) {
              db.all(sqliteSql, params, (err, rows) => {
                if (err) reject(err);
                else resolve({ rows });
              });
            } else {
              db.run(sqliteSql, params, function(err) {
                if (err) reject(err);
                else resolve({ rows: [], lastID: this.lastID, changes: this.changes });
              });
            }
          });
        },
        release: () => {},
        queryBegin: async () => { db.run('BEGIN'); },
        queryCommit: async () => { db.run('COMMIT'); },
        queryRollback: async () => { db.run('ROLLBACK'); }
      };
    }
  };
}

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err);
});

// ─── Middleware ─────────────────────────────────────────────────
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

// ─── Rate Limiting ────────────────────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many auth attempts' },
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Too many payment requests' },
});

app.use(generalLimiter);

// ─── Auth Middleware ──────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    req.userId = user.id;
    next();
  });
}

function requireAdmin(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (apiKey === ADMIN_API_KEY || req.user?.role === 'admin') {
    return next();
  }
  return res.status(403).json({ error: 'Admin access required' });
}

// ─── Pi Network Auth ──────────────────────────────────────────
async function verifyPiToken(accessToken) {
  try {
    const response = await fetch('https://api.minepi.com/v2/me', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!response.ok) return null;
    const data = await response.json();
    return data;
  } catch (e) {
    console.error('Pi token verification failed:', e);
    return null;
  }
}

// ─── Database Init ────────────────────────────────────────────
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT UNIQUE,
        role TEXT DEFAULT 'freelancer',
        balance_connects INTEGER DEFAULT 0,
        balance_pi REAL DEFAULT 0,
        rating REAL DEFAULT 0,
        total_jobs_posted INTEGER DEFAULT 0,
        total_jobs_completed INTEGER DEFAULT 0,
        bio TEXT,
        skills TEXT,
        kyc_verified BOOLEAN DEFAULT FALSE,
        availability TEXT DEFAULT 'available',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS jobs (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        category TEXT DEFAULT 'other',
        budget REAL DEFAULT 0,
        connects_spent INTEGER DEFAULT 0,
        skills TEXT,
        images TEXT,
        deadline TEXT,
        status TEXT DEFAULT 'open',
        posted_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        posted_by_name TEXT,
        applications INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        username TEXT,
        message TEXT,
        bid_amount REAL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS chat_rooms (
        id TEXT PRIMARY KEY,
        job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
        user1_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        user2_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        room_id TEXT NOT NULL REFERENCES chat_rooms(id) ON DELETE CASCADE,
        sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        sender_name TEXT,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS escrows (
        id TEXT PRIMARY KEY,
        job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        client_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        freelancer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount_pi REAL DEFAULT 0,
        amount_usd REAL DEFAULT 0,
        status TEXT DEFAULT 'pending',
        payment_id TEXT,
        txid TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        released_at TIMESTAMP,
        completed_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        escrow_id TEXT REFERENCES escrows(id) ON DELETE SET NULL,
        payer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        payee_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount_pi REAL NOT NULL,
        amount_usd REAL,
        status TEXT DEFAULT 'pending',
        txid TEXT,
        pi_payment_id TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS ratings (
        id SERIAL PRIMARY KEY,
        from_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        to_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS connects_transactions (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount INTEGER NOT NULL,
        type TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
      CREATE INDEX IF NOT EXISTS idx_jobs_posted_by ON jobs(posted_by);
      CREATE INDEX IF NOT EXISTS idx_applications_job ON applications(job_id);
      CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id);
      CREATE INDEX IF NOT EXISTS idx_chat_room ON chat_messages(room_id);
      CREATE INDEX IF NOT EXISTS idx_escrows_client ON escrows(client_id);
      CREATE INDEX IF NOT EXISTS idx_escrows_freelancer ON escrows(freelancer_id);
      CREATE INDEX IF NOT EXISTS idx_payments_payer ON payments(payer_id);
      CREATE INDEX IF NOT EXISTS idx_ratings_to ON ratings(to_user_id);
    `);
    console.log('Database initialized successfully');
  } finally {
    client.release();
  }
}

initDb().catch(console.error);

// ─── Helper Functions ─────────────────────────────────────────
function generateId(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

async function logAudit(userId, action, details, req) {
  const ip = req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown';
  await pool.query('INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES ($1, $2, $3, $4)',
    [userId, action, JSON.stringify(details), ip]);
}

// ─── Health ───────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected', timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ status: 'error', database: 'disconnected', error: e.message });
  }
});

// ─── Auth ─────────────────────────────────────────────────────
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { accessToken, userId } = req.body;
  
  if (!userId) {
    return res.status(400).json({ error: 'userId required' });
  }
  
  let piUser = null;
  if (accessToken) {
    piUser = await verifyPiToken(accessToken);
  }
  
  const client = await pool.connect();
  try {
    let user = await client.query('SELECT * FROM users WHERE id = $1', [userId]).then(r => r.rows[0]);
    
    if (!user) {
      const username = piUser?.username || userId;
      await client.query(
        'INSERT INTO users (id, username, role) VALUES ($1, $2, $3)',
        [userId, username, 'freelancer']
      );
      user = { id: userId, username, role: 'freelancer', balance_connects: 0, balance_pi: 0 };
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    await logAudit(user.id, 'login', { method: accessToken ? 'pi' : 'direct' }, req);
    
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, rating: user.rating, balance_connects: user.balance_connects, balance_pi: user.balance_pi } });
  } finally {
    client.release();
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const user = await client.query('SELECT * FROM users WHERE id = $1', [req.userId]).then(r => r.rows[0]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } finally {
    client.release();
  }
});

// ─── Users ────────────────────────────────────────────────────
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const user = await client.query(
      'SELECT id, username, email, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, kyc_verified, availability, created_at FROM users WHERE id = $1',
      [req.params.id]
    ).then(r => r.rows[0]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } finally {
    client.release();
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.userId !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
  const { username, email, bio, skills, availability } = req.body;
  const client = await pool.connect();
  try {
    await client.query(
      'UPDATE users SET username = COALESCE($1, username), email = COALESCE($2, email), bio = COALESCE($3, bio), skills = COALESCE($4, skills), availability = COALESCE($5, availability), updated_at = CURRENT_TIMESTAMP WHERE id = $6',
      [username, email, bio, skills, availability, req.params.id]
    );
    res.json({ success: true });
  } finally {
    client.release();
  }
});

// ─── Jobs ─────────────────────────────────────────────────────
app.post('/api/jobs', authenticateToken, async (req, res) => {
  const { title, description, category, budget, skills, images, deadline, connects_spent } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const user = await client.query('SELECT * FROM users WHERE id = $1', [req.userId]).then(r => r.rows[0]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    if (connects_spent > 0 && user.balance_connects < connects_spent) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient connects' });
    }
    
    const result = await client.query(
      'INSERT INTO jobs (title, description, category, budget, connects_spent, skills, images, deadline, posted_by, posted_by_name) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *',
      [title, description, category, budget, connects_spent || 0, skills, images, deadline, req.userId, user.username]
    );
    
    if (connects_spent > 0) {
      await client.query('UPDATE users SET balance_connects = balance_connects - $1, total_jobs_posted = total_jobs_posted + 1 WHERE id = $2',
        [connects_spent, req.userId]);
      await client.query('INSERT INTO connects_transactions (user_id, amount, type, description) VALUES ($1, $2, $3, $4)',
        [req.userId, -connects_spent, 'spend', `Posted job: ${title}`]);
    } else {
      await client.query('UPDATE users SET total_jobs_posted = total_jobs_posted + 1 WHERE id = $1', [req.userId]);
    }
    
    await client.query('COMMIT');
    await logAudit(req.userId, 'job_posted', { job_id: result.rows[0].id }, req);
    res.json({ job: result.rows[0] });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

app.get('/api/jobs', async (req, res) => {
  const { status, category, posted_by, limit = 50, offset = 0 } = req.query;
  let sql = 'SELECT * FROM jobs WHERE 1=1';
  const params = [];
  let idx = 1;
  
  if (status) { sql += ` AND status = $${idx++}`; params.push(status); }
  if (category) { sql += ` AND category = $${idx++}`; params.push(category); }
  if (posted_by) { sql += ` AND posted_by = $${idx++}`; params.push(posted_by); }
  sql += ` ORDER BY created_at DESC LIMIT $${idx++} OFFSET $${idx++}`;
  params.push(parseInt(limit), parseInt(offset));
  
  const client = await pool.connect();
  try {
    const jobs = await client.query(sql, params).then(r => r.rows);
    res.json({ jobs, count: jobs.length });
  } finally {
    client.release();
  }
});

app.get('/api/jobs/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    const job = await client.query('SELECT * FROM jobs WHERE id = $1', [req.params.id]).then(r => r.rows[0]);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json({ job });
  } finally {
    client.release();
  }
});

// ─── Applications ─────────────────────────────────────────────
app.post('/api/jobs/:id/apply', authenticateToken, async (req, res) => {
  const { message, bid_amount } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const job = await client.query('SELECT * FROM jobs WHERE id = $1', [req.params.id]).then(r => r.rows[0]);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.status !== 'open') return res.status(400).json({ error: 'Job not open' });
    if (job.posted_by === req.userId) return res.status(400).json({ error: 'Cannot apply to own job' });
    
    const existing = await client.query('SELECT * FROM applications WHERE job_id = $1 AND user_id = $2', [req.params.id, req.userId]).then(r => r.rows[0]);
    if (existing) return res.status(409).json({ error: 'Already applied' });
    
    const user = await client.query('SELECT * FROM users WHERE id = $1', [req.userId]).then(r => r.rows[0]);
    
    const result = await client.query(
      'INSERT INTO applications (job_id, user_id, username, message, bid_amount) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.params.id, req.userId, user.username, message, bid_amount]
    );
    
    await client.query('UPDATE jobs SET applications = applications + 1 WHERE id = $1', [req.params.id]);
    
    await client.query('COMMIT');
    res.json({ application: result.rows[0] });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

app.get('/api/jobs/:id/applications', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const job = await client.query('SELECT * FROM jobs WHERE id = $1', [req.params.id]).then(r => r.rows[0]);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const apps = await client.query('SELECT * FROM applications WHERE job_id = $1 ORDER BY created_at DESC', [req.params.id]).then(r => r.rows);
    res.json({ applications: apps });
  } finally {
    client.release();
  }
});

// ─── Chat ─────────────────────────────────────────────────────
app.post('/api/chat/rooms', authenticateToken, async (req, res) => {
  const { job_id, other_user_id } = req.body;
  const roomId = generateId('room');
  const client = await pool.connect();
  try {
    await client.query(
      'INSERT INTO chat_rooms (id, job_id, user1_id, user2_id) VALUES ($1, $2, $3, $4)',
      [roomId, job_id, req.userId, other_user_id]
    );
    res.json({ room_id: roomId });
  } finally {
    client.release();
  }
});

app.post('/api/chat/rooms/:id/messages', authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'Message required' });
  
  const client = await pool.connect();
  try {
    const room = await client.query('SELECT * FROM chat_rooms WHERE id = $1', [req.params.id]).then(r => r.rows[0]);
    if (!room) return res.status(404).json({ error: 'Room not found' });
    if (room.user1_id !== req.userId && room.user2_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const user = await client.query('SELECT username FROM users WHERE id = $1', [req.userId]).then(r => r.rows[0]);
    
    const result = await client.query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.id, req.userId, user.username, message.trim()]
    );
    res.json({ message: result.rows[0] });
  } finally {
    client.release();
  }
});

app.get('/api/chat/rooms/:id/messages', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const room = await client.query('SELECT * FROM chat_rooms WHERE id = $1', [req.params.id]).then(r => r.rows[0]);
    if (!room) return res.status(404).json({ error: 'Room not found' });
    if (room.user1_id !== req.userId && room.user2_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const messages = await client.query(
      'SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at ASC LIMIT 100',
      [req.params.id]
    ).then(r => r.rows);
    res.json({ messages });
  } finally {
    client.release();
  }
});

// ─── Escrow ───────────────────────────────────────────────────
app.post('/api/escrows', authenticateToken, paymentLimiter, async (req, res) => {
  const { job_id, freelancer_id, amount_pi, amount_usd } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const job = await client.query('SELECT * FROM jobs WHERE id = $1', [job_id]).then(r => r.rows[0]);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.posted_by !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    
    const escrowId = generateId('esc');
    await client.query(
      'INSERT INTO escrows (id, job_id, client_id, freelancer_id, amount_pi, amount_usd) VALUES ($1, $2, $3, $4, $5, $6)',
      [escrowId, job_id, req.userId, freelancer_id, amount_pi, amount_usd]
    );
    
    await client.query('UPDATE jobs SET status = $1 WHERE id = $2', ['in_progress', job_id]);
    
    await client.query('COMMIT');
    res.json({ escrow_id: escrowId });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

app.get('/api/escrows', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const escrows = await client.query(
      'SELECT * FROM escrows WHERE client_id = $1 OR freelancer_id = $1 ORDER BY created_at DESC',
      [req.userId]
    ).then(r => r.rows);
    res.json({ escrows });
  } finally {
    client.release();
  }
});

app.post('/api/escrows/:id/release', authenticateToken, paymentLimiter, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const escrow = await client.query('SELECT * FROM escrows WHERE id = $1', [req.params.id]).then(r => r.rows[0]);
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    if (escrow.client_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    if (escrow.status !== 'pending') return res.status(400).json({ error: 'Escrow already processed' });
    
    await client.query('UPDATE escrows SET status = $1, released_at = CURRENT_TIMESTAMP WHERE id = $2', ['released', req.params.id]);
    await client.query('UPDATE users SET balance_pi = balance_pi + $1 WHERE id = $2', [escrow.amount_pi, escrow.freelancer_id]);
    await client.query('UPDATE users SET total_jobs_completed = total_jobs_completed + 1 WHERE id = $1', [escrow.freelancer_id]);
    
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

// ─── Payments ─────────────────────────────────────────────────
app.post('/api/payments', authenticateToken, paymentLimiter, async (req, res) => {
  const { escrow_id, amount_pi, amount_usd, pi_payment_id } = req.body;
  const client = await pool.connect();
  try {
    const escrow = await client.query('SELECT * FROM escrows WHERE id = $1', [escrow_id]).then(r => r.rows[0]);
    if (!escrow) return res.status(404).json({ error: 'Escrow not found' });
    
    const paymentId = generateId('pay');
    await client.query(
      'INSERT INTO payments (id, escrow_id, payer_id, payee_id, amount_pi, amount_usd, pi_payment_id) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [paymentId, escrow_id, req.userId, escrow.freelancer_id, amount_pi, amount_usd, pi_payment_id]
    );
    res.json({ payment_id: paymentId, status: 'pending' });
  } finally {
    client.release();
  }
});

app.get('/api/payments/:id', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const payment = await client.query('SELECT * FROM payments WHERE id = $1', [req.params.id]).then(r => r.rows[0]);
    if (!payment) return res.status(404).json({ error: 'Payment not found' });
    res.json({ payment });
  } finally {
    client.release();
  }
});

app.post('/api/payments/:id/complete', authenticateToken, paymentLimiter, async (req, res) => {
  const { txid } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const payment = await client.query('SELECT * FROM payments WHERE id = $1', [req.params.id]).then(r => r.rows[0]);
    if (!payment) return res.status(404).json({ error: 'Payment not found' });
    if (payment.payer_id !== req.userId) return res.status(403).json({ error: 'Forbidden' });
    
    await client.query('UPDATE payments SET status = $1, txid = $2, completed_at = CURRENT_TIMESTAMP WHERE id = $3',
      ['completed', txid, req.params.id]);
    await client.query('UPDATE escrows SET status = $1, completed_at = CURRENT_TIMESTAMP WHERE id = $2',
      ['completed', payment.escrow_id]);
    
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

// ─── Ratings ──────────────────────────────────────────────────
app.post('/api/ratings', authenticateToken, async (req, res) => {
  const { to_user_id, job_id, rating, comment } = req.body;
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating 1-5 required' });
  
  const client = await pool.connect();
  try {
    await client.query(
      'INSERT INTO ratings (from_user_id, to_user_id, job_id, rating, comment) VALUES ($1, $2, $3, $4, $5)',
      [req.userId, to_user_id, job_id, rating, comment]
    );
    
    const avg = await client.query('SELECT AVG(rating)::numeric(10,2) as avg FROM ratings WHERE to_user_id = $1', [to_user_id]).then(r => r.rows[0]);
    await client.query('UPDATE users SET rating = $1 WHERE id = $2', [avg.avg, to_user_id]);
    
    res.json({ success: true });
  } finally {
    client.release();
  }
});

app.get('/api/users/:id/ratings', async (req, res) => {
  const client = await pool.connect();
  try {
    const ratings = await client.query(
      'SELECT r.*, u.username as from_username FROM ratings r JOIN users u ON r.from_user_id = u.id WHERE r.to_user_id = $1 ORDER BY r.created_at DESC',
      [req.params.id]
    ).then(r => r.rows);
    res.json({ ratings });
  } finally {
    client.release();
  }
});

// ─── Connects ─────────────────────────────────────────────────
app.post('/api/connects/purchase', authenticateToken, paymentLimiter, async (req, res) => {
  const { amount, pi_amount } = req.body;
  const client = await pool.connect();
  try {
    await client.query('UPDATE users SET balance_connects = balance_connects + $1 WHERE id = $2', [amount, req.userId]);
    await client.query(
      'INSERT INTO connects_transactions (user_id, amount, type, description) VALUES ($1, $2, $3, $4)',
      [req.userId, amount, 'purchase', `Purchased ${amount} connects`]
    );
    res.json({ success: true, balance_connects: amount });
  } finally {
    client.release();
  }
});

app.get('/api/connects/balance', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const user = await client.query('SELECT balance_connects FROM users WHERE id = $1', [req.userId]).then(r => r.rows[0]);
    res.json({ balance: user?.balance_connects || 0 });
  } finally {
    client.release();
  }
});

// ─── Admin ────────────────────────────────────────────────────
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const stats = {};
    const queries = [
      'SELECT COUNT(*) as total_users FROM users',
      'SELECT COUNT(*) as total_jobs FROM jobs',
      'SELECT COUNT(*) as total_applications FROM applications',
      'SELECT COUNT(*) as total_escrows FROM escrows',
      'SELECT COALESCE(SUM(amount_pi), 0) as total_revenue FROM payments WHERE status = $1',
      'SELECT COUNT(*) as active_escrows FROM escrows WHERE status = $2',
      'SELECT COUNT(*) as total_completed FROM jobs WHERE status = $3'
    ];
    
    const results = await Promise.all([
      client.query(queries[0]),
      client.query(queries[1]),
      client.query(queries[2]),
      client.query(queries[3]),
      client.query(queries[4], ['completed']),
      client.query(queries[5], ['pending']),
      client.query(queries[6], ['completed'])
    ]);
    
    stats.total_users = parseInt(results[0].rows[0].total_users);
    stats.total_jobs = parseInt(results[1].rows[0].total_jobs);
    stats.total_applications = parseInt(results[2].rows[0].total_applications);
    stats.total_escrows = parseInt(results[3].rows[0].total_escrows);
    stats.total_revenue = parseFloat(results[4].rows[0].total_revenue);
    stats.active_escrows = parseInt(results[5].rows[0].active_escrows);
    stats.total_completed = parseInt(results[6].rows[0].total_completed);
    
    res.json(stats);
  } finally {
    client.release();
  }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const users = await client.query('SELECT id, username, email, role, rating, balance_connects, balance_pi, created_at FROM users ORDER BY created_at DESC').then(r => r.rows);
    res.json({ users, count: users.length });
  } finally {
    client.release();
  }
});

app.get('/api/admin/jobs', authenticateToken, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const jobs = await client.query('SELECT * FROM jobs ORDER BY created_at DESC').then(r => r.rows);
    res.json({ jobs, count: jobs.length });
  } finally {
    client.release();
  }
});

app.get('/api/admin/escrows', authenticateToken, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const escrows = await client.query('SELECT * FROM escrows ORDER BY created_at DESC').then(r => r.rows);
    res.json({ escrows, count: escrows.length });
  } finally {
    client.release();
  }
});

app.get('/api/admin/earnings', authenticateToken, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const payments = await client.query('SELECT * FROM payments ORDER BY created_at DESC').then(r => r.rows);
    res.json({ payments, count: payments.length });
  } finally {
    client.release();
  }
});

app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
  const { limit = 100 } = req.query;
  const client = await pool.connect();
  try {
    const logs = await client.query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1', [parseInt(limit)]).then(r => r.rows);
    res.json({ logs, count: logs.length });
  } finally {
    client.release();
  }
});

app.post('/api/payments/complete', authenticateToken, paymentLimiter, async (req, res) => {
  const { txid, payment_id } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const payment = await client.query('SELECT * FROM payments WHERE id = $1 OR pi_payment_id = $2', [payment_id, payment_id]).then(r => r.rows[0]);
    if (!payment) return res.status(404).json({ error: 'Payment not found' });
    
    await client.query('UPDATE payments SET status = $1, txid = $2, completed_at = CURRENT_TIMESTAMP WHERE id = $3',
      ['completed', txid, payment.id]);
    await client.query('UPDATE escrows SET status = $1, completed_at = CURRENT_TIMESTAMP WHERE id = $2',
      ['completed', payment.escrow_id]);
    
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error', message: NODE_ENV === 'development' ? err.message : 'Something went wrong' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found', path: req.path });
});

// ─── Start Server ────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`WorkPro production server running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Database: PostgreSQL`);
});

module.exports = app;

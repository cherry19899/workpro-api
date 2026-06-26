const fs = require('fs').promises;
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

let db = {
  users: {}, jobs: {}, applications: {}, escrows: {}, payments: {},
  ratings: {}, chatRooms: {}, chatMessages: {}, auditLogs: [],
  counters: { jobs: 0, users: 0, applications: 0, escrows: 0, payments: 0, ratings: 0, chatRooms: 0, chatMessages: 0 }
};

async function loadJsonDb() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const data = await fs.readFile(DB_FILE, 'utf8');
    db = JSON.parse(data);
    console.log('[DB] JSON loaded');
  } catch (e) {
    console.log('[DB] Starting fresh JSON');
    await saveJsonDb();
  }
}

async function saveJsonDb() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const tmpFile = DB_FILE + '.tmp';
    await fs.writeFile(tmpFile, JSON.stringify(db, null, 2));
    await fs.rename(tmpFile, DB_FILE);
  } catch (e) {
    console.error('[DB] JSON save error:', e.message);
  }
}

async function healthCheck() {
  if (!usePg) return { ok: true, mode: 'json' };
  try {
    await pool.query('SELECT 1');
    return { ok: true, mode: 'pg' };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

setInterval(saveJsonDb, 30000);

// ─── PostgreSQL or JSON ─────────────────────────────────────────
const usePg = !!process.env.DATABASE_URL;
let pool = null;

async function query(text, params) {
  if (!usePg) throw new Error('PostgreSQL not configured');
  const start = Date.now();
  const result = await pool.query(text, params);
  if (process.env.NODE_ENV !== 'production') {
    console.log('PG query', { text: text.substring(0, 50), duration: Date.now() - start, rows: result.rowCount });
  }
  return result;
}

const MAX_RETRIES = 3;
async function queryWithRetry(text, params, retries = MAX_RETRIES) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await query(text, params);
    } catch (err) {
      // Only retry on transient connection errors, not logic/constraint errors
      const transient = err.code === 'ECONNRESET' || err.code === '57P01' || err.message.includes('Connection terminated');
      if (!transient || attempt === retries) throw err;
      await new Promise(r => setTimeout(r, 200 * attempt));
    }
  }
}

async function initDb() {
  if (!usePg) {
    await loadJsonDb();
    console.log('[DB] JSON fallback mode');
    return;
  }

  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 8,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  try {
    await query(`CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(255) PRIMARY KEY, username VARCHAR(255) NOT NULL, email VARCHAR(255),
      role VARCHAR(50) DEFAULT 'freelancer', balance_connects INTEGER DEFAULT 0,
      balance_pi DECIMAL(10,2) DEFAULT 0, rating DECIMAL(2,1) DEFAULT 0,
      total_jobs_posted INTEGER DEFAULT 0, total_jobs_completed INTEGER DEFAULT 0,
      bio TEXT, skills TEXT, avatar TEXT, kyc_verified BOOLEAN DEFAULT FALSE,
      availability VARCHAR(50) DEFAULT 'available', is_blocked BOOLEAN DEFAULT FALSE,
      status VARCHAR(50) DEFAULT 'active', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS jobs (
      id SERIAL PRIMARY KEY, title VARCHAR(500) NOT NULL, description TEXT NOT NULL,
      category VARCHAR(100) DEFAULT 'Other', budget DECIMAL(10,2) NOT NULL,
      skills TEXT, images TEXT, deadline TIMESTAMP, status VARCHAR(50) DEFAULT 'open',
      posted_by VARCHAR(255), posted_by_name VARCHAR(255), applications INTEGER DEFAULT 0,
      connects_spent INTEGER DEFAULT 1, apply_cost INTEGER DEFAULT 1,
      featured BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    // Add featured column to existing tables (idempotent — ALTER TABLE ADD COLUMN IF NOT EXISTS)
    await query(`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT false`).catch(() => {});
    await query(`CREATE TABLE IF NOT EXISTS applications (
      id SERIAL PRIMARY KEY, job_id INTEGER, job_title VARCHAR(500),
      freelancer_id VARCHAR(255), freelancer_name VARCHAR(255), message TEXT,
      status VARCHAR(50) DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS escrows (
      id SERIAL PRIMARY KEY, job_id INTEGER, client_id VARCHAR(255),
      freelancer_id VARCHAR(255), amount DECIMAL(10,2) NOT NULL,
      payment_id VARCHAR(255), status VARCHAR(50) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS payments (
      id VARCHAR(255) PRIMARY KEY, user_id VARCHAR(255), type VARCHAR(100),
      amount DECIMAL(10,2), status VARCHAR(50) DEFAULT 'pending',
      txid VARCHAR(255), metadata JSONB DEFAULT '{}',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    // Add missing columns if upgrading existing DB
    await query(`ALTER TABLE escrows ADD COLUMN IF NOT EXISTS payment_id VARCHAR(255)`).catch(() => {});
    await query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS txid VARCHAR(255)`).catch(() => {});
    await query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS payment_id VARCHAR(255)`).catch(() => {});
    await query(`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS hired_freelancer_id VARCHAR(255)`).catch(() => {});
    await query(`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS hired_freelancer_name VARCHAR(255)`).catch(() => {});
    await query(`ALTER TABLE jobs ADD COLUMN IF NOT EXISTS escrow_id INTEGER`).catch(() => {});
    await query(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS bid_amount DECIMAL(10,2)`).catch(() => {});
    await query(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS cover_letter TEXT`).catch(() => {});
    await query(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS viewed BOOLEAN DEFAULT FALSE`).catch(() => {});
    await query(`ALTER TABLE applications ADD COLUMN IF NOT EXISTS viewed_at TIMESTAMP`).catch(() => {});
    await query(`CREATE TABLE IF NOT EXISTS ratings (
      id SERIAL PRIMARY KEY, from_user_id VARCHAR(255), to_user_id VARCHAR(255),
      job_id INTEGER, rating INTEGER, comment TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS chat_rooms (
      id VARCHAR(255) PRIMARY KEY, client_id VARCHAR(255), freelancer_id VARCHAR(255),
      job_id INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS chat_messages (
      id SERIAL PRIMARY KEY, room_id VARCHAR(255), sender_id VARCHAR(255),
      sender_name VARCHAR(255), message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY, action VARCHAR(255) NOT NULL, data JSONB DEFAULT '{}',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await query(`INSERT INTO users (id, username, role, kyc_verified, status) VALUES ('pi_cherry19899', 'cherry19899', 'admin', true, 'active') ON CONFLICT (id) DO NOTHING`);
    console.log('[DB] PostgreSQL initialized');
  } catch (err) {
    console.error('[DB] PostgreSQL init error:', err.message);
    throw err;
  }
}

function getPool() { return pool; }
module.exports = { query, queryWithRetry, initDb, pool, getPool, usePg, db, saveJsonDb, healthCheck };

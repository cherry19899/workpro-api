require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const PI_API_KEY = process.env.PI_API_KEY;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || process.env.WORKPRO_API_ACCESS || 'workpro-admin-change-me-in-production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cherry19899.github.io';
const NODE_ENV = process.env.NODE_ENV || 'production';

// ─── Rate Limiting ────────────────────────────────────────────
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 100; // requests per window

function rateLimit(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  const entry = rateLimitMap.get(key) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };

  if (now > entry.resetTime) {
    entry.count = 0;
    entry.resetTime = now + RATE_LIMIT_WINDOW;
  }

  entry.count++;
  rateLimitMap.set(key, entry);

  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests, please try again later' });
  }
  next();
}

// ─── Admin Auth Middleware ────────────────────────────────────
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }
  const token = authHeader.slice(7);
  if (token !== ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Invalid admin token' });
  }
  next();
}

// ─── Payment Signature Verification ────────────────────────────
async function verifyPaymentWithPi(paymentId) {
  try {
    const response = await fetch(`https://api.minepi.com/v2/payments/${paymentId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Key ${PI_API_KEY}`,
        'Content-Type': 'application/json',
      },
    });
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    console.error('[Pi API] Verification error:', e.message);
    return null;
  }
}

// ─── TXID Validation ──────────────────────────────────────────
function isValidTxid(txid) {
  return typeof txid === 'string' && /^[a-fA-F0-9]{64}$/.test(txid);
}

// ─── CORS Configuration ───────────────────────────────────────
const corsOrigins = NODE_ENV === 'production'
  ? [FRONTEND_URL, 'https://cherry19899.github.io']
  : [FRONTEND_URL, 'https://cherry19899.github.io', 'http://localhost:5173', 'http://localhost:3000'];

app.use(cors({
  origin: corsOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(rateLimit);
app.use(express.json());

// ─── SQLite Database ────────────────────────────────────────────
const dbPath = path.join(__dirname, 'workpro.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT,
    amount REAL NOT NULL,
    memo TEXT,
    status TEXT DEFAULT 'pending',
    txid TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT DEFAULT 'freelancer',
    balance_connects INTEGER DEFAULT 0,
    balance_pi REAL DEFAULT 0,
    kyc_verified INTEGER DEFAULT 0,
    availability TEXT DEFAULT 'available',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Add availability column if not exists (migration)


  db.run(`CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'other',
    budget REAL DEFAULT 0,
    skills TEXT,
    images TEXT,
    deadline TEXT,
    status TEXT DEFAULT 'open',
    posted_by TEXT NOT NULL,
    posted_by_name TEXT,
    applications INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT,
    message TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS escrows (
    id TEXT PRIMARY KEY,
    job_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    freelancer_id TEXT,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    funded_at DATETIME,
    released_at DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS escrow_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    escrow_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_name TEXT,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS connects_purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    pi_amount REAL NOT NULL,
    payment_id TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY,
    reviewer_id TEXT NOT NULL,
    reviewer_name TEXT,
    target_id TEXT NOT NULL,
    target_name TEXT,
    job_id TEXT,
    job_title TEXT,
    rating INTEGER NOT NULL,
    text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS offers (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_name TEXT,
    freelancer_id TEXT NOT NULL,
    freelancer_name TEXT,
    job_id TEXT,
    job_title TEXT,
    amount REAL DEFAULT 0,
    message TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ─── Health Check ───────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Work Pro Backend Running', pi_api_configured: !!PI_API_KEY });
});

// ─── Approve Pi Payment ───────────────────────────────────────
app.post('/api/payments/:paymentId/approve', async (req, res) => {
  const { paymentId } = req.params;

  if (!PI_API_KEY) {
    return res.status(500).json({ error: 'PI_API_KEY not configured' });
  }

  // Verify payment exists on Pi Network before approving
  const piPayment = await verifyPaymentWithPi(paymentId);
  if (!piPayment) {
    return res.status(400).json({ error: 'Payment not found on Pi Network' });
  }

  try {
    const response = await fetch(`https://api.minepi.com/v2/payments/${paymentId}/approve`, {
      method: 'POST',
      headers: {
        'Authorization': `Key ${PI_API_KEY}`,
        'Content-Type': 'application/json',
      },
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('[Pi API] Approve failed:', data);
      return res.status(response.status).json({ error: data.error || 'Approval failed', details: data });
    }

    // Save payment record using verified data from Pi API
    const uid = piPayment.user_uid || req.body?.user?.uid || 'unknown';
    const username = piPayment.metadata?.user?.username || req.body?.user?.username || 'unknown';
    const amount = piPayment.amount || req.body?.amount || 0;
    const memo = piPayment.memo || req.body?.memo || '';

    db.run(
      `INSERT OR REPLACE INTO payments (id, user_id, username, amount, memo, status) VALUES (?, ?, ?, ?, ?, 'approved')`,
      [paymentId, uid, username, amount, memo],
      (err) => {
        if (err) console.error('[DB] Error saving payment:', err);
      }
    );

    console.log('[Pi API] Payment approved:', paymentId);
    res.json({ success: true, payment: data });
  } catch (err) {
    console.error('[Server] Approve error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

// ─── Complete Pi Payment ──────────────────────────────────────
app.post('/api/payments/:paymentId/complete', async (req, res) => {
  const { paymentId } = req.params;
  const { txid } = req.body;

  if (!PI_API_KEY) {
    return res.status(500).json({ error: 'PI_API_KEY not configured' });
  }

  if (!txid) {
    return res.status(400).json({ error: 'txid is required' });
  }

  // Validate txid format (64-char hex)
  if (!isValidTxid(txid)) {
    return res.status(400).json({ error: 'Invalid txid format. Must be 64-character hex string.' });
  }

  try {
    const response = await fetch(`https://api.minepi.com/v2/payments/${paymentId}/complete`, {
      method: 'POST',
      headers: {
        'Authorization': `Key ${PI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ txid }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('[Pi API] Complete failed:', data);
      return res.status(response.status).json({ error: data.error || 'Completion failed', details: data });
    }

    // Update payment status
    db.run(
      `UPDATE payments SET status = 'completed', txid = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [txid, paymentId],
      (err) => {
        if (err) console.error('[DB] Error updating payment:', err);
      }
    );

    console.log('[Pi API] Payment completed:', paymentId, 'txid:', txid);
    res.json({ success: true, payment: data });
  } catch (err) {
    console.error('[Server] Complete error:', err);
    res.status(500).json({ error: 'Server error', message: err.message });
  }
});

// ─── Cancelled Payment Webhook ──────────────────────────────────
app.post('/api/payments/:paymentId/cancelled', async (req, res) => {
  const { paymentId } = req.params;

  // Verify payment exists on Pi Network before cancelling
  const piPayment = await verifyPaymentWithPi(paymentId);
  if (!piPayment) {
    return res.status(400).json({ error: 'Payment not found on Pi Network' });
  }

  // Only allow cancelling payments that are still pending
  if (piPayment.status !== 'pending' && piPayment.status !== 'approved') {
    return res.status(400).json({ error: 'Payment cannot be cancelled in current state: ' + piPayment.status });
  }

  db.run(
    `UPDATE payments SET status = 'cancelled' WHERE id = ?`,
    [paymentId],
    (err) => {
      if (err) console.error('[DB] Error updating payment:', err);
    }
  );

  console.log('[Pi API] Payment cancelled:', paymentId);
  res.json({ success: true, message: 'Payment marked as cancelled' });
});

// ─── Buy Connects ─────────────────────────────────────────────
app.post('/api/connects/buy', async (req, res) => {
  const { user_id, username, package_amount, pi_amount, payment_id } = req.body;

  db.run(
    `INSERT INTO connects_purchases (user_id, amount, pi_amount, payment_id, status) VALUES (?, ?, ?, ?, 'pending')`,
    [user_id, package_amount, pi_amount, payment_id],
    function(err) {
      if (err) {
        console.error('[DB] Error saving connects purchase:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      // Update user connects balance
      db.get(`SELECT balance_connects FROM users WHERE id = ?`, [user_id], (err, row) => {
        if (row) {
          const newBalance = (row.balance_connects || 0) + package_amount;
          db.run(`UPDATE users SET balance_connects = ? WHERE id = ?`, [newBalance, user_id]);
        } else {
          db.run(`INSERT INTO users (id, username, balance_connects) VALUES (?, ?, ?)`, [user_id, username || 'user', package_amount]);
        }
      });

      res.json({ success: true, purchase_id: this.lastID, added_connects: package_amount });
    }
  );
});

// ─── Get User Data ────────────────────────────────────────────
app.get('/api/users/:userId', (req, res) => {
  const { userId } = req.params;
  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(row || { id: userId, balance_connects: 0, balance_pi: 0 });
  });
});

// ─── Update User Balance ──────────────────────────────────────
app.post('/api/users/:userId/balance', (req, res) => {
  const { userId } = req.params;
  const { connects, pi } = req.body;

  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, row) => {
    if (row) {
      const newConnects = connects !== undefined ? connects : (row.balance_connects || 0);
      const newPi = pi !== undefined ? pi : (row.balance_pi || 0);
      db.run(`UPDATE users SET balance_connects = ?, balance_pi = ? WHERE id = ?`, [newConnects, newPi, userId], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, balance_connects: newConnects, balance_pi: newPi });
      });
    } else {
      db.run(`INSERT INTO users (id, balance_connects, balance_pi) VALUES (?, ?, ?)`, [userId, connects || 0, pi || 0], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, balance_connects: connects || 0, balance_pi: pi || 0 });
      });
    }
  });
});

// ─── Get Payment Status ───────────────────────────────────────
app.get('/api/payments/:paymentId', (req, res) => {
  const { paymentId } = req.params;
  db.get(`SELECT * FROM payments WHERE id = ?`, [paymentId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(row || { id: paymentId, status: 'not_found' });
  });
});

// ─── Jobs ─────────────────────────────────────────────────────
app.get('/api/jobs', (req, res) => {
  const { category, search, page = 1, limit = 20 } = req.query;
  let sql = `SELECT * FROM jobs WHERE status = 'open'`;
  let params = [];
  
  if (category && category !== 'all') {
    sql += ` AND category = ?`;
    params.push(category);
  }
  if (search) {
    sql += ` AND (title LIKE ? OR description LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`);
  }
  sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    // Parse images JSON if stored as string
    rows.forEach(row => {
      if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
    });
    res.json({ jobs: rows, page: parseInt(page), total_pages: 1 });
  });
});

app.get('/api/jobs/:id', (req, res) => {
  const { id } = req.params;
  db.get(`SELECT * FROM jobs WHERE id = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'Job not found' });
    if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
    res.json(row);
  });
});

app.get('/api/jobs/user/:username', (req, res) => {
  const { username } = req.params;
  db.all(`SELECT * FROM jobs WHERE posted_by_name = ? ORDER BY created_at DESC`, [username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    rows.forEach(row => {
      if (row.images) try { row.images = JSON.parse(row.images); } catch(e) {}
    });
    res.json(rows);
  });
});

app.post('/api/jobs', (req, res) => {
  const { title, description, category, budget, skills, images, deadline, posted_by, posted_by_name } = req.body;
  
  if (!title || !description) {
    return res.status(400).json({ error: 'Title and description required' });
  }

  const imagesStr = images && Array.isArray(images) ? JSON.stringify(images) : null;
  
  db.run(
    `INSERT INTO jobs (title, description, category, budget, skills, images, deadline, posted_by, posted_by_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [title, description, category || 'other', budget || 0, skills || '', imagesStr, deadline || null, posted_by || 'unknown', posted_by_name || 'Anonymous'],
    function(err) {
      if (err) {
        console.error('[DB] Error creating job:', err);
        return res.status(500).json({ error: 'Failed to create job' });
      }
      res.json({ id: this.lastID, success: true, remaining_connects: 10 });
    }
  );
});

app.put('/api/jobs/:id', (req, res) => {
  const { id } = req.params;
  const { title, description, category, budget, skills, images, deadline, status } = req.body;
  const imagesStr = images && Array.isArray(images) ? JSON.stringify(images) : images;
  
  db.run(
    `UPDATE jobs SET title = ?, description = ?, category = ?, budget = ?, skills = ?, images = ?, deadline = ?, status = ? WHERE id = ?`,
    [title, description, category, budget, skills, imagesStr, deadline, status, id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update job' });
      res.json({ success: true });
    }
  );
});

app.delete('/api/jobs/:id', (req, res) => {
  const { id } = req.params;
  db.run(`DELETE FROM jobs WHERE id = ?`, [id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete job' });
    res.json({ success: true });
  });
});

// ─── Applications ────────────────────────────────────────────
app.post('/api/jobs/:jobId/apply', (req, res) => {
  const { jobId } = req.params;
  const { user_id, username, message } = req.body;
  
  db.run(
    `INSERT INTO applications (job_id, user_id, username, message) VALUES (?, ?, ?, ?)`,
    [jobId, user_id, username, message],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to apply' });
      // Increment applications count
      db.run(`UPDATE jobs SET applications = applications + 1 WHERE id = ?`, [jobId]);
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.get('/api/jobs/:jobId/applications', (req, res) => {
  const { jobId } = req.params;
  db.all(`SELECT * FROM applications WHERE job_id = ? ORDER BY created_at DESC`, [jobId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// ─── Update User Availability ─────────────────────────────────
app.post('/api/users/:userId/availability', (req, res) => {
  const { userId } = req.params;
  const { availability } = req.body;

  if (!availability || !['available', 'busy'].includes(availability)) {
    return res.status(400).json({ error: 'Invalid availability value' });
  }

  db.run(
    `UPDATE users SET availability = ? WHERE id = ?`,
    [availability, userId],
    function(err) {
      if (err) {
        console.error('[DB] Error updating availability:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (this.changes === 0) {
        // User not found, create with availability
        db.run(
          `INSERT INTO users (id, availability) VALUES (?, ?)`,
          [userId, availability],
          (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true, availability });
          }
        );
      } else {
        res.json({ success: true, availability });
      }
    }
  );
});

// ─── Application Management ────────────────────────────────────
app.post('/api/applications/:id/accept', (req, res) => {
  const { id } = req.params;
  db.run(`UPDATE applications SET status = 'accepted' WHERE id = ?`, [id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to accept' });
    if (this.changes === 0) return res.status(404).json({ error: 'Application not found' });
    res.json({ success: true, status: 'accepted' });
  });
});

app.post('/api/applications/:id/reject', (req, res) => {
  const { id } = req.params;
  db.run(`UPDATE applications SET status = 'rejected' WHERE id = ?`, [id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to reject' });
    if (this.changes === 0) return res.status(404).json({ error: 'Application not found' });
    res.json({ success: true, status: 'rejected' });
  });
});

app.get('/api/applications/user/:userId', (req, res) => {
  const { userId } = req.params;
  db.all(`SELECT * FROM applications WHERE user_id = ? ORDER BY created_at DESC`, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/applications/me', (req, res) => {
  const { user_id } = req.query;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  db.all(`SELECT * FROM applications WHERE user_id = ? ORDER BY created_at DESC`, [user_id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// ─── Escrows ──────────────────────────────────────────────────
app.get('/api/escrows/user/:userId', (req, res) => {
  const { userId } = req.params;
  db.all(`SELECT * FROM escrows WHERE client_id = ? OR freelancer_id = ? ORDER BY created_at DESC`, [userId, userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/escrows', (req, res) => {
  const { job_id, client_id, freelancer_id, amount } = req.body;
  const id = 'esc_' + Date.now();
  db.run(`INSERT INTO escrows (id, job_id, client_id, freelancer_id, amount) VALUES (?, ?, ?, ?, ?)`,
    [id, job_id, client_id, freelancer_id, amount],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create escrow' });
      res.json({ id, success: true });
    }
  );
});

app.post('/api/escrows/:id/fund', (req, res) => {
  const { id } = req.params;
  db.run(`UPDATE escrows SET status = 'funded', funded_at = CURRENT_TIMESTAMP WHERE id = ?`, [id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to fund' });
    res.json({ success: true, status: 'funded' });
  });
});

app.post('/api/escrows/:id/release', (req, res) => {
  const { id } = req.params;
  db.run(`UPDATE escrows SET status = 'released', released_at = CURRENT_TIMESTAMP WHERE id = ?`, [id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to release' });
    res.json({ success: true, status: 'released' });
  });
});

app.post('/api/escrows/:id/dispute', (req, res) => {
  const { id } = req.params;
  db.run(`UPDATE escrows SET status = 'disputed' WHERE id = ?`, [id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to dispute' });
    res.json({ success: true, status: 'disputed' });
  });
});

app.get('/api/escrows/:escrowId/room', (req, res) => {
  const { escrowId } = req.params;
  db.all(`SELECT * FROM escrow_messages WHERE escrow_id = ? ORDER BY created_at ASC`, [escrowId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ messages: rows, escrow_id: escrowId });
  });
});

app.post('/api/escrows/:escrowId/message', (req, res) => {
  const { escrowId } = req.params;
  const { sender_id, sender_name, message } = req.body;
  db.run(`INSERT INTO escrow_messages (escrow_id, sender_id, sender_name, message) VALUES (?, ?, ?, ?)`,
    [escrowId, sender_id, sender_name, message],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to send message' });
      res.json({ id: this.lastID, success: true });
    }
  );
});

// ─── Reviews ──────────────────────────────────────────────────
app.post('/api/reviews', (req, res) => {
  const { reviewer_id, reviewer_name, target_id, target_name, job_id, job_title, rating, text } = req.body;
  const id = 'rev_' + Date.now();
  db.run(
    `INSERT INTO reviews (id, reviewer_id, reviewer_name, target_id, target_name, job_id, job_title, rating, text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, reviewer_id, reviewer_name, target_id, target_name, job_id, job_title || '', rating, text],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to submit review' });
      res.json({ success: true, id });
    }
  );
});

app.get('/api/reviews/:username', (req, res) => {
  const { username } = req.params;
  db.all(`SELECT * FROM reviews WHERE target_name = ? ORDER BY created_at DESC`, [username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/reviews/stats/:username', (req, res) => {
  const { username } = req.params;
  db.all(`SELECT rating FROM reviews WHERE target_name = ?`, [username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const count = rows.length;
    const average_rating = count > 0 ? (rows.reduce((sum, r) => sum + r.rating, 0) / count).toFixed(1) : 0;
    res.json({ count, average_rating: parseFloat(average_rating) });
  });
});

// ─── Offers ───────────────────────────────────────────────────
app.get('/api/offers/:userId', (req, res) => {
  const { userId } = req.params;
  db.all(`SELECT * FROM offers WHERE freelancer_id = ? ORDER BY created_at DESC`, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/offers/:offerId/accept', (req, res) => {
  const { offerId } = req.params;
  db.run(`UPDATE offers SET status = 'accepted' WHERE id = ?`, [offerId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to accept offer' });
    res.json({ success: true });
  });
});

app.post('/api/offers/:offerId/decline', (req, res) => {
  const { offerId } = req.params;
  db.run(`UPDATE offers SET status = 'declined' WHERE id = ?`, [offerId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to decline offer' });
    res.json({ success: true });
  });
});

// ─── Admin (Protected) ────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  db.get(`SELECT COUNT(*) as total_users FROM users`, [], (err, usersRow) => {
    db.get(`SELECT COUNT(*) as total_jobs FROM jobs`, [], (err, jobsRow) => {
      db.get(`SELECT COUNT(*) as total_applications FROM applications`, [], (err, appsRow) => {
        db.get(`SELECT SUM(amount) as total_escrows FROM escrows`, [], (err, escRow) => {
          res.json({
            total_users: usersRow?.total_users || 0,
            total_jobs: jobsRow?.total_jobs || 0,
            total_applications: appsRow?.total_applications || 0,
            total_escrows: escRow?.total_escrows || 0,
          });
        });
      });
    });
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM users ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/admin/jobs/all', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM jobs ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/admin/earnings', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM payments WHERE status = 'completed' ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const total = rows.reduce((sum, p) => sum + (p.amount || 0), 0);
    res.json({ payments: rows, total });
  });
});

app.get('/api/admin/escrows', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM escrows ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// ─── Chat ─────────────────────────────────────────────────────
app.get('/api/chat/rooms/:userId', (req, res) => {
  res.json([]);
});

app.get('/api/chat/:roomId/messages', (req, res) => {
  res.json([]);
});

app.post('/api/chat/:roomId/messages', (req, res) => {
  res.json({ success: true, id: 'msg_' + Date.now() });
});

// ─── Start Server ───────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[WorkPro Backend] Running on port ${PORT}`);
  console.log(`[WorkPro Backend] Environment: ${NODE_ENV}`);
  console.log(`[WorkPro Backend] Frontend allowed: ${corsOrigins.join(', ')}`);
  console.log(`[WorkPro Backend] Pi API Key: ${PI_API_KEY ? 'Configured' : 'MISSING!'}`);
  console.log(`[WorkPro Backend] Admin API Key: ${ADMIN_API_KEY ? 'Configured' : 'MISSING!'}`);
});

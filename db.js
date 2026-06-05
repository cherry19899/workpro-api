const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function query(text, params) {
  const start = Date.now();
  const result = await pool.query(text, params);
  const duration = Date.now() - start;
  console.log('Executed query', { text: text.substring(0, 50), duration, rows: result.rowCount });
  return result;
}

async function initDb() {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        role VARCHAR(50) DEFAULT 'freelancer',
        balance_connects INTEGER DEFAULT 0,
        balance_pi DECIMAL(10,2) DEFAULT 0,
        rating DECIMAL(2,1) DEFAULT 0,
        total_jobs_posted INTEGER DEFAULT 0,
        total_jobs_completed INTEGER DEFAULT 0,
        bio TEXT,
        skills TEXT,
        avatar TEXT,
        kyc_verified BOOLEAN DEFAULT FALSE,
        availability VARCHAR(50) DEFAULT 'available',
        is_blocked BOOLEAN DEFAULT FALSE,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await query(`
      CREATE TABLE IF NOT EXISTS jobs (
        id SERIAL PRIMARY KEY,
        title VARCHAR(500) NOT NULL,
        description TEXT NOT NULL,
        category VARCHAR(100) DEFAULT 'Other',
        budget DECIMAL(10,2) NOT NULL,
        skills TEXT,
        images TEXT,
        deadline TIMESTAMP,
        status VARCHAR(50) DEFAULT 'open',
        posted_by VARCHAR(255) REFERENCES users(id),
        posted_by_name VARCHAR(255),
        applications INTEGER DEFAULT 0,
        connects_spent INTEGER DEFAULT 1,
        apply_cost INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
        job_title VARCHAR(500),
        freelancer_id VARCHAR(255) REFERENCES users(id),
        freelancer_name VARCHAR(255),
        message TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await query(`
      CREATE TABLE IF NOT EXISTS escrows (
        id SERIAL PRIMARY KEY,
        job_id INTEGER REFERENCES jobs(id),
        client_id VARCHAR(255) REFERENCES users(id),
        freelancer_id VARCHAR(255) REFERENCES users(id),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await query(`
      CREATE TABLE IF NOT EXISTS payments (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) REFERENCES users(id),
        type VARCHAR(100),
        amount DECIMAL(10,2),
        status VARCHAR(50) DEFAULT 'pending',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await query(`
      CREATE TABLE IF NOT EXISTS ratings (
        id SERIAL PRIMARY KEY,
        from_user_id VARCHAR(255) REFERENCES users(id),
        to_user_id VARCHAR(255) REFERENCES users(id),
        job_id INTEGER REFERENCES jobs(id),
        rating INTEGER CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await query(`
      CREATE TABLE IF NOT EXISTS chat_rooms (
        id VARCHAR(255) PRIMARY KEY,
        client_id VARCHAR(255) REFERENCES users(id),
        freelancer_id VARCHAR(255) REFERENCES users(id),
        job_id INTEGER REFERENCES jobs(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        room_id VARCHAR(255) REFERENCES chat_rooms(id) ON DELETE CASCADE,
        sender_id VARCHAR(255) REFERENCES users(id),
        sender_name VARCHAR(255),
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        action VARCHAR(255) NOT NULL,
        data JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Insert admin user
    await query(`
      INSERT INTO users (id, username, role, kyc_verified, status) 
      VALUES ('cherry19899', 'cherry19899', 'admin', true, 'active')
      ON CONFLICT (id) DO NOTHING
    `);
    
    console.log('[DB] PostgreSQL initialized');
  } catch (err) {
    console.error('[DB] Init error:', err);
    throw err;
  }
}

module.exports = { query, initDb, pool };

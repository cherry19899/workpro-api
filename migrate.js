const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

require('dotenv').config();

const sqlitePath = process.env.SQLITE_PATH || './workpro.db';
const db = new sqlite3.Database(sqlitePath);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  console.log('Starting migration...');
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Migrate users
    const users = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM users', [], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
    
    for (const user of users) {
      await client.query(
        `INSERT INTO users (id, username, email, role, balance_connects, balance_pi, rating, total_jobs_posted, total_jobs_completed, bio, skills, kyc_verified, availability, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         ON CONFLICT (id) DO NOTHING`,
        [user.id, user.username, user.email, user.role, user.balance_connects, user.balance_pi, user.rating, user.total_jobs_posted, user.total_jobs_completed, user.bio, user.skills, user.kyc_verified === 1, user.availability, user.created_at]
      );
    }
    console.log(`Migrated ${users.length} users`);
    
    // Migrate jobs
    const jobs = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM jobs', [], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
    
    for (const job of jobs) {
      await client.query(
        `INSERT INTO jobs (id, title, description, category, budget, connects_spent, skills, images, deadline, status, posted_by, posted_by_name, applications, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         ON CONFLICT (id) DO NOTHING`,
        [job.id, job.title, job.description, job.category, job.budget, job.connects_spent, job.skills, job.images, job.deadline, job.status, job.posted_by, job.posted_by_name, job.applications, job.created_at]
      );
    }
    console.log(`Migrated ${jobs.length} jobs`);
    
    // Migrate applications
    const applications = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM applications', [], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
    
    for (const app of applications) {
      await client.query(
        `INSERT INTO applications (id, job_id, user_id, username, message, bid_amount, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO NOTHING`,
        [app.id, app.job_id, app.user_id, app.username, app.message, app.bid_amount, app.status, app.created_at]
      );
    }
    console.log(`Migrated ${applications.length} applications`);
    
    // Migrate chat_rooms
    const chatRooms = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM chat_rooms', [], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
    
    for (const room of chatRooms) {
      await client.query(
        `INSERT INTO chat_rooms (id, job_id, user1_id, user2_id, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO NOTHING`,
        [room.id, room.job_id, room.user1_id, room.user2_id, room.created_at]
      );
    }
    console.log(`Migrated ${chatRooms.length} chat rooms`);
    
    // Migrate chat_messages
    const chatMessages = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM chat_messages', [], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
    
    for (const msg of chatMessages) {
      await client.query(
        `INSERT INTO chat_messages (id, room_id, sender_id, sender_name, message, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO NOTHING`,
        [msg.id, msg.room_id, msg.sender_id, msg.sender_name, msg.message, msg.created_at]
      );
    }
    console.log(`Migrated ${chatMessages.length} chat messages`);
    
    // Migrate escrows
    const escrows = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM escrows', [], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
    
    for (const escrow of escrows) {
      await client.query(
        `INSERT INTO escrows (id, job_id, client_id, freelancer_id, amount_pi, amount_usd, status, payment_id, txid, created_at, released_at, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT (id) DO NOTHING`,
        [escrow.id, escrow.job_id, escrow.client_id, escrow.freelancer_id, escrow.amount_pi, escrow.amount_usd, escrow.status, escrow.payment_id, escrow.txid, escrow.created_at, escrow.released_at, escrow.completed_at]
      );
    }
    console.log(`Migrated ${escrows.length} escrows`);
    
    // Migrate payments
    const payments = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM payments', [], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
    
    for (const payment of payments) {
      await client.query(
        `INSERT INTO payments (id, escrow_id, payer_id, payee_id, amount_pi, amount_usd, status, txid, pi_payment_id, created_at, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (id) DO NOTHING`,
        [payment.id, payment.escrow_id, payment.payer_id, payment.payee_id, payment.amount_pi, payment.amount_usd, payment.status, payment.txid, payment.pi_payment_id, payment.created_at, payment.completed_at]
      );
    }
    console.log(`Migrated ${payments.length} payments`);
    
    // Migrate ratings
    const ratings = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM ratings', [], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
    
    for (const rating of ratings) {
      await client.query(
        `INSERT INTO ratings (id, from_user_id, to_user_id, job_id, rating, comment, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING`,
        [rating.id, rating.from_user_id, rating.to_user_id, rating.job_id, rating.rating, rating.comment, rating.created_at]
      );
    }
    console.log(`Migrated ${ratings.length} ratings`);
    
    await client.query('COMMIT');
    console.log('Migration completed successfully!');
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Migration failed:', error);
    throw error;
  } finally {
    client.release();
    db.close();
    await pool.end();
  }
}

migrate().catch(console.error);

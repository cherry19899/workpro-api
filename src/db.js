/**
 * src/db.js — Re-exports from the root db.js so route modules can use a clean import path.
 * The actual pool, query helper, initDb, and getPool live in /db.js (project root).
 */
const { query, initDb, pool, getPool, usePg, db, saveJsonDb } = require('../db');

module.exports = { query, initDb, pool, getPool, usePg, db, saveJsonDb };

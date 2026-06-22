#!/usr/bin/env node
/**
 * scripts/backup.js
 *
 * Dumps the Postgres DB via pg_dump every 6h, keeps the 10 most recent backups,
 * and notifies on failure via the WorkPro notify helper (in-app) or console.
 *
 * Run standalone:  node scripts/backup.js
 * Schedule (PM2):  pm2 start scripts/backup.js --cron "0 */6 * * *" --no-autorestart
 * Render:          Not available (Render free tier doesn't run cron jobs).
 *                  Use a free external cron (cron-job.org) to hit GET /api/admin/backup/trigger
 *                  with the ADMIN_API_KEY — see the companion admin endpoint below.
 *
 * Env vars required:
 *   DATABASE_URL   — Postgres connection string (already set on Render)
 *   BACKUP_DIR     — local directory for .dump files (default: /tmp/backups)
 *   BACKUP_KEEP    — number of backups to keep (default: 10)
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const util = require('util');
const execFileP = util.promisify(execFile);

const DATABASE_URL = process.env.DATABASE_URL;
const BACKUP_DIR   = process.env.BACKUP_DIR || '/tmp/backups';
const KEEP         = parseInt(process.env.BACKUP_KEEP || '10', 10);

async function run() {
  if (!DATABASE_URL) throw new Error('DATABASE_URL env var is not set');

  fs.mkdirSync(BACKUP_DIR, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename  = `workpro-${timestamp}.dump`;
  const filepath  = path.join(BACKUP_DIR, filename);

  console.log(`[backup] Starting dump → ${filepath}`);
  const start = Date.now();

  await execFileP('pg_dump', [
    '--format=custom',
    '--no-password',
    `--file=${filepath}`,
    DATABASE_URL,
  ]);

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  const size    = fs.statSync(filepath).size;
  console.log(`[backup] Done in ${elapsed}s (${(size / 1024).toFixed(0)} KB) → ${filename}`);

  // Prune old backups — keep newest KEEP files
  const dumps = fs.readdirSync(BACKUP_DIR)
    .filter(f => f.startsWith('workpro-') && f.endsWith('.dump'))
    .map(f => ({ f, mtime: fs.statSync(path.join(BACKUP_DIR, f)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);

  for (const old of dumps.slice(KEEP)) {
    fs.unlinkSync(path.join(BACKUP_DIR, old.f));
    console.log(`[backup] Pruned old backup: ${old.f}`);
  }

  return { filename, size, elapsed };
}

// Allow running directly or requiring as a module
if (require.main === module) {
  run().catch(err => {
    console.error('[backup] FAILED:', err.message);
    process.exit(1);
  });
}

module.exports = { run };

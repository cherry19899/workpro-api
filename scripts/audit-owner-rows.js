#!/usr/bin/env node
/**
 * scripts/audit-owner-rows.js — find and repair accounts that took the owner's
 * name, and the admin roles that were handed out because of it.
 *
 * Background. Admin used to be granted by matching the username 'cherry19899',
 * in several places, and `users.username` has no UNIQUE index. The login routes
 * would also copy a request-body username into the stored row whenever Pi
 * returned a uid without a username. So anyone could take the owner's name and
 * be promoted — by the login self-heal, by adminAuth, by GET /api/admin/verify,
 * and by a blanket promote that ran on every server boot.
 *
 * All of those paths are keyed on uid now. What the code fix cannot do is take
 * back a role that was already written: a poisoned row that already reads
 * role='admin' still passes the *fixed* checks, because they look the role up by
 * id and the role is genuinely there. That is what this script is for.
 *
 * Usage (DATABASE_URL must point at the database you mean to inspect):
 *
 *   node scripts/audit-owner-rows.js            # report only, changes nothing
 *   node scripts/audit-owner-rows.js --apply    # demote + rename the impostors
 *   node scripts/audit-owner-rows.js --apply --add-unique-index
 *
 * Reporting is the default on purpose: read the output before you let it write.
 * The owner's own uids are never touched in any mode.
 */
const { Pool } = require('pg');

// The real owner. Everything else claiming this name is an impostor.
const OWNER_UIDS = ['pi_cherry19899', 'pi_a2b617f7-f510-4502-a046-805facedcc29'];
const OWNER_USERNAME = 'cherry19899';

const APPLY = process.argv.includes('--apply');
const ADD_INDEX = process.argv.includes('--add-unique-index');

function line() { console.log('─'.repeat(72)); }
function rows(rs, cols) {
  if (!rs.length) { console.log('   (none)'); return; }
  for (const r of rs) console.log('   ' + cols.map(c => `${c}=${JSON.stringify(r[c])}`).join('  '));
}

(async () => {
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is not set — point it at the database you want to inspect.');
    process.exit(2);
  }
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false },
    max: 2,
    connectionTimeoutMillis: 15000,
  });

  try {
    console.log(APPLY ? '\nMODE: APPLY — changes will be written\n' : '\nMODE: report only — nothing will be written\n');

    // 1. Who holds the owner's name?
    line();
    console.log('1. Accounts using the owner username, any case');
    const named = await pool.query(
      `SELECT id, username, role, is_blocked, status, balance_pi, balance_connects, created_at
         FROM users WHERE LOWER(username) = $1 ORDER BY created_at`,
      [OWNER_USERNAME]
    );
    rows(named.rows, ['id', 'username', 'role', 'is_blocked', 'created_at']);
    const impostors = named.rows.filter(r => !OWNER_UIDS.includes(r.id));
    console.log(`\n   owner rows: ${named.rows.length - impostors.length}   IMPOSTORS: ${impostors.length}`);

    // 2. Every admin. Anything here you did not grant yourself is suspect.
    line();
    console.log('2. All accounts holding role=admin');
    const admins = await pool.query(
      `SELECT id, username, role, created_at FROM users WHERE role = 'admin' ORDER BY created_at`
    );
    rows(admins.rows, ['id', 'username', 'created_at']);
    const oddAdmins = admins.rows.filter(r => !OWNER_UIDS.includes(r.id));
    console.log(`\n   non-owner admins: ${oddAdmins.length}  ← confirm each of these is deliberate`);

    // 3. Duplicate names generally — the UNIQUE index will refuse to build
    //    while any of these exist, so they have to be resolved first.
    line();
    console.log('3. Any duplicated username (blocks the UNIQUE index)');
    const dupes = await pool.query(
      `SELECT LOWER(username) AS name, COUNT(*) AS n, ARRAY_AGG(id) AS ids
         FROM users WHERE username IS NOT NULL AND username <> ''
        GROUP BY LOWER(username) HAVING COUNT(*) > 1 ORDER BY COUNT(*) DESC`
    );
    rows(dupes.rows, ['name', 'n', 'ids']);

    // ── Repair ────────────────────────────────────────────────────────────
    line();
    if (!impostors.length) {
      console.log('Nothing to repair: no account other than the owner holds that name.');
    } else if (!APPLY) {
      console.log('Would repair (re-run with --apply):');
      for (const r of impostors) {
        console.log(`   ${r.id}: role ${r.role} → freelancer, username '${r.username}' → 'user_${r.id}'`);
        if (parseFloat(r.balance_pi || 0) > 0 || parseInt(r.balance_connects || 0) > 0) {
          console.log(`      NOTE: holds balance_pi=${r.balance_pi} balance_connects=${r.balance_connects} — balances are left untouched`);
        }
      }
    } else {
      // Demote and rename in one transaction. Balances are deliberately left
      // alone: this script fixes identity and authority, it does not adjudicate
      // whether someone is owed money.
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        for (const r of impostors) {
          await client.query(
            `UPDATE users SET role = 'freelancer', username = $2, updated_at = NOW() WHERE id = $1`,
            [r.id, `user_${r.id}`]
          );
          console.log(`   repaired ${r.id} (was role=${r.role}, username=${r.username})`);
        }
        await client.query('COMMIT');
        console.log(`\n   ${impostors.length} row(s) demoted and renamed.`);
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally { client.release(); }
    }

    // ── The missing index ─────────────────────────────────────────────────
    if (ADD_INDEX) {
      line();
      if (!APPLY) {
        console.log('--add-unique-index needs --apply too. Not creating anything.');
      } else {
        console.log('Creating UNIQUE INDEX on LOWER(username)…');
        const IDX = 'idx_users_username_unique';
        const validity = () => pool.query(
          `SELECT idx.indisvalid FROM pg_index idx
             JOIN pg_class i ON i.oid = idx.indexrelid WHERE i.relname = $1`, [IDX]);
        try {
          // A failed CREATE INDEX CONCURRENTLY leaves an INVALID index behind,
          // and a later IF NOT EXISTS then matches that corpse and does nothing
          // — reporting success while no uniqueness is enforced at all. Clear
          // any such leftover before trying again.
          const before = await validity();
          if (before.rows.length && !before.rows[0].indisvalid) {
            console.log('   found an INVALID index from an earlier failed attempt — dropping it first');
            await pool.query(`DROP INDEX CONCURRENTLY IF EXISTS ${IDX}`);
          }
          // CONCURRENTLY cannot run inside a transaction, hence the plain query.
          await pool.query(`CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ${IDX} ON users (LOWER(username))`);
          // Never trust the absence of an exception here — confirm it is live.
          const after = await validity();
          if (after.rows.length && after.rows[0].indisvalid) {
            console.log('   created and verified valid. Taking the owner\'s name is now impossible at the database level.');
          } else {
            console.error('   FAILED: the index exists but is NOT valid, so nothing is enforced.');
            console.error('   Resolve the duplicates in section 3 and run this again.');
            process.exitCode = 1;
          }
        } catch (e) {
          console.error(`   FAILED: ${e.message}`);
          console.error('   Almost certainly duplicates remain — see section 3 above, resolve them, then retry.');
          await pool.query(`DROP INDEX CONCURRENTLY IF EXISTS ${IDX}`).catch(() => {});
          process.exitCode = 1;
        }
      }
    } else {
      line();
      console.log('Once section 3 is empty, add the index that was missing all along:');
      console.log('   node scripts/audit-owner-rows.js --apply --add-unique-index');
    }
    line();
  } catch (err) {
    console.error('\nFailed:', err.message);
    process.exitCode = 1;
  } finally {
    await pool.end().catch(() => {});
  }
})();

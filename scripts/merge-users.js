#!/usr/bin/env node
/**
 * Merge duplicate accounts belonging to one person into a single id.
 *
 *   node scripts/merge-users.js --into <target> --from <a,b,c>            # rehearsal
 *   node scripts/merge-users.js --into <target> --from <a,b,c> --apply    # for real
 *
 * Without --apply the whole thing runs inside a transaction that is rolled
 * back at the end. That is deliberately not a simulation: every statement
 * executes against the real rows and reports what it actually did, so the
 * rehearsal cannot disagree with the run. The only difference between the two
 * modes is COMMIT versus ROLLBACK.
 *
 * Why this exists: Pi hands out a different uid per app registration, and
 * sandbox and mainnet count as different registrations. One person ends up
 * with several accounts, and their money, jobs, escrows and reputation are
 * split across them — a client sees one review instead of four.
 *
 * The target must be the id the person currently signs in as. Merging into
 * any other id means the next sign-in recreates the split.
 */
const { Pool } = require('pg');

const argv = process.argv.slice(2);
const arg = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const APPLY = argv.includes('--apply');
const TARGET = arg('--into');
const SOURCES = (arg('--from') || '').split(',').map(s => s.trim()).filter(Boolean);

if (!TARGET || !SOURCES.length) {
  console.error('usage: merge-users.js --into <id> --from <id,id,...> [--apply]');
  process.exit(2);
}
if (SOURCES.includes(TARGET)) {
  console.error('target cannot also be a source');
  process.exit(2);
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const log = (...a) => console.log(...a);

// Columns holding a user id, discovered rather than listed. A hand-written
// list silently misses whichever table was added last, and a missed column
// leaves rows pointing at an account that no longer exists.
const DISCOVER = `
  SELECT table_name AS t, column_name AS c
    FROM information_schema.columns
   WHERE table_schema = 'public'
     AND data_type LIKE '%char%'
     AND table_name <> 'users'
     AND (column_name LIKE '%user_id' OR column_name IN
          ('posted_by','hired_freelancer_id','freelancer_id','client_id',
           'sender_id','uploader_id','reviewer_id','reviewee_id','updated_by'))
   ORDER BY 1, 2`;

async function main() {
  const client = await pool.connect();
  const ALL = [TARGET, ...SOURCES];
  try {
    await client.query('BEGIN');

    // ── The record, before anything moves ──────────────────────────────────
    const before = await client.query(
      `SELECT id, username, status, role, balance_pi, balance_connects, rating, total_reviews, created_at
         FROM users WHERE id = ANY($1) ORDER BY created_at`, [ALL]);
    if (before.rows.length !== ALL.length) {
      throw new Error(`expected ${ALL.length} accounts, found ${before.rows.length} — check the ids`);
    }
    log('\n=== ДО ===');
    console.table(before.rows);
    log('ПОЛНЫЙ ДАМП (для отката):');
    log(JSON.stringify(before.rows));

    const cols = (await client.query(DISCOVER)).rows;

    // ── 1. Feedback that would become self-feedback ────────────────────────
    // cherry19899 rated Cherry19899. Once both are the same person that is a
    // review of oneself, inflating the rating with their own stars.
    const selfR = await client.query(
      `DELETE FROM ratings WHERE from_user_id = ANY($1) AND to_user_id = ANY($1) RETURNING id`, [ALL]);
    const selfV = await client.query(
      `DELETE FROM reviews WHERE reviewer_id = ANY($1) AND reviewee_id = ANY($1) RETURNING id`, [ALL]);
    log(`\n[1] самооценки удалены: ratings ${selfR.rowCount}, reviews ${selfV.rowCount}`);

    // ── 2. Duplicate chat rooms, merged rather than dropped ───────────────
    // chat_rooms is unique on (client_id, freelancer_id[, job_id]). Two rooms
    // that become the same pair after the remap must collapse into one — but
    // deleting the loser would orphan its messages, so the conversation is
    // moved across first and only the empty shell is removed. Losing a client's
    // chat history to a bookkeeping merge would be worse than the split it
    // fixes.
    const roomGroups = await client.query(`
      SELECT id, ROW_NUMBER() OVER (
               PARTITION BY (CASE WHEN client_id = ANY($1) THEN $2 ELSE client_id END),
                            (CASE WHEN freelancer_id = ANY($1) THEN $2 ELSE freelancer_id END),
                            job_id
               ORDER BY created_at, id) AS rn,
             FIRST_VALUE(id) OVER (
               PARTITION BY (CASE WHEN client_id = ANY($1) THEN $2 ELSE client_id END),
                            (CASE WHEN freelancer_id = ANY($1) THEN $2 ELSE freelancer_id END),
                            job_id
               ORDER BY created_at, id) AS keeper
        FROM chat_rooms
       WHERE client_id = ANY($1) OR freelancer_id = ANY($1)`, [ALL, TARGET]);
    const losers = roomGroups.rows.filter(r => r.rn > 1);
    let movedMsgs = 0;
    for (const l of losers) {
      const m = await client.query('UPDATE chat_messages SET room_id = $1 WHERE room_id = $2', [l.keeper, l.id]);
      movedMsgs += m.rowCount;
      await client.query('UPDATE chat_attachments SET room_id = $1 WHERE room_id = $2', [l.keeper, l.id]).catch(() => {});
      // Read markers are keyed on (room_id, user_id); the surviving room may
      // already have one, so drop the loser's rather than collide. At worst a
      // few messages show as unread again.
      await client.query('DELETE FROM chat_room_reads WHERE room_id = $1', [l.id]);
      await client.query('DELETE FROM chat_rooms WHERE id = $1', [l.id]);
    }
    log(`[2] дублей чат-комнат объединено: ${losers.length}, перенесено сообщений: ${movedMsgs}`);

    // ── 2b. The portfolio header worth keeping ────────────────────────────
    // Run before the generic pass below, which would otherwise keep whichever
    // row is oldest. Here the fullest one wins: an empty header written later
    // must not erase a filled-in one.
    const port = await client.query(`
      DELETE FROM portfolios p USING (
        SELECT user_id, ROW_NUMBER() OVER (
                 ORDER BY (COALESCE(LENGTH(headline),0) + COALESCE(LENGTH(summary),0)) DESC,
                          user_id) AS rn
          FROM portfolios WHERE user_id = ANY($1)
      ) x WHERE p.user_id = x.user_id AND x.rn > 1`, [ALL]);
    log(`[2b] лишних заголовков портфолио удалено: ${port.rowCount}`);

    // ── 3. Every other unique index, discovered rather than guessed ────────
    // The first rehearsal died on applications(job_id, freelancer_id) — a
    // constraint that was simply not on my list. Rather than fix that one and
    // wait to trip over the next, the indexes are read from the catalog and
    // each is pre-deduplicated against the ids it will hold after the remap.
    // ctid is the tiebreaker because not every one of these tables has an id.
    const uniq = await client.query(`
      SELECT t.relname AS tbl,
             -- ::text so the driver hands back a real array. attname has the
             -- pg type "name", and node-pg has no parser for name[] — it
             -- arrives as the raw string "{job_id,freelancer_id}" and the
             -- .filter below blows up on it.
             array_agg(a.attname::text ORDER BY k.ord) AS cols,
             pg_get_expr(x.indpred, x.indrelid) AS pred
        FROM pg_index x
        JOIN pg_class t ON t.oid = x.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN LATERAL unnest(x.indkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
        JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = k.attnum
       WHERE n.nspname = 'public' AND x.indisunique AND t.relname NOT IN ('users','chat_rooms')
       GROUP BY t.relname, x.indexrelid, x.indpred, x.indrelid`);

    const userCols = new Set(cols.map(c => c.c));
    let deduped = 0;
    for (const ix of uniq.rows) {
      const involved = ix.cols.filter(c => userCols.has(c));
      if (!involved.length) continue;           // not affected by the remap
      const keyExpr = ix.cols.map(c => userCols.has(c)
        ? `(CASE WHEN ${c} = ANY($1) THEN $2 ELSE ${c} END)` : c).join(', ');
      const scope = involved.map(c => `${c} = ANY($1)`).join(' OR ');
      const where = ix.pred ? `(${scope}) AND (${ix.pred})` : `(${scope})`;
      const hasCreated = await client.query(
        `SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name='created_at'`,
        [ix.tbl]);
      const order = hasCreated.rows.length ? 'created_at, ctid' : 'ctid';
      const r = await client.query(`
        DELETE FROM ${ix.tbl} d USING (
          SELECT ctid AS c, ROW_NUMBER() OVER (PARTITION BY ${keyExpr} ORDER BY ${order}) AS rn
            FROM ${ix.tbl} WHERE ${where}
        ) x WHERE d.ctid = x.c AND x.rn > 1`, [ALL, TARGET]);
      if (r.rowCount) { deduped += r.rowCount; log(`[3] ${ix.tbl} (${ix.cols.join(',')}): снято ${r.rowCount}`); }
    }
    log(`[3] всего дублей снято: ${deduped}`);

    // ── 4. Every remaining reference points at the target ─────────────────
    let moved = 0;
    for (const { t, c } of cols) {
      const r = await client.query(
        `UPDATE ${t} SET ${c} = $1 WHERE ${c} = ANY($2)`, [TARGET, SOURCES]).catch(e => {
          throw new Error(`${t}.${c}: ${e.message}`);
        });
      if (r.rowCount) { moved += r.rowCount; log(`[4] ${t}.${c}: ${r.rowCount}`); }
    }
    log(`[4] всего строк перенесено: ${moved}`);

    // ── 5. Chats with oneself, created by the merge ───────────────────────
    const selfChat = await client.query(
      `SELECT COUNT(*) n FROM chat_rooms WHERE client_id = $1 AND freelancer_id = $1`, [TARGET]);
    log(`[5] комнат «сам с собой» после слияния: ${selfChat.rows[0].n} (оставлены, данных не теряют)`);

    // ── 6. Money and connects add up ──────────────────────────────────────
    const sums = await client.query(
      `SELECT COALESCE(SUM(balance_pi),0) pi, COALESCE(SUM(balance_connects),0) cn
         FROM users WHERE id = ANY($1)`, [ALL]);
    await client.query(
      `UPDATE users SET balance_pi = $2, balance_connects = $3, updated_at = NOW() WHERE id = $1`,
      [TARGET, sums.rows[0].pi, sums.rows[0].cn]);
    // Zeroed as well as retired: a balance left on a retired row is money the
    // books still count but nobody can ever reach.
    await client.query(
      `UPDATE users SET status = 'deleted', balance_pi = 0, balance_connects = 0, updated_at = NOW()
        WHERE id = ANY($1)`, [SOURCES]);
    log(`[6] на целевой аккаунт: ${sums.rows[0].pi}π, ${sums.rows[0].cn} коннектов`);

    // ── 7. Nothing may still point at a retired account ───────────────────
    let leftovers = 0;
    for (const { t, c } of cols) {
      const r = await client.query(`SELECT COUNT(*) n FROM ${t} WHERE ${c} = ANY($1)`, [SOURCES]);
      if (+r.rows[0].n) { leftovers += +r.rows[0].n; log(`  ОСТАЛОСЬ ${t}.${c}: ${r.rows[0].n}`); }
    }
    if (leftovers) throw new Error(`${leftovers} строк всё ещё ссылаются на старые аккаунты`);
    log('[7] висячих ссылок нет');

    const after = await client.query(
      `SELECT id, username, status, balance_pi, balance_connects FROM users WHERE id = ANY($1) ORDER BY created_at`, [ALL]);
    log('\n=== ПОСЛЕ ===');
    console.table(after.rows);

    if (APPLY) {
      await client.query('COMMIT');
      log('\n>>> ЗАПИСАНО. Рейтинг и счётчик отзывов пересчитает почасовой обход.');
    } else {
      await client.query('ROLLBACK');
      log('\n>>> ОТКАЧЕНО — это была репетиция. Для записи добавь --apply');
    }
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('\n!!! ОТКАТ, ничего не изменено:', e.message);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

main();

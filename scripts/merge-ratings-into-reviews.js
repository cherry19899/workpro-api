#!/usr/bin/env node
/**
 * Fold the legacy `ratings` table into `reviews`.
 *
 *   node scripts/merge-ratings-into-reviews.js            # rehearsal
 *   node scripts/merge-ratings-into-reviews.js --apply    # for real
 *
 * Without --apply everything runs inside a transaction that is rolled back at
 * the end — the same statements against the same rows, differing only in
 * COMMIT versus ROLLBACK, so a rehearsal cannot disagree with the run.
 *
 * Why: feedback lived in two tables. Every consumer had to read a UNION of
 * both, and legacy rows had to be handed out with negated ids so the two id
 * spaces could not collide in a list the client keys on. That trick works but
 * is a trap: the moment anything wants to act on a review by id — reply to it,
 * report it, hide it — a negative id has nowhere to go.
 *
 * Since eb96f75 all three rating routes write to `reviews`, so `ratings` no
 * longer grows. Moving the history across is what finally makes it one table.
 *
 * Rows in `ratings` that a `reviews` row already mirrors are skipped: those
 * are the same opinion recorded twice, not two opinions.
 */
const { Pool } = require('pg');

const APPLY = process.argv.includes('--apply');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const log = (...a) => console.log(...a);

// The rows worth moving: a legacy rating with no matching review, and with
// both sides still present as accounts. A rating pointing at a user that no
// longer exists is not feedback anyone can act on.
const MOVABLE = `
  SELECT g.id, g.job_id, g.from_user_id, g.to_user_id, g.rating,
         NULLIF(g.comment, '') AS text, g.created_at
    FROM ratings g
   WHERE g.from_user_id IS NOT NULL AND g.to_user_id IS NOT NULL
     AND g.from_user_id <> g.to_user_id
     AND NOT EXISTS (
       SELECT 1 FROM reviews r
        WHERE r.reviewee_id = g.to_user_id
          AND r.reviewer_id = g.from_user_id
          AND r.job_id IS NOT DISTINCT FROM g.job_id)`;

async function main() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const before = await client.query(
      'SELECT (SELECT COUNT(*) FROM reviews) rev, (SELECT COUNT(*) FROM ratings) rat');
    log(`\n=== ДО ===  reviews ${before.rows[0].rev}, ratings ${before.rows[0].rat}`);

    // Snapshot what every profile shows right now, before anything moves. The
    // whole migration is only correct if these numbers are identical
    // afterwards — reputation must survive being moved between tables.
    await client.query(`
      CREATE TEMP TABLE before_counts ON COMMIT DROP AS
        SELECT uid, COUNT(*) AS n FROM (
          SELECT r.reviewee_id AS uid FROM reviews r WHERE r.hidden = FALSE AND r.reviewee_id IS NOT NULL
          UNION ALL
          SELECT g.to_user_id FROM ratings g
           WHERE g.to_user_id IS NOT NULL AND NOT EXISTS (
             SELECT 1 FROM reviews r2 WHERE r2.reviewee_id = g.to_user_id
               AND r2.reviewer_id = g.from_user_id AND r2.job_id IS NOT DISTINCT FROM g.job_id)
        ) t GROUP BY uid`);

    const movable = await client.query(`SELECT COUNT(*) n FROM (${MOVABLE}) m`);
    log(`[1] переносим: ${movable.rows[0].n}`);
    const skipped = await client.query(`
      SELECT COUNT(*) n FROM ratings g WHERE NOT (
        g.from_user_id IS NOT NULL AND g.to_user_id IS NOT NULL
        AND g.from_user_id <> g.to_user_id
        AND NOT EXISTS (SELECT 1 FROM reviews r
             WHERE r.reviewee_id=g.to_user_id AND r.reviewer_id=g.from_user_id
               AND r.job_id IS NOT DISTINCT FROM g.job_id))`);
    log(`[1] пропускаем (уже есть в reviews, самооценка или без адресата): ${skipped.rows[0].n}`);

    // created_at is carried over, not defaulted: the weighting counts recent
    // feedback more heavily, so stamping today's date on a year-old rating
    // would quietly inflate the reputations this migration is meant to
    // preserve.
    const moved = await client.query(`
      INSERT INTO reviews (job_id, reviewer_id, reviewee_id, rating, text, created_at)
      SELECT job_id, from_user_id, to_user_id, rating, text, created_at FROM (${MOVABLE}) m
      RETURNING id`);
    log(`[2] перенесено строк: ${moved.rowCount}`);

    const after = await client.query(
      'SELECT (SELECT COUNT(*) FROM reviews) rev, (SELECT COUNT(*) FROM ratings) rat');
    log(`[3] стало: reviews ${after.rows[0].rev}, ratings ${after.rows[0].rat} (старая таблица не трогается)`);

    // The point of the whole exercise: what every screen shows must not change.
    // Compared per person against the snapshot taken before the move — a single
    // row of disagreement means someone's reputation shifted, and the migration
    // is wrong regardless of how tidy the table now looks.
    const drift = await client.query(`
      SELECT COALESCE(b.uid, a.uid) AS uid, COALESCE(b.n, 0) AS was, COALESCE(a.n, 0) AS now_
        FROM before_counts b
        FULL JOIN (
          SELECT reviewee_id AS uid, COUNT(*) AS n FROM reviews
           WHERE hidden = FALSE AND reviewee_id IS NOT NULL GROUP BY reviewee_id
        ) a ON a.uid = b.uid
       WHERE COALESCE(b.n, 0) <> COALESCE(a.n, 0)`);
    if (drift.rowCount) {
      console.table(drift.rows);
      throw new Error(`у ${drift.rowCount} человек изменилось число отзывов — перенос неверен`);
    }
    log('[4] число отзывов у каждого совпало до и после');

    if (APPLY) {
      await client.query('COMMIT');
      log('\n>>> ЗАПИСАНО. Старая таблица оставлена как есть — на случай отката.');
    } else {
      await client.query('ROLLBACK');
      log('\n>>> ОТКАЧЕНО — репетиция. Для записи добавь --apply');
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

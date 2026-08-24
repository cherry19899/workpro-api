// Keeps users.rating / users.total_reviews honest.
//
// Three routes write a rating (/api/ratings, /api/reviews, /api/reviews/v2) and
// for a long time they disagreed: two wrote a plain average and never touched
// total_reviews, while the third wrote a time-weighted one through
// computeBadges. The column therefore meant whatever the last writer intended,
// and production ended up with people showing a 5.0 next to a review count of
// 0. The routes now share one formula, but rows written before that stay wrong
// until something recomputes them — and a stored count can also drift if a
// rating row is ever removed by hand.
//
// So rather than a one-off backfill, this runs on the hourly sweep and only
// touches rows that actually disagree with the ratings on record. Once
// everything agrees it updates nothing and costs one grouped read.
const { query } = require('./db');
const { FEEDBACK_ALL, WEIGHT_SQL } = require('./feedback');

// The truth, from the same union every other consumer reads (src/feedback.js).
// This used to group over `ratings` alone, so it reconciled users.rating
// against a different set than the profile actually lists.
const TRUTH = `
  SELECT uid,
         COUNT(*) AS n,
         ROUND(SUM(rating * ${WEIGHT_SQL}) / SUM(${WEIGHT_SQL}), 2) AS w
    FROM (${FEEDBACK_ALL}) f
   GROUP BY uid`;

async function resyncRatings(logger) {
  try {
    // IS DISTINCT FROM, not <>, so a NULL on either side still counts as a
    // disagreement — a user who has ratings but a NULL rating column is
    // exactly the case worth fixing, and <> would skip it silently.
    const fixed = await query(`
      UPDATE users u
         SET rating = s.w, total_reviews = s.n, updated_at = NOW()
        FROM (${TRUTH}) s
       WHERE u.id = s.uid
         AND (u.total_reviews IS DISTINCT FROM s.n OR u.rating IS DISTINCT FROM s.w)
      RETURNING u.id`);

    // The mirror case: a stored rating with nothing on record behind it. Left
    // alone, it advertises a score to clients choosing whom to hire that no
    // one ever gave.
    const cleared = await query(`
      UPDATE users
         SET rating = NULL, total_reviews = 0, updated_at = NOW()
       WHERE (COALESCE(rating, 0) > 0 OR COALESCE(total_reviews, 0) > 0)
         AND NOT EXISTS (SELECT 1 FROM (${FEEDBACK_ALL}) f WHERE f.uid = users.id)
      RETURNING id`);

    return { resynced: fixed.rowCount || 0, cleared: cleared.rowCount || 0 };
  } catch (err) {
    // logger.info is a no-op under NODE_ENV=production on Render, so anything
    // worth seeing has to go out as an error.
    if (logger) logger.error('[rating-resync] failed:', err.message);
    return { resynced: 0, cleared: 0, error: err.message };
  }
}

module.exports = { resyncRatings };

// One definition of "the feedback a user has received".
//
// It used to be a UNION of two tables. `reviews` held what the app writes,
// while the older `ratings` held everything the earlier rating routes had left
// behind — so every consumer had to read both, and legacy rows were handed out
// with negated ids to keep the two id spaces from colliding in a list the
// client keys on. That worked, but a negative id is a dead end: nothing can
// ever reply to such a review, report it, or hide it.
//
// Both halves of that are now gone. Since eb96f75 all three rating routes
// write to `reviews`, and scripts/merge-ratings-into-reviews.js moved the
// history across (3 rows; the other 19 were already mirrored). `ratings` is
// kept only so the migration can be undone, and is no longer read anywhere.
//
// What has to stay true: rating, review count and the visible list all derive
// from here, so a review counts because it exists — not because some second
// write happened to succeed.
const FEEDBACK_FOR_USER = `
  SELECT r.id, r.job_id, r.reviewer_id, r.rating, r.text, r.reply, r.created_at
    FROM reviews r
   WHERE r.reviewee_id = $1 AND r.hidden = FALSE`;

// The same set for every user at once, for the reconciling sweep.
const FEEDBACK_ALL = `
  SELECT r.reviewee_id AS uid, r.rating, r.created_at
    FROM reviews r
   WHERE r.hidden = FALSE AND r.reviewee_id IS NOT NULL`;

// Recency weighting, shared so the sweep and the per-review recompute cannot
// drift into two different definitions of the same number.
const WEIGHT_SQL = `CASE WHEN created_at > NOW() - INTERVAL '6 months' THEN 1.5 ELSE 1.0 END`;
const WEIGHT_MONTHS_MS = 6 * 30 * 24 * 60 * 60 * 1000;

function weightFor(createdAt, now = Date.now()) {
  return new Date(createdAt).getTime() > now - WEIGHT_MONTHS_MS ? 1.5 : 1.0;
}

module.exports = { FEEDBACK_FOR_USER, FEEDBACK_ALL, WEIGHT_SQL, weightFor };

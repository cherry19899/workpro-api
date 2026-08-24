// One definition of "the feedback a user has received".
//
// Feedback lives in two tables: `reviews`, written by /api/reviews/v2 (the
// route the app calls), and the older `ratings`, which the other two rating
// routes write and which v2 also mirrors into. Every consumer used to pick a
// table and hope:
//
//   * computeBadges read `ratings`, so the rating depended on a mirror insert
//     that was fire-and-forget with a swallowed error — if it failed, the
//     review existed but did not count, silently and forever;
//   * the list endpoint read `reviews`, so anything left through the older
//     routes was invisible;
//   * the resync sweep read `ratings` again, so the number and the list it
//     described could disagree by construction.
//
// Deriving all three from this module means a review counts because it exists,
// not because a second write happened to succeed.
//
// A `ratings` row is skipped when a `reviews` row already covers the same
// (reviewer, reviewee, job) — that is the mirror, not a second opinion.
const NOT_MIRRORED = `
  NOT EXISTS (
    SELECT 1 FROM reviews r2
     WHERE r2.reviewee_id = g.to_user_id
       AND r2.reviewer_id = g.from_user_id
       AND r2.job_id IS NOT DISTINCT FROM g.job_id
  )`;

// Feedback for one user ($1). Legacy ids come back negated so the two id
// spaces cannot collide in a list the client will key on.
const FEEDBACK_FOR_USER = `
  SELECT r.id, r.job_id, r.reviewer_id, r.rating, r.text, r.reply, r.created_at
    FROM reviews r
   WHERE r.reviewee_id = $1 AND r.hidden = FALSE
  UNION ALL
  SELECT -g.id, g.job_id, g.from_user_id, g.rating, NULLIF(g.comment, ''), NULL, g.created_at
    FROM ratings g
   WHERE g.to_user_id = $1 AND ${NOT_MIRRORED}`;

// The same set for every user at once, for the reconciling sweep.
const FEEDBACK_ALL = `
  SELECT r.reviewee_id AS uid, r.rating, r.created_at
    FROM reviews r
   WHERE r.hidden = FALSE AND r.reviewee_id IS NOT NULL
  UNION ALL
  SELECT g.to_user_id, g.rating, g.created_at
    FROM ratings g
   WHERE g.to_user_id IS NOT NULL AND ${NOT_MIRRORED}`;

// Recency weighting, shared so the sweep and the per-review recompute cannot
// drift into two different definitions of the same number.
const WEIGHT_SQL = `CASE WHEN created_at > NOW() - INTERVAL '6 months' THEN 1.5 ELSE 1.0 END`;
const WEIGHT_MONTHS_MS = 6 * 30 * 24 * 60 * 60 * 1000;

function weightFor(createdAt, now = Date.now()) {
  return new Date(createdAt).getTime() > now - WEIGHT_MONTHS_MS ? 1.5 : 1.0;
}

module.exports = { FEEDBACK_FOR_USER, FEEDBACK_ALL, NOT_MIRRORED, WEIGHT_SQL, weightFor };

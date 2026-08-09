/**
 * Who may rate whom.
 *
 * Ratings are the whole reputation system: users.rating is rewritten from the
 * average after every insert, and it is what a client looks at before hiring.
 * So the question "is this caller allowed to rate this person for this job?"
 * has to be answered before the row is written, and answered the same way by
 * all three rating routes.
 *
 * The bug this covers: POST /api/ratings and POST /api/reviews wrapped the
 * whole participation check in `if (jobCheck.rows.length)`, so a job_id that
 * matched no job skipped every check and fell through to the INSERT. Any
 * logged-in account could rate any stranger — repeatedly, because the
 * duplicate guard keys on job_id and invented job_ids are unlimited — and each
 * insert overwrote the victim's public rating with the new average.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { ratingTarget, parseJobId } = require('../src/helpers');

const completedJob = { posted_by: 'pi_client', hired_freelancer_id: 'pi_freelancer', status: 'completed' };

test('a job_id that matches nothing is refused, not waved through', () => {
  // This is the whole vulnerability: null used to mean "no checks to run".
  const v = ratingTarget(null, 'pi_stranger', 'pi_victim');
  assert.equal(v.code, 404);
  assert.equal(v.targetId, undefined, 'nothing may be written');
});

test('undefined is refused too — a missing row must never read as permission', () => {
  assert.equal(ratingTarget(undefined, 'pi_stranger', 'pi_victim').code, 404);
});

test('the two sides of a completed job may rate each other', () => {
  assert.deepEqual(ratingTarget(completedJob, 'pi_client', 'pi_freelancer'), { targetId: 'pi_freelancer' });
  assert.deepEqual(ratingTarget(completedJob, 'pi_freelancer', 'pi_client'), { targetId: 'pi_client' });
});

test('a bystander cannot rate either side', () => {
  const v = ratingTarget(completedJob, 'pi_stranger', 'pi_freelancer');
  assert.equal(v.code, 403);
  assert.match(v.error, /not a participant/);
});

test('nobody is rated before the job is finished', () => {
  for (const status of ['open', 'in_progress', 'cancelled', 'disputed', null]) {
    const v = ratingTarget({ ...completedJob, status }, 'pi_client', 'pi_freelancer');
    assert.equal(v.code, 400, `status '${status}' must not allow a rating`);
  }
});

test('a participant cannot redirect the rating at a third party', () => {
  // Being on the job is permission to rate the other side of *that* job, not
  // permission to write a row naming whoever the body asks for.
  const v = ratingTarget(completedJob, 'pi_client', 'pi_someone_else');
  assert.equal(v.code, 403);
  assert.match(v.error, /other participant/);
});

test('id spelling does not decide who is a participant', () => {
  // normalizeId is used on both sides everywhere else; the target comparison
  // used to be a strict ===, so the real freelancer got a 403 on their own job.
  assert.deepEqual(ratingTarget(completedJob, 'CLIENT', 'freelancer'), { targetId: 'pi_freelancer' });
  assert.deepEqual(ratingTarget(completedJob, 'pi_Client', 'PI_FREELANCER'), { targetId: 'pi_freelancer' });
});

test('the id handed back is the job row s spelling, never the caller s', () => {
  // Otherwise 'FREELANCER' and 'pi_freelancer' accumulate separate averages
  // and separate duplicate guards for one person.
  const v = ratingTarget(completedJob, 'pi_client', 'FreeLancer');
  assert.equal(v.targetId, 'pi_freelancer');
});

test('a completed job with nobody hired has no one to rate', () => {
  const v = ratingTarget({ posted_by: 'pi_client', hired_freelancer_id: null, status: 'completed' }, 'pi_client', 'pi_anyone');
  assert.equal(v.code, 403, 'an empty other side must not match an empty-ish target');
});

test('an unhired job does not let the poster rate a null target', () => {
  // normalizeId(null) is '', and '' === '' would have matched had the empty
  // target not been rejected outright.
  const v = ratingTarget({ posted_by: 'pi_client', hired_freelancer_id: null, status: 'completed' }, 'pi_client', '');
  assert.equal(v.code, 403);
});

// ─── job_id parsing ──────────────────────────────────────────────────────────

test('a real job id survives as a number', () => {
  assert.equal(parseJobId(42), 42);
  assert.equal(parseJobId('42'), 42, 'JSON bodies send it as a string often enough');
  assert.equal(parseJobId(' 42 '), 42);
});

test('naming no job at all is allowed — that is the general-review path', () => {
  assert.equal(parseJobId(undefined), null);
  assert.equal(parseJobId(null), null);
  assert.equal(parseJobId(''), null);
  // The rating modal sends `job_id: e.job_id || 0` for an escrow with no job,
  // and the old `if (job_id)` read that 0 as "no job". Rejecting it would have
  // broken review submission for every already-deployed bundle.
  assert.equal(parseJobId(0), null);
  assert.equal(parseJobId('0'), null);
});

test('a value that is present but is not a job id is rejected', () => {
  // parseInt('5abc') is 5, so the old isNaN(parseInt(...)) check passed this
  // through to `WHERE id = $1` and Postgres answered with a 500.
  for (const bad of ['5abc', 'abc', '1e5x', '--1', '+7']) {
    assert.ok(Number.isNaN(parseJobId(bad)), `'${bad}' must not read as a job id`);
  }
});

test('other numeric notations do not become job ids', () => {
  // Number('0x10') is 16 and Number('1e5') is 100000: both would have looked up
  // a real job nobody named.
  for (const bad of ['0x10', '0b101', '0o17', '1e5']) {
    assert.ok(Number.isNaN(parseJobId(bad)), `'${bad}' must not read as a job id`);
  }
});

test('an id past int4 is refused here rather than by Postgres', () => {
  assert.equal(parseJobId(2147483647), 2147483647, 'the largest id that can exist still works');
  assert.ok(Number.isNaN(parseJobId(2147483648)));
  assert.ok(Number.isNaN(parseJobId('99999999999')));
});

test('ids that cannot exist are rejected rather than queried', () => {
  for (const bad of [-1, '-7', 1.5, '3.5', Infinity, NaN]) {
    assert.ok(Number.isNaN(parseJobId(bad)), `${bad} must not read as a job id`);
  }
});

test('non-scalar bodies cannot smuggle an id through Number()', () => {
  // Number([5]) is 5 and Number(true) is 1 — both would have become real
  // lookups against a job the caller never named.
  for (const bad of [[5], true, false, {}, { id: 5 }, () => 5]) {
    assert.ok(Number.isNaN(parseJobId(bad)), `${JSON.stringify(bad)} must not read as a job id`);
  }
});

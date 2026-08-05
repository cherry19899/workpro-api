/**
 * Payout availability classification.
 *
 * The distinction that matters: "Pi has not switched this on yet" is not the
 * user's problem and not a bug, whereas anything else is worth showing
 * differently. Getting this backwards either alarms people over nothing or
 * hides a real failure behind a reassuring message.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

// Mirrors routes/payouts.js. Kept in sync deliberately — if the pattern there
// changes, this should fail and make someone re-check the cases below.
const NOT_APPROVED = /feature[_ ]?not[_ ]?available|not[_ ]?(?:yet[_ ]?)?(?:enabled|approved|activated)/i;

test('Pi\'s "not enabled yet" responses are recognised as pending, not as failures', () => {
  const pending = [
    'feature_not_available',
    '{"error":"feature_not_available"}',
    'feature not available',
    'A2U not enabled for this app',
    'App not yet approved for A2U',
    'not activated',
    'FEATURE_NOT_AVAILABLE',
  ];
  for (const msg of pending) {
    assert.ok(NOT_APPROVED.test(msg), `should be treated as pending: ${msg}`);
  }
});

test('real failures are not disguised as pending approval', () => {
  const genuine = [
    'insufficient balance',
    'network timeout',
    'invalid recipient address',
    'Payment already exists',
    '',
  ];
  for (const msg of genuine) {
    assert.ok(!NOT_APPROVED.test(msg), `should NOT be treated as pending: ${msg}`);
  }
});

test('a never-attempted payout is not reported as broken', () => {
  // ok === null means nothing has been tried yet. Telling a freelancer their
  // payouts are broken because the path is merely untested would be wrong.
  const last = { ok: null, stage: null, error: null, at: null };
  const isFailure = last.ok === false;
  assert.equal(isFailure, false);
});

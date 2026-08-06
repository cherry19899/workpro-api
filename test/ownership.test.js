/**
 * Identity comparison and escrow cancellation rules.
 *
 * Both cases here were reported as "it doesn't work" and turned out to be
 * one-line omissions with money-shaped consequences.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

// Copied from routes/payments.js. Pi user ids reach us with inconsistent case
// and an optional pi_ prefix, so every ownership check has to normalise before
// comparing — a raw !== silently 403s the rightful owner.
const normalizeId = (id) => (id || '').toString().toLowerCase().replace(/^pi_/, '');

test('the same user is recognised across the id spellings Pi actually sends', () => {
  const pairs = [
    ['pi_a2b617f7', 'a2b617f7'],
    ['pi_Cherry19899', 'cherry19899'],
    ['Cherry19899', 'pi_cherry19899'],
    ['pi_ABC', 'pi_abc'],
  ];
  for (const [stored, incoming] of pairs) {
    assert.equal(
      normalizeId(stored), normalizeId(incoming),
      `${stored} and ${incoming} are the same person and must compare equal`,
    );
  }
});

test('different users still do not match', () => {
  assert.notEqual(normalizeId('pi_alice'), normalizeId('pi_bob'));
  assert.notEqual(normalizeId('pi_alice'), normalizeId(''));
  assert.notEqual(normalizeId(null), normalizeId('pi_alice'));
});

test('a raw comparison would have rejected the owner — this is why normalizeId exists', () => {
  const stored = 'pi_a2b617f7';
  const incoming = 'a2b617f7';
  assert.notEqual(stored, incoming, 'raw compare fails, which is the bug');
  assert.equal(normalizeId(stored), normalizeId(incoming), 'normalised compare succeeds');
});

// ─── Escrow cancellation ─────────────────────────────────────────────────────

// Mirrors the guard in POST /api/escrows/:id/cancel.
function mayCancel(escrowStatus, jobStatus) {
  if (!['pending', 'funded'].includes(escrowStatus)) return false;
  if (jobStatus === 'submitted') return false;   // work already delivered
  return true;
}

test('a client cannot cancel after the freelancer has delivered', () => {
  assert.equal(
    mayCancel('funded', 'submitted'), false,
    'cancelling here would return the money to a client who already has the work',
  );
});

test('cancelling is still allowed before delivery', () => {
  assert.equal(mayCancel('pending', 'open'), true);
  assert.equal(mayCancel('funded', 'open'), true);
  assert.equal(mayCancel('funded', 'in_progress'), true);
});

test('a settled escrow cannot be cancelled at all', () => {
  for (const status of ['released', 'refunded', 'completed', 'disputed']) {
    assert.equal(mayCancel(status, 'open'), false, `${status} escrows are already settled`);
  }
});

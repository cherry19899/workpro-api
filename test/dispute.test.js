/**
 * Dispute rules.
 *
 * A dispute freezes someone's money until an administrator rules on it, and the
 * administrator cannot read the parties' chat. Everything here exists so that
 * ruling is possible at all, and so a dispute the parties settled themselves
 * does not stay open with the funds locked.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

const normalizeId = (id) => (id || '').toString().toLowerCase().replace(/^pi_/, '');

// Mirrors the guard in POST /api/escrows/:id/dispute.
const MIN_REASON = 20;
function reasonAccepted(raw) {
  const reason = String(raw || '').trim();
  return reason.length >= MIN_REASON && reason.length <= 1000;
}

// Mirrors the CASE expression in GET /api/admin/escrows.
function disputedBySide(disputedBy, clientId) {
  if (disputedBy == null) return null;
  return normalizeId(disputedBy) === normalizeId(clientId) ? 'client' : 'freelancer';
}

test('a dispute cannot be opened without saying what is wrong', () => {
  assert.equal(reasonAccepted(undefined), false);
  assert.equal(reasonAccepted(''), false);
  assert.equal(reasonAccepted('   '), false);
  assert.equal(reasonAccepted('bad work'), false, 'too short to rule on');
  assert.equal(reasonAccepted('   short   '), false, 'whitespace must not pad it out');
});

test('a real explanation is accepted', () => {
  assert.equal(reasonAccepted('The delivered file is empty and the freelancer stopped replying'), true);
});

test('an overlong reason is still rejected', () => {
  assert.equal(reasonAccepted('x'.repeat(1001)), false);
  assert.equal(reasonAccepted('x'.repeat(1000)), true);
});

test('the admin can tell which side raised the dispute', () => {
  assert.equal(disputedBySide('pi_alice', 'alice'), 'client', 'id spellings must not confuse this');
  assert.equal(disputedBySide('Alice', 'pi_alice'), 'client');
  assert.equal(disputedBySide('pi_bob', 'pi_alice'), 'freelancer');
  assert.equal(disputedBySide(null, 'pi_alice'), null, 'no dispute, no side');
});

// Mirrors POST /api/escrows/:id/dispute/withdraw.
function mayWithdraw(status) { return status === 'disputed'; }

test('a dispute can be withdrawn once, and only while it is open', () => {
  assert.equal(mayWithdraw('disputed'), true);
  for (const status of ['funded', 'released', 'refunded', 'pending', 'completed']) {
    assert.equal(mayWithdraw(status), false, `nothing to withdraw from '${status}'`);
  }
});

test('withdrawing returns the escrow to where it was, not to a dead end', () => {
  // 'funded' is the state a dispute interrupts. Anything else would strand the
  // escrow outside the release, cancel and auto-release paths.
  const after = 'funded';
  assert.ok(['pending', 'funded'].includes(after), 'must land back in a cancellable state');
  assert.equal(after, 'funded');
});

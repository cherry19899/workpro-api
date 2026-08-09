/**
 * What the unauthenticated payment webhook is allowed to believe.
 *
 * POST /api/payments/webhook has no auth and Pi sends no signature, so every
 * field in the request body is attacker-controlled. The route used to resolve
 * the status as:
 *
 *     piPayment?.status?.developer_completed ? 'completed'
 *       : piPayment?.status?.cancelled      ? 'cancelled'
 *       : status || 'completed'              // <- the body
 *
 * The last branch is reached whenever the Pi lookup returns nothing — a network
 * blip, a Pi outage, or PI_API_KEY simply not being set — which meant an
 * anonymous POST of {payment_id, status:'completed'} wrote 'completed' onto any
 * payment row. resolveWebhookStatus removes that branch: only Pi decides.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

process.env.ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'test-admin-key-0123456789abcdef';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret';

const { resolveWebhookStatus } = require('../src/helpers');

test('an unverifiable payment yields no status at all', () => {
  // This is the case the old fallback turned into 'completed'.
  for (const unverifiable of [null, undefined]) {
    assert.equal(resolveWebhookStatus(unverifiable), null);
  }
});

test('Pi saying completed is the only way to reach completed', () => {
  assert.equal(resolveWebhookStatus({ status: { developer_completed: true } }), 'completed');
});

test('Pi saying cancelled is the only way to reach cancelled', () => {
  assert.equal(resolveWebhookStatus({ status: { cancelled: true } }), 'cancelled');
  assert.equal(resolveWebhookStatus({ status: { user_cancelled: true } }), 'cancelled');
});

test('a payment Pi still considers in flight resolves to nothing', () => {
  assert.equal(
    resolveWebhookStatus({ status: { developer_approved: true, transaction_verified: false } }),
    null,
    'an approved-but-unsettled payment must not be written as completed',
  );
  assert.equal(resolveWebhookStatus({ status: {} }), null);
  assert.equal(resolveWebhookStatus({}), null);
});

test('nothing in the caller-supplied body can influence the outcome', () => {
  // The function only ever sees Pi's answer — there is no parameter through
  // which a request body could claim a status. Guard the shape so a future
  // edit cannot quietly reintroduce one.
  assert.equal(resolveWebhookStatus.length, 1, 'resolveWebhookStatus takes only Pi\'s payment object');
  // A body-shaped object (status as a string, as the webhook body sends it)
  // must not be mistaken for Pi's nested status flags.
  assert.equal(resolveWebhookStatus({ status: 'completed' }), null);
  assert.equal(resolveWebhookStatus({ status: 'cancelled' }), null);
});

test('completed wins over cancelled if Pi somehow reports both', () => {
  assert.equal(
    resolveWebhookStatus({ status: { developer_completed: true, cancelled: true } }),
    'completed',
    'money already moved — the row must reflect that',
  );
});

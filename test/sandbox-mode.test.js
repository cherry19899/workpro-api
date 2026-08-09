/**
 * The sandbox switch.
 *
 * Sandbox skips Pi accessToken verification outright — in that mode POST
 * /api/me hands out a JWT for whatever uid the caller names. So the switch is
 * a security boundary, not a convenience flag, and the thing that decides it
 * must never be a truthiness check on the raw environment variable: that reads
 * SANDBOX_MODE="false" — the obvious way to turn it off — as ON.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

const HELPERS = require.resolve('../src/helpers');

/** Load helpers fresh with SANDBOX_MODE set to `value` (undefined = unset). */
function sandboxWith(value) {
  const previous = process.env.SANDBOX_MODE;
  if (value === undefined) delete process.env.SANDBOX_MODE;
  else process.env.SANDBOX_MODE = value;
  delete require.cache[HELPERS];
  const { SANDBOX_MODE } = require('../src/helpers');
  delete require.cache[HELPERS];
  if (previous === undefined) delete process.env.SANDBOX_MODE;
  else process.env.SANDBOX_MODE = previous;
  return SANDBOX_MODE;
}

test('only the exact string "true" enables sandbox', () => {
  assert.equal(sandboxWith('true'), true);
});

test('values that look like "off" do not enable sandbox', () => {
  // "false" is the whole reason this test exists: under the old truthiness
  // check it silently disabled Pi token verification in production.
  for (const value of ['false', '0', 'no', 'off', '', ' ']) {
    assert.equal(sandboxWith(value), false, `SANDBOX_MODE=${JSON.stringify(value)} must stay off`);
  }
});

test('an unset variable does not enable sandbox', () => {
  assert.equal(sandboxWith(undefined), false);
});

test('the check is case-sensitive, so no near-miss turns it on by accident', () => {
  for (const value of ['True', 'TRUE', ' true', 'true ']) {
    assert.equal(sandboxWith(value), false, `SANDBOX_MODE=${JSON.stringify(value)} must stay off`);
  }
});

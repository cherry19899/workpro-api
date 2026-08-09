/**
 * Admin-configurable connects economy.
 *
 * The apply cost is the lever against spray-and-pray applications, so it has to
 * be changeable without a deploy. It also has to stay identical on both sides:
 * the divisor was hardcoded in the frontend while the server had its own copy,
 * which is exactly how the published platform fee came to disagree with the one
 * actually charged.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

const { applyCostFor } = require('../src/helpers');

test('applying costs one connect per divisor-worth of budget, rounded up', () => {
  assert.equal(applyCostFor(50, 50), 1);
  assert.equal(applyCostFor(51, 50), 2, 'a fraction over rounds up — never charge less than the work implies');
  assert.equal(applyCostFor(100, 50), 2);
  assert.equal(applyCostFor(500, 50), 10);
});

test('lowering the divisor makes applying more expensive', () => {
  // This is the whole point of the setting.
  assert.ok(applyCostFor(100, 25) > applyCostFor(100, 50));
  assert.equal(applyCostFor(100, 25), 4);
});

test('applying always costs at least one connect', () => {
  for (const budget of [0, 0.5, 1, 49]) {
    assert.equal(applyCostFor(budget, 50), 1, `${budget}π must still cost a connect`);
  }
});

test('a missing or nonsense divisor falls back rather than dividing by zero', () => {
  assert.equal(applyCostFor(100, 0), 2, 'zero would be Infinity — must fall back to the default');
  assert.equal(applyCostFor(100, undefined), 2);
  assert.equal(applyCostFor(100, null), 2);
  assert.equal(applyCostFor(100, NaN), 2);
});

test('a malformed budget does not produce a nonsense charge', () => {
  for (const budget of [undefined, null, '', 'abc', NaN]) {
    const cost = applyCostFor(budget, 50);
    assert.ok(Number.isInteger(cost) && cost >= 1, `${String(budget)} gave ${cost}`);
  }
});

test('the cost is always a whole number of connects', () => {
  for (const budget of [1, 33, 77.7, 149.99, 1000]) {
    assert.ok(Number.isInteger(applyCostFor(budget, 50)), `${budget}π gave a fraction`);
  }
});

test('the configured divisor, not a hardcoded 50, decides the apply cost', () => {
  // routes/jobs.js recomputed apply_cost on a budget edit with a hardcoded
  // `Math.ceil(b / 50)`, so an admin who raised the apply cost saw it apply to
  // newly posted jobs and silently revert on any job edited afterwards. These
  // are the budgets where that difference is actually visible — below the
  // divisor the one-connect floor hides it.
  const hardcoded = (b) => Math.ceil(b / 50);
  for (const budget of [100, 200, 500]) {
    assert.notEqual(applyCostFor(budget, 25), hardcoded(budget),
      `at ${budget}π a divisor of 25 must not agree with the old /50 constant`);
    assert.equal(applyCostFor(budget, 50), hardcoded(budget),
      `at ${budget}π a divisor of 50 must still reproduce the old result`);
  }
});

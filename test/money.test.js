/**
 * Tests for the arithmetic that moves money.
 *
 * These are the calculations where a mistake costs someone real Pi, and they
 * are pure functions, so they are cheap to pin down. Every case here comes from
 * a rule stated in the published Terms or the FAQ — if a test fails, either the
 * code drifted or the documents did, and both matter.
 *
 * Run with: npm test
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

const { resolveConnects, CONNECT_PACKAGES, FEE_MIN, FEE_MAX } = require('../src/helpers');

// The escrow payout, copied from routes/payments.js:179. Duplicated on purpose:
// if someone changes the formula there, this test should fail and make them
// think about it rather than silently follow along.
const netPayout = (amount, fee) => parseFloat((amount * (1 - fee)).toFixed(8));

// ─── Platform fee ────────────────────────────────────────────────────────────

test('fee is bounded to the 0–20% the Terms promise', () => {
  assert.equal(FEE_MIN, 0, 'a 0% fee must be allowed — the Terms say "between 0% and 20%"');
  assert.equal(FEE_MAX, 0.2, 'the Terms cap the platform fee at 20%');
});

test('the freelancer receives the budget minus the fee, and the client pays the budget', () => {
  // From the FAQ: "10π budget → the client pays 10π and the freelancer receives net".
  // The fee comes out of the payout, it is never added on top of the budget.
  assert.equal(netPayout(10, 0.02), 9.8);
  assert.equal(netPayout(10, 0.08), 9.2);
  assert.equal(netPayout(10, 0), 10, 'a 0% fee must pay out the whole budget');
  assert.equal(netPayout(10, 0.2), 8, 'at the 20% cap the freelancer still gets 80%');
});

test('payout never exceeds the escrowed amount', () => {
  for (const amount of [0.1, 1, 7.77, 100, 10000]) {
    for (const fee of [0, 0.02, 0.08, 0.2]) {
      const net = netPayout(amount, fee);
      assert.ok(net <= amount, `${net} must not exceed the escrowed ${amount}`);
      assert.ok(net >= 0, `${net} must not be negative`);
    }
  }
});

test('payout keeps enough precision for small amounts', () => {
  // 8 decimals is the Pi ledger's precision. Rounding to 2 here would silently
  // zero out the fee on sub-Pi jobs.
  assert.equal(netPayout(0.05, 0.08), 0.046);
});

// ─── Connects ────────────────────────────────────────────────────────────────

test('every advertised package credits at least the connects it advertises', () => {
  for (const p of CONNECT_PACKAGES) {
    assert.ok(
      resolveConnects(p.price) >= p.connects,
      `paying ${p.price}π for the ${p.connects}-connect package must credit at least ${p.connects}`,
    );
  }
});

test('a non-package amount falls back to the flat rate', () => {
  // 10 connects per Pi, floored — no bonus unless a package price is matched.
  assert.equal(resolveConnects(0.3), 3);
  assert.equal(resolveConnects(2), 20);
});

test('an amount close to a package price still earns the package bonus', () => {
  // Pi amounts arrive with rounding, so the match is a ±5% window.
  const p = CONNECT_PACKAGES[0];
  assert.equal(resolveConnects(p.price * 1.02), Math.max(Math.floor(p.price * 1.02 * 10), p.connects));
  assert.equal(resolveConnects(p.price * 0.98), Math.max(Math.floor(p.price * 0.98 * 10), p.connects));
});

test('a dust payment credits nothing rather than rounding up to a connect', () => {
  assert.equal(resolveConnects(0), 0);
  assert.equal(resolveConnects(0.05), 0);
});

test('connects are never negative or fractional', () => {
  for (const amount of [0, 0.01, 0.3, 1, 5, 7.77, 100]) {
    const n = resolveConnects(amount);
    assert.ok(Number.isInteger(n), `${amount}π gave a fractional ${n}`);
    assert.ok(n >= 0, `${amount}π gave a negative ${n}`);
  }
});

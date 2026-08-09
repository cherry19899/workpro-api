/**
 * Rewarded ads must be all-or-nothing.
 *
 * The reward is written to ad_rewards and the connect is added to the user's
 * balance. Those were two separate statements, and the ad_rewards primary key
 * is what stops an adId from ever being redeemed twice — so when the balance
 * update failed, the reward row stayed behind and locked the ad out forever.
 * The user watched the ad, got no connect, and could never retry it.
 *
 * These tests drive the real route over a fake pool, because the property that
 * matters is a transaction boundary and nothing below the route can show it.
 */
// Set before anything is required: config refuses to load in production
// without the real secrets, and this suite supplies none of them.
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');

const ROOT = path.join(__dirname, '..');

// The pretend table, reset before each test. `failUpdate` makes the balance
// update throw the way a dropped connection does.
const state = { rewards: [], balance: 4, failUpdate: false, txStart: [] };

function runSql(sql, params) {
  const s = sql.replace(/\s+/g, ' ').trim();
  if (/^BEGIN$/i.test(s)) { state.txStart = state.rewards.slice(); return { rows: [] }; }
  if (/^COMMIT$/i.test(s)) return { rows: [] };
  if (/^ROLLBACK$/i.test(s)) { state.rewards = state.txStart.slice(); return { rows: [] }; }
  if (/FROM users WHERE id IN \(\$1,\$2\) AND is_blocked/i.test(s)) return { rows: [] };
  if (/SELECT user_id FROM ad_rewards WHERE ad_id/i.test(s)) {
    return { rows: state.rewards.filter((r) => r.ad_id === params[0]) };
  }
  if (/SELECT COUNT\(\*\) FROM ad_rewards WHERE user_id/i.test(s)) {
    return { rows: [{ count: String(state.rewards.length) }] };
  }
  if (/INSERT INTO ad_rewards/i.test(s)) {
    if (state.rewards.some((r) => r.ad_id === params[0])) {
      const e = new Error('duplicate key value violates unique constraint');
      e.code = '23505';
      throw e;
    }
    state.rewards.push({ ad_id: params[0], user_id: params[1] });
    return { rows: [] };
  }
  if (/UPDATE users SET balance_connects/i.test(s)) {
    if (state.failUpdate === 'no-rows') return { rows: [] };   // no such user
    if (state.failUpdate) throw new Error('connection terminated unexpectedly');
    state.balance += params[0];
    return { rows: [{ balance_connects: state.balance }] };
  }
  return { rows: [] };
}

const fakeClient = { query: async (sql, params) => runSql(sql, params), release() {} };
const fakeDb = {
  query: async (sql, params) => runSql(sql, params),
  getPool: () => ({ connect: async () => fakeClient }),
  pool: { connect: async () => fakeClient },
};
// routes/ads.js requires '../db'; src/helpers requires './db'. Both resolve to
// their own module id, so both caches need the fake.
for (const p of [path.join(ROOT, 'db.js'), path.join(ROOT, 'src/db.js')]) {
  let id;
  try { id = require.resolve(p); } catch { continue; }
  require.cache[id] = { id, filename: id, loaded: true, exports: fakeDb };
}

// Pi is the authority on whether the ad paid out; say yes so the tests reach
// the part being tested. (That it is consulted at all is covered by the route
// refusing any status other than 'granted'.)
const helpersId = require.resolve(path.join(ROOT, 'src/helpers.js'));
const realHelpers = require(helpersId);
require.cache[helpersId].exports = {
  ...realHelpers,
  piApiRequest: async () => ({ mediator_ack_status: 'granted' }),
  audit: async () => {},
};

const app = express();
app.use(express.json());
app.use(require(path.join(ROOT, 'routes/ads.js')));
const server = app.listen(0);
test.after(() => server.close());

// `id`, not `userId`: that is the claim the auth middleware reads into
// req.userId, and a token without it authenticates as nobody.
const token = jwt.sign({ id: 'pi_alice', username: 'alice' }, process.env.JWT_SECRET, { expiresIn: '1h' });

async function redeem(adId) {
  const r = await fetch(`http://127.0.0.1:${server.address().port}/api/ads/reward`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ adId }),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
}

test.beforeEach(() => {
  state.rewards = [];
  state.balance = 4;
  state.failUpdate = false;
});

test('a verified ad credits one connect and reports the stored balance', async () => {
  const r = await redeem('ad-1');
  assert.equal(r.status, 200);
  assert.equal(r.body.connects_added, 1);
  // The balance comes from the UPDATE's RETURNING, not from arithmetic on the
  // client's idea of the balance.
  assert.equal(r.body.balance_connects, 5);
  assert.equal(state.balance, 5);
  // The reward is recorded against the authenticated caller, not whatever the
  // request body claimed.
  assert.deepEqual(state.rewards, [{ ad_id: 'ad-1', user_id: 'pi_alice' }]);
});

test('the same adId cannot be redeemed twice', async () => {
  await redeem('ad-1');
  const again = await redeem('ad-1');
  assert.equal(again.status, 409);
  assert.equal(state.balance, 5, 'a replay must not credit a second connect');
});

test('a failed balance update leaves no reward row behind', async () => {
  state.failUpdate = true;
  const r = await redeem('ad-2');
  assert.equal(r.status, 500, 'a failure must not be reported as success');
  assert.equal(state.rewards.length, 0);
  assert.equal(state.balance, 4);
});

test('so the ad is still redeemable once the fault clears', async () => {
  state.failUpdate = true;
  await redeem('ad-2');
  state.failUpdate = false;

  const retry = await redeem('ad-2');
  assert.equal(retry.status, 200, 'the ad must not be spent by a failed attempt');
  assert.equal(retry.body.balance_connects, 5);
});

test('an ad for a user that no longer exists grants nothing', async () => {
  // Zero rows updated means no such user. Committing then would leave a reward
  // row recorded against a user that never received the connect.
  state.failUpdate = 'no-rows';
  const r = await redeem('ad-3');
  assert.equal(r.status, 500);
  assert.equal(state.rewards.length, 0);
});

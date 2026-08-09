// serverError() decides the status code every route's catch block returns.
//
// Most id path params in this app go into `WHERE id = $1` without being parsed,
// and jobs, escrows, applications, reviews, notifications, saved_searches and
// escrow_milestones all have SERIAL ids. So `DELETE /api/saved-searches/abc`
// reached Postgres, Postgres refused the cast with SQLSTATE 22P02, and the
// caller was told the server had broken — a 500 for what is plainly a bad
// request, on roughly thirty routes.
//
// These tests pin the mapping in both directions: the three "the caller sent a
// value this column cannot hold" codes answer 400, everything else still
// answers 500 and is still recorded for /api/health?deep=1.
const { test } = require('node:test');
const assert = require('node:assert/strict');

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.NODE_ENV = 'test';

const { serverError, last500, isIdParam } = require('../src/helpers');

// Minimal express-shaped response: records what the handler chose.
function fakeRes() {
  const r = { code: null, body: null };
  r.status = (c) => { r.code = c; return r; };
  r.json = (b) => { r.body = b; return r; };
  return r;
}

// serverError console.errors on every path; keep the test output readable.
function quiet(fn) {
  const real = console.error;
  console.error = () => {};
  try { return fn(); } finally { console.error = real; }
}

const pgError = (code, message) => Object.assign(new Error(message), { code });

test('22P02 (non-numeric id for a SERIAL column) is a 400, not a 500', () => {
  const res = fakeRes();
  quiet(() => serverError(pgError('22P02', 'invalid input syntax for type integer: "abc"'), res));
  assert.equal(res.code, 400);
  assert.equal(res.body.error, 'Invalid value in request');
});

test('22003 (id past int4) is a 400', () => {
  const res = fakeRes();
  quiet(() => serverError(pgError('22003', 'value "99999999999" is out of range for type integer'), res));
  assert.equal(res.code, 400);
  assert.equal(res.body.error, 'Value out of range');
});

test('22001 (value longer than the VARCHAR) is a 400', () => {
  const res = fakeRes();
  quiet(() => serverError(pgError('22001', 'value too long for type character varying(255)'), res));
  assert.equal(res.code, 400);
  assert.equal(res.body.error, 'Value too long');
});

test('a client-data error is not recorded as the last 500', () => {
  // /api/health?deep=1 reports last_500 to diagnose server faults. A caller
  // typing a bad id must not overwrite the real fault sitting in that field.
  const before = fakeRes();
  quiet(() => serverError(new Error('genuine fault'), before));
  const recorded = last500();
  assert.equal(recorded.error, 'genuine fault');

  quiet(() => serverError(pgError('22P02', 'invalid input syntax'), fakeRes()));
  assert.equal(last500().error, 'genuine fault', 'bad input overwrote the recorded server fault');
  assert.equal(last500().at, recorded.at);
});

test('every other Postgres error is still a 500', () => {
  // 23505 unique_violation, 23503 foreign_key_violation, 42P01 undefined_table,
  // 57014 query_canceled — real faults or conditions the route must handle
  // itself. None of them may be softened into a 400.
  for (const code of ['23505', '23503', '23502', '42P01', '42703', '57014', '08006']) {
    const res = fakeRes();
    quiet(() => serverError(pgError(code, `pg ${code}`), res));
    assert.equal(res.code, 500, `SQLSTATE ${code} should stay a 500`);
    assert.equal(res.body.error, 'Internal server error');
  }
});

test('a plain Error with no code is still a 500', () => {
  const res = fakeRes();
  quiet(() => serverError(new TypeError('x is not a function'), res));
  assert.equal(res.code, 500);
});

test('a thrown non-Error does not crash the responder', () => {
  // Some catch blocks receive strings or undefined; reading .code off those
  // must not throw inside the error handler itself.
  for (const thrown of [undefined, null, 'boom', 42, {}]) {
    const res = fakeRes();
    quiet(() => serverError(thrown, res));
    assert.equal(res.code, 500);
  }
});

// ─── isIdParam ────────────────────────────────────────────────────────────
// The 400-mapping above is the safety net. isIdParam is the guard that keeps
// bad ids out of the database in the first place, on all 31 routes that used
// `isNaN(parseInt(req.params.id))`.

test('a real id passes', () => {
  for (const v of ['1', '7', '42', '2147483647']) {
    assert.equal(isIdParam(v), true, `${v} is a usable id`);
  }
});

test("parseInt's prefix parsing does not get a second chance", () => {
  // The whole reason this helper exists: parseInt('5abc') is 5, so the old
  // guard passed '5abc' through and handed the raw string to Postgres.
  for (const v of ['5abc', '1 OR 1=1', '12.5', '1e5', '0x10', ' 7', '7 ', '+7', '-3', '']) {
    assert.equal(isIdParam(v), false, `${JSON.stringify(v)} must not reach the query`);
  }
});

test('0 is not an id', () => {
  // Every id column here is SERIAL, which starts at 1.
  assert.equal(isIdParam('0'), false);
  assert.equal(isIdParam('00'), false);
});

test('an id past int4 is refused before Postgres raises 22003', () => {
  assert.equal(isIdParam('2147483648'), false);
  assert.equal(isIdParam('99999999999'), false);
  // 11+ digits are rejected on length alone, so no huge string is ever coerced.
  assert.equal(isIdParam('9'.repeat(400)), false);
});

test('only strings pass', () => {
  // Express always hands over strings, but a route could pass a body value by
  // mistake; Number-like objects must not slip through a numeric coercion.
  for (const v of [5, null, undefined, {}, [], ['5'], true, NaN, Infinity]) {
    assert.equal(isIdParam(v), false, `${String(v)} is not a path param`);
  }
});

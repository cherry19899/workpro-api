/**
 * Constant-time secret comparison.
 *
 * The admin key was compared as `key.length === ADMIN_API_KEY.length &&
 * crypto.timingSafeEqual(Buffer.from(key), Buffer.from(ADMIN_API_KEY))`.
 * That gate measures *characters* while timingSafeEqual measures *bytes*, and
 * timingSafeEqual throws RangeError when the byte lengths differ — so a token
 * of multi-byte characters whose character count matched the key turned a
 * would-be 403 into a thrown RangeError inside an async handler, i.e. an
 * unhandled rejection and a request that never answers.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

process.env.ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'test-admin-key-0123456789abcdef';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret';

const { timingSafeStrEqual } = require('../src/middleware');

test('the real key matches itself', () => {
  assert.equal(timingSafeStrEqual('s3cret-value', 's3cret-value'), true);
});

test('a wrong key of the same length does not match', () => {
  assert.equal(timingSafeStrEqual('s3cret-value', 's3cret-valuf'), false);
});

test('a multi-byte token with a matching character count returns false, not a throw', () => {
  // 12 Cyrillic characters = 24 bytes vs a 12-byte ASCII key. The old code
  // passed its character-length gate and then threw inside timingSafeEqual.
  const key = 's3cret-value';
  const attack = 'фффффффффффф';
  assert.equal(attack.length, key.length, 'the crafted token clears a character-length gate');
  assert.notEqual(Buffer.byteLength(attack), Buffer.byteLength(key), 'but its byte length differs');
  assert.doesNotThrow(() => timingSafeStrEqual(attack, key));
  assert.equal(timingSafeStrEqual(attack, key), false);
});

test('empty and missing tokens never match', () => {
  for (const bad of ['', null, undefined]) {
    assert.equal(timingSafeStrEqual(bad, 's3cret-value'), false, `${JSON.stringify(bad)} must not authenticate`);
  }
});

test('an empty configured secret cannot be matched by an empty token', () => {
  // Otherwise an unset ADMIN_API_KEY would authenticate every anonymous caller.
  assert.equal(timingSafeStrEqual('', ''), false);
  assert.equal(timingSafeStrEqual(undefined, undefined), false);
});

test('length differences alone do not match', () => {
  assert.equal(timingSafeStrEqual('short', 's3cret-value'), false);
  assert.equal(timingSafeStrEqual('s3cret-value-and-more', 's3cret-value'), false);
});

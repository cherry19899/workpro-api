/**
 * The owner's username is a credential.
 *
 * routes/auth.js grants the admin role to any account whose username is
 * 'cherry19899' (GET /api/me self-heal and the POST /api/me login path), and
 * routes/admin.js repeats the same rule in its own SQL. Meanwhile two write
 * paths accepted a username straight from the request body:
 *
 *   - POST /api/me took `username` from the body even on a Pi-verified login,
 *     so one request with a real accessToken and {username:'cherry19899'}
 *     wrote that name and the self-heal handed over the admin role.
 *   - POST /api/users/:id wrote whatever the body said, with no uniqueness
 *     check at all — and the users table has no UNIQUE index on username.
 *
 * The name is now reserved to the owner's real uids, and the login path
 * prefers the username Pi vouches for over the one the caller typed.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

process.env.ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'test-admin-key-0123456789abcdef';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret';

const { isOwnerUid, OWNER_USERNAME } = require('../src/helpers');

test('the owner\'s real uids are recognised', () => {
  assert.equal(isOwnerUid('pi_cherry19899'), true);
  assert.equal(isOwnerUid('pi_a2b617f7-f510-4502-a046-805facedcc29'), true);
});

test('uid matching is case-insensitive, as the login path is', () => {
  // The real owner authenticates as "Cherry19899" with a capital C — a
  // lowercase-only guard is exactly what once locked them out of their own app.
  assert.equal(isOwnerUid('PI_Cherry19899'), true);
  assert.equal(isOwnerUid('pi_A2B617F7-F510-4502-A046-805FACEDCC29'), true);
});

test('nobody else is', () => {
  for (const uid of [
    'pi_attacker',
    'cherry19899',              // no pi_ prefix — not a uid this app issues
    'pi_cherry198990',          // trailing digit
    'pi_cherry1989',            // truncated
    'pi_cherry19899 ',          // trailing space
    '',
    null,
    undefined,
  ]) {
    assert.equal(isOwnerUid(uid), false, `${JSON.stringify(uid)} must not be treated as the owner`);
  }
});

test('non-string uids cannot pass the guard', () => {
  assert.equal(isOwnerUid({ toString: () => 'pi_cherry19899' }), false);
  assert.equal(isOwnerUid(['pi_cherry19899']), false);
});

test('the reserved username is stored lowercase so comparisons are total', () => {
  // Callers lowercase the candidate before comparing; if this constant ever
  // gained a capital letter every one of those comparisons would silently
  // stop matching and the name would be claimable again.
  assert.equal(OWNER_USERNAME, OWNER_USERNAME.toLowerCase());
  assert.ok(OWNER_USERNAME.length > 0);
});

/**
 * Authority is a uid question. Never a username.
 *
 * A username is not a credential in this app: `users.username` has no UNIQUE
 * index, and the login routes used to copy a request-body username into the
 * stored row and into the JWT whenever Pi returned a uid without a username
 * (which Pi does when the username scope was not granted). Admin was then
 * granted by matching that name, in six separate places, so anyone could take
 * the owner's name and be promoted:
 *
 *   - POST /api/auth/refresh looked the user up by the JWT's username claim.
 *     `OR LOWER(username) = $3 ... LIMIT 1` over a non-UNIQUE column with no
 *     ORDER BY returns whichever row the scan reaches first — the older owner
 *     row — and the endpoint then minted a fresh 30-day token for it. Anyone
 *     could take over the owner's account.
 *   - POST /api/me granted admin off `uname`, which fell back to the body.
 *   - adminAuth granted req.isAdmin off the JWT username claim with no database
 *     lookup at all, commented "signed → safe". A signature proves only that we
 *     issued the token, never that the name inside it is true.
 *   - GET /api/admin/verify did the same, and promoted every row bearing the
 *     name — so a poisoned row then satisfied the *fixed* adminAuth by id.
 *   - server.js ran that blanket promote on every boot, so a restart alone
 *     re-granted admin to impostors.
 *   - The block/remove-admin guards treated any row named cherry19899 as the
 *     owner, making an impostor un-blockable and un-demotable.
 *
 * An earlier pass fixed only the *write* paths and reasoned that the reads were
 * therefore safe. That reasoning was wrong — the write path was not actually
 * closed (the Pi-returns-no-username case), which left the reads exploitable.
 * These tests pin the rule that replaced it: admin comes from ADMIN_API_KEY,
 * from role='admin' on a row found BY ID, or from the owner's uid. If a future
 * change reintroduces a name comparison anywhere in that decision, one of these
 * fails.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

// Comments describe the old bug on purpose, so they must not count as matches.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/--.*$/gm, '');
}

const AUTHORITY_FILES = [
  'src/middleware.js',
  'routes/admin.js',
  'routes/auth.js',
  'server.js',
  'scripts/audit-owner-rows.js',
];

test('no live code decides authority by matching the owner username', () => {
  for (const file of AUTHORITY_FILES) {
    const code = stripComments(read(file));

    // `LOWER(username) = 'cherry19899'` in SQL — the blanket promote and the
    // OR-username lookups. routes/users.js is exempt and not in this list: its
    // LOWER(username) = LOWER($1) is a "is this name taken" uniqueness check,
    // which is a legitimate use of a name.
    assert.equal(
      /LOWER\(username\)\s*=\s*'cherry19899'/i.test(code), false,
      `${file}: grants or promotes by matching the owner username in SQL`
    );

    // `someUsername.toLowerCase() === 'cherry19899'` in JS.
    const jsNameCompare = /(\w*[Uu]sername\w*)\s*(?:\?\.)?\.toLowerCase\(\)\s*===\s*'cherry19899'/g;
    for (const m of code.matchAll(jsNameCompare)) {
      // The ONE legitimate case: a username Pi itself vouched for. Pi is the
      // identity authority, so a name it returns is evidence; one the caller
      // typed is not.
      assert.match(
        m[1], /^verifiedUsername$/,
        `${file}: decides authority from '${m[1]}', which is not Pi-verified`
      );
    }
  }
});

test('the owner uid list lives in exactly one place', () => {
  // It used to be copied, in three different shapes, into middleware.js,
  // admin.js (x4), auth.js (x2), server.js and the remediation script — and then
  // it went stale. Production turned out to hold FOUR owner-admin rows while the
  // copies listed two, so two of the owner's real logins sat outside every owner
  // check, and the remediation script would have demoted them. Authority checks
  // must import from src/helpers.js, never re-declare.
  const { OWNER_UIDS } = require('../src/helpers');
  assert.ok(OWNER_UIDS.length >= 4, 'the owner uid list lost entries');

  for (const file of AUTHORITY_FILES) {
    if (file === 'src/helpers.js') continue;
    // The `pi_pi_` corruption-repair UPDATEs in server.js name one specific
    // legacy id as DATA, not as an authority decision — exempt those lines.
    const code = stripComments(read(file))
      .split('\n').filter(l => !l.includes('pi_pi_')).join('\n');
    for (const uid of OWNER_UIDS) {
      // A bare uid literal in an authority file means someone re-declared the
      // list instead of importing it.
      assert.equal(
        code.includes(`'${uid}'`), false,
        `${file}: hardcodes the owner uid '${uid}' — import OWNER_UIDS/isOwnerId from src/helpers.js instead`
      );
    }
  }
});

test('every file that calls isOwnerId also imports it', () => {
  // Caught for real while making this refactor: the import was dropped from
  // middleware.js while the calls stayed. `isOwnerId` was then undefined, the
  // ReferenceError was swallowed by adminAuth's `catch (_) {}`, and the owner
  // got a 403 from their own admin panel. Neither a source-text check nor a
  // `require()` smoke test sees it — the throw only happens at call time, and
  // only on the branch that GRANTS access, so every "must refuse" test still
  // passed. Cheap static guard for a class of bug that hides behind a catch.
  for (const file of AUTHORITY_FILES) {
    const code = stripComments(read(file));
    if (!/\bisOwnerId\s*\(/.test(code)) continue;
    assert.match(
      code, /require\([^)]*helpers[^)]*\)/,
      `${file}: calls isOwnerId but never requires helpers — it will throw at call time`
    );
    assert.match(
      code.match(/const\s*\{[^}]*\}\s*=\s*require\([^)]*helpers[^)]*\)/)?.[0] || '',
      /\bisOwnerId\b/,
      `${file}: calls isOwnerId but does not destructure it from helpers`
    );
  }
});

test('isOwnerId accepts the owner in every spelling, and nobody else', () => {
  const { isOwnerId } = require('../src/helpers');
  // Both prefixed and bare, any case — the call sites compare against twin ids
  // that arrive either way.
  for (const id of [
    'pi_cherry19899', 'cherry19899', 'PI_Cherry19899',
    'pi_a2b617f7-f510-4502-a046-805facedcc29', 'a2b617f7-f510-4502-a046-805facedcc29',
    'pi_a2b617f7', 'pi_e85a1c9b-9bdf-42cd-a4d0-11b4b278df78',
  ]) {
    assert.equal(isOwnerId(id), true, `${id} must be recognised as the owner`);
  }
  for (const id of [
    'pi_attacker', 'pi_a2b617f7x', 'pi_a2b617f', '', null, undefined,
    { toString: () => 'pi_cherry19899' }, ['pi_cherry19899'],
  ]) {
    assert.equal(isOwnerId(id), false, `${JSON.stringify(id)} must NOT be the owner`);
  }
});

test('the owner lookup in adminAuth is by id, not by username', () => {
  const code = stripComments(read('src/middleware.js'));
  // The lookup that decides admin must not reach for a username column.
  const lookup = code.match(/SELECT[^`'"]*FROM users WHERE id = \$1[^`'"]*/i);
  assert.ok(lookup, 'adminAuth must still look the caller up by id');
  assert.equal(
    /username/i.test(lookup[0]), false,
    'adminAuth resolves the caller by username again — that is the takeover bug'
  );
});

test('/api/auth/refresh resolves the token holder by id only', () => {
  const code = stripComments(read('routes/auth.js'));
  const refresh = code.slice(code.indexOf("'/api/auth/refresh'"));
  const lookup = refresh.match(/SELECT[^`'"]*FROM users[^`'"]*/i);
  assert.ok(lookup, 'refresh must still look the user up');
  assert.equal(
    /LOWER\(username\)/i.test(lookup[0]), false,
    'refresh matches on username again — this minted owner tokens for anyone'
  );
});

test('nothing promotes to admin by name; promotes are keyed on id', () => {
  for (const file of AUTHORITY_FILES) {
    const code = stripComments(read(file));
    for (const m of code.matchAll(/UPDATE users SET role\s*=\s*'admin'[^`'"]*/gi)) {
      assert.equal(
        /LOWER\(username\)/i.test(m[0]), false,
        `${file}: promotes to admin by username — that re-grants admin to impostor rows`
      );
      assert.match(
        m[0], /WHERE[^`'"]*\bid\b/i,
        `${file}: a promote must be scoped to a specific id`
      );
    }
  }
});

test('the block and demote guards protect the owner by uid, not by name', () => {
  const code = stripComments(read('routes/admin.js'));
  // Both guards build `isOwner` from the OWNER_IDS allowlist. If a username
  // fallback comes back, an abuser can rename themselves un-blockable.
  const guards = [...code.matchAll(/const isOwner = [^;]*/g)];
  assert.ok(guards.length >= 2, 'expected the block and remove-admin owner guards');
  for (const g of guards) {
    assert.equal(
      /username/i.test(g[0]), false,
      'an owner guard accepts a username again — impostors become un-blockable'
    );
    assert.match(g[0], /isOwnerId/, 'owner guards must go through the shared isOwnerId');
  }
});

test('a stored username is only written when Pi vouched for it', () => {
  const code = stripComments(read('routes/auth.js'));
  // POST /api/me: the branch that overwrites the stored username must be gated
  // on verifiedUsername, not merely on an accessToken being present.
  assert.match(
    code, /if \(accessToken && verifiedUsername\)/,
    'the username-overwriting upsert is no longer gated on a Pi-verified name'
  );
  // POST /api/auth/login: same rule.
  assert.match(
    code, /else if \(piUser && piUser\.username\)/,
    'the login route writes the username again without Pi having returned one'
  );
});

test('GET /api/me self-heals the owner by uid alone', () => {
  const code = stripComments(read('routes/auth.js'));
  const getMe = code.slice(code.indexOf("router.get('/api/me'"), code.indexOf("router.post('/api/me'"));
  assert.match(getMe, /isOwnerId\(u\.id\)/, 'the GET /api/me owner self-heal disappeared');
  assert.equal(
    /u\.username/i.test(getMe), false,
    'GET /api/me grants admin from the stored username again — poisoned rows would re-escalate on every call'
  );
});

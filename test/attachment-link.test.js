/**
 * Download links for chat attachments carry their own credential in the URL,
 * so the token has to be narrow: one attachment, one user, a few minutes, and
 * never interchangeable with a session token.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { mintDownloadToken, verifyDownloadToken, attachmentDisposition } = require('../src/attachment-link');

const SECRET = 'test-jwt-secret';

test('a link opens the attachment it was minted for', () => {
  const t = mintDownloadToken(SECRET, 'att_a', 'pi_user');
  const claims = verifyDownloadToken(SECRET, t, 'att_a');
  assert.equal(claims.uid, 'pi_user');
});

test('a link for one attachment does not open another', () => {
  const t = mintDownloadToken(SECRET, 'att_a', 'pi_user');
  assert.equal(verifyDownloadToken(SECRET, t, 'att_b'), null);
});

test('a link signed under another secret is refused', () => {
  const t = mintDownloadToken('some-other-secret', 'att_a', 'pi_user');
  assert.equal(verifyDownloadToken(SECRET, t, 'att_a'), null);
});

test('an expired link is refused', () => {
  const crypto = require('crypto');
  const key = crypto.createHmac('sha256', SECRET).update('workpro:attachment-download').digest('hex');
  const t = jwt.sign({ typ: 'att-dl', att: 'att_a', uid: 'pi_user', exp: Math.floor(Date.now() / 1000) - 1 }, key);
  assert.equal(verifyDownloadToken(SECRET, t, 'att_a'), null);
});

test('a session token cannot be used as a download link', () => {
  const session = jwt.sign({ id: 'pi_user', username: 'u' }, SECRET, { expiresIn: '30d' });
  assert.equal(verifyDownloadToken(SECRET, session, 'att_a'), null);
});

test('a download token is not a valid session token', () => {
  const t = mintDownloadToken(SECRET, 'att_a', 'pi_user');
  assert.throws(() => jwt.verify(t, SECRET));
});

test('missing or junk tokens are refused, not thrown', () => {
  for (const t of [undefined, null, '', 'garbage', ['x'], { t: 1 }]) {
    assert.equal(verifyDownloadToken(SECRET, t, 'att_a'), null);
  }
});

test('the saved file keeps a non-ASCII name, and the header cannot be broken out of', () => {
  const h = attachmentDisposition('фото "отчёт".jpg');
  assert.match(h, /^attachment; /);
  assert.match(h, /filename\*=UTF-8''%D1%84%D0%BE%D1%82%D0%BE/);
  // the ASCII fallback must not contain a raw quote that would end the value early
  const fallback = h.match(/filename="([^"]*)"/)[1];
  assert.ok(!fallback.includes('"'));
  assert.ok(!/[\r\n]/.test(h));
});

test('CR/LF in a filename cannot inject a header', () => {
  const h = attachmentDisposition('a\r\nSet-Cookie: x=1.png');
  assert.ok(!/[\r\n]/.test(h));
});

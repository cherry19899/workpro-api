/**
 * What may be stored in a portfolio link.
 *
 * Portfolio website/github/linkedin are typed by the portfolio's owner and
 * rendered as `<a href={...}>` on a page every other user can open, so the
 * stored value is the payload: `javascript:alert(document.cookie)` saved as a
 * website ran in the *viewer's* session when they tapped it. Nothing validated
 * these fields on the way in and nothing checked them on the way out.
 *
 * safeHttpUrl is an allowlist on purpose — a blocklist loses to
 * `javascript://%0aalert(1)`, `JaVaScRiPt:`, and `\tjavascript:`.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');

process.env.ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'test-admin-key-0123456789abcdef';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret';

const { safeHttpUrl, MAX_URL_LEN } = require('../src/helpers');

test('ordinary links survive unchanged', () => {
  for (const url of [
    'https://github.com/someone',
    'http://example.com',
    'https://example.com/a/b?c=d#e',
    'HTTPS://Example.COM/Path',
  ]) {
    assert.equal(safeHttpUrl(url), url);
  }
});

test('a scheme-less host gets https, because that is what people type', () => {
  assert.equal(safeHttpUrl('example.com'), 'https://example.com');
  assert.equal(safeHttpUrl('  github.com/someone  '), 'https://github.com/someone');
});

test('clearing the field is allowed and is not an error', () => {
  for (const empty of ['', '   ', null, undefined]) {
    assert.equal(safeHttpUrl(empty), '', `${JSON.stringify(empty)} should clear the link, not reject`);
  }
});

test('script-bearing schemes are refused, however they are dressed up', () => {
  const attacks = [
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    '  javascript:alert(1)',
    'javascript://%0aalert(1)',       // the `//` comments out the rest for the regex-minded
    'javascript:/*--></title></style></textarea></script></xmp><svg onload=alert(1)>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    'about:blank',
  ];
  for (const attack of attacks) {
    assert.equal(safeHttpUrl(attack), null, `${attack} must be refused`);
  }
});

test('a protocol-relative link is refused', () => {
  // `//evil.com` inherits the page's scheme and reads as a real link.
  assert.equal(safeHttpUrl('//evil.com'), null);
});

test('http(s) with nothing after it is refused', () => {
  assert.equal(safeHttpUrl('https://'), null);
  assert.equal(safeHttpUrl('http:// '), null);
});

test('an absurdly long URL is refused rather than stored', () => {
  const long = 'https://example.com/' + 'a'.repeat(MAX_URL_LEN);
  assert.ok(long.length > MAX_URL_LEN);
  assert.equal(safeHttpUrl(long), null);
  const atLimit = 'https://e.co/' + 'a'.repeat(MAX_URL_LEN - 'https://e.co/'.length);
  assert.equal(atLimit.length, MAX_URL_LEN);
  assert.equal(safeHttpUrl(atLimit), atLimit, 'exactly at the limit is still fine');
});

test('non-string input cannot slip through', () => {
  assert.equal(safeHttpUrl({ toString: () => 'javascript:alert(1)' }), null);
  assert.equal(safeHttpUrl(['javascript:alert(1)']), null);
  assert.equal(safeHttpUrl(0), null, '"0" is not a URL');
  assert.equal(safeHttpUrl(false), null);
});

test('embedded whitespace is refused, not silently kept', () => {
  // A newline inside an href is a classic filter-bypass carrier.
  assert.equal(safeHttpUrl('https://example.com/a b'), null);
  assert.equal(safeHttpUrl('https://exa\nmple.com'), null);
});

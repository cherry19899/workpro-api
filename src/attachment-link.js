/**
 * Short-lived download links for chat attachments.
 *
 * Attachments are served behind the Authorization header, which a plain link
 * cannot carry — and a plain link is the only way to get a file onto the phone
 * in Pi Browser. Measured on-device 2026-10-05: a page-made blob: download is
 * ignored, the share sheet does not accept files, and long-press offers no
 * "Save image"; but navigating to an ordinary HTTPS URL that answers with
 * Content-Disposition: attachment downloads straight to /sdcard/Download.
 *
 * So a room member asks for a link (authenticated), and the link itself carries
 * a token good for one attachment, one user, five minutes.
 *
 * The token is signed with a key derived from JWT_SECRET rather than with
 * JWT_SECRET itself, so a download token can never be presented as a session
 * token or the other way round — they are not valid under each other's key.
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const TTL = '5m';
const TYP = 'att-dl';

function keyFrom(secret) {
  return crypto.createHmac('sha256', String(secret)).update('workpro:attachment-download').digest('hex');
}

function mintDownloadToken(secret, attId, uid) {
  return jwt.sign({ typ: TYP, att: attId, uid }, keyFrom(secret), { expiresIn: TTL });
}

/** The token's claims if it is valid for exactly this attachment, else null. */
function verifyDownloadToken(secret, token, attId) {
  if (typeof token !== 'string' || !token) return null;
  let claims;
  try { claims = jwt.verify(token, keyFrom(secret)); } catch { return null; }
  if (!claims || claims.typ !== TYP || claims.att !== attId || !claims.uid) return null;
  return claims;
}

/**
 * Content-Disposition that names the saved file correctly for any language.
 * `filename` is a plain-ASCII fallback for old clients; `filename*` (RFC 5987)
 * carries the real UTF-8 name. Quotes, backslashes and control characters are
 * stripped from the fallback so a crafted filename cannot break out of the
 * header value.
 */
function attachmentDisposition(filename) {
  const name = String(filename || 'file');
  const ascii = name.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_') || 'file';
  const encoded = encodeURIComponent(name).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

module.exports = { mintDownloadToken, verifyDownloadToken, attachmentDisposition };

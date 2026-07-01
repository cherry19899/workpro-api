/**
 * src/sanitize.js — XSS / injection protection helpers (no external deps)
 */

// Strip all HTML tags and encode dangerous characters.
// Used for any user-supplied text stored in the DB and rendered in UI.
function stripTags(str) {
  if (str == null) return '';
  return String(str)
    .replace(/<[^>]*>/g, '')        // strip HTML tags
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}

// Light version: strip tags but keep the raw text without entity-encoding.
// Use for fields that are displayed as plain text (not HTML rendered).
function sanitizeText(str, maxLen = 10000) {
  if (str == null) return '';
  return String(str)
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<[^>]*>/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .slice(0, maxLen)
    .trim();
}

// Sanitize a username: alphanumeric + _ + . only, max 50 chars
function sanitizeUsername(str) {
  if (str == null) return '';
  return String(str).replace(/[^a-zA-Z0-9_.]/g, '').slice(0, 50);
}

// Validate and sanitize a URL (must be http/https)
function sanitizeUrl(str) {
  if (str == null) return '';
  const s = String(str).trim();
  if (!/^https?:\/\/.+/.test(s)) return '';
  if (s.length > 2000) return '';
  return s;
}

// Sanitize an integer — returns null if not a valid integer
function sanitizeInt(val, min = 0, max = Number.MAX_SAFE_INTEGER) {
  const n = parseInt(val, 10);
  if (isNaN(n)) return null;
  return Math.max(min, Math.min(max, n));
}

// Sanitize a float
function sanitizeFloat(val, min = 0, max = Number.MAX_VALUE) {
  const n = parseFloat(val);
  if (isNaN(n)) return null;
  return Math.max(min, Math.min(max, n));
}

// Sanitize an object by applying sanitizeText to all string fields
function sanitizeBody(obj, schema) {
  const out = {};
  for (const [key, opts] of Object.entries(schema)) {
    const raw = obj[key];
    if (raw == null || raw === undefined) {
      if (opts.required) throw new Error(`Field '${key}' is required`);
      continue;
    }
    if (opts.type === 'string') {
      out[key] = sanitizeText(raw, opts.maxLen || 10000);
    } else if (opts.type === 'int') {
      out[key] = sanitizeInt(raw, opts.min, opts.max);
    } else if (opts.type === 'float') {
      out[key] = sanitizeFloat(raw, opts.min, opts.max);
    } else if (opts.type === 'url') {
      out[key] = sanitizeUrl(raw);
    } else if (opts.type === 'boolean') {
      out[key] = Boolean(raw);
    } else {
      out[key] = raw;
    }
  }
  return out;
}

module.exports = { stripTags, sanitizeText, sanitizeUsername, sanitizeUrl, sanitizeInt, sanitizeFloat, sanitizeBody };

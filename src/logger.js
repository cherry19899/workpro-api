'use strict';
const isProd = process.env.NODE_ENV === 'production';
module.exports = {
  info:  (...a) => { if (!isProd) console.log('[INFO]', ...a); },
  warn:  (...a) => { if (!isProd) console.warn('[WARN]', ...a); },
  error: (...a) => console.error('[ERROR]', ...a),
  debug: (...a) => { if (!isProd) console.log('[DEBUG]', ...a); },
};

'use strict';
const { stripTags, sanitizeText, sanitizeUsername, sanitizeUrl, sanitizeInt, sanitizeFloat, sanitizeBody } = require('../src/sanitize');

describe('sanitize.js', () => {
  describe('stripTags', () => {
    it('removes HTML tags', () => {
      expect(stripTags('<b>hello</b>')).toBe('hello');
      expect(stripTags('<script>alert(1)</script>world')).toBe('world');
      expect(stripTags('no tags')).toBe('no tags');
    });

    it('encodes & entities', () => {
      expect(stripTags('a & b')).toContain('&amp;');
    });
  });

  describe('sanitizeText', () => {
    it('strips script tags', () => {
      const r = sanitizeText('<script>evil()</script>hello');
      expect(r).not.toContain('<script>');
      expect(r).toContain('hello');
    });

    it('removes javascript: URIs', () => {
      const r = sanitizeText('click javascript:alert(1)');
      expect(r).not.toContain('javascript:');
    });

    it('removes on* event handlers', () => {
      const r = sanitizeText('hello onclick=bad onerror=bad');
      expect(r).not.toMatch(/onclick=/i);
    });

    it('respects maxLen', () => {
      const long = 'a'.repeat(1000);
      expect(sanitizeText(long, 100).length).toBeLessThanOrEqual(100);
    });

    it('returns empty string for null/undefined', () => {
      expect(sanitizeText(null)).toBe('');
      expect(sanitizeText(undefined)).toBe('');
    });
  });

  describe('sanitizeUsername', () => {
    it('allows alphanumeric, _ and .', () => {
      expect(sanitizeUsername('user_name.123')).toBe('user_name.123');
    });

    it('strips disallowed characters', () => {
      expect(sanitizeUsername('user@name!')).toBe('username');
    });

    it('limits to 50 chars', () => {
      const long = 'a'.repeat(100);
      expect(sanitizeUsername(long).length).toBeLessThanOrEqual(50);
    });
  });

  describe('sanitizeUrl', () => {
    it('allows http and https URLs', () => {
      expect(sanitizeUrl('https://example.com')).toBe('https://example.com');
      expect(sanitizeUrl('http://example.com/path?q=1')).toBe('http://example.com/path?q=1');
    });

    it('rejects javascript: URIs', () => {
      expect(sanitizeUrl('javascript:alert(1)')).toBe('');
    });

    it('rejects data: URIs', () => {
      expect(sanitizeUrl('data:text/html,<h1>hi</h1>')).toBe('');
    });

    it('limits to 2000 chars', () => {
      const long = 'https://example.com/' + 'a'.repeat(3000);
      expect(sanitizeUrl(long).length).toBeLessThanOrEqual(2000);
    });
  });

  describe('sanitizeInt', () => {
    it('clamps to range', () => {
      expect(sanitizeInt(5, 1, 10)).toBe(5);
      expect(sanitizeInt(-5, 1, 10)).toBe(1);
      expect(sanitizeInt(99, 1, 10)).toBe(10);
    });

    it('parses strings', () => {
      expect(sanitizeInt('7', 1, 10)).toBe(7);
    });

    it('returns null for invalid', () => {
      expect(sanitizeInt('abc', 1, 10)).toBeNull();
    });
  });

  describe('sanitizeFloat', () => {
    it('clamps to range', () => {
      expect(sanitizeFloat(3.14, 0, 10)).toBeCloseTo(3.14);
      expect(sanitizeFloat(-1, 0, 10)).toBe(0);
      expect(sanitizeFloat(99.9, 0, 10)).toBe(10);
    });

    it('returns null for invalid', () => {
      expect(sanitizeFloat('not a number', 0, 10)).toBeNull();
    });
  });

  describe('sanitizeBody', () => {
    it('sanitizes according to schema', () => {
      const schema = {
        title: { type: 'text', maxLen: 100 },
        budget: { type: 'float', min: 0, max: 10000 },
        page: { type: 'int', min: 1, max: 1000 },
      };
      const out = sanitizeBody({ title: '<b>Test</b>', budget: '99.5', page: '3' }, schema);
      expect(out.title).not.toContain('<b>');
      expect(out.budget).toBeCloseTo(99.5);
      expect(out.page).toBe(3);
    });

    it('handles missing fields as undefined', () => {
      const out = sanitizeBody({}, { title: { type: 'text' } });
      expect(out.title).toBeUndefined();
    });
  });
});

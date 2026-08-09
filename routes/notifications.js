/**
 * routes/notifications.js — /api/notifications/*
 */
const router = require('express').Router();
const { query } = require('../src/db');
const { serverError, isIdParam } = require('../src/helpers');
const { auth } = require('../src/middleware');

// GET /api/notifications/unread-count (alias: /unread)
router.get(['/api/notifications/unread-count', '/api/notifications/unread'], auth, async (req, res) => {
  try {
    const result = await query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false',
      [req.userId]
    );
    const unread_count = parseInt(result.rows[0].count) || 0;
    res.json({ unread_count, count: unread_count });
  } catch (err) {
    // Was `res.json({ unread_count: 0 })`: a failed query was indistinguishable
    // from an empty inbox, and nothing was logged at all. App.tsx already
    // `.catch(() => {})`s this call, so an error leaves the badge at its last
    // known value — which is honest, where a fabricated 0 was not.
    serverError(err, res);
  }
});

// GET /api/notifications
router.get('/api/notifications', auth, async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const [result, totalRes, unreadRes] = await Promise.all([
      query('SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.userId, limit, offset]),
      query('SELECT COUNT(*) FROM notifications WHERE user_id = $1', [req.userId]),
      query('SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = false', [req.userId]),
    ]);
    res.json({
      notifications: result.rows,
      total: parseInt(totalRes.rows[0].count),
      unread_count: parseInt(unreadRes.rows[0].count),
      limit,
      offset,
    });
  } catch (err) {
    // This returned an empty list with HTTP 200, so Notifications.tsx's
    // `.catch(() => setLoadError(true))` could never fire and its error state
    // was unreachable code: when the query failed the user was shown "No
    // notifications" and had no way to tell that from actually having none.
    serverError(err, res);
  }
});

// POST /api/notifications/mark-read (alias: /read-all)
router.post(['/api/notifications/mark-read', '/api/notifications/read-all'], auth, async (req, res) => {
  try {
    await query('UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false', [req.userId]);
    res.json({ success: true });
  } catch (err) {
    // Reporting success for a write that did not happen. The client cleared the
    // badge on that answer and the rows stayed unread, so the count reappeared
    // on the next load — and Notifications.tsx's markAll() rollback, which
    // exists for exactly this, never ran because the call had "succeeded".
    serverError(err, res);
  }
});

// POST /api/notifications/:id/read
router.post('/api/notifications/:id/read', auth, async (req, res) => {
  // `isNaN(parseInt('5abc'))` is false, so '5abc' passed this guard and went
  // into `WHERE id = $1`, where Postgres refused the cast.
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Notification not found' });
  try {
    const result = await query(
      'UPDATE notifications SET is_read = true WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Notification not found' });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/notifications/:id
router.delete('/api/notifications/:id', auth, async (req, res) => {
  if (!isIdParam(req.params.id)) return res.status(404).json({ error: 'Notification not found' });
  try {
    const result = await query(
      'DELETE FROM notifications WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Notification not found' });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/notifications — delete all
router.delete('/api/notifications', auth, async (req, res) => {
  try {
    await query('DELETE FROM notifications WHERE user_id = $1', [req.userId]);
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

module.exports = router;

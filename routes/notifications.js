/**
 * routes/notifications.js — /api/notifications/*
 */
const router = require('express').Router();
const { query } = require('../src/db');
const { serverError } = require('../src/helpers');
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
    res.json({ unread_count: 0, count: 0 });
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
    res.json({ notifications: [], unread_count: 0, total: 0 });
  }
});

// POST /api/notifications/mark-read (alias: /read-all)
router.post(['/api/notifications/mark-read', '/api/notifications/read-all'], auth, async (req, res) => {
  try {
    await query('UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false', [req.userId]);
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true });
  }
});

// POST /api/notifications/:id/read
router.post('/api/notifications/:id/read', auth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Notification not found' });
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
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Notification not found' });
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

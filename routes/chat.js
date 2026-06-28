/**
 * routes/chat.js — /api/chat/*, /api/push/*
 */
const router = require('express').Router();
const crypto = require('crypto');
const { query } = require('../src/db');
const { notify, serverError } = require('../src/helpers');
const { auth, softAuth, checkBlocked, messageLimiter } = require('../src/middleware');
const multer = require('multer');
const normalizeId = (id) => (id || '').toString().toLowerCase().replace(/^pi_/, '');
// memoryStorage — NOT disk: Render's filesystem is ephemeral (wiped on every
// restart/deploy), so 'uploads/' would lose files. We persist bytes in Postgres
// (chat_attachments) so attachments survive restarts. 5 MB cap.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// GET /api/chat/rooms
router.get('/api/chat/rooms', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const [result, totalRes] = await Promise.all([
      query(
        `SELECT r.*,
          (SELECT message FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message,
          (SELECT created_at FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
          j.title as job_title,
          CASE WHEN r.client_id = $1 THEN r.freelancer_id ELSE r.client_id END as other_user_id,
          CASE WHEN r.client_id = $1 THEN uf.username ELSE uc.username END as other_user_name
         FROM chat_rooms r
         LEFT JOIN jobs j ON j.id = r.job_id
         LEFT JOIN users uc ON uc.id = r.client_id
         LEFT JOIN users uf ON uf.id = r.freelancer_id
         WHERE r.client_id = $1 OR r.freelancer_id = $1
         ORDER BY last_message_at DESC NULLS LAST
         LIMIT $2 OFFSET $3`,
        [req.userId, limit, offset]
      ),
      query('SELECT COUNT(*) FROM chat_rooms WHERE client_id = $1 OR freelancer_id = $1', [req.userId]),
    ]);
    res.json({ rooms: result.rows, total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/chat/rooms
router.post('/api/chat/rooms', auth, checkBlocked, messageLimiter, async (req, res) => {
  const { freelancer_id, job_id } = req.body;
  const cId = req.userId;
  if (!freelancer_id || !job_id) return res.status(400).json({ error: 'freelancer_id and job_id required' });
  if (freelancer_id === cId) return res.status(400).json({ error: 'Cannot create a chat room with yourself' });
  try {
    const targetExists = await query('SELECT id FROM users WHERE id = $1 LIMIT 1', [freelancer_id]);
    if (!targetExists.rows.length) return res.status(404).json({ error: 'User not found' });
    const jobCheck = await query('SELECT posted_by, hired_freelancer_id FROM jobs WHERE id = $1', [job_id]);
    if (!jobCheck.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobCheck.rows[0];
    if (job.posted_by !== cId) {
      const appCheck = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2 LIMIT 1', [job_id, cId]);
      if (!appCheck.rows.length) return res.status(403).json({ error: 'You are not a participant in this job' });
    }
    const existing = await query(
      'SELECT * FROM chat_rooms WHERE job_id = $1 AND ((client_id = $2 AND freelancer_id = $3) OR (client_id = $3 AND freelancer_id = $2))',
      [job_id, cId, freelancer_id]
    );
    if (existing.rows.length) return res.json({ room: existing.rows[0] });
    const roomId = 'room_' + crypto.randomUUID();
    const result = await query(
      'INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [roomId, cId, freelancer_id, job_id]
    );
    res.json({ room: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

// GET /api/chat/rooms/:id — specific room details
router.get('/api/chat/rooms/:id', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT cr.*,
              u1.username as client_username, u2.username as freelancer_username
       FROM chat_rooms cr
       LEFT JOIN users u1 ON u1.id = cr.client_id
       LEFT JOIN users u2 ON u2.id = cr.freelancer_id
       WHERE cr.id = $1 AND (cr.client_id = $2 OR cr.freelancer_id = $2)`,
      [req.params.id, req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Room not found' });
    res.json({ room: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

// GET /api/chat/rooms/:id/messages
router.get('/api/chat/rooms/:id/messages', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 100, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const [result, totalRes] = await Promise.all([
      query('SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3', [req.params.id, limit, offset]),
      query('SELECT COUNT(*) FROM chat_messages WHERE room_id = $1', [req.params.id]),
    ]);
    const messages = result.rows.map(m => ({ ...m, content: m.message, text: m.message }));
    res.json({ messages, total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/chat/rooms/:id/messages
router.post('/api/chat/rooms/:id/messages', auth, checkBlocked, messageLimiter, async (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });
  if (message.length > 2000) return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const userResult = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userResult.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.id, req.userId, senderName, message.trim()]
    );
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    const otherUserId = normalizeId(room.rows[0].client_id) === normalizeId(req.userId) ? room.rows[0].freelancer_id : room.rows[0].client_id;
    if (otherUserId) {
      await notify(otherUserId, 'message', `Новое сообщение от ${senderName}`, message.trim().substring(0, 100), null, req.params.id);
    }
    res.json({ message: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

// POST /api/chat/start
router.post('/api/chat/start', auth, checkBlocked, messageLimiter, async (req, res) => {
  const { other_user_id, job_id } = req.body;
  if (!other_user_id) return res.status(400).json({ error: 'other_user_id required' });
  if (other_user_id === req.userId) return res.status(400).json({ error: 'Cannot start a chat with yourself' });
  try {
    const otherExists = await query('SELECT id FROM users WHERE id = $1 LIMIT 1', [other_user_id]);
    if (!otherExists.rows.length) return res.status(404).json({ error: 'User not found' });
    const jobId = job_id ? parseInt(job_id) : null;
    if (jobId) {
      const jobCheck = await query('SELECT posted_by FROM jobs WHERE id = $1', [jobId]);
      if (!jobCheck.rows.length) return res.status(404).json({ error: 'Job not found' });
      if (normalizeId(jobCheck.rows[0].posted_by) !== normalizeId(req.userId)) {
        const appCheck = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2 LIMIT 1', [jobId, req.userId]);
        if (!appCheck.rows.length) return res.status(403).json({ error: 'You are not a participant in this job' });
      }
    }
    const existing = jobId
      ? await query(
          'SELECT * FROM chat_rooms WHERE job_id = $3 AND ((client_id = $1 AND freelancer_id = $2) OR (client_id = $2 AND freelancer_id = $1))',
          [req.userId, other_user_id, jobId]
        )
      : await query(
          'SELECT * FROM chat_rooms WHERE job_id IS NULL AND ((client_id = $1 AND freelancer_id = $2) OR (client_id = $2 AND freelancer_id = $1))',
          [req.userId, other_user_id]
        );
    if (existing.rows.length) return res.json({ conversation: existing.rows[0], id: existing.rows[0].id });
    const roomId = 'room_' + crypto.randomUUID();
    const result = await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *', [roomId, req.userId, other_user_id, jobId]);
    res.json({ conversation: result.rows[0], id: result.rows[0].id });
  } catch (err) { serverError(err, res); }
});

// GET /api/chat/conversations — alias for rooms
router.get('/api/chat/conversations', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const [result, totalRes] = await Promise.all([
      query(
        `SELECT r.*,
          (SELECT message FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message,
          (SELECT created_at FROM chat_messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
          j.title as job_title,
          CASE WHEN r.client_id = $1 THEN r.freelancer_id ELSE r.client_id END as other_user_id,
          CASE WHEN r.client_id = $1 THEN uf.username ELSE uc.username END as other_user_name
         FROM chat_rooms r
         LEFT JOIN jobs j ON j.id = r.job_id
         LEFT JOIN users uc ON uc.id = r.client_id
         LEFT JOIN users uf ON uf.id = r.freelancer_id
         WHERE r.client_id = $1 OR r.freelancer_id = $1
         ORDER BY last_message_at DESC NULLS LAST
         LIMIT $2 OFFSET $3`,
        [req.userId, limit, offset]
      ),
      query('SELECT COUNT(*) FROM chat_rooms WHERE client_id = $1 OR freelancer_id = $1', [req.userId]),
    ]);
    res.json({ conversations: result.rows, rooms: result.rows, total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/chat/conversations
router.post('/api/chat/conversations', auth, checkBlocked, messageLimiter, async (req, res) => {
  const { freelancer_id, job_id, other_user_id } = req.body;
  const cId = req.userId;
  const fId = freelancer_id || other_user_id;
  if (!fId || !job_id) return res.status(400).json({ error: 'freelancer_id and job_id required' });
  if (fId === cId) return res.status(400).json({ error: 'Cannot create a conversation with yourself' });
  try {
    const targetExists = await query('SELECT id FROM users WHERE id = $1 LIMIT 1', [fId]);
    if (!targetExists.rows.length) return res.status(404).json({ error: 'User not found' });
    const jobCheck = await query('SELECT posted_by, hired_freelancer_id FROM jobs WHERE id = $1', [job_id]);
    if (!jobCheck.rows.length) return res.status(404).json({ error: 'Job not found' });
    const job = jobCheck.rows[0];
    const isJobPoster = job.posted_by === cId;
    if (!isJobPoster) {
      const appCheck = await query('SELECT id FROM applications WHERE job_id = $1 AND freelancer_id = $2 LIMIT 1', [job_id, cId]);
      if (!appCheck.rows.length) return res.status(403).json({ error: 'You are not a participant in this job' });
    }
    const existing = await query('SELECT * FROM chat_rooms WHERE job_id = $1 AND ((client_id = $2 AND freelancer_id = $3) OR (client_id = $3 AND freelancer_id = $2))', [job_id, cId, fId]);
    if (existing.rows.length) return res.json({ conversation: existing.rows[0], room: existing.rows[0] });
    const roomId = 'room_' + crypto.randomUUID();
    const result = await query('INSERT INTO chat_rooms (id, client_id, freelancer_id, job_id) VALUES ($1, $2, $3, $4) RETURNING *', [roomId, cId, fId, job_id]);
    res.json({ conversation: result.rows[0], room: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

// GET /api/chat/conversations/:id/messages
router.get('/api/chat/conversations/:id/messages', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 100, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const [result, totalRes] = await Promise.all([
      query('SELECT * FROM chat_messages WHERE room_id = $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3', [req.params.id, limit, offset]),
      query('SELECT COUNT(*) FROM chat_messages WHERE room_id = $1', [req.params.id]),
    ]);
    const messages = result.rows.map(m => ({ ...m, content: m.message, text: m.message }));
    res.json({ messages, total: parseInt(totalRes.rows[0].count), limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/chat/conversations/:id/messages
router.post('/api/chat/conversations/:id/messages', auth, checkBlocked, messageLimiter, async (req, res) => {
  const msg = req.body.content || req.body.message;
  if (!msg || !msg.trim()) return res.status(400).json({ error: 'Message required' });
  if (msg.length > 2000) return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
  try {
    const room = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!room.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const userResult = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userResult.rows[0]?.username || req.userId;
    const result = await query('INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *', [req.params.id, req.userId, senderName, msg.trim()]);
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    const otherUserId = normalizeId(room.rows[0].client_id) === normalizeId(req.userId) ? room.rows[0].freelancer_id : room.rows[0].client_id;
    const newMsg = result.rows[0];
    // Emit real-time event to all sockets in this room
    const io = req.app.get('io');
    if (io) io.to(req.params.id).emit('new_message', newMsg);
    if (otherUserId) {
      await notify(otherUserId, 'message', `Новое сообщение от ${senderName}`, msg.trim().substring(0, 100), null, req.params.id).catch(() => {});
      // Web Push notification to recipient
      const webpush = req.app.get('webpush');
      if (webpush) {
        const subRow = await query('SELECT endpoint, keys FROM push_subscriptions WHERE user_id = $1', [otherUserId]).catch(() => null);
        if (subRow && subRow.rows.length) {
          const sub = subRow.rows[0];
          webpush.sendNotification(
            { endpoint: sub.endpoint, keys: sub.keys },
            JSON.stringify({ title: `Message from ${senderName}`, body: msg.trim().substring(0, 80), icon: '/icon-192.png' })
          ).catch(() => {}); // fire-and-forget
        }
      }
    }
    res.json({ message: newMsg });
  } catch (err) { serverError(err, res); }
});

// GET /api/chat/unread
router.get('/api/chat/unread', auth, async (req, res) => {
  try {
    const result = await query(
      `SELECT COUNT(*) FROM chat_messages cm
       JOIN chat_rooms r ON r.id = cm.room_id
       WHERE (r.client_id = $1 OR r.freelancer_id = $1) AND cm.sender_id != $1
       AND cm.created_at > COALESCE(
         (SELECT last_read_at FROM chat_room_reads WHERE room_id = r.id AND user_id = $1),
         NOW() - INTERVAL '7 days'
       )`,
      [req.userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) { res.json({ count: 0 }); }
});

// GET /api/chat/unread/:roomId
router.get('/api/chat/unread/:roomId', auth, async (req, res) => {
  try {
    const access = await query('SELECT id FROM chat_rooms WHERE id=$1 AND (client_id=$2 OR freelancer_id=$2)', [req.params.roomId, req.userId]);
    if (!access.rows.length) return res.status(403).json({ error: 'Forbidden' });
    const result = await query(
      `SELECT COUNT(*) FROM chat_messages
       WHERE room_id=$1 AND sender_id!=$2
       AND created_at > COALESCE(
         (SELECT last_read_at FROM chat_room_reads WHERE room_id=$1 AND user_id=$2),
         NOW() - INTERVAL '7 days'
       )`,
      [req.params.roomId, req.userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) { res.json({ count: 0 }); }
});

// POST /api/chat/read-all
router.post('/api/chat/read-all', auth, messageLimiter, async (req, res) => {
  try {
    const { room_id } = req.body;
    if (room_id) {
      const access = await query('SELECT id FROM chat_rooms WHERE id=$1 AND (client_id=$2 OR freelancer_id=$2)', [room_id, req.userId]);
      if (access.rows.length) {
        await query(
          `INSERT INTO chat_room_reads (room_id, user_id, last_read_at) VALUES ($1,$2,NOW())
           ON CONFLICT (room_id, user_id) DO UPDATE SET last_read_at=NOW()`,
          [room_id, req.userId]
        );
      }
    } else {
      const rooms = await query('SELECT id FROM chat_rooms WHERE client_id=$1 OR freelancer_id=$1', [req.userId]);
      for (const row of rooms.rows) {
        await query(
          `INSERT INTO chat_room_reads (room_id, user_id, last_read_at) VALUES ($1,$2,NOW())
           ON CONFLICT (room_id, user_id) DO UPDATE SET last_read_at=NOW()`,
          [row.id, req.userId]
        ).catch(() => {});
      }
    }
    res.json({ success: true });
  } catch (_) { res.json({ success: true }); }
});

// POST /api/chat/:roomId/messages — alias
router.post('/api/chat/:roomId/messages', auth, messageLimiter, checkBlocked, async (req, res) => {
  const { content, message, text } = req.body;
  const msg = content || message || text || '';
  if (!msg.trim()) return res.status(400).json({ error: 'Message content required' });
  if (msg.length > 2000) return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
  try {
    const roomCheck = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.roomId, req.userId]);
    if (!roomCheck.rows.length) return res.status(403).json({ error: 'Not in this room' });
    const userRes = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userRes.rows[0]?.username || req.userId;
    const result = await query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.params.roomId, req.userId, senderName, msg]
    );
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.roomId]);
    // Real-time: broadcast to everyone in the room (this is the route the frontend actually uses).
    const io = req.app.get('io');
    if (io) io.to(req.params.roomId).emit('new_message', result.rows[0]);
    const otherUserId2 = normalizeId(roomCheck.rows[0].client_id) === normalizeId(req.userId) ? roomCheck.rows[0].freelancer_id : roomCheck.rows[0].client_id;
    if (otherUserId2) {
      await notify(otherUserId2, 'message', `Новое сообщение от ${senderName}`, msg.substring(0, 100), null, req.params.roomId).catch(() => {});
      // Web Push to recipient (same as the /conversations route — this is the route the frontend uses).
      const webpush = req.app.get('webpush');
      if (webpush) {
        const subRow = await query('SELECT endpoint, keys FROM push_subscriptions WHERE user_id = $1', [otherUserId2]).catch(() => null);
        if (subRow && subRow.rows.length) {
          const sub = subRow.rows[0];
          webpush.sendNotification(
            { endpoint: sub.endpoint, keys: sub.keys },
            JSON.stringify({ title: `Message from ${senderName}`, body: msg.substring(0, 80), icon: '/icon-192.png' })
          ).catch(() => {}); // fire-and-forget
        }
      }
    }
    res.json({ message: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// GET /api/chat/:roomId/messages — alias
router.get('/api/chat/:roomId/messages', auth, async (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 100, 200));
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  try {
    const roomCheck = await query(
      'SELECT id FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)',
      [req.params.roomId, req.userId]
    );
    if (!roomCheck.rows.length) return res.status(403).json({ error: 'Access denied' });
    const result = await query(
      `SELECT cm.*, u.username as sender_username,
              cm.message as content, cm.message as text
       FROM chat_messages cm
       LEFT JOIN users u ON u.id = cm.sender_id
       WHERE cm.room_id = $1
       ORDER BY cm.created_at ASC
       LIMIT $2 OFFSET $3`,
      [req.params.roomId, limit, offset]
    );
    res.json({ messages: result.rows, limit, offset });
  } catch (err) { serverError(err, res); }
});

// POST /api/chat/rooms/:id/upload — upload a file attachment to a chat room.
// File is stored in Postgres (durable across Render restarts), then posted as a
// chat message whose body links to GET /api/chat/attachments/:attId.
const uploadSingle = (req, res, next) => upload.single('file')(req, res, (err) => {
  if (err) {
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'File too large (max 5 MB)' });
    return res.status(400).json({ error: err.message || 'Upload failed' });
  }
  next();
});
router.post('/api/chat/rooms/:id/upload', auth, checkBlocked, messageLimiter, uploadSingle, async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded (field name must be "file")' });
    const roomCheck = await query('SELECT * FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [req.params.id, req.userId]);
    if (!roomCheck.rows.length) return res.status(403).json({ error: 'Not in this room' });
    const attId = 'att_' + crypto.randomBytes(12).toString('hex');
    await query(
      'INSERT INTO chat_attachments (id, room_id, uploader_id, filename, mimetype, size, data) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [attId, req.params.id, req.userId, req.file.originalname, req.file.mimetype, req.file.size, req.file.buffer]
    );
    const userRes = await query('SELECT username FROM users WHERE id = $1', [req.userId]);
    const senderName = userRes.rows[0]?.username || req.userId;
    const body = `📎 ${req.file.originalname}|/api/chat/attachments/${attId}`;
    const result = await query(
      'INSERT INTO chat_messages (room_id, sender_id, sender_name, message) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.params.id, req.userId, senderName, body]
    );
    await query('UPDATE chat_rooms SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    const io = req.app.get('io');
    if (io) io.to(req.params.id).emit('new_message', result.rows[0]);
    const otherId = normalizeId(roomCheck.rows[0].client_id) === normalizeId(req.userId) ? roomCheck.rows[0].freelancer_id : roomCheck.rows[0].client_id;
    if (otherId) await notify(otherId, 'message', `Файл от ${senderName}`, req.file.originalname, null, req.params.id).catch(() => {});
    res.json({ success: true, attachment_id: attId, url: `/api/chat/attachments/${attId}`, message: result.rows[0] });
  } catch (err) { serverError(err, res); }
});

// GET /api/chat/attachments/:attId — stream a stored attachment (room members only).
router.get('/api/chat/attachments/:attId', auth, async (req, res) => {
  try {
    const r = await query('SELECT * FROM chat_attachments WHERE id = $1', [req.params.attId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Attachment not found' });
    const att = r.rows[0];
    const member = await query('SELECT id FROM chat_rooms WHERE id = $1 AND (client_id = $2 OR freelancer_id = $2)', [att.room_id, req.userId]);
    if (!member.rows.length) return res.status(403).json({ error: 'Access denied' });
    res.setHeader('Content-Type', att.mimetype || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(att.filename)}"`);
    res.send(att.data);
  } catch (err) { serverError(err, res); }
});

// GET /api/push/vapid-key — return the VAPID public key for the client
router.get('/api/push/vapid-key', (req, res) => {
  const key = process.env.VAPID_PUBLIC_KEY || null;
  if (!key) return res.status(503).json({ error: 'Web Push not configured' });
  res.json({ publicKey: key });
});

// POST /api/push/subscribe — Web Push notification subscription
router.post('/api/push/subscribe', softAuth, async (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (endpoint && !endpoint.startsWith('https://')) {
    return res.status(400).json({ error: 'Invalid push endpoint' });
  }
  if (req.userId && endpoint) {
    await query(
      `INSERT INTO push_subscriptions (user_id, endpoint, keys, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id) DO UPDATE SET endpoint=$2, keys=$3, updated_at=NOW()`,
      [req.userId, endpoint, JSON.stringify(keys || {})]
    ).catch(() => {});
  }
  res.json({ success: true });
});

module.exports = router;

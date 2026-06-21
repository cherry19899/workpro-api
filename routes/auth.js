/**
 * routes/auth.js — /api/me, /api/auth/*, /api/users/me routes
 */
const router = require('express').Router();
const jwt = require('jsonwebtoken');
const { query } = require('../src/db');
const { piApiRequest, audit, serverError } = require('../src/helpers');
const { auth, softAuth, checkBlocked, authLimiter, JWT_SECRET } = require('../src/middleware');

// ─── Level helper (used by GET /api/me) ──────────────────────────────────────
function computeLevel(completedJobs, rating) {
  const r = parseFloat(rating) || 0;
  const j = parseInt(completedJobs) || 0;
  if (j >= 50 && r >= 4.7) return { level: 5, title: 'Легенда', emoji: '🏆', nextJobs: null, nextRating: null };
  if (j >= 25 && r >= 4.5) return { level: 4, title: 'Эксперт', emoji: '💎', nextJobs: 50, nextRating: 4.7 };
  if (j >= 10 && r >= 4.3) return { level: 3, title: 'Профи', emoji: '🥇', nextJobs: 25, nextRating: 4.5 };
  if (j >= 3 && r >= 4.0) return { level: 2, title: 'Восходящий талант', emoji: '⭐', nextJobs: 10, nextRating: 4.3 };
  return { level: 1, title: 'Новичок', emoji: '🌱', nextJobs: 3, nextRating: 4.0 };
}

// PUT /api/me — update profile
router.put('/api/me', auth, checkBlocked, async (req, res) => {
  const { username, bio, skills, display_name } = req.body;
  if (bio && bio.length > 1000) return res.status(400).json({ error: 'Bio too long (max 1000)' });
  try {
    const uname = display_name || username;
    if (uname && uname.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
    const skillsStr = Array.isArray(skills) ? skills.join(',') : (skills || null);
    if (skillsStr && skillsStr.length > 300) return res.status(400).json({ error: 'Skills too long (max 300)' });
    await query(
      'UPDATE users SET username = COALESCE($1, username), bio = COALESCE($2, bio), skills = COALESCE($3, skills), updated_at = NOW() WHERE id = $4',
      [uname || null, bio || null, skillsStr, req.userId]
    );
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1', [req.userId]);
    const u = result.rows[0];
    if (!Array.isArray(u.skills)) {
      u.skills = (typeof u.skills === 'string' && u.skills && u.skills !== '{}')
        ? u.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
    }
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { serverError(err, res); }
});

// GET /api/me — get current user profile
router.get('/api/me', auth, async (req, res) => {
  try {
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1', [req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    if (!Array.isArray(u.skills)) {
      u.skills = (typeof u.skills === 'string' && u.skills && u.skills !== '{}')
        ? u.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
    }
    const levelInfo = computeLevel(u.total_jobs_completed, u.rating);
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin', level: levelInfo });
  } catch (err) { serverError(err, res); }
});

// POST /api/me — alias login endpoint used by Auth.js + bundle registration
router.post('/api/me', authLimiter, async (req, res) => {
  const { uid, username, accessToken } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid required' });
  if (username && username.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
  try {
    if (accessToken) {
      try {
        const piUser = await piApiRequest('/v2/me', 'GET', null, accessToken);
        const piUid = piUser && (piUser.uid || piUser.username);
        if (!piUid) return res.status(403).json({ error: 'Pi identity verification failed: no uid returned' });
        const normalizedPiUid = piUid.startsWith('pi_') ? piUid : 'pi_' + piUid;
        if (normalizedPiUid !== uid && piUid !== uid) {
          return res.status(403).json({ error: 'Token does not match uid' });
        }
      } catch (e) {
        return res.status(401).json({ error: 'Pi token verification failed. Please re-authenticate.' });
      }
    } else {
      if (!process.env.SANDBOX_MODE) {
        return res.status(401).json({ error: 'accessToken required' });
      }
      // SANDBOX_MODE only — skip Pi verification for local/test environments
      const existing = await query('SELECT id FROM users WHERE id = $1', [uid]);
      if (!existing.rows.length) {
        return res.status(401).json({ error: 'accessToken required for new account registration' });
      }
    }
    const uname = username || uid.replace(/^pi_/, '') || uid;
    if (accessToken) {
      await query(
        `INSERT INTO users (id, username, role, balance_connects, created_at, updated_at)
         VALUES ($1, $2, 'freelancer', 10, NOW(), NOW())
         ON CONFLICT (id) DO UPDATE SET username = EXCLUDED.username, updated_at = NOW()`,
        [uid, uname]
      );
    } else {
      await query(
        `INSERT INTO users (id, username, role, balance_connects, created_at, updated_at)
         VALUES ($1, $2, 'freelancer', 10, NOW(), NOW())
         ON CONFLICT (id) DO UPDATE SET updated_at = NOW()`,
        [uid, uname]
      );
    }
    // Migrate legacy 'cherry19899' records to 'pi_cherry19899' (idempotent, runs every login)
    if (uid === 'pi_cherry19899') {
      try {
        await query(`UPDATE users SET role = 'admin' WHERE id = 'pi_cherry19899' AND role != 'admin'`).catch(() => {});
        const r1 = await query(`UPDATE jobs SET posted_by = 'pi_cherry19899' WHERE posted_by = 'cherry19899'`);
        const r2 = await query(`UPDATE applications SET freelancer_id = 'pi_cherry19899' WHERE freelancer_id = 'cherry19899'`);
        await query(`UPDATE escrows SET client_id = 'pi_cherry19899' WHERE client_id = 'cherry19899'`);
        await query(`UPDATE escrows SET freelancer_id = 'pi_cherry19899' WHERE freelancer_id = 'cherry19899'`);
        const legacyUser = await query(`SELECT balance_connects, bio, skills FROM users WHERE id = 'cherry19899'`);
        if (legacyUser.rows.length > 0) {
          const old = legacyUser.rows[0];
          await query(`UPDATE users SET balance_connects = GREATEST(balance_connects, $1), bio = COALESCE(NULLIF(bio,''), $2), skills = COALESCE(NULLIF(skills,''), $3) WHERE id = 'pi_cherry19899'`,
            [old.balance_connects || 0, old.bio || '', old.skills || '']);
          await query(`DELETE FROM users WHERE id = 'cherry19899'`);
        }
        await query(`UPDATE notifications SET user_id = 'pi_cherry19899' WHERE user_id = 'cherry19899'`);
        if (r1.rowCount > 0 || r2.rowCount > 0) console.log(`[Migration] cherry19899→pi_cherry19899: jobs=${r1.rowCount} apps=${r2.rowCount}`);
      } catch (mErr) { console.error('[Migration] error:', mErr.message); }
    }
    // Owner self-heal: any uid whose username is cherry19899 (any case) always gets admin.
    // On Pi mainnet the real uid is pi_<uuid>, not pi_cherry19899, so a uid check alone never fires.
    if ((uname && uname.toLowerCase() === 'cherry19899') ||
        uid === 'pi_cherry19899' ||
        uid === 'pi_a2b617f7-f510-4502-a046-805facedcc29') {
      await query(`UPDATE users SET role = 'admin' WHERE id = $1 AND role != 'admin'`, [uid]).catch(() => {});
    }
    await query(`UPDATE users SET total_jobs_posted = (SELECT COUNT(*) FROM jobs WHERE posted_by = $1), updated_at = NOW() WHERE id = $1`, [uid]).catch(() => {});
    const user = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at FROM users WHERE id = $1', [uid]);
    const u = user.rows[0];
    if (u && u.status === 'deleted') {
      return res.status(403).json({ error: 'Account has been deleted' });
    }
    await audit('user_login', { user_id: uid });
    const token = jwt.sign({ id: uid, username: uname }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin', token });
  } catch (err) { serverError(err, res); }
});

// POST /api/auth/refresh — exchange any JWT (including expired) for a fresh 30-day token
router.post('/api/auth/refresh', async (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  if (!authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Token required' });
  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
    const user = await query('SELECT id, username, role, status FROM users WHERE id = $1 LIMIT 1', [decoded.id]);
    if (!user.rows.length) return res.status(401).json({ error: 'User not found' });
    const u = user.rows[0];
    if (u.status === 'deleted') return res.status(403).json({ error: 'Account has been deleted' });
    const newToken = jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token: newToken, is_admin: u.role === 'admin' });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// POST /api/auth/login
router.post('/api/auth/login', async (req, res) => {
  const { userId, username, accessToken } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  if (username && username.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
  try {
    let piUser = null;
    if (accessToken) {
      try {
        piUser = await piApiRequest('/v2/me', 'GET', null, accessToken);
      } catch (e) {
        return res.status(401).json({ error: 'Pi token verification failed. Please re-authenticate.' });
      }
      const piUid = piUser && (piUser.uid || piUser.username);
      if (!piUid) return res.status(403).json({ error: 'Pi identity verification failed: no uid returned' });
      const normalizedPiUid = piUid.startsWith('pi_') ? piUid : 'pi_' + piUid;
      if (normalizedPiUid !== userId && piUid !== userId) {
        return res.status(403).json({ error: 'Token does not match userId' });
      }
    } else {
      if (!process.env.SANDBOX_MODE) {
        return res.status(401).json({ error: 'accessToken required' });
      }
      // SANDBOX_MODE only — skip Pi verification for local/test environments
      const existing = await query('SELECT id FROM users WHERE id = $1', [userId]);
      if (!existing.rows.length) {
        return res.status(401).json({ error: 'accessToken required for new account registration' });
      }
    }
    const uid = userId;
    const uname = (piUser && piUser.username) || username || uid;
    const paymentsEnabled = piUser ? piUser.payments_enabled === true : false;
    const existing = await query('SELECT id, username, role FROM users WHERE id = $1', [uid]);
    if (!existing.rows.length) {
      await query(
        'INSERT INTO users (id, username, role, balance_connects, created_at, updated_at) VALUES ($1, $2, $3, 10, NOW(), NOW())',
        [uid, uname, 'freelancer']
      );
    } else if (piUser) {
      await query('UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2', [uname, uid]);
    } else {
      await query('UPDATE users SET updated_at = NOW() WHERE id = $1', [uid]);
    }
    const user = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at FROM users WHERE id = $1', [uid]);
    if (user.rows[0]?.status === 'deleted') {
      return res.status(403).json({ error: 'Account has been deleted' });
    }
    const token = jwt.sign({ id: uid, username: uname }, JWT_SECRET, { expiresIn: '30d' });
    await audit('user_login', { user_id: uid });
    res.json({ token, user: { ...user.rows[0], payments_enabled: paymentsEnabled } });
  } catch (err) { serverError(err, res); }
});

// GET /api/auth/me
router.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1',
      [req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    if (!Array.isArray(u.skills)) {
      u.skills = (typeof u.skills === 'string' && u.skills && u.skills !== '{}')
        ? u.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
    }
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { serverError(err, res); }
});

// GET /api/users/me — get current user profile
router.get('/api/users/me', auth, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1',
      [req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { serverError(err, res); }
});

// PUT /api/users/me — update current user profile
router.put('/api/users/me', auth, checkBlocked, async (req, res) => {
  const { username, bio, skills, availability, avatar, email } = req.body;
  if (username && username.length > 50) return res.status(400).json({ error: 'Username too long (max 50)' });
  if (bio && bio.length > 1000) return res.status(400).json({ error: 'Bio too long (max 1000)' });
  const skillsStr = skills !== undefined ? (Array.isArray(skills) ? skills.join(',') : (skills || null)) : undefined;
  if (skillsStr && skillsStr.length > 300) return res.status(400).json({ error: 'Skills too long (max 300)' });
  if (avatar && !/^https?:\/\//i.test(avatar) && !/^data:image\//i.test(avatar)) {
    return res.status(400).json({ error: 'Avatar must be a URL (http/https) or base64 image (data:image/...)' });
  }
  if (avatar && avatar.length > 2 * 1024 * 1024 * 1.37) return res.status(400).json({ error: 'Avatar too large (max 2MB)' });
  if (email && (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return res.status(400).json({ error: 'Invalid email address' });
  const ALLOWED_AVAILABILITY = ['available', 'busy', 'away', 'unavailable'];
  if (availability && !ALLOWED_AVAILABILITY.includes(availability)) {
    return res.status(400).json({ error: 'Invalid availability value' });
  }
  try {
    const fields = [], vals = [];
    let i = 1;
    if (username) { fields.push(`username=$${i++}`); vals.push(username); }
    if (bio !== undefined) { fields.push(`bio=$${i++}`); vals.push(bio); }
    if (skillsStr !== undefined) { fields.push(`skills=$${i++}`); vals.push(skillsStr); }
    if (availability) { fields.push(`availability=$${i++}`); vals.push(availability); }
    if (avatar) { fields.push(`avatar=$${i++}`); vals.push(avatar); }
    if (email) { fields.push(`email=$${i++}`); vals.push(email); }
    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
    fields.push(`updated_at=NOW()`);
    vals.push(req.userId);
    await query(`UPDATE users SET ${fields.join(',')} WHERE id=$${i}`, vals);
    const result = await query('SELECT id, username, role, rating, total_jobs_posted, total_jobs_completed, bio, skills, avatar, kyc_verified, availability, balance_connects, balance_pi, is_blocked, status, created_at, updated_at FROM users WHERE id = $1', [req.userId]);
    const u = result.rows[0];
    if (!Array.isArray(u.skills)) {
      u.skills = (typeof u.skills === 'string' && u.skills && u.skills !== '{}')
        ? u.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
    }
    res.json({ ...u, uid: u.id, is_admin: u.role === 'admin' });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/users/me — account deletion
router.delete('/api/users/me', auth, async (req, res) => {
  try {
    const active = await query(
      `(SELECT 1 FROM jobs WHERE posted_by=$1 AND status IN ('open','in_progress','submitted') LIMIT 1)
       UNION ALL
       (SELECT 1 FROM jobs WHERE hired_freelancer_id=$1 AND status IN ('in_progress','submitted') LIMIT 1)
       UNION ALL
       (SELECT 1 FROM escrows WHERE (client_id=$1 OR freelancer_id=$1) AND status IN ('pending','funded') LIMIT 1)`,
      [req.userId]
    );
    if (active.rows.length > 0) {
      return res.status(400).json({ error: 'Нельзя удалить аккаунт с активными задачами или эскроу' });
    }
    await query('UPDATE users SET is_blocked = true, status = $1, updated_at = NOW() WHERE id = $2', ['deleted', req.userId]);
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

// PUT /api/users/me/portfolio
router.put('/api/users/me/portfolio', auth, checkBlocked, async (req, res) => {
  const { headline, summary, experience_years, website, github, linkedin } = req.body;
  if (headline && headline.length > 200) return res.status(400).json({ error: 'Headline too long (max 200)' });
  if (summary && summary.length > 2000) return res.status(400).json({ error: 'Summary too long (max 2000)' });
  if (website && !/^https?:\/\//i.test(website)) return res.status(400).json({ error: 'Website must start with http:// or https://' });
  if (github && (github.length > 200 || !/^https?:\/\//i.test(github))) return res.status(400).json({ error: 'GitHub must be a valid http/https URL (max 200)' });
  if (linkedin && (linkedin.length > 200 || !/^https?:\/\//i.test(linkedin))) return res.status(400).json({ error: 'LinkedIn must be a valid http/https URL (max 200)' });
  if (experience_years !== undefined && (parseInt(experience_years) < 0 || parseInt(experience_years) > 60)) {
    return res.status(400).json({ error: 'experience_years must be 0–60' });
  }
  try {
    await query(
      `INSERT INTO portfolios (user_id, headline, summary, experience_years, website, github, linkedin)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (user_id) DO UPDATE SET headline=$2, summary=$3, experience_years=$4, website=$5, github=$6, linkedin=$7, updated_at=NOW()`,
      [req.userId, headline || '', summary || '', parseInt(experience_years || 0), website || '', github || '', linkedin || '']
    );
    const result = await query('SELECT * FROM portfolios WHERE user_id = $1', [req.userId]);
    res.json({ portfolio: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// POST /api/users/me/portfolio/items
router.post('/api/users/me/portfolio/items', auth, checkBlocked, async (req, res) => {
  const { title, description, image_url, url, category, tags } = req.body;
  const finalUrl = image_url || url || '';
  if (!title) return res.status(400).json({ error: 'title required' });
  if (String(title).length > 200) return res.status(400).json({ error: 'Title too long (max 200)' });
  if (description && description.length > 2000) return res.status(400).json({ error: 'Description too long (max 2000)' });
  if (category && category.length > 100) return res.status(400).json({ error: 'Category too long (max 100)' });
  const tagsRaw = Array.isArray(tags) ? tags.join(',') : (tags || '');
  if (tagsRaw.length > 500) return res.status(400).json({ error: 'Tags too long (max 500 chars combined)' });
  if (finalUrl && !/^https?:\/\//i.test(finalUrl)) return res.status(400).json({ error: 'URL must start with http:// or https://' });
  try {
    const itemCount = await query('SELECT COUNT(*) FROM portfolio_items WHERE user_id = $1', [req.userId]);
    if (parseInt(itemCount.rows[0].count) >= 20) return res.status(400).json({ error: 'Portfolio limited to 20 items' });
    const result = await query(
      'INSERT INTO portfolio_items (user_id, title, description, image_url, category, tags) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.userId, title, description || '', finalUrl, category || 'Other', tagsRaw]
    );
    res.json({ item: result.rows[0], success: true });
  } catch (err) { serverError(err, res); }
});

// DELETE /api/users/me/portfolio/items/:id
router.delete('/api/users/me/portfolio/items/:id', auth, async (req, res) => {
  if (isNaN(parseInt(req.params.id))) return res.status(404).json({ error: 'Portfolio item not found' });
  try {
    const result = await query('DELETE FROM portfolio_items WHERE id = $1 AND user_id = $2 RETURNING id', [req.params.id, req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Portfolio item not found' });
    res.json({ success: true });
  } catch (err) { serverError(err, res); }
});

module.exports = router;

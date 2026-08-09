/**
 * Pi Ads Network — rewarded ad redemption.
 *
 * The client can only report that an ad was watched; it cannot be trusted to
 * say the reward was earned. Every adId is verified against the Pi Platform API
 * and may be redeemed exactly once, enforced by the primary key on ad_rewards
 * rather than by a read-then-write check (two requests racing with the same
 * adId would both pass that check).
 */
const express = require('express');
const router = express.Router();
const { query, getPool } = require('../db');
const { piApiRequest, audit, serverError } = require('../src/helpers');
const { auth, checkBlocked } = require('../src/middleware');
const logger = require('../src/logger');

// Connects granted per verified rewarded ad.
const REWARD_CONNECTS = 1;
// Per-user daily cap, so ad inventory can't be farmed into unlimited connects.
const DAILY_AD_LIMIT = 10;

// POST /api/ads/reward — { adId }
router.post('/api/ads/reward', auth, checkBlocked, async (req, res) => {
  const adId = String(req.body?.adId || '').trim();
  if (!adId || adId.length > 200) return res.status(400).json({ error: 'adId required' });

  try {
    const used = await query('SELECT user_id FROM ad_rewards WHERE ad_id = $1', [adId]);
    if (used.rows.length) return res.status(409).json({ error: 'This ad was already redeemed' });

    const today = await query(
      "SELECT COUNT(*) FROM ad_rewards WHERE user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'",
      [req.userId]
    );
    if (parseInt(today.rows[0].count, 10) >= DAILY_AD_LIMIT) {
      return res.status(429).json({ error: 'Daily ad reward limit reached', limit: DAILY_AD_LIMIT });
    }

    // Pi is the only authority on whether this ad actually paid out.
    let status;
    try {
      status = await piApiRequest(`/v2/ads_network/status/${encodeURIComponent(adId)}`);
    } catch (e) {
      // .error, not .warn: warn is a no-op under NODE_ENV=production, so every
      // failed verification against Pi printed nothing at all on Render.
      logger.error(`[ads] verification failed for ${adId}: ${e.message}`);
      return res.status(502).json({ error: 'Could not verify the ad with Pi. Try again shortly.' });
    }
    if (status?.mediator_ack_status !== 'granted') {
      return res.status(400).json({ error: 'Ad reward not granted', status: status?.mediator_ack_status ?? null });
    }

    // The insert is the lock: a duplicate adId violates the primary key, so a
    // replayed or raced request can never credit connects twice.
    //
    // In one transaction with the balance update, because the two were separate
    // statements before: if the UPDATE failed, the ad_rewards row survived, so
    // the ad was spent — it counted against the daily cap and the primary key
    // barred it from ever being redeemed again — while no connect was granted.
    // The user watched the ad and got nothing, permanently.
    const pgAds = await getPool().connect();
    let balance = null;
    try {
      await pgAds.query('BEGIN');
      await pgAds.query('INSERT INTO ad_rewards (ad_id, user_id, connects, created_at) VALUES ($1,$2,$3,NOW())',
        [adId, req.userId, REWARD_CONNECTS]);
      const upd = await pgAds.query(
        'UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2 RETURNING balance_connects',
        [REWARD_CONNECTS, req.userId]
      );
      // No row updated means no such user, which must not leave a reward behind.
      if (!upd.rows.length) throw new Error(`ad reward for unknown user ${req.userId}`);
      await pgAds.query('COMMIT');
      balance = upd.rows[0].balance_connects;
    } catch (e) {
      await pgAds.query('ROLLBACK').catch(() => {});
      if (e.code === '23505') return res.status(409).json({ error: 'This ad was already redeemed' });
      throw e;
    } finally {
      pgAds.release();
    }
    await audit('ad_reward_granted', { user_id: req.userId, ad_id: adId, connects: REWARD_CONNECTS });

    res.json({
      success: true,
      connects_added: REWARD_CONNECTS,
      balance_connects: balance,
      remaining_today: Math.max(0, DAILY_AD_LIMIT - parseInt(today.rows[0].count, 10) - 1),
    });
  } catch (err) { serverError(err, res); }
});

// GET /api/ads/quota — how many rewarded ads the caller can still redeem today
router.get('/api/ads/quota', auth, async (req, res) => {
  try {
    const r = await query(
      "SELECT COUNT(*) FROM ad_rewards WHERE user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'",
      [req.userId]
    );
    const usedToday = parseInt(r.rows[0].count, 10);
    res.json({
      used_today: usedToday,
      limit: DAILY_AD_LIMIT,
      remaining: Math.max(0, DAILY_AD_LIMIT - usedToday),
      connects_per_ad: REWARD_CONNECTS,
    });
  } catch (err) { serverError(err, res); }
});

module.exports = router;

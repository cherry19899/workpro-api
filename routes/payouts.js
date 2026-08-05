/**
 * Payout availability.
 *
 * A freelancer's `balance_pi` is money they have earned, but it only reaches
 * their Pi wallet once Pi Network has enabled App-to-User payments for this
 * app. Until then the funds sit in the app wallet. Showing a bare number with
 * no explanation is how a working app looks like a scam to the first person who
 * tries to withdraw — this endpoint lets the client say what is actually going
 * on.
 */
const express = require('express');
const router = express.Router();
const { auth } = require('../src/middleware');
const { a2uEnabled, a2uStatus } = require('../src/pi-a2u');

// Pi returns this when the app is not yet approved for mainnet A2U. It is not a
// bug on our side and not something the user can act on.
const NOT_APPROVED = /feature[_ ]?not[_ ]?available|not[_ ]?(?:yet[_ ]?)?(?:enabled|approved|activated)/i;

// GET /api/payouts/status
router.get('/api/payouts/status', auth, (req, res) => {
  const last = a2uStatus();

  if (!a2uEnabled()) {
    return res.json({
      available: false,
      reason: 'not_configured',
      last_attempt_at: null,
    });
  }

  // A failure Pi attributes to the feature not being live yet is the pending
  // case; anything else is a genuine error worth surfacing differently.
  if (last && last.ok === false && NOT_APPROVED.test(last.error || '')) {
    return res.json({
      available: false,
      reason: 'pending_pi_approval',
      last_attempt_at: last.at || null,
    });
  }

  if (last && last.ok === false) {
    return res.json({
      available: false,
      reason: 'last_attempt_failed',
      last_attempt_at: last.at || null,
    });
  }

  // ok === true means a payout has actually landed. null means nothing has been
  // attempted yet — configured and not known to be broken, so treat it as
  // available rather than alarming people over an untested path.
  return res.json({
    available: true,
    reason: last && last.ok ? 'ok' : 'untested',
    last_attempt_at: last ? last.at : null,
  });
});

module.exports = router;

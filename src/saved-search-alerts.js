// Saved-search alerts: notify users about new open jobs matching their saved
// searches. Called from the hourly sweep in server.js (and the admin endpoint).
const { query } = require('./db');
const { notify } = require('./helpers');
const logger = require('./logger');

async function checkSavedSearchAlerts() {
  const searches = await query("SELECT * FROM saved_searches WHERE alert_enabled=TRUE AND (last_alerted_at IS NULL OR last_alerted_at < NOW() - INTERVAL '1 day')");
  let alerted = 0;
  let failed = 0;
  for (const s of searches.rows) {
    // Per search, not around the loop. query_params is user-supplied JSONB, so
    // one row whose `q` is an object (or anything else plainto_tsquery refuses)
    // used to throw out of the whole sweep — and every user ordered after that
    // row silently stopped receiving alerts, every hour, indefinitely.
    try {
    const params = s.query_params || {};
    // Coerced, because these reach plainto_tsquery and ILIKE as bind values:
    // a nested object arrives as '[object Object]' and matches nothing, which
    // is the right outcome for a search nobody can satisfy.
    const q = String(params.q || params.search || '').slice(0, 200);
    const cat = String(params.category || '').slice(0, 100);
    const conditions = ["status='open'"];
    const qParams = [];
    let idx = 1;
    if (q) { conditions.push(`search_vector @@ plainto_tsquery('english',$${idx++})`); qParams.push(q); }
    if (cat && cat !== 'all') { conditions.push(`category ILIKE $${idx++}`); qParams.push(cat); }
    conditions.push(`created_at > COALESCE((SELECT last_alerted_at FROM saved_searches WHERE id=$${idx++}), NOW()-INTERVAL '1 day')`);
    qParams.push(s.id);
    const newJobs = await query(`SELECT id, title, budget FROM jobs WHERE ${conditions.join(' AND ')} LIMIT 5`, qParams);
    if (newJobs.rows.length > 0) {
      // Link the notification to the first matching job so tapping it opens something useful.
      await notify(s.user_id, 'saved_search_alert', 'Новые задачи по вашему поиску',
        `${newJobs.rows.length} нов. задач(и) по запросу «${s.name}»: ${newJobs.rows.map(j => j.title).join(', ').substring(0, 120)}`,
        newJobs.rows[0].id, null,
        { key: 'nSavedSearchHits', params: { count: newJobs.rows.length, name: s.name, titles: newJobs.rows.map(j => j.title).join(', ').substring(0, 120) } }).catch(() => {});
      await query('UPDATE saved_searches SET last_alerted_at=NOW() WHERE id=$1', [s.id]);
      alerted++;
    }
    } catch (e) {
      failed++;
      logger.error(`[saved-search] search ${s.id} (user ${s.user_id}) failed: ${e.message}`);
    }
  }
  return { alerted, failed, total: searches.rows.length };
}

module.exports = { checkSavedSearchAlerts };

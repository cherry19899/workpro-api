// Saved-search alerts: notify users about new open jobs matching their saved
// searches. Called from the hourly sweep in server.js (and the admin endpoint).
const { query } = require('./db');
const { notify } = require('./helpers');

async function checkSavedSearchAlerts() {
  const searches = await query("SELECT * FROM saved_searches WHERE alert_enabled=TRUE AND (last_alerted_at IS NULL OR last_alerted_at < NOW() - INTERVAL '1 day')");
  let alerted = 0;
  for (const s of searches.rows) {
    const params = s.query_params || {};
    const q = params.q || params.search || '';
    const cat = params.category || '';
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
        newJobs.rows[0].id, null).catch(() => {});
      await query('UPDATE saved_searches SET last_alerted_at=NOW() WHERE id=$1', [s.id]);
      alerted++;
    }
  }
  return { alerted, total: searches.rows.length };
}

module.exports = { checkSavedSearchAlerts };

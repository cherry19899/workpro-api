/**
 * One-time cleanup, authorised by the owner on 2026-10-20: close the test jobs
 * that filled the live feed. Of 21 open jobs, 17 were test posts — "QA Test
 * Job" four times, "gate tgt4", "unblock check", "Refund test" and the like,
 * several left behind by automated checks — and real users could spend
 * connects applying to them.
 *
 * Closed, not deleted. escrows.job_id is ON DELETE CASCADE, so deleting a job
 * erases its escrow rows and their history along with it. Setting status to
 * 'cancelled' takes the job out of the feed (which shows only 'open') and
 * blocks hiring on it, while every payment record stays.
 *
 * Refunds mirror DELETE /api/admin/jobs/:id: each pending applicant gets the
 * job's apply_cost back and the poster gets their posting connect back.
 *
 * Each job is matched by id AND exact title, and skipped if it is no longer
 * open or if an escrow on it holds money — those are left for a person. The
 * guards make this idempotent: once a job is cancelled it is skipped, so a
 * second boot does nothing.
 */
const TEST_JOBS = [
  [194, 'Проверка 5'], [190, 'Проверка'], [188, 'Test2'], [156, 'Klaipeda cod'],
  [149, 'Test'], [137, 'upl test'], [130, 'owner ok'], [129, 'unblock check'],
  [128, 'gate tgt4'], [116, 'gate target'], [103, 'Refund test'],
  [99, 'QA Test Job'], [98, 'QA Test Job'], [97, 'QA Test Job'],
  [80, 'ReactDevNeeded'], [24, 'QA Test Job'], [19, 'Apply Test Job'],
];

async function closeOne(client, id, title) {
  await client.query('BEGIN');
  const j = await client.query(
    'SELECT id, title, status, apply_cost, posted_by FROM jobs WHERE id = $1 FOR UPDATE', [id]);
  const job = j.rows[0];
  let skip = null;
  if (!job) skip = 'not found';
  else if (job.title !== title) skip = 'title mismatch';
  else if (job.status !== 'open') skip = 'not open';
  else {
    const esc = await client.query(
      "SELECT 1 FROM escrows WHERE job_id = $1 AND status IN ('pending','funded','disputed') LIMIT 1", [id]);
    if (esc.rows.length) skip = 'escrow holds money';
  }
  if (skip) { await client.query('ROLLBACK'); return { id, skipped: skip }; }

  const cost = Number(job.apply_cost) || 1;
  const pending = await client.query(
    "SELECT DISTINCT freelancer_id FROM applications WHERE job_id = $1 AND status = 'pending'", [id]);
  for (const row of pending.rows) {
    await client.query(
      'UPDATE users SET balance_connects = balance_connects + $1, updated_at = NOW() WHERE id = $2',
      [cost, row.freelancer_id]);
  }
  if (job.posted_by) {
    await client.query(
      'UPDATE users SET balance_connects = balance_connects + 1, updated_at = NOW() WHERE id = $1',
      [job.posted_by]);
  }
  await client.query("UPDATE applications SET status = 'rejected' WHERE job_id = $1 AND status = 'pending'", [id]);
  await client.query("UPDATE jobs SET status = 'cancelled', updated_at = NOW() WHERE id = $1", [id]);
  await client.query('COMMIT');
  return { id, closed: true, applicantsRefunded: pending.rows.length, perApplicant: cost };
}

async function closeTestJobs({ getPool, audit, logger }) {
  const results = [];
  for (const [id, title] of TEST_JOBS) {
    const client = await getPool().connect();
    try {
      results.push(await closeOne(client, id, title));
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      results.push({ id, error: e.message });
    } finally {
      client.release();
    }
  }
  for (const r of results.filter(x => x.closed)) {
    await audit('test_job_closed', {
      job_id: r.id, applicants_refunded: r.applicantsRefunded, per_applicant: r.perApplicant,
      by: 'system:cleanup-2026-10-20',
    }).catch(() => {});
  }
  // logger.error on purpose: it is the only level Render keeps in production.
  if (results.some(r => r.closed || r.error)) {
    logger.error(`[cleanup] test jobs: ${JSON.stringify(results)}`);
  }
  return results;
}

module.exports = { closeTestJobs, TEST_JOBS };

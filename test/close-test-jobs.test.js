/**
 * The test-job cleanup runs against live data, so its guards are the whole
 * point: it must close only the jobs it names, never one whose title changed,
 * never one that is no longer open, never one with money in escrow — and must
 * refund the connects people spent applying.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { closeTestJobs, TEST_JOBS } = require('../src/close-test-jobs');

// A fake pg pool holding just enough state to answer the queries closeTestJobs runs.
function fakeDb({ jobs = {}, escrows = [], applications = [] } = {}) {
  const users = {};
  const statements = [];
  const client = {
    async query(sql, params = []) {
      statements.push(sql);
      if (/^(BEGIN|COMMIT|ROLLBACK)/.test(sql)) return { rows: [] };
      if (sql.startsWith('SELECT id, title, status')) {
        const j = jobs[params[0]];
        return { rows: j ? [{ id: params[0], ...j }] : [] };
      }
      if (sql.startsWith('SELECT 1 FROM escrows')) {
        return { rows: escrows.filter(e => e.job_id === params[0] && ['pending', 'funded', 'disputed'].includes(e.status)) };
      }
      if (sql.startsWith('SELECT DISTINCT freelancer_id')) {
        const ids = [...new Set(applications.filter(a => a.job_id === params[0] && a.status === 'pending').map(a => a.freelancer_id))];
        return { rows: ids.map(freelancer_id => ({ freelancer_id })) };
      }
      if (sql.startsWith('UPDATE users SET balance_connects = balance_connects + $1')) {
        users[params[1]] = (users[params[1]] || 0) + params[0]; return { rows: [] };
      }
      if (sql.startsWith('UPDATE users SET balance_connects = balance_connects + 1')) {
        users[params[0]] = (users[params[0]] || 0) + 1; return { rows: [] };
      }
      if (sql.startsWith("UPDATE applications SET status = 'rejected'")) {
        applications.filter(a => a.job_id === params[0] && a.status === 'pending').forEach(a => { a.status = 'rejected'; });
        return { rows: [] };
      }
      if (sql.startsWith("UPDATE jobs SET status = 'cancelled'")) {
        jobs[params[0]].status = 'cancelled'; return { rows: [] };
      }
      throw new Error('unexpected SQL: ' + sql);
    },
    release() {},
  };
  return { jobs, users, statements, getPool: () => ({ connect: async () => client }) };
}

const quiet = { audit: async () => {}, logger: { error() {} } };

test('closes a listed open job and refunds every pending applicant', async () => {
  const db = fakeDb({
    jobs: { 194: { title: 'Проверка 5', status: 'open', apply_cost: 1, posted_by: 'pi_poster' } },
    applications: [
      { job_id: 194, freelancer_id: 'pi_a', status: 'pending' },
      { job_id: 194, freelancer_id: 'pi_b', status: 'pending' },
      { job_id: 194, freelancer_id: 'pi_c', status: 'rejected' },   // already handled — no refund
    ],
  });
  await closeTestJobs({ getPool: db.getPool, ...quiet });
  assert.equal(db.jobs[194].status, 'cancelled');
  assert.equal(db.users.pi_a, 1);
  assert.equal(db.users.pi_b, 1);
  assert.equal(db.users.pi_c, undefined);
  assert.equal(db.users.pi_poster, 1, 'the poster gets the posting connect back');
});

test('refunds the job\'s own apply cost, not a flat 1', async () => {
  const db = fakeDb({
    jobs: { 80: { title: 'ReactDevNeeded', status: 'open', apply_cost: 2, posted_by: 'pi_p' } },
    applications: [{ job_id: 80, freelancer_id: 'pi_a', status: 'pending' }],
  });
  await closeTestJobs({ getPool: db.getPool, ...quiet });
  assert.equal(db.users.pi_a, 2);
});

test('a job whose title no longer matches is left alone', async () => {
  const db = fakeDb({ jobs: { 194: { title: 'A real job now', status: 'open', apply_cost: 1, posted_by: 'pi_p' } } });
  const res = await closeTestJobs({ getPool: db.getPool, ...quiet });
  assert.equal(db.jobs[194].status, 'open');
  assert.equal(res.find(r => r.id === 194).skipped, 'title mismatch');
  assert.ok(!db.statements.some(s => s.startsWith('UPDATE')), 'nothing written');
});

test('a job that is no longer open is left alone', async () => {
  const db = fakeDb({ jobs: { 149: { title: 'Test', status: 'in_progress', apply_cost: 1, posted_by: 'pi_p' } } });
  const res = await closeTestJobs({ getPool: db.getPool, ...quiet });
  assert.equal(db.jobs[149].status, 'in_progress');
  assert.equal(res.find(r => r.id === 149).skipped, 'not open');
});

test('a job with money in escrow is left for a person', async () => {
  for (const status of ['pending', 'funded', 'disputed']) {
    const db = fakeDb({
      jobs: { 103: { title: 'Refund test', status: 'open', apply_cost: 1, posted_by: 'pi_p' } },
      escrows: [{ job_id: 103, status }],
    });
    const res = await closeTestJobs({ getPool: db.getPool, ...quiet });
    assert.equal(db.jobs[103].status, 'open', `escrow ${status} must block the close`);
    assert.equal(res.find(r => r.id === 103).skipped, 'escrow holds money');
  }
});

test('a finished escrow does not block the close, and is not touched', async () => {
  const db = fakeDb({
    jobs: { 99: { title: 'QA Test Job', status: 'open', apply_cost: 1, posted_by: 'pi_p' } },
    escrows: [{ job_id: 99, status: 'released' }],
  });
  await closeTestJobs({ getPool: db.getPool, ...quiet });
  assert.equal(db.jobs[99].status, 'cancelled');
  assert.ok(!db.statements.some(s => /escrows/.test(s) && s.startsWith('UPDATE')), 'escrow history untouched');
  assert.ok(!db.statements.some(s => s.startsWith('DELETE')), 'nothing is ever deleted');
});

test('running it twice changes nothing the second time', async () => {
  const db = fakeDb({
    jobs: { 194: { title: 'Проверка 5', status: 'open', apply_cost: 1, posted_by: 'pi_p' } },
    applications: [{ job_id: 194, freelancer_id: 'pi_a', status: 'pending' }],
  });
  await closeTestJobs({ getPool: db.getPool, ...quiet });
  await closeTestJobs({ getPool: db.getPool, ...quiet });
  assert.equal(db.users.pi_a, 1, 'refunded once, not twice');
  assert.equal(db.users.pi_p, 1);
});

test('the four realistic-looking jobs are not on the list', () => {
  const ids = TEST_JOBS.map(([id]) => id);
  for (const keep of [20, 5, 4, 3]) assert.ok(!ids.includes(keep), `job ${keep} must not be closed`);
  assert.equal(ids.length, 17);
});

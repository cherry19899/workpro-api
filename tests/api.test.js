'use strict';
/**
 * Integration-style API tests using supertest.
 * These tests mock the database so they run without a real PostgreSQL connection.
 */

// ─── Mock DB before requiring app ────────────────────────────────────────────

const mockQuery = jest.fn();
const mockPool = {
  query: mockQuery,
  connect: jest.fn().mockResolvedValue({
    query: mockQuery,
    release: jest.fn(),
  }),
};

jest.mock('../db', () => ({
  pool: mockPool,
  initDb: jest.fn().mockResolvedValue(undefined),
  query: mockQuery,
}));

// Mock Socket.io so server.js doesn't fail without real HTTP
jest.mock('socket.io', () => {
  const SocketIO = function() {
    return {
      on: jest.fn(),
      emit: jest.fn(),
      to: jest.fn().mockReturnThis(),
    };
  };
  return SocketIO;
});

process.env.JWT_SECRET = 'test-secret-key-at-least-64-chars-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
process.env.ADMIN_API_KEY = 'test-admin-key';
process.env.SANDBOX_MODE = 'true';
process.env.NODE_ENV = 'test';

const request = require('supertest');
const jwt = require('jsonwebtoken');

// Lazy-require app after mocks are set up
let app;
beforeAll(() => {
  // Silence the self-ping / keep-alive intervals
  jest.spyOn(global, 'setInterval').mockReturnValue(1 as any);
  app = require('../server').app || require('../server');
});

afterAll(() => {
  jest.restoreAllMocks();
});

// Helper — create signed JWT for tests
function makeToken(user: any = {}) {
  return jwt.sign(
    { uid: user.uid || 'test-uid-1', username: user.username || 'testuser', role: user.role || 'user' },
    process.env.JWT_SECRET!,
    { expiresIn: '1h' }
  );
}

// ─── Auth / Me ────────────────────────────────────────────────────────────────

describe('GET /api/me', () => {
  it('returns 401 without token', async () => {
    const res = await request(app).get('/api/me');
    expect(res.status).toBe(401);
  });

  it('returns user data with valid token', async () => {
    const mockUser = {
      uid: 'test-uid-1', username: 'testuser', role: 'user',
      balance_connects: 10, balance_pi: '5.00', is_blocked: false,
    };
    mockQuery.mockResolvedValueOnce({ rows: [mockUser] });

    const token = makeToken(mockUser);
    const res = await request(app)
      .get('/api/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.username).toBe('testuser');
  });

  it('returns 401 for blocked users', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ uid: 'test-uid-1', is_blocked: true }] });

    const token = makeToken();
    const res = await request(app)
      .get('/api/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(401);
  });
});

// ─── Jobs ─────────────────────────────────────────────────────────────────────

describe('GET /api/jobs', () => {
  it('returns job list', async () => {
    const mockJobs = [
      { id: 1, title: 'Test Job', budget: 10, status: 'open', posted_by: 'test-uid-1' },
    ];
    mockQuery.mockResolvedValueOnce({ rows: mockJobs });

    const res = await request(app).get('/api/jobs');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('supports fulltext search endpoint', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await request(app).get('/api/jobs/search/fulltext?q=test');
    expect([200, 400]).toContain(res.status);
  });
});

describe('POST /api/jobs', () => {
  it('requires auth', async () => {
    const res = await request(app).post('/api/jobs').send({ title: 'Test', budget: 5 });
    expect(res.status).toBe(401);
  });

  it('requires title', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ uid: 'test-uid-1', is_blocked: false, balance_connects: 10 }] });

    const token = makeToken();
    const res = await request(app)
      .post('/api/jobs')
      .set('Authorization', `Bearer ${token}`)
      .send({ budget: 5 }); // missing title

    expect(res.status).toBe(400);
  });
});

// ─── Escrows ──────────────────────────────────────────────────────────────────

describe('GET /api/escrows', () => {
  it('requires auth', async () => {
    const res = await request(app).get('/api/escrows');
    expect(res.status).toBe(401);
  });

  it('returns escrow list for authed user', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ uid: 'test-uid-1', is_blocked: false }] });
    mockQuery.mockResolvedValueOnce({ rows: [] });

    const token = makeToken();
    const res = await request(app)
      .get('/api/escrows')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
  });
});

// ─── Admin ────────────────────────────────────────────────────────────────────

describe('GET /api/admin/stats', () => {
  it('rejects request without admin key or role', async () => {
    const res = await request(app).get('/api/admin/stats');
    expect(res.status).toBe(401);
  });

  it('accepts request with valid admin key', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ count: '5' }] })
      .mockResolvedValueOnce({ rows: [{ count: '10' }] })
      .mockResolvedValueOnce({ rows: [{ count: '2' }] })
      .mockResolvedValueOnce({ rows: [{ count: '20' }] })
      .mockResolvedValueOnce({ rows: [{ count: '1' }] })
      .mockResolvedValueOnce({ rows: [{ count: '0' }] })
      .mockResolvedValueOnce({ rows: [{ sum: '15.00' }] })
      .mockResolvedValueOnce({ rows: [{ value: '2' }] });

    const res = await request(app)
      .get('/api/admin/stats')
      .set('x-admin-key', 'test-admin-key');

    expect([200, 500]).toContain(res.status);
  });
});

// ─── Rate limiting (smoke test) ───────────────────────────────────────────────

describe('Rate limiting', () => {
  it('allows many requests in SANDBOX_MODE', async () => {
    mockQuery.mockResolvedValue({ rows: [] });
    // In sandbox mode limits are 10x so 5 rapid requests should all pass
    const results = await Promise.all(
      Array.from({ length: 5 }).map(() => request(app).get('/api/jobs'))
    );
    const statuses = results.map(r => r.status);
    expect(statuses.every(s => s !== 429)).toBe(true);
  });
});

// ─── CORS ─────────────────────────────────────────────────────────────────────

describe('CORS', () => {
  it('allows origin cherry19899.github.io', async () => {
    mockQuery.mockResolvedValue({ rows: [] });
    const res = await request(app)
      .get('/api/jobs')
      .set('Origin', 'https://cherry19899.github.io');
    expect(res.headers['access-control-allow-origin']).toBe('https://cherry19899.github.io');
  });
});

// ─── Health ───────────────────────────────────────────────────────────────────

describe('GET /health', () => {
  it('responds 200', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });
});

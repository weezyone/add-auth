/**
 * PAU-18: CSRF protection on the real /api/auth stack.
 */
import request from 'supertest';
import type { Express } from 'express';
import {
  setupInfrastructure, resetState, teardownInfrastructure, loadApp,
  Client, uniqueEmail, STRONG_PASSWORD,
} from './helpers';

const registerBody = () => ({
  email: uniqueEmail(),
  password: STRONG_PASSWORD,
  confirmPassword: STRONG_PASSWORD,
  username: 'csrfuser',
});

describe('CSRF protection', () => {
  let app: Express;

  beforeAll(async () => {
    await setupInfrastructure();
    app = loadApp();
  });
  beforeEach(resetState);
  afterAll(teardownInfrastructure);

  it('issues a token from GET /api/auth/csrf-token (body + header)', async () => {
    const res = await request(app).get('/api/auth/csrf-token');
    expect(res.status).toBe(200);
    expect(res.body.csrfToken).toEqual(expect.any(String));
    expect(res.headers['x-csrf-token']).toEqual(expect.any(String));
  });

  it('rejects a state-changing request with no token (403)', async () => {
    const res = await request(app).post('/api/auth/register').send(registerBody());
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('CSRF token missing');
  });

  it('rejects a forged token (403)', async () => {
    const client = new Client(app);
    await client.fetchCsrfToken();
    client.csrfToken = 'forged-token-value';
    const res = await client.post('/api/auth/register', registerBody());
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Invalid CSRF token');
  });

  it('keeps an issued token valid after unrelated GET requests', async () => {
    const client = new Client(app);
    await client.fetchCsrfToken();
    // Typical SPA traffic between fetching the token and submitting a form
    await client.get('/');
    await client.get('/api/auth/me');
    await client.get('/api/auth/csrf-token');
    const res = await client.post('/api/auth/register', registerBody());
    expect(res.status).toBe(201);
  });

  it('does not accept a token bound to a different client', async () => {
    const a = new Client(app, 'browser-A');
    const b = new Client(app, 'browser-B');
    b.csrfToken = await a.fetchCsrfToken();
    const res = await b.post('/api/auth/register', registerBody());
    expect(res.status).toBe(403);
  });

  it('does not accept the token from the csrf-token cookie alone (cookies ride along on cross-site requests)', async () => {
    const client = new Client(app);
    const token = await client.fetchCsrfToken();
    const res = await client.agent
      .post('/api/auth/register')
      .set('User-Agent', client.userAgent)
      .set('Cookie', `csrf-token=${token}`)
      .send(registerBody());
    expect(res.status).toBe(403);
  });
});

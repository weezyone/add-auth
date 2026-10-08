/**
 * PAU-18: security middleware on the real stack — rate limiting, XSS, SQLi,
 * security headers.
 */
import request from 'supertest';
import type { Express } from 'express';
import { db } from '../../src/database/connection';
import {
  setupInfrastructure, resetState, teardownInfrastructure, loadApp,
  Client, uniqueEmail, STRONG_PASSWORD,
} from './helpers';

async function userCount(email: string): Promise<number> {
  const r = await db.query('SELECT count(*)::int AS n FROM users WHERE email = $1', [email.toLowerCase()]);
  return r.rows[0].n;
}

describe('security middleware', () => {
  let app: Express;

  beforeAll(async () => {
    await setupInfrastructure();
    app = loadApp();
  });
  beforeEach(resetState);
  afterAll(teardownInfrastructure);

  describe('rate limiting', () => {
    it('limits registrations to 5 per hour per IP (429 on the 6th)', async () => {
      const client = new Client(app);
      for (let i = 0; i < 5; i++) {
        expect((await client.register(uniqueEmail())).status).toBe(201);
      }
      const res = await client.register(uniqueEmail());
      expect(res.status).toBe(429);
      expect(res.headers['ratelimit-limit']).toBeDefined();
    });

    it('limits login attempts per IP (429 once the limit is hit)', async () => {
      const client = new Client(app);
      const statuses: number[] = [];
      for (let i = 0; i < 12; i++) {
        statuses.push((await client.login('nobody@example.com', 'Wr0ng!Password')).status);
      }
      expect(statuses).toContain(429);
      expect(statuses.slice(0, 5).every((s) => s === 401)).toBe(true);
    });

    it('does not throttle a signed-in user\'s normal use of /api/auth (successful requests)', async () => {
      // The blanket /api/auth limiter allowed 10 requests per 15 min per IP,
      // counting every request; register -> verify -> login -> a few /me
      // calls was enough to lock a real user (or a whole office NAT) out.
      const client = new Client(app);
      const { login } = await client.signUp();
      const token = login.body.tokens.accessToken;
      const statuses: number[] = [];
      for (let i = 0; i < 15; i++) {
        statuses.push((await client.get('/api/auth/me').set('Authorization', `Bearer ${token}`)).status);
      }
      expect(statuses.every((s) => s === 200)).toBe(true);
    });

    it('still throttles repeated failures across /api/auth endpoints', async () => {
      const client = new Client(app);
      const statuses: number[] = [];
      for (let i = 0; i < 12; i++) {
        statuses.push((await client.get('/api/auth/me').set('Authorization', 'Bearer not-a-jwt')).status);
      }
      expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true);
      expect(statuses.slice(10)).toEqual([429, 429]);
    });

    it('cannot be bypassed by rotating a spoofed X-Forwarded-For header', async () => {
      // An attacker can fetch a fresh CSRF token for each spoofed address, so
      // the only thing standing between them and unlimited guesses is that the
      // limiter keys on the real peer address, not a client-supplied header.
      const client = new Client(app);
      const statuses: number[] = [];
      for (let i = 0; i < 12; i++) {
        const spoofed = `203.0.113.${i + 1}`;
        const tokenRes = await client.agent
          .get('/api/auth/csrf-token')
          .set('User-Agent', client.userAgent)
          .set('X-Forwarded-For', spoofed);
        const res = await client.agent
          .post('/api/auth/login')
          .set('User-Agent', client.userAgent)
          .set('X-CSRF-Token', tokenRes.body.csrfToken ?? 'none')
          .set('X-Forwarded-For', spoofed)
          .send({ email: 'nobody@example.com', password: 'Wr0ng!Password' });
        statuses.push(res.status);
      }
      expect(statuses).toContain(429);
    });
  });

  describe('XSS', () => {
    it('sets XSS-related security headers', async () => {
      const res = await request(app).get('/api/auth/csrf-token');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('DENY');
      expect(res.headers['content-security-policy']).toMatch(/default-src 'self'/);
    });

    it('rejects a script payload in the request body (400) and creates no user', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      const res = await client.post('/api/auth/register', {
        email,
        password: STRONG_PASSWORD,
        confirmPassword: STRONG_PASSWORD,
        username: 'abc',
        firstName: '<script>alert(1)</script>',
      });
      expect(res.status).toBe(400);
      expect(await userCount(email)).toBe(0);
    });

    it('never reflects raw markup back in error responses', async () => {
      const client = new Client(app);
      const res = await client.post('/api/auth/login', {
        email: '<img src=x onerror=alert(1)>@example.com',
        password: 'x',
      });
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).not.toMatch(/<img/i);
    });
  });

  describe('SQL injection', () => {
    it('classic tautology in the password does not log in', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      await client.register(email);
      const res = await client.login(email, "' OR '1'='1");
      expect([400, 401]).toContain(res.status);
      expect(res.body.tokens).toBeUndefined();
    });

    it('a request blocked as SQL injection is not processed any further', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      const password = 'Str0ng!Pass; DROP TABLE users';
      const res = await client.post('/api/auth/register', {
        email, password, confirmPassword: password, username: 'abc',
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Malicious input detected');
      // give a (buggy) downstream handler time to run
      await new Promise((r) => setTimeout(r, 300));
      expect(await userCount(email)).toBe(0);
    });

    it('a password containing a literal % is accepted (no 500 from URI decoding)', async () => {
      const client = new Client(app);
      const res = await client.register(uniqueEmail(), 'Str0ng!100%Sure');
      expect(res.status).toBe(201);
    });
  });
});

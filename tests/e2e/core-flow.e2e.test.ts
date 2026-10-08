/**
 * PAU-18: Registration -> login -> JWT issuance -> refresh -> logout,
 * exercised through the real HTTP stack (rate limiting, CSRF, XSS/SQLi
 * middleware, Joi validation, Postgres, Redis sessions).
 */
import jwt from 'jsonwebtoken';
import type { Express } from 'express';
import { db } from '../../src/database/connection';
import {
  setupInfrastructure, resetState, teardownInfrastructure, loadApp,
  Client, uniqueEmail, STRONG_PASSWORD,
} from './helpers';

describe('core auth flow', () => {
  let app: Express;

  beforeAll(async () => {
    await setupInfrastructure();
    app = loadApp();
  });
  beforeEach(resetState);
  afterAll(teardownInfrastructure);

  it('registers, logs in, reads /me, refreshes, and logs out', async () => {
    const client = new Client(app);
    const email = uniqueEmail();

    // Register
    const reg = await client.register(email);
    expect(reg.status).toBe(201);
    expect(reg.body.user.email).toBe(email);
    expect(reg.body.user.email_verified).toBeUndefined(); // not exposed on register
    expect(reg.body.tokens.accessToken).toEqual(expect.any(String));
    expect(reg.body.tokens.refreshToken).toEqual(expect.any(String));
    expect(reg.headers['set-cookie'].join(';')).toMatch(/sessionId=/);

    // Login
    const login = await client.login(email);
    expect(login.status).toBe(200);
    const { accessToken, refreshToken } = login.body.tokens;
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET!) as any;
    expect(decoded.id).toBe(reg.body.user.id);
    expect(decoded.email).toBe(email);
    expect(Array.isArray(decoded.roles)).toBe(true);

    // /me with the access token
    const me = await client.get('/api/auth/me').set('Authorization', `Bearer ${accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.user.id).toBe(reg.body.user.id);
    expect(me.body.user.email_verified).toBe(false);

    // Refresh rotates the token pair
    const refreshed = await client.post('/api/auth/refresh', { refreshToken });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.tokens.accessToken).toEqual(expect.any(String));
    expect(refreshed.body.tokens.refreshToken).not.toBe(refreshToken);

    // The old refresh token is single-use after rotation
    const replay = await client.post('/api/auth/refresh', { refreshToken });
    expect(replay.status).toBe(401);

    // New access token works
    const newAccess = refreshed.body.tokens.accessToken;
    const me2 = await client.get('/api/auth/me').set('Authorization', `Bearer ${newAccess}`);
    expect(me2.status).toBe(200);

    // Logout revokes access token + refresh token and destroys the session
    const logout = await client.post(
      '/api/auth/logout',
      { refreshToken: refreshed.body.tokens.refreshToken },
      newAccess,
    );
    expect(logout.status).toBe(200);

    const meAfter = await client.get('/api/auth/me').set('Authorization', `Bearer ${newAccess}`);
    expect(meAfter.status).toBe(401);
  });

  it('a user who has roles can log in, and the roles are in the access token', async () => {
    const client = new Client(app);
    const email = uniqueEmail();
    const reg = await client.register(email);
    await db.query(
      `INSERT INTO user_roles (user_id, role_id, assigned_by)
       SELECT $1, id, $1 FROM roles WHERE name IN ('user', 'moderator')`,
      [reg.body.user.id],
    );
    const login = await client.login(email);
    expect(login.status).toBe(200);
    const decoded = jwt.decode(login.body.tokens.accessToken) as any;
    expect(decoded.roles.sort()).toEqual(['moderator', 'user']);
  });

  it('rejects duplicate registration with 409', async () => {
    const client = new Client(app);
    const email = uniqueEmail();
    expect((await client.register(email)).status).toBe(201);
    const dup = await client.register(email);
    expect(dup.status).toBe(409);
  });

  it('rejects registration with a weak password with 400', async () => {
    const client = new Client(app);
    const res = await client.register(uniqueEmail(), 'weakpass');
    expect(res.status).toBe(400);
  });

  it('rejects a wrong password with 401 and does not issue tokens', async () => {
    const client = new Client(app);
    const email = uniqueEmail();
    await client.register(email);
    const res = await client.login(email, 'Wr0ng!Password');
    expect(res.status).toBe(401);
    expect(res.body.tokens).toBeUndefined();
  });

  it('locks the account after 5 failed logins (423), even with the right password', async () => {
    const client = new Client(app);
    const email = uniqueEmail();
    await client.register(email);
    for (let i = 0; i < 5; i++) {
      expect((await client.login(email, 'Wr0ng!Password')).status).toBe(401);
    }
    const res = await client.login(email, STRONG_PASSWORD);
    expect(res.status).toBe(423);
  });

  it('rejects /me without a token, with a garbage token, and with a token signed by another secret', async () => {
    const client = new Client(app);
    expect((await client.get('/api/auth/me')).status).toBe(401);
    expect((await client.get('/api/auth/me').set('Authorization', 'Bearer not-a-jwt')).status).toBe(401);
    const forged = jwt.sign({ id: 'x', email: 'x@example.com', roles: ['admin'] }, 'some-other-secret-that-is-long-enough!!');
    expect((await client.get('/api/auth/me').set('Authorization', `Bearer ${forged}`)).status).toBe(401);
  });

  it('rejects an expired access token', async () => {
    const client = new Client(app);
    const expired = jwt.sign(
      { id: 'x', email: 'x@example.com', roles: [], sessionId: 's' },
      process.env.JWT_SECRET!,
      { expiresIn: -10 },
    );
    const res = await client.get('/api/auth/me').set('Authorization', `Bearer ${expired}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Token expired');
  });

  it('does not accept a refresh token as an access token', async () => {
    const client = new Client(app);
    const reg = await client.register(uniqueEmail());
    const res = await client
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${reg.body.tokens.refreshToken}`);
    expect(res.status).toBe(401);
  });

  it('does not accept an access token as a refresh token', async () => {
    const client = new Client(app);
    const reg = await client.register(uniqueEmail());
    const res = await client.post('/api/auth/refresh', { refreshToken: reg.body.tokens.accessToken });
    expect(res.status).toBe(401);
  });

  it('a refresh token presented at logout can no longer be used to refresh', async () => {
    const client = new Client(app);
    const reg = await client.register(uniqueEmail());
    const { accessToken, refreshToken } = reg.body.tokens;
    expect((await client.post('/api/auth/logout', { refreshToken }, accessToken)).status).toBe(200);
    const res = await client.post('/api/auth/refresh', { refreshToken });
    expect(res.status).toBe(401);
  });
});

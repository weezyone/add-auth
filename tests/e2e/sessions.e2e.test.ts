/**
 * PAU-18: Redis-backed session management (/api/auth/sessions*, /session/extend)
 */
import type { Express } from 'express';
import { getRedisClient } from '../../src/utils/redis';
import { db } from '../../src/database/connection';
import {
  setupInfrastructure, resetState, teardownInfrastructure, loadApp,
  Client, uniqueEmail, STRONG_PASSWORD,
} from './helpers';

describe('Redis session management', () => {
  let app: Express;

  beforeAll(async () => {
    await setupInfrastructure();
    app = loadApp();
  });
  beforeEach(resetState);
  afterAll(teardownInfrastructure);

  async function registerAndLogin(client: Client, email = uniqueEmail()) {
    const reg = await client.register(email);
    expect(reg.status).toBe(201);
    const login = await client.login(email);
    expect(login.status).toBe(200);
    return { email, userId: reg.body.user.id as string, login };
  }

  it('stores the login session in Redis (and a Postgres backup row)', async () => {
    const client = new Client(app);
    const { userId, login } = await registerAndLogin(client);
    const sessionId = login.body.session.id;

    const redis = getRedisClient();
    const raw = await redis.get(`session:${sessionId}`);
    expect(raw).not.toBeNull();
    expect(JSON.parse(raw!).user_id).toBe(userId);
    expect(await redis.sIsMember(`user_sessions:${userId}`, sessionId)).toBeTruthy();
    expect(await redis.ttl(`session:${sessionId}`)).toBeGreaterThan(0);

    const rows = await db.query('SELECT count(*)::int AS n FROM sessions WHERE user_id = $1', [userId]);
    expect(rows.rows[0].n).toBeGreaterThanOrEqual(1);
  });

  it('rememberMe uses the 7-day TTL', async () => {
    const client = new Client(app);
    const email = uniqueEmail();
    await client.register(email);
    const login = await client.post('/api/auth/login', { email, password: STRONG_PASSWORD, rememberMe: true });
    expect(login.status).toBe(200);
    const ttl = await getRedisClient().ttl(`session:${login.body.session.id}`);
    expect(ttl).toBeGreaterThan(86400);
  });

  it('lists the current user\'s sessions via the session cookie and marks the current one', async () => {
    const client = new Client(app);
    const { login } = await registerAndLogin(client);
    const res = await client.get('/api/auth/sessions');
    expect(res.status).toBe(200);
    expect(res.body.total).toBeGreaterThanOrEqual(1);
    const current = res.body.sessions.find((s: any) => s.is_current);
    expect(current.id).toBe(login.body.session.id);
    // no secrets leak
    expect(res.body.sessions[0].token).toBeUndefined();
  });

  it('lists sessions with only a valid bearer access token (no cookie)', async () => {
    const client = new Client(app);
    const { login } = await registerAndLogin(client);
    const bearerOnly = new Client(app);
    const res = await bearerOnly
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${login.body.tokens.accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body.total).toBeGreaterThanOrEqual(1);
  });

  it('rejects /sessions with no credentials and with a garbage bearer token', async () => {
    const client = new Client(app);
    expect((await client.get('/api/auth/sessions')).status).toBe(401);
    expect((await client.get('/api/auth/sessions').set('Authorization', 'Bearer garbage')).status).toBe(401);
  });

  it('revokes a specific session, and cannot revoke another user\'s session', async () => {
    const alice = new Client(app, 'alice-browser');
    const { email } = await registerAndLogin(alice);
    // second session for alice from the same browser
    const second = await alice.login(email);
    const secondId = second.body.session.id;

    const mallory = new Client(app, 'mallory-browser');
    await registerAndLogin(mallory);
    const steal = await mallory.delete(`/api/auth/sessions/${secondId}`);
    expect(steal.status).toBe(404);
    expect(await getRedisClient().get(`session:${secondId}`)).not.toBeNull();

    // alice's cookie now points at the second session; revoke the register-time one
    const list = await alice.get('/api/auth/sessions');
    const other = list.body.sessions.find((s: any) => !s.is_current);
    const revoke = await alice.delete(`/api/auth/sessions/${other.id}`);
    expect(revoke.status).toBe(200);
    expect(await getRedisClient().get(`session:${other.id}`)).toBeNull();
  });

  it('revokes all other sessions but keeps the current one', async () => {
    const client = new Client(app);
    const { email, userId } = await registerAndLogin(client);
    await client.login(email);
    const current = await client.login(email);
    const res = await client.delete('/api/auth/sessions');
    expect(res.status).toBe(200);
    expect(res.body.revokedCount).toBeGreaterThanOrEqual(2);
    const remaining = await getRedisClient().sMembers(`user_sessions:${userId}`);
    expect(remaining).toEqual([current.body.session.id]);
  });

  it('extends the current session', async () => {
    const client = new Client(app);
    const { login } = await registerAndLogin(client);
    const before = new Date(login.body.session.expires_at).getTime();
    const res = await client.put('/api/auth/session/extend');
    expect(res.status).toBe(200);
    expect(res.body.session.id).toBe(login.body.session.id);
    expect(new Date(res.body.session.expires_at).getTime()).toBeGreaterThan(Date.now() + 23 * 3600 * 1000);
    expect(Number.isFinite(before)).toBe(true);
  });

  it('caps concurrent sessions at 5 per user, evicting the oldest', async () => {
    const client = new Client(app);
    const email = uniqueEmail();
    const reg = await client.register(email); // session #1
    const userId = reg.body.user.id;
    for (let i = 0; i < 5; i++) {
      expect((await client.login(email)).status).toBe(200);
    }
    const ids = await getRedisClient().sMembers(`user_sessions:${userId}`);
    expect(ids.length).toBe(5);
    expect(ids).not.toContain(reg.body.session.id);
  });

  it('destroys the session when the cookie is replayed from a different User-Agent', async () => {
    const victim = new Client(app, 'Mozilla/5.0 victim');
    const { login } = await registerAndLogin(victim);
    const sessionId = login.body.session.id;

    const attacker = new Client(app, 'curl/8.0 attacker');
    const res = await attacker.get('/api/auth/sessions').set('Cookie', `sessionId=${sessionId}`);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('SESSION_SECURITY_FAILED');
    expect(await getRedisClient().get(`session:${sessionId}`)).toBeNull();
  });

  it('logout destroys the Redis session and clears the cookie', async () => {
    const client = new Client(app);
    const { login } = await registerAndLogin(client);
    const sessionId = login.body.session.id;
    const res = await client.post('/api/auth/logout', {}, login.body.tokens.accessToken);
    expect(res.status).toBe(200);
    expect(res.headers['set-cookie'].join(';')).toMatch(/sessionId=;/);
    expect(await getRedisClient().get(`session:${sessionId}`)).toBeNull();
    expect((await client.get('/api/auth/sessions')).status).toBe(401);
  });

  it('change-password destroys every session for the user', async () => {
    const client = new Client(app);
    const { userId, login } = await registerAndLogin(client);
    const res = await client.post(
      '/api/auth/change-password',
      { currentPassword: STRONG_PASSWORD, newPassword: 'N3w!Passw0rdX', confirmPassword: 'N3w!Passw0rdX' },
      login.body.tokens.accessToken,
    );
    expect(res.status).toBe(200);
    expect(await getRedisClient().sMembers(`user_sessions:${userId}`)).toEqual([]);
  });

  it('a second device for the same user can use session management', async () => {
    const email = uniqueEmail();
    const laptop = new Client(app, 'Mozilla/5.0 (Macintosh) laptop');
    await registerAndLogin(laptop, email);

    const phone = new Client(app, 'Mozilla/5.0 (iPhone) phone');
    const login = await phone.login(email);
    expect(login.status).toBe(200);
    const res = await phone.get('/api/auth/sessions');
    expect(res.status).toBe(200);
  });
});

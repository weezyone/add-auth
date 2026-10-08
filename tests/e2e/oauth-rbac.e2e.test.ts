/**
 * PAU-18: OAuth (Google, GitHub) and RBAC, against src/app.ts — the
 * express-session + Passport server that hosts the OAuth routes and the
 * session-based RBAC middleware. Provider HTTP endpoints are mocked with nock;
 * nothing leaves the box.
 */
import nock from 'nock';
import request from 'supertest';
import type { Express } from 'express';
import { db } from '../../src/database/connection';
import {
  setupInfrastructure, resetState, teardownInfrastructure, loadApp, Client, STRONG_PASSWORD,
} from './helpers';

type Agent = ReturnType<typeof request.agent>;

function loadOAuthApp(): Express {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('../../src/app').default;
}

function mockGoogle(profile: Record<string, unknown>) {
  nock('https://www.googleapis.com')
    .post('/oauth2/v4/token')
    .reply(200, { access_token: 'google-at', refresh_token: 'google-rt', token_type: 'Bearer', expires_in: 3600 })
    .get('/oauth2/v3/userinfo').query(true)
    .reply(200, profile);
}

function mockGitHub(user: Record<string, unknown>, emails: Array<Record<string, unknown>>) {
  nock('https://github.com')
    .post('/login/oauth/access_token')
    .reply(200, { access_token: 'github-at', token_type: 'bearer', scope: 'user:email' });
  nock('https://api.github.com')
    .get('/user').query(true).reply(200, user)
    .get('/user/emails').query(true).reply(200, emails);
}

/** Start the flow like a browser would, return the authorize URL. */
async function startFlow(agent: Agent, provider: 'google' | 'github'): Promise<URL> {
  const res = await agent.get(`/auth/${provider}`);
  expect(res.status).toBe(302);
  return new URL(res.headers.location);
}

/** Simulate the provider redirecting back with ?code (and the state it was given). */
async function completeFlow(agent: Agent, authorizeUrl: URL) {
  const redirectUri = new URL(authorizeUrl.searchParams.get('redirect_uri')!);
  const state = authorizeUrl.searchParams.get('state');
  const qs = new URLSearchParams({ code: 'provider-auth-code' });
  if (state) qs.set('state', state);
  return agent.get(`${redirectUri.pathname}?${qs.toString()}`);
}

async function oauthLogin(app: Express, provider: 'google' | 'github', mock: () => void): Promise<Agent> {
  const agent = request.agent(app);
  const authorizeUrl = await startFlow(agent, provider);
  mock();
  const cb = await completeFlow(agent, authorizeUrl);
  expect(cb.status).toBe(302);
  expect(cb.headers.location).toBe('/dashboard');
  return agent;
}

async function grantRole(email: string, roleName: string) {
  await db.query(
    `INSERT INTO user_roles (user_id, role_id, assigned_by)
     SELECT u.id, r.id, u.id FROM users u, roles r WHERE u.email = $1 AND r.name = $2
     ON CONFLICT DO NOTHING`,
    [email, roleName],
  );
}

const googleProfile = (email = 'ada@example.com', verified = true) => ({
  sub: 'google-123', name: 'Ada Lovelace', given_name: 'Ada', family_name: 'Lovelace',
  email, email_verified: verified,
});

describe('OAuth + RBAC (src/app.ts)', () => {
  let app: Express;

  beforeAll(async () => {
    await setupInfrastructure();
    nock.disableNetConnect();
    nock.enableNetConnect(/127\.0\.0\.1|localhost/);
    app = loadOAuthApp();
  });
  beforeEach(resetState);
  afterEach(() => nock.cleanAll());
  afterAll(async () => {
    nock.enableNetConnect();
    await teardownInfrastructure();
  });

  describe('Google', () => {
    it('redirects to Google with our client id and a redirect_uri that this app actually serves', async () => {
      const agent = request.agent(app);
      const url = await startFlow(agent, 'google');
      expect(url.host).toBe('accounts.google.com');
      expect(url.searchParams.get('client_id')).toBe(process.env.GOOGLE_CLIENT_ID);
      const redirectPath = new URL(url.searchParams.get('redirect_uri')!).pathname;
      const probe = await request(app).get(redirectPath);
      expect(probe.status).not.toBe(404);
    });

    it('sends a state parameter (OAuth login-CSRF protection)', async () => {
      const url = await startFlow(request.agent(app), 'google');
      expect(url.searchParams.get('state')).toEqual(expect.any(String));
    });

    it('signs up a new user, assigns the default role, and establishes a session', async () => {
      const agent = await oauthLogin(app, 'google', () => mockGoogle(googleProfile()));

      const user = (await db.query("SELECT * FROM users WHERE email = 'ada@example.com'")).rows[0];
      expect(user).toBeDefined();
      expect(user.email_verified).toBe(true);
      const account = (await db.query('SELECT * FROM oauth_accounts WHERE user_id = $1', [user.id])).rows[0];
      expect(account.provider).toBe('google');
      expect(account.provider_id).toBe('google-123');
      const roles = (await db.query(
        'SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1', [user.id],
      )).rows.map((r: any) => r.name);
      expect(roles).toEqual(['user']);

      const dash = await agent.get('/dashboard');
      expect(dash.status).toBe(200);
      expect(dash.body.userId).toBe(user.id);
    });

    it('an OAuth sign-up with a verified provider email counts as verified (timestamped)', async () => {
      await oauthLogin(app, 'google', () => mockGoogle(googleProfile()));
      const user = (await db.query("SELECT * FROM users WHERE email = 'ada@example.com'")).rows[0];
      expect(user.email_verified).toBe(true);
      expect(user.email_verified_at).not.toBeNull();
    });

    it('a verified Google sign-in to an unverified password account verifies it and voids the unverified password', async () => {
      // Pre-account-takeover: someone registers the victim's address with a
      // password they know, then waits for the real owner to verify it.
      const squatter = new Client(loadApp());
      expect((await squatter.register('ada@example.com')).status).toBe(201);

      await oauthLogin(app, 'google', () => mockGoogle(googleProfile()));
      const user = (await db.query("SELECT * FROM users WHERE email = 'ada@example.com'")).rows;
      expect(user).toHaveLength(1);
      expect(user[0].email_verified).toBe(true);
      expect(user[0].email_verified_at).not.toBeNull();
      expect(user[0].password_hash).toBeNull();

      // The squatter's password no longer gets in
      const login = await squatter.login('ada@example.com', STRONG_PASSWORD);
      expect(login.status).toBe(401);
      expect(login.body.tokens).toBeUndefined();
    });

    it('logs a returning Google user into the same account', async () => {
      await oauthLogin(app, 'google', () => mockGoogle(googleProfile()));
      const agent = await oauthLogin(app, 'google', () => mockGoogle(googleProfile()));
      const users = (await db.query("SELECT id FROM users WHERE email = 'ada@example.com'")).rows;
      expect(users).toHaveLength(1);
      expect((await agent.get('/dashboard')).body.userId).toBe(users[0].id);
    });

    it('rejects a callback that does not carry the state issued to this browser', async () => {
      const victim = request.agent(app);
      await startFlow(victim, 'google');
      mockGoogle(googleProfile('attacker@example.com'));
      const res = await victim.get('/auth/google/callback?code=attacker-code&state=forged');
      expect(res.headers.location).not.toBe('/dashboard');
      expect((await victim.get('/dashboard')).status).not.toBe(200);
    });

    it('does not link an existing account via an unverified Google email', async () => {
      await db.query(
        "INSERT INTO users (email, password_hash, status, email_verified) VALUES ('victim@example.com', 'x', 'active', true)",
      );
      const agent = request.agent(app);
      const url = await startFlow(agent, 'google');
      mockGoogle({ ...googleProfile('victim@example.com', false), sub: 'google-evil' });
      const cb = await completeFlow(agent, url);
      expect(cb.headers.location).not.toBe('/dashboard');
      const linked = await db.query(
        "SELECT 1 FROM oauth_accounts oa JOIN users u ON u.id = oa.user_id WHERE u.email = 'victim@example.com'",
      );
      expect(linked.rowCount).toBe(0);
    });

    it('logout destroys the session', async () => {
      const agent = await oauthLogin(app, 'google', () => mockGoogle(googleProfile()));
      expect((await agent.post('/logout')).status).toBe(200);
      expect((await agent.get('/dashboard')).status).toBe(401);
    });
  });

  describe('GitHub', () => {
    const ghUser = { id: 4242, login: 'octo', name: 'Octo Cat', email: null };

    it('signs up a new user from the primary verified email', async () => {
      const agent = await oauthLogin(app, 'github', () =>
        mockGitHub(ghUser, [
          { email: 'octo-old@example.com', primary: false, verified: true },
          { email: 'octo@example.com', primary: true, verified: true },
        ]),
      );
      const user = (await db.query("SELECT * FROM users WHERE email = 'octo@example.com'")).rows[0];
      expect(user).toBeDefined();
      const account = (await db.query('SELECT * FROM oauth_accounts WHERE user_id = $1', [user.id])).rows[0];
      expect(account.provider).toBe('github');
      expect(account.provider_id).toBe('4242');
      expect((await agent.get('/dashboard')).body.userId).toBe(user.id);
    });

    it('does not link/log into an existing account via an unverified GitHub email (account takeover)', async () => {
      // victim registered with a password
      await db.query(
        "INSERT INTO users (email, password_hash, status, email_verified) VALUES ('victim@example.com', 'x', 'active', true)",
      );
      const agent = request.agent(app);
      const url = await startFlow(agent, 'github');
      mockGitHub({ id: 6666, login: 'mallory', name: 'Mallory', email: null }, [
        { email: 'victim@example.com', primary: true, verified: false },
      ]);
      const cb = await completeFlow(agent, url);
      expect(cb.headers.location).not.toBe('/dashboard');
      const linked = await db.query(
        "SELECT 1 FROM oauth_accounts oa JOIN users u ON u.id = oa.user_id WHERE u.email = 'victim@example.com'",
      );
      expect(linked.rowCount).toBe(0);
    });
  });

  describe('RBAC', () => {
    it('returns 401 (not 403) for unauthenticated requests to protected routes', async () => {
      for (const path of ['/dashboard', '/admin', '/moderator', '/users', '/audit-logs']) {
        const res = await request(app).get(path);
        expect({ path, status: res.status }).toEqual({ path, status: 401 });
      }
    });

    it('enforces roles and permissions for a session user', async () => {
      const agent = await oauthLogin(app, 'google', () => mockGoogle(googleProfile()));

      // default 'user' role: user:read_own, session:*_own
      expect((await agent.get('/admin')).status).toBe(403);
      expect((await agent.get('/moderator')).status).toBe(403);
      expect((await agent.get('/users')).status).toBe(403);
      expect((await agent.get('/audit-logs')).status).toBe(403);

      await grantRole('ada@example.com', 'moderator');
      expect((await agent.get('/moderator')).status).toBe(200);
      expect((await agent.get('/users')).status).toBe(200); // user:read
      expect((await agent.post('/users')).status).toBe(200); // user:write
      expect((await agent.delete('/users/123')).status).toBe(403); // user:delete is admin-only
      expect((await agent.get('/audit-logs')).status).toBe(200); // audit:read
      expect((await agent.get('/admin')).status).toBe(403);

      await grantRole('ada@example.com', 'admin');
      const admin = await agent.get('/admin');
      expect(admin.status).toBe(200);
      expect(admin.body.userRoles).toEqual(expect.arrayContaining(['admin', 'moderator', 'user']));
      expect((await agent.delete('/users/123')).status).toBe(200);
    });
  });
});

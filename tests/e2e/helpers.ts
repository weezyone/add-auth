/**
 * Shared harness for the e2e suite.
 *
 * - Runs pending SQL migrations against the test database once.
 * - Truncates all user data and FLUSHes the dedicated test Redis between tests,
 *   so rate-limit counters, CSRF secrets and sessions never leak across tests.
 * - Provides a cookie-aware client that performs the CSRF handshake the way a
 *   browser SPA would (GET /api/auth/csrf-token, then send X-CSRF-Token).
 */
import request from 'supertest';
import type { Express } from 'express';
import { db } from '../../src/database/connection';
import { migrationManager } from '../../src/database/migrate';
import { createRedisClient, getRedisClient, closeRedisConnection } from '../../src/utils/redis';
import { redisClient as rateLimitRedis, closeRedisConnection as closeRateLimitRedis } from '../../src/middleware/rateLimiter';
import { MemoryMailTransport, setMailTransport } from '../../src/services/mailer';

export const STRONG_PASSWORD = 'Str0ng!Passw0rd';

let migrated = false;

/** Every email the app sends during a test lands here instead of SMTP. */
export const mailbox = new MemoryMailTransport();

/** Pull the verification token out of the newest verification email sent to `email`. */
export function latestVerificationToken(email: string): string {
  const messages = mailbox.to(email);
  const last = messages[messages.length - 1];
  if (!last) throw new Error(`no email was sent to ${email}`);
  const match = /verify-email\?token=([A-Za-z0-9_-]+)/.exec(last.text);
  if (!match) throw new Error(`no verification link in email to ${email}: ${last.text}`);
  return match[1]!;
}

/** Wait (briefly) for an email that is sent in the background, e.g. by /resend-verification. */
export async function waitForMail(email: string, count: number, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (mailbox.to(email).length < count) {
    if (Date.now() > deadline) {
      throw new Error(`expected ${count} email(s) to ${email}, got ${mailbox.to(email).length}`);
    }
    await new Promise((r) => setTimeout(r, 20));
  }
}

export async function setupInfrastructure(): Promise<void> {
  if (!migrated) {
    await migrationManager.migrate();
    migrated = true;
  }
  await createRedisClient();
  setMailTransport(mailbox);
}

export async function resetState(): Promise<void> {
  await db.query('TRUNCATE users, sessions, user_roles, audit_logs, oauth_accounts CASCADE');
  await getRedisClient().flushDb();
  mailbox.clear();
}

export async function teardownInfrastructure(): Promise<void> {
  await closeRedisConnection();
  await closeRateLimitRedis();
  await db.close();
}

export function loadApp(): Express {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('../../src/index').default;
}

let counter = 0;
export function uniqueEmail(prefix = 'user'): string {
  counter += 1;
  return `${prefix}.${Date.now()}.${counter}@example.com`;
}

/**
 * A browser-like client: keeps cookies between requests and knows how to fetch
 * and attach a CSRF token for state-changing requests.
 */
export class Client {
  readonly agent: ReturnType<typeof request.agent>;
  csrfToken: string | null = null;

  constructor(app: Express, readonly userAgent = 'add-auth-e2e/1.0') {
    this.agent = request.agent(app);
  }

  async fetchCsrfToken(): Promise<string> {
    const res = await this.agent
      .get('/api/auth/csrf-token')
      .set('User-Agent', this.userAgent);
    if (res.status !== 200 || !res.body.csrfToken) {
      throw new Error(`csrf-token failed: ${res.status} ${JSON.stringify(res.body)}`);
    }
    this.csrfToken = res.body.csrfToken;
    return res.body.csrfToken;
  }

  get(path: string) {
    return this.agent.get(path).set('User-Agent', this.userAgent);
  }

  async post(path: string, body: Record<string, unknown> = {}, accessToken?: string) {
    const token = this.csrfToken ?? (await this.fetchCsrfToken());
    const req = this.agent
      .post(path)
      .set('User-Agent', this.userAgent)
      .set('X-CSRF-Token', token)
      .send(body);
    if (accessToken) req.set('Authorization', `Bearer ${accessToken}`);
    return req;
  }

  async put(path: string, body: Record<string, unknown> = {}, accessToken?: string) {
    const token = this.csrfToken ?? (await this.fetchCsrfToken());
    const req = this.agent
      .put(path)
      .set('User-Agent', this.userAgent)
      .set('X-CSRF-Token', token)
      .send(body);
    if (accessToken) req.set('Authorization', `Bearer ${accessToken}`);
    return req;
  }

  async delete(path: string, accessToken?: string) {
    const token = this.csrfToken ?? (await this.fetchCsrfToken());
    const req = this.agent
      .delete(path)
      .set('User-Agent', this.userAgent)
      .set('X-CSRF-Token', token);
    if (accessToken) req.set('Authorization', `Bearer ${accessToken}`);
    return req;
  }

  async register(email = uniqueEmail(), password = STRONG_PASSWORD) {
    return this.post('/api/auth/register', { email, password, confirmPassword: password, username: 'e2euser' });
  }

  async login(email: string, password = STRONG_PASSWORD) {
    return this.post('/api/auth/login', { email, password });
  }

  async verifyEmail(token: string) {
    return this.post('/api/auth/verify-email', { token });
  }

  /**
   * The full happy path a real user takes: register, click the link in the
   * verification email, log in. Returns the login response (tokens + session)
   * plus the user id.
   */
  async signUp(email = uniqueEmail(), password = STRONG_PASSWORD) {
    const reg = await this.register(email, password);
    if (reg.status !== 201) throw new Error(`register failed: ${reg.status} ${JSON.stringify(reg.body)}`);
    const verified = await this.verifyEmail(latestVerificationToken(email));
    if (verified.status !== 200) throw new Error(`verify failed: ${verified.status} ${JSON.stringify(verified.body)}`);
    const login = await this.login(email, password);
    if (login.status !== 200) throw new Error(`login failed: ${login.status} ${JSON.stringify(login.body)}`);
    return { email, userId: reg.body.user.id as string, login };
  }
}

export { rateLimitRedis };

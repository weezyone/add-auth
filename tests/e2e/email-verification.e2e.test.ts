/**
 * PAU-18: email verification blocks password login until the address is
 * verified. Covers register -> email -> verify -> login, token single-use /
 * expiry, resend (enumeration-safe + rate limited), refresh for unverified
 * users, and the migration that grandfathers existing accounts.
 */
import crypto from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import type { Express } from 'express';
import { db } from '../../src/database/connection';
import { getRedisClient } from '../../src/utils/redis';
import { EmailVerificationService } from '../../src/services/emailVerificationService';
import {
  setupInfrastructure, resetState, teardownInfrastructure, loadApp,
  Client, uniqueEmail, STRONG_PASSWORD, mailbox, latestVerificationToken, waitForMail,
} from './helpers';

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

async function emailVerified(email: string): Promise<boolean> {
  const r = await db.query('SELECT email_verified FROM users WHERE email = $1', [email]);
  return r.rows[0].email_verified;
}

describe('email verification', () => {
  let app: Express;

  beforeAll(async () => {
    await setupInfrastructure();
    app = loadApp();
  });
  beforeEach(resetState);
  afterAll(teardownInfrastructure);

  describe('registration', () => {
    it('creates an unverified user, issues no tokens or session, and emails a verification link', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      const reg = await client.register(email);

      expect(reg.status).toBe(201);
      expect(reg.body.verificationRequired).toBe(true);
      expect(reg.body.user).toMatchObject({ email, email_verified: false });
      expect(reg.body.tokens).toBeUndefined();
      expect(reg.body.session).toBeUndefined();
      expect((reg.headers['set-cookie'] ?? []).join(';')).not.toMatch(/sessionId=/);
      expect(await emailVerified(email)).toBe(false);
      expect(await getRedisClient().sCard(`user_sessions:${reg.body.user.id}`)).toBe(0);

      const mails = mailbox.to(email);
      expect(mails).toHaveLength(1);
      expect(mails[0]!.text).toContain(`${process.env.FRONTEND_URL}/verify-email?token=`);
      expect(mails[0]!.text).toContain('24 hours');
    });

    it('stores only a hash of the token, expiring in ~24h', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      const reg = await client.register(email);
      const token = latestVerificationToken(email);
      expect(token).toMatch(/^[a-f0-9]{64}$/); // 256 bits

      const rows = await db.query(
        'SELECT token_hash, expires_at, used_at FROM email_verification_tokens WHERE user_id = $1',
        [reg.body.user.id],
      );
      expect(rows.rows).toHaveLength(1);
      expect(rows.rows[0].token_hash).toBe(sha256(token));
      expect(rows.rows[0].token_hash).not.toContain(token);
      expect(rows.rows[0].used_at).toBeNull();
      const ttlMs = new Date(rows.rows[0].expires_at).getTime() - Date.now();
      expect(ttlMs).toBeGreaterThan(23.9 * 3600e3);
      expect(ttlMs).toBeLessThanOrEqual(24 * 3600e3);
    });
  });

  describe('login', () => {
    it('refuses an unverified user with 403 EMAIL_NOT_VERIFIED and issues no tokens or session', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      const reg = await client.register(email);

      const res = await client.login(email);
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('EMAIL_NOT_VERIFIED');
      expect(res.body.tokens).toBeUndefined();
      expect(res.body.session).toBeUndefined();
      expect((res.headers['set-cookie'] ?? []).join(';')).not.toMatch(/sessionId=/);
      expect(await getRedisClient().sCard(`user_sessions:${reg.body.user.id}`)).toBe(0);
    });

    it('does not reveal verification state to someone without the password (401, not 403)', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      await client.register(email);
      const res = await client.login(email, 'Wr0ng!Password');
      expect(res.status).toBe(401);
      expect(res.body.code).toBeUndefined();
    });

    it('works once the email is verified', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      await client.register(email);
      const verify = await client.verifyEmail(latestVerificationToken(email));
      expect(verify.status).toBe(200);
      expect(verify.body.code).toBe('EMAIL_VERIFIED');
      expect(await emailVerified(email)).toBe(true);

      const login = await client.login(email);
      expect(login.status).toBe(200);
      expect(login.body.user.email_verified).toBe(true);
      expect(login.body.tokens.accessToken).toEqual(expect.any(String));
    });
  });

  describe('verify endpoint', () => {
    it('consumes the token once (400 VERIFICATION_TOKEN_USED on reuse)', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      await client.register(email);
      const token = latestVerificationToken(email);
      expect((await client.verifyEmail(token)).status).toBe(200);
      const again = await client.verifyEmail(token);
      expect(again.status).toBe(400);
      expect(again.body.code).toBe('VERIFICATION_TOKEN_USED');
    });

    it('rejects an expired token (400 VERIFICATION_TOKEN_EXPIRED) and leaves the user unverified', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      await client.register(email);
      const token = latestVerificationToken(email);
      await db.query(
        "UPDATE email_verification_tokens SET expires_at = NOW() - interval '1 minute' WHERE token_hash = $1",
        [sha256(token)],
      );
      const res = await client.verifyEmail(token);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VERIFICATION_TOKEN_EXPIRED');
      expect(await emailVerified(email)).toBe(false);
    });

    it('rejects an unknown token (400 VERIFICATION_TOKEN_INVALID) and a missing token (400)', async () => {
      const client = new Client(app);
      const unknown = await client.verifyEmail(crypto.randomBytes(32).toString('hex'));
      expect(unknown.status).toBe(400);
      expect(unknown.body.code).toBe('VERIFICATION_TOKEN_INVALID');
      const missing = await client.post('/api/auth/verify-email', {});
      expect(missing.status).toBe(400);
    });

    it('two concurrent uses of one token verify exactly once', async () => {
      const a = new Client(app);
      const b = new Client(app, 'add-auth-e2e/2.0');
      const email = uniqueEmail();
      await a.register(email);
      const token = latestVerificationToken(email);
      await b.fetchCsrfToken();
      const results = await Promise.all([a.verifyEmail(token), b.verifyEmail(token)]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    });
  });

  describe('resend endpoint', () => {
    const resend = (client: Client, email: string) =>
      client.post('/api/auth/resend-verification', { email });

    it('answers identically for an unverified user, a verified user, and an unknown address', async () => {
      const client = new Client(app);
      const unverified = uniqueEmail();
      await client.register(unverified);
      const { email: verified } = await new Client(app, 'add-auth-e2e/other').signUp();

      const responses = await Promise.all([
        resend(client, unverified),
        resend(client, verified),
        resend(client, uniqueEmail('nobody')),
      ]);
      for (const r of responses) {
        expect(r.status).toBe(202);
        expect(r.body).toEqual(responses[0]!.body);
      }
    });

    it('emails a fresh link to an unverified user; the previous link stops working', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      await client.register(email);
      const first = latestVerificationToken(email);

      expect((await resend(client, email)).status).toBe(202);
      await waitForMail(email, 2);
      const second = latestVerificationToken(email);
      expect(second).not.toBe(first);

      const old = await client.verifyEmail(first);
      expect(old.status).toBe(400);
      expect((await client.verifyEmail(second)).status).toBe(200);
      expect((await client.login(email)).status).toBe(200);
    });

    it('sends nothing for unknown or already-verified addresses', async () => {
      const { email: verified } = await new Client(app).signUp();
      mailbox.clear();
      const unknown = uniqueEmail('nobody');
      await EmailVerificationService.resend(verified);
      await EmailVerificationService.resend(unknown);
      expect(mailbox.messages).toHaveLength(0);
    });

    it('sends at most one email per address per cooldown window', async () => {
      const client = new Client(app);
      const email = uniqueEmail();
      await client.register(email); // 1st email
      await EmailVerificationService.resend(email); // 2nd
      await EmailVerificationService.resend(email); // suppressed by cooldown
      expect(mailbox.to(email)).toHaveLength(2);
    });

    it('is rate limited per IP (429 once the limit is hit)', async () => {
      const client = new Client(app);
      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) {
        statuses.push((await resend(client, uniqueEmail('nobody'))).status);
      }
      expect(statuses.slice(0, 5)).toEqual([202, 202, 202, 202, 202]);
      expect(statuses[5]).toBe(429);
    });
  });

  describe('refresh', () => {
    it('fails with 403 EMAIL_NOT_VERIFIED if the user is no longer verified', async () => {
      const client = new Client(app);
      const { email, login } = await client.signUp();
      await db.query('UPDATE users SET email_verified = FALSE WHERE email = $1', [email]);
      const res = await client.post('/api/auth/refresh', { refreshToken: login.body.tokens.refreshToken });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('EMAIL_NOT_VERIFIED');
      expect(res.body.tokens).toBeUndefined();
    });
  });

  describe('migration 006', () => {
    it('grandfathers every pre-existing account as verified (and is safe to re-run)', async () => {
      const sql = readFileSync(
        join(__dirname, '../../src/database/migrations/006_email_verification.sql'),
        'utf8',
      );
      const email = uniqueEmail('legacy');
      await db.transaction(async (c) => {
        await c.query(
          "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', FALSE)",
          [email],
        );
        await c.query(sql);
        const r = await c.query(
          'SELECT email_verified, email_verified_at FROM users WHERE email = $1',
          [email],
        );
        expect(r.rows[0].email_verified).toBe(true);
        // grandfathered rows are distinguishable: verified with no verification timestamp
        expect(r.rows[0].email_verified_at).toBeNull();
        await c.query('ROLLBACK');
        await c.query('BEGIN'); // db.transaction will COMMIT this empty txn
      });
      const after = await db.query('SELECT 1 FROM users WHERE email = $1', [email]);
      expect(after.rows).toHaveLength(0);
    });

    it('a user who verifies through the link gets email_verified_at set', async () => {
      const client = new Client(app);
      const { email } = await client.signUp();
      const r = await db.query('SELECT email_verified_at FROM users WHERE email = $1', [email]);
      expect(r.rows[0].email_verified_at).not.toBeNull();
    });
  });
});

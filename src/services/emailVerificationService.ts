/**
 * Email verification (PAU-18).
 *
 * - issue(): random 256-bit token, only its SHA-256 is stored, expires after
 *   EMAIL_VERIFICATION_TTL_HOURS (default 24). Issuing a new token supersedes
 *   any outstanding one for that user.
 * - verify(): consumes a token exactly once (row lock), marks the user verified.
 * - resend(): enumeration-safe; silently does nothing for unknown, inactive or
 *   already-verified addresses, and at most once per address per cooldown.
 */
import crypto from 'crypto';
import { db } from '../database/connection';
import { appConfig } from '../config';
import { UserModel } from '../models/User';
import { UserStatus } from '../types/user';
import { getMailTransport } from './mailer';
import { buildVerificationEmail } from '../utils/emailService';
import { getRedisClient } from '../utils/redis';
import { logger } from '../utils/logger';

export const EMAIL_NOT_VERIFIED = 'EMAIL_NOT_VERIFIED';

/** Minimum time between verification emails to one address via resend. */
export const RESEND_COOLDOWN_SECONDS = 60;

export type VerifyFailure = 'VERIFICATION_TOKEN_INVALID' | 'VERIFICATION_TOKEN_EXPIRED' | 'VERIFICATION_TOKEN_USED';
export type VerifyResult = { ok: true; userId: string } | { ok: false; code: VerifyFailure };

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export class EmailVerificationService {
  static hashToken(token: string): string {
    return sha256(token);
  }

  /** Create a fresh token for the user and email the link. Rejects if the mail can't be sent. */
  static async issue(user: { id: string; email: string }): Promise<void> {
    // Hex, not base64url: the SQL-injection middleware treats "--" as a comment.
    const token = crypto.randomBytes(32).toString('hex');
    const ttlHours = appConfig.emailVerification.ttlHours;

    await db.transaction(async (client) => {
      await client.query(
        'UPDATE email_verification_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL',
        [user.id]
      );
      await client.query(
        `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() + ($3::numeric * INTERVAL '1 hour'))`,
        [user.id, sha256(token), ttlHours]
      );
    });

    const url = `${appConfig.emailVerification.frontendUrl}/verify-email?token=${token}`;
    const template = buildVerificationEmail(url, ttlHours);
    await getMailTransport().send({
      to: user.email,
      subject: template.subject,
      text: template.text,
      html: template.html,
    });
    logger.info('Verification email sent', { userId: user.id });
  }

  static async verify(token: string): Promise<VerifyResult> {
    return db.transaction(async (client): Promise<VerifyResult> => {
      const found = await client.query(
        `SELECT id, user_id, used_at, expires_at <= NOW() AS expired
         FROM email_verification_tokens WHERE token_hash = $1 FOR UPDATE`,
        [sha256(token)]
      );
      const row = found.rows[0];
      if (!row) return { ok: false, code: 'VERIFICATION_TOKEN_INVALID' };
      if (row.used_at) return { ok: false, code: 'VERIFICATION_TOKEN_USED' };
      if (row.expired) return { ok: false, code: 'VERIFICATION_TOKEN_EXPIRED' };

      await client.query('UPDATE email_verification_tokens SET used_at = NOW() WHERE id = $1', [row.id]);
      await client.query(
        `UPDATE users SET email_verified = TRUE, email_verified_at = COALESCE(email_verified_at, NOW())
         WHERE id = $1`,
        [row.user_id]
      );
      logger.info('Email verified', { userId: row.user_id });
      return { ok: true, userId: row.user_id };
    });
  }

  /**
   * Send a new link if (and only if) the address belongs to an active,
   * unverified account and the per-address cooldown has passed. Never reveals
   * which case applied.
   */
  static async resend(email: string): Promise<void> {
    const normalized = email.toLowerCase().trim();
    const user = await UserModel.findByEmail(normalized);
    if (!user || user.email_verified || user.status !== UserStatus.ACTIVE) {
      return;
    }
    if (!(await this.acquireResendCooldown(normalized))) {
      logger.info('Verification resend suppressed (cooldown)', { userId: user.id });
      return;
    }
    await this.issue(user);
  }

  private static async acquireResendCooldown(email: string): Promise<boolean> {
    try {
      const result = await getRedisClient().set(`email-verification:resend:${sha256(email)}`, '1', {
        NX: true,
        EX: RESEND_COOLDOWN_SECONDS,
      });
      return result === 'OK';
    } catch (error) {
      // Redis down: fall back to the per-IP route limiter only.
      logger.warn('Resend cooldown unavailable (Redis); continuing', { error });
      return true;
    }
  }
}

/**
 * Pluggable outbound mail.
 *
 * Application code calls getMailTransport().send(...) and never talks to SMTP
 * directly, so tests (and local dev) can swap the transport:
 *
 * - SmtpMailTransport: delegates to the existing nodemailer-based EmailService.
 *   Selected automatically when EMAIL_USER and EMAIL_PASS are set.
 * - ConsoleMailTransport: the default otherwise. Outside production it logs the
 *   whole message so a developer can click the verification link; in production
 *   it only warns that mail is not being delivered (never logs links/tokens).
 * - MemoryMailTransport: records messages in memory; used by the test suites.
 */
import { EmailService } from '../utils/emailService';
import { logger } from '../utils/logger';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export interface MailTransport {
  readonly name: string;
  /** Resolves when the message is accepted; rejects if it could not be sent. */
  send(message: MailMessage): Promise<void>;
}

export class ConsoleMailTransport implements MailTransport {
  readonly name = 'console';

  constructor(private readonly nodeEnv: string = process.env.NODE_ENV || 'development') {}

  async send(message: MailMessage): Promise<void> {
    if (this.nodeEnv === 'production') {
      logger.warn('Mail transport not configured (set EMAIL_USER/EMAIL_PASS); email NOT delivered', {
        to: message.to,
        subject: message.subject,
      });
      return;
    }
    logger.info('[mail:console] email not delivered (dev transport)', {
      to: message.to,
      subject: message.subject,
      text: message.text,
    });
  }
}

type EmailSender = Pick<EmailService, 'sendEmail'>;

export class SmtpMailTransport implements MailTransport {
  readonly name = 'smtp';

  constructor(private readonly service: EmailSender = new EmailService()) {}

  async send(message: MailMessage): Promise<void> {
    const ok = await this.service.sendEmail({
      to: message.to,
      subject: message.subject,
      text: message.text,
      ...(message.html !== undefined ? { html: message.html } : {}),
    });
    if (!ok) {
      throw new Error('SMTP delivery failed');
    }
  }
}

export class MemoryMailTransport implements MailTransport {
  readonly name = 'memory';
  readonly messages: MailMessage[] = [];

  async send(message: MailMessage): Promise<void> {
    this.messages.push(message);
  }

  to(address: string): MailMessage[] {
    return this.messages.filter((m) => m.to.toLowerCase() === address.toLowerCase());
  }

  clear(): void {
    this.messages.length = 0;
  }
}

export function createDefaultMailTransport(): MailTransport {
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    return new SmtpMailTransport();
  }
  return new ConsoleMailTransport();
}

let transport: MailTransport | null = null;

export function getMailTransport(): MailTransport {
  if (!transport) {
    transport = createDefaultMailTransport();
  }
  return transport;
}

/** Override the transport (tests, alternative providers). Pass null to reset to the default. */
export function setMailTransport(next: MailTransport | null): void {
  transport = next;
}

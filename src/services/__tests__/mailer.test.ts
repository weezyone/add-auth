import { logger } from '../../utils/logger';
import {
  ConsoleMailTransport,
  MemoryMailTransport,
  SmtpMailTransport,
  createDefaultMailTransport,
  getMailTransport,
  setMailTransport,
} from '../mailer';
import { buildVerificationEmail } from '../../utils/emailService';

describe('mailer', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
    setMailTransport(null);
    jest.restoreAllMocks();
  });

  it('defaults to the console transport when SMTP is not configured', () => {
    delete process.env.EMAIL_USER;
    delete process.env.EMAIL_PASS;
    expect(createDefaultMailTransport()).toBeInstanceOf(ConsoleMailTransport);
  });

  it('uses SMTP (the existing EmailService) when EMAIL_USER and EMAIL_PASS are set', () => {
    process.env.EMAIL_USER = 'user';
    process.env.EMAIL_PASS = 'pass';
    expect(createDefaultMailTransport()).toBeInstanceOf(SmtpMailTransport);
  });

  it('setMailTransport overrides the transport used by getMailTransport', async () => {
    const memory = new MemoryMailTransport();
    setMailTransport(memory);
    await getMailTransport().send({ to: 'a@example.com', subject: 's', text: 't' });
    expect(memory.messages).toEqual([{ to: 'a@example.com', subject: 's', text: 't' }]);
    expect(memory.to('a@example.com')).toHaveLength(1);
    memory.clear();
    expect(memory.messages).toHaveLength(0);
  });

  it('console transport prints the message outside production (so devs get the link)', async () => {
    const info = jest.spyOn(logger, 'info').mockImplementation((() => logger) as any);
    await new ConsoleMailTransport('development').send({ to: 'a@example.com', subject: 's', text: 'secret-link' });
    expect(JSON.stringify(info.mock.calls)).toContain('secret-link');
  });

  it('console transport never logs the body in production', async () => {
    const calls: unknown[] = [];
    for (const level of ['info', 'warn', 'error', 'debug'] as const) {
      jest.spyOn(logger, level).mockImplementation(((...args: unknown[]) => { calls.push(args); return logger; }) as any);
    }
    await new ConsoleMailTransport('production').send({ to: 'a@example.com', subject: 's', text: 'secret-link' });
    expect(JSON.stringify(calls)).not.toContain('secret-link');
    expect(calls.length).toBeGreaterThan(0); // but it does warn that mail is not being delivered
  });

  it('smtp transport throws when the EmailService reports failure', async () => {
    const service = { sendEmail: jest.fn().mockResolvedValue(false) };
    await expect(
      new SmtpMailTransport(service as any).send({ to: 'a@example.com', subject: 's', text: 't' }),
    ).rejects.toThrow();
    service.sendEmail.mockResolvedValue(true);
    await expect(
      new SmtpMailTransport(service as any).send({ to: 'a@example.com', subject: 's', text: 't', html: '<p>t</p>' }),
    ).resolves.toBeUndefined();
    expect(service.sendEmail).toHaveBeenLastCalledWith({ to: 'a@example.com', subject: 's', text: 't', html: '<p>t</p>' });
  });

  it('verification template carries the link and the real expiry', () => {
    const t = buildVerificationEmail('https://app.example.com/verify-email?token=abc', 48);
    expect(t.text).toContain('https://app.example.com/verify-email?token=abc');
    expect(t.html).toContain('https://app.example.com/verify-email?token=abc');
    expect(t.text).toContain('48 hours');
  });
});

import { detectSQLInjection, sqlInjectionPrevention } from '../sqlInjectionPrevention';

describe('detectSQLInjection', () => {
  it('gives the same answer for the same input every time (no global-regex lastIndex state)', () => {
    const input = '1; DROP TABLE users';
    const results = Array.from({ length: 4 }, () => detectSQLInjection(input, { strict: true }).detected);
    expect(results).toEqual([true, true, true, true]);
  });

  it('does not throw on input with a stray % (malformed URI escape)', () => {
    expect(() => detectSQLInjection('100%sure', { strict: true })).not.toThrow();
    expect(detectSQLInjection('100%sure', { strict: true }).detected).toBe(false);
  });

  it('does not accumulate customPatterns across calls', () => {
    const custom = /forbidden-word/gi;
    detectSQLInjection('hello', { strict: true, customPatterns: [custom] });
    // a later call without customPatterns must not still apply them
    expect(detectSQLInjection('forbidden-word', { strict: true }).detected).toBe(false);
  });
});

describe('sqlInjectionPrevention middleware', () => {
  const run = (body: any, config = {}) => {
    const res: any = { statusCode: 200, body: undefined };
    res.status = jest.fn((code: number) => { res.statusCode = code; return res; });
    res.json = jest.fn((b: any) => { res.body = b; return res; });
    const next = jest.fn();
    const req: any = { body, query: {}, params: {}, ip: '127.0.0.1', method: 'POST', url: '/', headers: {}, get: () => undefined };
    sqlInjectionPrevention(config)(req, res, next);
    return { res, next };
  };

  it('blocks with 400 and does NOT call next() when injection is detected', () => {
    const { res, next } = run({ password: 'x; DROP TABLE users' });
    expect(res.statusCode).toBe(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next() for clean input', () => {
    const { res, next } = run({ email: 'a@example.com' });
    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('does not log request headers (they carry bearer tokens and cookies)', () => {
    const { logger } = require('../../utils/logger');
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => logger);
    const res: any = { status: jest.fn(() => res), json: jest.fn(() => res) };
    const req: any = {
      body: { q: 'x; DROP TABLE users' }, query: {}, params: {}, ip: '127.0.0.1', method: 'POST', url: '/',
      headers: { authorization: 'Bearer secret-token', cookie: 'sessionId=secret' }, get: () => undefined,
    };
    sqlInjectionPrevention()(req, res, jest.fn());
    expect(JSON.stringify(warn.mock.calls)).not.toMatch(/secret-token|sessionId=secret/);
    warn.mockRestore();
  });
});

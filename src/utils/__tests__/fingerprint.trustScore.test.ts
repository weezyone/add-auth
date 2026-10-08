import { FingerprintService, DeviceFingerprint } from '../fingerprint';

const fp = (userAgent: string, ip = '10.0.0.1'): DeviceFingerprint => ({
  hash: `${userAgent}|${ip}`,
  ip,
  userAgent,
  acceptLanguage: 'en-US',
  acceptEncoding: 'gzip',
  timestamp: new Date(),
});

// sessionSecurityMiddleware destroys sessions below this score
const LOW_TRUST_CUTOFF = 0.3;

describe('FingerprintService.calculateTrustScore', () => {
  const laptop = fp('Mozilla/5.0 (Macintosh)');
  const phone = fp('Mozilla/5.0 (iPhone)');

  it('gives a neutral 0.5 to a user with no history', () => {
    expect(FingerprintService.calculateTrustScore([], laptop)).toBe(0.5);
  });

  it('gives full trust to a device that matches all history', () => {
    expect(FingerprintService.calculateTrustScore([laptop, laptop], laptop)).toBe(1);
  });

  it('treats a new device for an existing user as neutral, not untrusted', () => {
    const score = FingerprintService.calculateTrustScore([laptop], phone);
    expect(score).toBe(0.5);
    expect(score).toBeGreaterThanOrEqual(LOW_TRUST_CUTOFF);
  });

  it('does not penalise a known device for the user also having other devices', () => {
    const score = FingerprintService.calculateTrustScore([laptop, phone], phone);
    expect(score).toBeGreaterThanOrEqual(0.5);
    expect(score).toBeLessThanOrEqual(1);
  });

  it('trusts a device more the more consistently it has been seen', () => {
    const once = FingerprintService.calculateTrustScore([laptop, laptop, laptop, phone], phone);
    const mostly = FingerprintService.calculateTrustScore([laptop, phone, phone, phone], phone);
    expect(mostly).toBeGreaterThan(once);
  });
});

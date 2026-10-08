import crypto from 'crypto';
import { Request } from 'express';
import { logger } from './logger';

export interface DeviceFingerprint {
  hash: string;
  ip: string;
  userAgent: string;
  acceptLanguage?: string;
  acceptEncoding?: string;
  timestamp: Date;
}

export interface FingerprintValidationResult {
  isValid: boolean;
  risk: 'low' | 'medium' | 'high';
  changes: string[];
  recommendations: string[];
}

export class FingerprintService {
  private static readonly CRITICAL_HEADERS = ['user-agent', 'accept-language'];
  private static readonly MONITORED_HEADERS = ['accept-encoding', 'x-forwarded-for'];

  /**
   * Generate a device fingerprint from request headers
   */
  static generateFingerprint(req: Request): DeviceFingerprint {
    const ip = this.getClientIP(req);
    const userAgent = req.get('user-agent') || '';
    const acceptLanguage = req.get('accept-language');
    const acceptEncoding = req.get('accept-encoding');

    // Create a hash of the fingerprint components
    const fingerprintData = {
      ip,
      userAgent,
      acceptLanguage,
      acceptEncoding,
    };

    const hash = crypto
      .createHash('sha256')
      .update(JSON.stringify(fingerprintData))
      .digest('hex');

    const fingerprint: DeviceFingerprint = {
      hash,
      ip,
      userAgent,
      acceptLanguage,
      acceptEncoding,
      timestamp: new Date(),
    };

    logger.debug('Generated device fingerprint', {
      hash: fingerprint.hash,
      ip: fingerprint.ip,
      userAgent: fingerprint.userAgent?.substring(0, 50) + '...',
    });

    return fingerprint;
  }

  /**
   * Validate a current fingerprint against a stored one
   */
  static validateFingerprint(
    currentFingerprint: DeviceFingerprint,
    storedFingerprint: DeviceFingerprint
  ): FingerprintValidationResult {
    const changes: string[] = [];
    let risk: 'low' | 'medium' | 'high' = 'low';
    const recommendations: string[] = [];

    // Check IP address change
    if (currentFingerprint.ip !== storedFingerprint.ip) {
      changes.push('IP address changed');
      risk = 'medium';
      recommendations.push('Consider requiring re-authentication');
    }

    // Check User-Agent change
    if (currentFingerprint.userAgent !== storedFingerprint.userAgent) {
      changes.push('User-Agent changed');
      risk = 'high';
      recommendations.push('Require immediate re-authentication');
    }

    // Check Accept-Language change
    if (currentFingerprint.acceptLanguage !== storedFingerprint.acceptLanguage) {
      changes.push('Accept-Language changed');
      if (risk === 'low') risk = 'medium';
      recommendations.push('Monitor for suspicious activity');
    }

    // Check Accept-Encoding change
    if (currentFingerprint.acceptEncoding !== storedFingerprint.acceptEncoding) {
      changes.push('Accept-Encoding changed');
      if (risk === 'low') risk = 'medium';
    }

    const isValid = changes.length === 0 || 
                   (changes.length === 1 && changes[0] === 'IP address changed');

    logger.info('Fingerprint validation completed', {
      currentHash: currentFingerprint.hash,
      storedHash: storedFingerprint.hash,
      isValid,
      risk,
      changes,
    });

    return {
      isValid,
      risk,
      changes,
      recommendations,
    };
  }

  /**
   * Get the real client IP address from request
   */
  private static getClientIP(req: Request): string {
    const forwarded = req.get('x-forwarded-for');
    const realIP = req.get('x-real-ip');
    const connectingIP = req.get('x-connecting-ip');

    if (forwarded) {
      // X-Forwarded-For can contain multiple IPs, take the first one
      return forwarded.split(',')[0].trim();
    }

    if (realIP) {
      return realIP;
    }

    if (connectingIP) {
      return connectingIP;
    }

    return req.connection.remoteAddress || req.socket.remoteAddress || req.ip || 'unknown';
  }

  /**
   * Create a secure session token with fingerprint binding
   */
  static createSecureSessionToken(
    userId: string,
    fingerprint: DeviceFingerprint
  ): string {
    const tokenData = {
      userId,
      fingerprintHash: fingerprint.hash,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
    };

    const token = crypto
      .createHash('sha256')
      .update(JSON.stringify(tokenData))
      .digest('hex');

    return token;
  }

  /**
   * Check if fingerprint indicates potential session hijacking
   */
  static detectSessionHijacking(
    currentFingerprint: DeviceFingerprint,
    storedFingerprint: DeviceFingerprint
  ): boolean {
    // High-risk indicators
    const userAgentChanged = currentFingerprint.userAgent !== storedFingerprint.userAgent;
    const significantIPChange = this.isSignificantIPChange(
      currentFingerprint.ip,
      storedFingerprint.ip
    );

    // If both critical components changed, it's likely hijacking
    if (userAgentChanged && significantIPChange) {
      logger.warn('Potential session hijacking detected', {
        currentIP: currentFingerprint.ip,
        storedIP: storedFingerprint.ip,
        currentUA: currentFingerprint.userAgent?.substring(0, 50),
        storedUA: storedFingerprint.userAgent?.substring(0, 50),
      });
      return true;
    }

    return false;
  }

  /**
   * Check if IP change is significant (different subnets)
   */
  private static isSignificantIPChange(currentIP: string, storedIP: string): boolean {
    // Simple check for IPv4 - same /24 subnet
    if (currentIP.includes('.') && storedIP.includes('.')) {
      const currentParts = currentIP.split('.');
      const storedParts = storedIP.split('.');
      
      // If first 3 octets are the same, it's likely the same network
      return !(
        currentParts[0] === storedParts[0] &&
        currentParts[1] === storedParts[1] &&
        currentParts[2] === storedParts[2]
      );
    }

    // For IPv6 or other cases, any change is significant
    return currentIP !== storedIP;
  }

  /**
   * Generate a device trust score based on fingerprint history
   */
  static calculateTrustScore(
    fingerprintHistory: DeviceFingerprint[],
    currentFingerprint: DeviceFingerprint
  ): number {
    if (fingerprintHistory.length === 0) {
      return 0.5; // Neutral score for new devices
    }

    // Score how familiar *this* device is. The previous formula subtracted a
    // penalty for every history entry from a different device and then
    // multiplied by the match ratio, so any user with a second device scored 0
    // there (and still < 0.3 after logging in again), and
    // sessionSecurityMiddleware destroyed the session on first use.
    // A never-seen device now gets the same neutral 0.5 as a brand-new user;
    // a known device scales from 0.5 up to 1.0 with how consistently it has
    // been seen. Session hijacking (UA + network change on an existing
    // session) is still caught by detectSessionHijacking/validateFingerprint.
    let consistentSessions = 0;

    for (const historical of fingerprintHistory) {
      if (this.validateFingerprint(currentFingerprint, historical).isValid) {
        consistentSessions++;
      }
    }

    const consistencyRatio = consistentSessions / fingerprintHistory.length;
    const trustScore = Math.max(0, Math.min(1, 0.5 + 0.5 * consistencyRatio));

    logger.debug('Calculated device trust score', {
      fingerprintHash: currentFingerprint.hash,
      trustScore,
      consistentSessions,
      totalSessions: fingerprintHistory.length,
    });

    return trustScore;
  }
}

export default FingerprintService;
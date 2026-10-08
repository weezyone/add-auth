/**
 * CSRF Protection Middleware
 * Implements Cross-Site Request Forgery protection with token generation and validation
 */

import { Request, Response, NextFunction } from 'express';
import csrf from 'csrf';
import { logger } from '../utils/logger';
import { redisClient } from './rateLimiter';

// CSRF token handler
const csrfTokens = new csrf();

/**
 * Interface for CSRF token storage
 */
interface CSRFTokenData {
  token: string;
  secret: string;
  createdAt: number;
  expiresAt: number;
}

/**
 * CSRF Protection Configuration
 */
export interface CSRFConfig {
  saltLength?: number;
  secretLength?: number;
  tokenExpiry?: number; // in milliseconds
  cookieName?: string;
  headerName?: string;
  skipOnSameSite?: boolean;
  exemptMethods?: string[];
}

const defaultConfig: Required<CSRFConfig> = {
  saltLength: 16,
  secretLength: 32,
  tokenExpiry: 60 * 60 * 1000, // 1 hour
  cookieName: 'csrf-token',
  headerName: 'x-csrf-token',
  skipOnSameSite: true,
  exemptMethods: ['GET', 'HEAD', 'OPTIONS']
};

/**
 * Generate CSRF token and secret
 */
export const generateCSRFToken = async (sessionId: string, config: CSRFConfig = {}): Promise<{ token: string; secret: string }> => {
  const cfg = { ...defaultConfig, ...config };
  
  try {
    const key = `csrf:${sessionId}`;

    // Reuse the session's existing, unexpired secret. Tokens are salted per
    // call, so every token minted from the same secret stays valid. Minting a
    // fresh secret on every safe request (any GET passing through
    // csrfProtection) silently invalidated every token handed out before it.
    const existing = await redisClient.get(key);
    if (existing) {
      const stored: CSRFTokenData = JSON.parse(existing);
      if (stored.secret && Date.now() < stored.expiresAt) {
        const token = csrfTokens.create(stored.secret);
        return { token, secret: stored.secret };
      }
    }

    const secret = csrfTokens.secretSync();
    const token = csrfTokens.create(secret);
    
    const tokenData: CSRFTokenData = {
      token,
      secret,
      createdAt: Date.now(),
      expiresAt: Date.now() + cfg.tokenExpiry
    };

    // Store in Redis with expiration
    await redisClient.setex(key, Math.floor(cfg.tokenExpiry / 1000), JSON.stringify(tokenData));
    
    logger.debug('CSRF token generated', { 
      sessionId, 
      tokenLength: token.length,
      expiresAt: tokenData.expiresAt
    });
    
    return { token, secret };
  } catch (error) {
    logger.error('Error generating CSRF token:', error);
    throw new Error('Failed to generate CSRF token');
  }
};

/**
 * Validate CSRF token
 */
export const validateCSRFToken = async (sessionId: string, token: string, config: CSRFConfig = {}): Promise<boolean> => {
  const cfg = { ...defaultConfig, ...config };
  
  try {
    const key = `csrf:${sessionId}`;
    const tokenDataStr = await redisClient.get(key);
    
    if (!tokenDataStr) {
      logger.warn('CSRF token not found in storage', { sessionId });
      return false;
    }

    const tokenData: CSRFTokenData = JSON.parse(tokenDataStr);
    
    // Check if token is expired
    if (Date.now() > tokenData.expiresAt) {
      logger.warn('CSRF token expired', { sessionId, expiresAt: tokenData.expiresAt });
      await redisClient.del(key); // Clean up expired token
      return false;
    }

    // Validate token
    const isValid = csrfTokens.verify(tokenData.secret, token);
    
    if (!isValid) {
      logger.warn('Invalid CSRF token', { sessionId, providedToken: token.substring(0, 8) + '...' });
    }
    
    return isValid;
  } catch (error) {
    logger.error('Error validating CSRF token:', error);
    return false;
  }
};

/**
 * Get session ID from request
 */
const getSessionId = (req: Request): string => {
  // Try to get session ID from various sources
  if (req.session && req.session.id) {
    return req.session.id;
  }
  
  // Fallback to a combination of IP and user agent
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.get('user-agent') || 'unknown';
  return `${ip}:${Buffer.from(userAgent).toString('base64').substring(0, 16)}`;
};

/**
 * CSRF token generation middleware
 */
export const generateCSRFMiddleware = (config: CSRFConfig = {}) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const sessionId = getSessionId(req);
      const { token, secret } = await generateCSRFToken(sessionId, config);
      
      // Add token to response locals for template rendering
      res.locals.csrfToken = token;
      
      // Set token in cookie if configured
      if (config.cookieName || defaultConfig.cookieName) {
        res.cookie(config.cookieName || defaultConfig.cookieName, token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: config.tokenExpiry || defaultConfig.tokenExpiry
        });
      }
      
      // Add token to response header
      res.setHeader('X-CSRF-Token', token);
      
      next();
    } catch (error) {
      logger.error('CSRF token generation failed:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to generate CSRF token'
      });
    }
  };
};

/**
 * CSRF validation middleware
 */
export const validateCSRFMiddleware = (config: CSRFConfig = {}) => {
  const cfg = { ...defaultConfig, ...config };
  
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Skip validation for exempt methods
      if (cfg.exemptMethods.includes(req.method)) {
        return next();
      }
      
      // Skip validation for same-site requests if configured
      if (cfg.skipOnSameSite && req.get('sec-fetch-site') === 'same-origin') {
        return next();
      }
      
      const sessionId = getSessionId(req);
      
      // Get token from various sources
      let token = req.get(cfg.headerName);
      
      if (!token && req.body && req.body._csrf) {
        token = req.body._csrf;
      }
      
      if (!token && req.query && req.query._csrf) {
        token = req.query._csrf as string;
      }
      
      if (!token && req.cookies && req.cookies[cfg.cookieName]) {
        token = req.cookies[cfg.cookieName];
      }
      
      if (!token) {
        logger.warn('CSRF token missing from request', {
          sessionId,
          method: req.method,
          path: req.path,
          ip: req.ip
        });
        return res.status(403).json({
          error: 'CSRF token missing',
          message: 'CSRF token is required for this request'
        });
      }
      
      const isValid = await validateCSRFToken(sessionId, token, config);
      
      if (!isValid) {
        logger.warn('CSRF token validation failed', {
          sessionId,
          method: req.method,
          path: req.path,
          ip: req.ip,
          userAgent: req.get('user-agent')
        });
        return res.status(403).json({
          error: 'Invalid CSRF token',
          message: 'CSRF token validation failed'
        });
      }
      
      next();
    } catch (error) {
      logger.error('CSRF validation error:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'CSRF validation failed'
      });
    }
  };
};

/**
 * Get CSRF token endpoint
 */
export const getCSRFTokenEndpoint = (config: CSRFConfig = {}) => {
  return async (req: Request, res: Response) => {
    try {
      const sessionId = getSessionId(req);
      const { token } = await generateCSRFToken(sessionId, config);
      
      res.json({
        csrfToken: token,
        expiresAt: Date.now() + (config.tokenExpiry || defaultConfig.tokenExpiry)
      });
    } catch (error) {
      logger.error('Failed to provide CSRF token:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to generate CSRF token'
      });
    }
  };
};

/**
 * Clean up expired CSRF tokens
 */
export const cleanupExpiredCSRFTokens = async (): Promise<void> => {
  try {
    const keys = await redisClient.keys('csrf:*');
    let cleaned = 0;
    
    for (const key of keys) {
      const tokenDataStr = await redisClient.get(key);
      if (tokenDataStr) {
        const tokenData: CSRFTokenData = JSON.parse(tokenDataStr);
        if (Date.now() > tokenData.expiresAt) {
          await redisClient.del(key);
          cleaned++;
        }
      }
    }
    
    if (cleaned > 0) {
      logger.info(`Cleaned up ${cleaned} expired CSRF tokens`);
    }
  } catch (error) {
    logger.error('Error cleaning up expired CSRF tokens:', error);
  }
};

/**
 * CSRF protection middleware with both generation and validation
 */
export const csrfProtection = (config: CSRFConfig = {}) => {
  const cfg = { ...defaultConfig, ...config };
  
  return async (req: Request, res: Response, next: NextFunction) => {
    // Generate token for safe methods
    if (cfg.exemptMethods.includes(req.method)) {
      return generateCSRFMiddleware(config)(req, res, next);
    }
    
    // Validate token for unsafe methods
    return validateCSRFMiddleware(config)(req, res, next);
  };
};

// Schedule cleanup of expired tokens every hour
setInterval(cleanupExpiredCSRFTokens, 60 * 60 * 1000);

export default csrfProtection;
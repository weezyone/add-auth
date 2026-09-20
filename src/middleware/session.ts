import session from 'express-session';
import { Request, Response, NextFunction, RequestHandler } from 'express';
import { getRedisClient } from '../utils/redis';
import { appConfig } from '../config';
import { logger } from '../utils/logger';
import { FingerprintService, DeviceFingerprint } from '../utils/fingerprint';
import { SessionModel } from '../models/Session';
import { SessionService, RedisSession } from '../services/sessionService';

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    roleId?: string;
    fingerprint?: DeviceFingerprint;
    isAuthenticated?: boolean;
    lastActivity?: Date;
    trustScore?: number;
    returnTo?: string;
  }
}

// Custom Redis session store
class RedisSessionStore extends session.Store {
  private redisClient: ReturnType<typeof getRedisClient> | null = null;
  private ttl: number;

  constructor(options: { ttl?: number } = {}) {
    super();
    this.ttl = options.ttl || appConfig.security.sessionTimeout / 1000; // Convert to seconds
  }

  private getClient() {
    if (!this.redisClient) {
      this.redisClient = getRedisClient();
    }
    return this.redisClient;
  }

  async get(sid: string, callback: (err: any, session?: session.SessionData) => void): Promise<void> {
    try {
      const key = `session:${sid}`;
      const data = await this.getClient().get(key);
      
      if (!data) {
        return callback(null);
      }

      const session = JSON.parse(data);
      callback(null, session);
    } catch (error) {
      logger.error('Error getting session from Redis', { sessionId: sid, error });
      callback(error);
    }
  }

  async set(sid: string, session: session.SessionData, callback?: (err?: any) => void): Promise<void> {
    try {
      const key = `session:${sid}`;
      const data = JSON.stringify(session);
      
      await this.getClient().setEx(key, this.ttl, data);
      
      if (callback) callback();
    } catch (error) {
      logger.error('Error setting session in Redis', { sessionId: sid, error });
      if (callback) callback(error);
    }
  }

  async destroy(sid: string, callback?: (err?: any) => void): Promise<void> {
    try {
      const key = `session:${sid}`;
      await this.getClient().del(key);
      
      if (callback) callback();
    } catch (error) {
      logger.error('Error destroying session in Redis', { sessionId: sid, error });
      if (callback) callback(error);
    }
  }

  async touch(sid: string, session: session.SessionData, callback?: (err?: any) => void): Promise<void> {
    try {
      const key = `session:${sid}`;
      await this.getClient().expire(key, this.ttl);
      
      if (callback) callback();
    } catch (error) {
      logger.error('Error touching session in Redis', { sessionId: sid, error });
      if (callback) callback(error);
    }
  }

  async clear(callback?: (err?: any) => void): Promise<void> {
    try {
      const keys = await this.getClient().keys('session:*');
      if (keys.length > 0) {
        await this.getClient().del(keys);
      }
      
      if (callback) callback();
    } catch (error) {
      logger.error('Error clearing sessions from Redis', { error });
      if (callback) callback(error);
    }
  }

  async length(callback: (err: any, length?: number) => void): Promise<void> {
    try {
      const keys = await this.getClient().keys('session:*');
      callback(null, keys.length);
    } catch (error) {
      logger.error('Error getting session count from Redis', { error });
      callback(error);
    }
  }
}

// Session configuration
export const sessionConfig = {
  store: new RedisSessionStore(),
  secret: appConfig.security.sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: appConfig.server.nodeEnv === 'production',
    httpOnly: true,
    maxAge: appConfig.security.sessionTimeout,
    sameSite: 'strict' as const,
  },
  name: 'sessionId',
};

// Session middleware
export const sessionMiddleware: RequestHandler = session(sessionConfig);

// Fingerprint validation middleware
export const fingerprintMiddleware: RequestHandler = async (req, res, next) => {
  try {
    const currentFingerprint = FingerprintService.generateFingerprint(req);
    
    // Store current fingerprint in session
    if (req.session) {
      if (req.session.fingerprint) {
        // Validate against stored fingerprint
        const validation = FingerprintService.validateFingerprint(
          currentFingerprint,
          req.session.fingerprint
        );

        if (!validation.isValid) {
          logger.warn('Session fingerprint validation failed', {
            sessionId: req.sessionID,
            userId: req.session.userId,
            risk: validation.risk,
            changes: validation.changes,
          });

          // Handle based on risk level
          if (validation.risk === 'high') {
            // Destroy session and require re-authentication
            req.session.destroy((err) => {
              if (err) {
                logger.error('Error destroying session after fingerprint validation failure', { error: err });
              }
            });
            
            return void res.status(401).json({
              error: 'Session security validation failed',
              message: 'Please log in again',
              code: 'FINGERPRINT_VALIDATION_FAILED',
            });
          } else if (validation.risk === 'medium') {
            // Update fingerprint but log the change
            req.session.fingerprint = currentFingerprint;
            req.session.trustScore = (req.session.trustScore || 1.0) * 0.8;
            
            logger.info('Session fingerprint updated due to medium risk changes', {
              sessionId: req.sessionID,
              userId: req.session.userId,
              changes: validation.changes,
            });
          }
        }
      } else {
        // First time - store fingerprint
        req.session.fingerprint = currentFingerprint;
        req.session.trustScore = 0.5; // Neutral score for new sessions
      }
    }

    next();
  } catch (error) {
    logger.error('Error in fingerprint middleware', { error });
    next(error);
  }
};

// Session activity tracking middleware
export const sessionActivityMiddleware: RequestHandler = async (req, res, next) => {
  try {
    if (req.session && req.session.isAuthenticated && req.session.userId) {
      const now = new Date();
      const lastActivity = req.session.lastActivity ? new Date(req.session.lastActivity) : null;
      
      // Check for session timeout
      if (lastActivity) {
        const timeSinceLastActivity = now.getTime() - lastActivity.getTime();
        if (timeSinceLastActivity > appConfig.security.sessionTimeout) {
          logger.info('Session expired due to inactivity', {
            sessionId: req.sessionID,
            userId: req.session.userId,
            lastActivity: lastActivity.toISOString(),
          });
          
          req.session.destroy((err) => {
            if (err) {
              logger.error('Error destroying expired session', { error: err });
            }
          });
          
          return void res.status(401).json({
            error: 'Session expired',
            message: 'Please log in again',
            code: 'SESSION_EXPIRED',
          });
        }
      }
      
      // Update last activity
      req.session.lastActivity = now;
      
      // Update session in database
      try {
        await SessionModel.updateLastAccessed(req.sessionID);
      } catch (error) {
        logger.error('Error updating session last accessed in database', { 
          sessionId: req.sessionID,
          error 
        });
      }
    }
    
    next();
  } catch (error) {
    logger.error('Error in session activity middleware', { error });
    next(error);
  }
};

// Session cleanup utility
export const cleanupExpiredSessions = async (): Promise<void> => {
  try {
    // Clean up database sessions
    const deletedCount = await SessionModel.cleanupExpiredSessions();
    logger.info('Cleaned up expired sessions from database', { deletedCount });
    
    // Clean up Redis sessions (they should auto-expire, but this is a safety measure)
    const redisClient = getRedisClient();
    const keys = await redisClient.keys('session:*');
    
    let expiredRedisSessionsCount = 0;
    for (const key of keys) {
      const ttl = await redisClient.ttl(key);
      if (ttl === -1) {
        // Session without TTL, remove it
        await redisClient.del(key);
        expiredRedisSessionsCount++;
      }
    }
    
    if (expiredRedisSessionsCount > 0) {
      logger.info('Cleaned up orphaned Redis sessions', { count: expiredRedisSessionsCount });
    }
  } catch (error) {
    logger.error('Error during session cleanup', { error });
  }
};

// Redis Session Validation Middleware
export const redisSessionValidationMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Extract session ID from cookie or header
    const sessionId = req.cookies?.sessionId || req.headers['x-session-id'] as string;
    
    if (!sessionId) {
      return next();
    }

    // Validate session using Redis SessionService
    const validation = await SessionService.validateSession(sessionId, req);
    
    if (!validation.isValid) {
      logger.info('Redis session validation failed', {
        sessionId,
        reason: validation.reason,
        requiresReauth: validation.requiresReauth,
      });

      // Clear the session cookie
      res.clearCookie('sessionId');
      
      if (validation.requiresReauth) {
        return void res.status(401).json({
          error: 'Authentication required',
          message: 'Session security validation failed. Please log in again.',
          code: 'SESSION_SECURITY_FAILED',
        });
      }

      return next();
    }

    // Attach validated session to request
    req.redisSession = validation.session;
    req.user = {
      id: validation.session!.user_id,
      email: '', // Will be populated by auth middleware if needed
      roles: [],
    };

    logger.debug('Redis session validated successfully', {
      sessionId,
      userId: validation.session!.user_id,
      trustScore: validation.session!.trust_score,
    });

    next();
  } catch (error) {
    logger.error('Error in Redis session validation middleware', { error });
    next(error);
  }
};

// Enhanced authentication middleware that works with Redis sessions
export const enhancedAuthMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Check if we have a validated Redis session
    if (req.redisSession && req.redisSession.is_active) {
      logger.debug('Request authenticated via Redis session', {
        sessionId: req.redisSession.id,
        userId: req.redisSession.user_id,
      });
      return next();
    }

    // Fall back to JWT token validation if no Redis session
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return void res.status(401).json({
        error: 'Authentication required',
        message: 'No valid session or token provided',
        code: 'AUTHENTICATION_REQUIRED',
      });
    }

    // If we get here, the standard JWT middleware should handle it
    next();
  } catch (error) {
    logger.error('Error in enhanced authentication middleware', { error });
    next(error);
  }
};

// Middleware to enforce session limits and detect anomalies
export const sessionSecurityMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.redisSession) {
      return next();
    }

    const session = req.redisSession;

    // Check trust score
    if (session.trust_score < 0.3) {
      logger.warn('Low trust score detected, requiring re-authentication', {
        sessionId: session.id,
        userId: session.user_id,
        trustScore: session.trust_score,
      });

      await SessionService.destroySession(session.id);
      res.clearCookie('sessionId');

      return void res.status(401).json({
        error: 'Security validation failed',
        message: 'Session trust level too low. Please log in again.',
        code: 'LOW_TRUST_SCORE',
      });
    }

    // Check for excessive concurrent sessions (max 5)
    if (session.concurrent_count > 5) {
      logger.warn('Excessive concurrent sessions detected', {
        sessionId: session.id,
        userId: session.user_id,
        concurrentCount: session.concurrent_count,
      });

      // This should have been handled during session creation, but double-check
      const userSessions = await SessionService.getUserSessions(session.user_id);
      if (userSessions.length > 5) {
        await SessionService.destroyUserSessions(session.user_id, session.id);
      }
    }

    // Log session access for monitoring
    logger.debug('Session security check passed', {
      sessionId: session.id,
      userId: session.user_id,
      trustScore: session.trust_score,
      concurrentCount: session.concurrent_count,
      lastAccessed: session.last_accessed,
    });

    next();
  } catch (error) {
    logger.error('Error in session security middleware', { error });
    next(error);
  }
};

// Extend Express Request interface to include Redis session
declare global {
  namespace Express {
    interface Request {
      redisSession?: RedisSession;
    }
  }
}

// Schedule session cleanup (run every hour)
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// Also cleanup Redis sessions
setInterval(async () => {
  try {
    const cleanupCount = await SessionService.cleanupExpiredSessions();
    logger.info('Redis session cleanup completed', { cleanupCount });
  } catch (error) {
    logger.error('Redis session cleanup failed', { error });
  }
}, 60 * 60 * 1000);

export default sessionMiddleware;
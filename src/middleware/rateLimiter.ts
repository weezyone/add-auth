/**
 * Rate Limiting Middleware
 * Implements Redis-based rate limiting for API endpoints
 */

import { rateLimit } from 'express-rate-limit';
import { RedisStore, SendCommandFn, RedisReply } from 'rate-limit-redis';
import { Redis } from 'ioredis';
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { appConfig } from '../config';

const redisClient = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD || undefined,
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

class RateLimitRedisCommands {
  static sendCommand: SendCommandFn = async (...args: string[]): Promise<RedisReply> => {
    const [command, ...commandArgs] = args;
    if (!command) {
      throw new Error('Redis command is required');
    }
    return redisClient.call(command, commandArgs) as Promise<RedisReply>;
  };
}

// Redis connection event handlers
redisClient.on('connect', () => {
  logger.info('Redis connected for rate limiting');
});

redisClient.on('error', (err) => {
  logger.error('Redis connection error:', err);
});

redisClient.on('close', () => {
  logger.warn('Redis connection closed');
});

/**
 * Rate limiter configurations for different endpoints
 */
export const rateLimiters = {
  // General API rate limiting
  general: rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: '15 minutes'
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    keyGenerator: (req: Request) => {
      // Use IP address as key, with fallback to connection info
      return req.ip || req.connection.remoteAddress || 'unknown';
    },
    handler: (req: Request, res: Response) => {
      logger.warn(`Rate limit exceeded for IP: ${req.ip}`, {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        path: req.path,
        method: req.method
      });
      res.status(429).json({
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: '15 minutes'
      });
    }
  }),

  // Authentication endpoints (more restrictive)
  auth: rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 auth attempts per windowMs
    message: {
      error: 'Too many authentication attempts from this IP, please try again later.',
      retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      return `auth:${req.ip || req.connection.remoteAddress || 'unknown'}`;
    },
    handler: (req: Request, res: Response) => {
      logger.warn(`Auth rate limit exceeded for IP: ${req.ip}`, {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        path: req.path,
        method: req.method
      });
      res.status(429).json({
        error: 'Too many authentication attempts',
        message: 'Too many login attempts. Please try again later.',
        retryAfter: '15 minutes'
      });
    }
  }),

  // Password reset endpoints (very restrictive)
  passwordReset: rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // limit each IP to 3 password reset attempts per hour
    message: {
      error: 'Too many password reset attempts from this IP, please try again later.',
      retryAfter: '1 hour'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      return `password-reset:${req.ip || req.connection.remoteAddress || 'unknown'}`;
    },
    handler: (req: Request, res: Response) => {
      logger.warn(`Password reset rate limit exceeded for IP: ${req.ip}`, {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        path: req.path,
        method: req.method
      });
      res.status(429).json({
        error: 'Too many password reset attempts',
        message: 'Too many password reset attempts. Please try again later.',
        retryAfter: '1 hour'
      });
    }
  }),

  // Login endpoints (alias for auth)
  login: rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => `login:${req.ip || req.connection.remoteAddress || 'unknown'}`,
  }),

  // Refresh token endpoints
  refresh: rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => `refresh:${req.ip || req.connection.remoteAddress || 'unknown'}`,
  }),

  // Admin action endpoints
  adminActions: rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: 15 * 60 * 1000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => `admin:${req.ip || req.connection.remoteAddress || 'unknown'}`,
  }),

  // Registration endpoints
  registration: rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // limit each IP to 5 registrations per hour
    message: {
      error: 'Too many registration attempts from this IP, please try again later.',
      retryAfter: '1 hour'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      return `registration:${req.ip || req.connection.remoteAddress || 'unknown'}`;
    },
    handler: (req: Request, res: Response) => {
      logger.warn(`Registration rate limit exceeded for IP: ${req.ip}`, {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        path: req.path,
        method: req.method
      });
      res.status(429).json({
        error: 'Too many registration attempts',
        message: 'Too many registration attempts. Please try again later.',
        retryAfter: '1 hour'
      });
    }
  })
};

/**
 * Create a custom rate limiter with specific configuration
 */
export const createCustomRateLimiter = (options: {
  windowMs: number;
  max: number;
  keyPrefix: string;
  message?: string;
  retryAfter?: string;
}) => {
  return rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: options.windowMs,
    max: options.max,
    message: {
      error: options.message || 'Too many requests from this IP, please try again later.',
      retryAfter: options.retryAfter || 'later'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      return `${options.keyPrefix}:${req.ip || req.connection.remoteAddress || 'unknown'}`;
    },
    handler: (req: Request, res: Response) => {
      logger.warn(`Rate limit exceeded for ${options.keyPrefix} from IP: ${req.ip}`, {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        path: req.path,
        method: req.method,
        keyPrefix: options.keyPrefix
      });
      res.status(429).json({
        error: 'Too many requests',
        message: options.message || 'Rate limit exceeded. Please try again later.',
        retryAfter: options.retryAfter || 'later'
      });
    }
  });
};

/**
 * Advanced rate limiter with user-specific limits
 */
export const createUserRateLimiter = (options: {
  windowMs: number;
  max: number;
  keyPrefix: string;
  message?: string;
  retryAfter?: string;
}) => {
  return rateLimit({
    store: new RedisStore({
      sendCommand: (...args: string[]) => RateLimitRedisCommands.sendCommand(...args),
    }),
    windowMs: options.windowMs,
    max: options.max,
    message: {
      error: options.message || 'Too many requests, please try again later.',
      retryAfter: options.retryAfter || 'later'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      // Use user ID if authenticated, otherwise fall back to IP
      const userId = (req as any).user?.id;
      const key = userId || req.ip || req.connection.remoteAddress || 'unknown';
      return `${options.keyPrefix}:${key}`;
    },
    handler: (req: Request, res: Response) => {
      const userId = (req as any).user?.id;
      logger.warn(`User rate limit exceeded for ${options.keyPrefix}`, {
        userId,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        path: req.path,
        method: req.method,
        keyPrefix: options.keyPrefix
      });
      res.status(429).json({
        error: 'Too many requests',
        message: options.message || 'Rate limit exceeded. Please try again later.',
        retryAfter: options.retryAfter || 'later'
      });
    }
  });
};

/**
 * Rate limiter health check middleware
 */
export const rateLimiterHealthCheck = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await redisClient.ping();
    next();
  } catch (error) {
    logger.error('Redis health check failed:', error);
    // Continue without rate limiting if Redis is down
    next();
  }
};

/**
 * Clean up Redis connection on app shutdown
 */
export const closeRedisConnection = async () => {
  try {
    await redisClient.quit();
    logger.info('Redis connection closed');
  } catch (error) {
    logger.error('Error closing Redis connection:', error);
  }
};

// Export Redis client for other modules if needed
export { redisClient };
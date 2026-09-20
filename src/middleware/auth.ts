import { Request, Response, NextFunction } from 'express';
import { verifyToken, extractTokenFromHeader } from '../utils/jwt';
import { enforceTokenBlacklist } from '../utils/tokenBlacklist';
import { TokenBlacklistedError } from '../types/jwt';
import { logger } from '../utils/logger';

/**
 * Authentication middleware that validates JWT tokens
 */
export async function authenticateToken(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'No token provided'
      });
      return;
    }

    // Check if token is blacklisted
    try {
      await enforceTokenBlacklist(token);
    } catch (error) {
      if (error instanceof TokenBlacklistedError) {
        res.status(401).json({
          error: 'Token invalid',
          message: 'Token has been revoked'
        });
        return;
      }
      throw error;
    }

    // Verify token
    const payload = verifyToken(token);
    req.user = payload;
    
    logger.info('User authenticated successfully', { 
      userId: payload.id, 
      email: payload.email 
    });
    
    next();
  } catch (error: any) {
    logger.error('Authentication error:', error);
    
    if (error.name === 'TokenExpiredError') {
      res.status(401).json({
        error: 'Token expired',
        message: 'Please refresh your token'
      });
    } else if (error.name === 'TokenInvalidError') {
      res.status(401).json({
        error: 'Invalid token',
        message: 'Token is malformed or invalid'
      });
    } else {
      res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid token'
      });
    }
  }
}

/**
 * Optional authentication middleware - doesn't fail if no token
 */
export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      next();
      return;
    }

    // Check if token is blacklisted
    try {
      await enforceTokenBlacklist(token);
    } catch (error) {
      if (error instanceof TokenBlacklistedError) {
        next();
        return;
      }
      throw error;
    }

    // Verify token
    const payload = verifyToken(token);
    req.user = payload;
    
    next();
  } catch (error: any) {
    logger.warn('Optional auth failed:', error);
    // Continue without authentication
    next();
  }
}

/**
 * Require specific roles
 */
export function requireRole(roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    const userRoles = req.user.roles || [];
    const hasRequiredRole = roles.some(role => userRoles.includes(role));

    if (!hasRequiredRole) {
      res.status(403).json({
        error: 'Insufficient permissions',
        message: `Required roles: ${roles.join(', ')}`
      });
      return;
    }

    next();
  };
}

/**
 * Error handling middleware for authentication errors
 */
export function handleAuthErrors(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (err.name === 'TokenExpiredError') {
    res.status(401).json({
      error: 'Token expired',
      message: 'Please refresh your token',
      code: 'TOKEN_EXPIRED'
    });
    return;
  }

  if (err.name === 'TokenInvalidError') {
    res.status(401).json({
      error: 'Invalid token',
      message: 'Token is malformed or invalid',
      code: 'TOKEN_INVALID'
    });
    return;
  }

  if (err.name === 'TokenBlacklistedError') {
    res.status(401).json({
      error: 'Token revoked',
      message: 'Token has been blacklisted',
      code: 'TOKEN_BLACKLISTED'
    });
    return;
  }

  if (err.name === 'JWTError') {
    res.status(err.statusCode || 500).json({
      error: 'JWT Error',
      message: err.message,
      code: err.code
    });
    return;
  }

  // Pass to next error handler
  next(err);
}
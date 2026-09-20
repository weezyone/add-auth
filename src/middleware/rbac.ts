import { Request, Response, NextFunction } from 'express';
import { RoleModel } from '../models/Role';
import { logger } from '../utils/logger';

// Extend Express Request interface to include user roles
declare global {
  namespace Express {
    interface Request {
      userRoles?: string[];
      userPermissions?: string[];
    }
  }
}

export interface RBACOptions {
  roles?: string[];
  permissions?: string[];
  requireAll?: boolean; // If true, user must have ALL specified roles/permissions
  onUnauthorized?: (req: Request, res: Response) => void;
}

/**
 * Role-Based Access Control middleware
 * Checks if user has required roles or permissions
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session?.isAuthenticated || !req.session?.userId) {
    logger.warn('Unauthorized access attempt - no valid session', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      path: req.path,
    });
    
    res.status(401).json({
      error: 'Authentication required',
      message: 'Please log in to access this resource',
      code: 'AUTHENTICATION_REQUIRED',
    });
    return;
  }

  next();
}

/**
 * Role-based authorization middleware
 */
export function requireRole(roles: string | string[], options: Partial<RBACOptions> = {}) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.isAuthenticated || !req.session?.userId) {
        return handleUnauthorized(req, res, 'Authentication required', options.onUnauthorized);
      }

      const userId = req.session.userId;
      const requiredRoles = Array.isArray(roles) ? roles : [roles];
      const requireAll = options.requireAll || false;

      // Get user roles
      const userRoles = await RoleModel.getUserRoles(userId);
      const userRoleNames = userRoles.map(role => role.name);
      
      // Store user roles in request for later use
      req.userRoles = userRoleNames;

      // Check if user has required roles
      const hasRequiredRole = requireAll
        ? requiredRoles.every(role => userRoleNames.includes(role))
        : requiredRoles.some(role => userRoleNames.includes(role));

      if (!hasRequiredRole) {
        logger.warn('Access denied - insufficient roles', {
          userId,
          userRoles: userRoleNames,
          requiredRoles,
          requireAll,
          path: req.path,
        });

        return handleUnauthorized(
          req, 
          res, 
          'Insufficient permissions - required roles not found',
          options.onUnauthorized
        );
      }

      logger.debug('Role authorization successful', {
        userId,
        userRoles: userRoleNames,
        requiredRoles,
        path: req.path,
      });

      next();
    } catch (error) {
      logger.error('Error in role authorization middleware', { error });
      res.status(500).json({
        error: 'Internal server error',
        message: 'Authorization check failed',
        code: 'AUTHORIZATION_ERROR',
      });
    }
  };
}

/**
 * Permission-based authorization middleware
 */
export function requirePermission(permissions: string | string[], options: Partial<RBACOptions> = {}) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.isAuthenticated || !req.session?.userId) {
        return handleUnauthorized(req, res, 'Authentication required', options.onUnauthorized);
      }

      const userId = req.session.userId;
      const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];
      const requireAll = options.requireAll || false;

      // Get user permissions
      const userPermissions = await RoleModel.getUserPermissions(userId);
      
      // Store user permissions in request for later use
      req.userPermissions = userPermissions;

      // Check if user has required permissions
      const hasRequiredPermission = requireAll
        ? requiredPermissions.every(permission => userPermissions.includes(permission))
        : requiredPermissions.some(permission => userPermissions.includes(permission));

      if (!hasRequiredPermission) {
        logger.warn('Access denied - insufficient permissions', {
          userId,
          userPermissions,
          requiredPermissions,
          requireAll,
          path: req.path,
        });

        return handleUnauthorized(
          req, 
          res, 
          'Insufficient permissions - required permissions not found',
          options.onUnauthorized
        );
      }

      logger.debug('Permission authorization successful', {
        userId,
        userPermissions,
        requiredPermissions,
        path: req.path,
      });

      next();
    } catch (error) {
      logger.error('Error in permission authorization middleware', { error });
      res.status(500).json({
        error: 'Internal server error',
        message: 'Authorization check failed',
        code: 'AUTHORIZATION_ERROR',
      });
    }
  };
}

/**
 * Combined role and permission middleware
 */
export function requireRoleOrPermission(
  roles: string | string[],
  permissions: string | string[],
  options: Partial<RBACOptions> = {}
) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.isAuthenticated || !req.session?.userId) {
        return handleUnauthorized(req, res, 'Authentication required', options.onUnauthorized);
      }

      const userId = req.session.userId;
      const requiredRoles = Array.isArray(roles) ? roles : [roles];
      const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];

      // Get user roles and permissions
      const [userRoles, userPermissions] = await Promise.all([
        RoleModel.getUserRoles(userId),
        RoleModel.getUserPermissions(userId),
      ]);

      const userRoleNames = userRoles.map(role => role.name);
      
      // Store in request for later use
      req.userRoles = userRoleNames;
      req.userPermissions = userPermissions;

      // Check if user has required roles OR permissions
      const hasRequiredRole = requiredRoles.some(role => userRoleNames.includes(role));
      const hasRequiredPermission = requiredPermissions.some(permission => userPermissions.includes(permission));

      if (!hasRequiredRole && !hasRequiredPermission) {
        logger.warn('Access denied - insufficient roles and permissions', {
          userId,
          userRoles: userRoleNames,
          userPermissions,
          requiredRoles,
          requiredPermissions,
          path: req.path,
        });

        return handleUnauthorized(
          req, 
          res, 
          'Insufficient permissions - required roles or permissions not found',
          options.onUnauthorized
        );
      }

      logger.debug('Combined authorization successful', {
        userId,
        userRoles: userRoleNames,
        userPermissions,
        requiredRoles,
        requiredPermissions,
        path: req.path,
      });

      next();
    } catch (error) {
      logger.error('Error in combined authorization middleware', { error });
      res.status(500).json({
        error: 'Internal server error',
        message: 'Authorization check failed',
        code: 'AUTHORIZATION_ERROR',
      });
    }
  };
}

/**
 * Middleware to check if user owns a resource
 */
export function requireOwnership(resourceUserIdField: string = 'user_id') {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.isAuthenticated || !req.session?.userId) {
        return handleUnauthorized(req, res, 'Authentication required');
      }

      const userId = req.session.userId;
      const resourceUserId = req.params[resourceUserIdField] || req.body[resourceUserIdField];

      if (!resourceUserId) {
        logger.warn('Resource ownership check failed - no resource user ID found', {
          userId,
          resourceUserIdField,
          params: req.params,
          body: req.body,
          path: req.path,
        });

        return void res.status(400).json({
          error: 'Bad request',
          message: 'Resource user ID not found',
          code: 'RESOURCE_USER_ID_MISSING',
        });
      }

      if (userId !== resourceUserId) {
        logger.warn('Access denied - resource ownership mismatch', {
          userId,
          resourceUserId,
          path: req.path,
        });

        return handleUnauthorized(req, res, 'You can only access your own resources');
      }

      logger.debug('Resource ownership check successful', {
        userId,
        resourceUserId,
        path: req.path,
      });

      next();
    } catch (error) {
      logger.error('Error in ownership middleware', { error });
      res.status(500).json({
        error: 'Internal server error',
        message: 'Ownership check failed',
        code: 'OWNERSHIP_CHECK_ERROR',
      });
    }
  };
}

/**
 * Middleware to check if user has admin privileges
 */
export const requireAdmin = requireRole('admin');

/**
 * Middleware to check if user has moderator or admin privileges
 */
export const requireModerator = requireRole(['admin', 'moderator']);

/**
 * Middleware to check user trust score
 */
export function requireTrustScore(minimumScore: number = 0.5) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.session?.isAuthenticated || !req.session?.userId) {
      return handleUnauthorized(req, res, 'Authentication required');
    }

    const trustScore = req.session.trustScore || 0;

    if (trustScore < minimumScore) {
      logger.warn('Access denied - insufficient trust score', {
        userId: req.session.userId,
        trustScore,
        minimumScore,
        path: req.path,
      });

      return handleUnauthorized(req, res, 'Additional security verification required');
    }

    next();
  };
}

/**
 * Handle unauthorized access
 */
function handleUnauthorized(
  req: Request,
  res: Response,
  message: string,
  customHandler?: (req: Request, res: Response) => void
): void {
  if (customHandler) {
    customHandler(req, res);
    return;
  }

  res.status(403).json({
    error: 'Forbidden',
    message,
    code: 'INSUFFICIENT_PERMISSIONS',
  });
}

/**
 * Utility function to check if user has specific permission
 */
export async function hasPermission(userId: string, permission: string): Promise<boolean> {
  try {
    return await RoleModel.hasPermission(userId, permission);
  } catch (error) {
    logger.error('Error checking permission', { userId, permission, error });
    return false;
  }
}

/**
 * Utility function to get user roles
 */
export async function getUserRoles(userId: string): Promise<string[]> {
  try {
    const roles = await RoleModel.getUserRoles(userId);
    return roles.map(role => role.name);
  } catch (error) {
    logger.error('Error getting user roles', { userId, error });
    return [];
  }
}

/**
 * Utility function to get user permissions
 */
export async function getUserPermissions(userId: string): Promise<string[]> {
  try {
    return await RoleModel.getUserPermissions(userId);
  } catch (error) {
    logger.error('Error getting user permissions', { userId, error });
    return [];
  }
}

export default {
  requireAuth,
  requireRole,
  requirePermission,
  requireRoleOrPermission,
  requireOwnership,
  requireAdmin,
  requireModerator,
  requireTrustScore,
  hasPermission,
  getUserRoles,
  getUserPermissions,
};
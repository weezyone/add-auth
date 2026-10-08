/**
 * Authentication Routes
 * Core authentication API endpoints with comprehensive security
 */

import { Router } from 'express';
import { 
  rateLimiters,
  csrfProtection,
  validateBody,
  validationSchemas,
  securityMiddleware,
  authenticateToken
} from '../middleware';
import { createCustomRateLimiter } from '../middleware/rateLimiter';
import { redisSessionValidationMiddleware, enhancedAuthMiddleware, sessionSecurityMiddleware } from '../middleware/session';
import {
  register,
  login,
  logout,
  refresh,
  getUserInfo,
  updateProfile,
  getUserSessions,
  revokeSession,
  revokeAllOtherSessions,
  extendSession,
  changePassword,
  verifyEmail,
  resendVerification
} from '../controllers/auth';

const router = Router();

// Email verification limits (per IP). Resend is additionally limited to one
// email per address per minute inside EmailVerificationService.
const verifyEmailLimiter = createCustomRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyPrefix: 'verify-email',
  message: 'Too many verification attempts. Please try again later.',
  retryAfter: '15 minutes'
});
const resendVerificationLimiter = createCustomRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyPrefix: 'resend-verification',
  message: 'Too many verification emails requested. Please try again later.',
  retryAfter: '1 hour'
});

// Apply base security middleware to all auth routes
router.use(securityMiddleware.auth);

/**
 * POST /api/auth/register
 * User registration with comprehensive security
 */
router.post(
  '/register',
  // Apply registration-specific rate limiting
  rateLimiters.registration,
  // Validate request body
  validateBody(validationSchemas.userRegistration),
  // Controller implementation
  register
);

/**
 * POST /api/auth/verify-email
 * Body: { token }. Consumes the token from the verification email (once).
 */
router.post(
  '/verify-email',
  verifyEmailLimiter,
  validateBody(validationSchemas.emailVerification),
  verifyEmail
);

/**
 * POST /api/auth/resend-verification
 * Body: { email }. Always 202; never reveals whether the account exists.
 */
router.post(
  '/resend-verification',
  resendVerificationLimiter,
  validateBody(validationSchemas.resendVerification),
  resendVerification
);

/**
 * POST /api/auth/login
 * User login with security protection
 */
router.post(
  '/login',
  // Apply login-specific rate limiting
  rateLimiters.login,
  // Validate login credentials
  validateBody(validationSchemas.userLogin),
  // Controller implementation
  login
);

/**
 * POST /api/auth/logout
 * User logout with token blacklisting
 */
router.post(
  '/logout',
  // Authenticate user first
  authenticateToken,
  // CSRF protection for state-changing operations
  csrfProtection(),
  // Controller implementation
  logout
);

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
router.post(
  '/refresh',
  // Apply refresh-specific rate limiting
  rateLimiters.refresh,
  // Validate refresh token
  validateBody(validationSchemas.refreshToken),
  // Controller implementation
  refresh
);

/**
 * GET /api/auth/me
 * Get current user information
 */
router.get(
  '/me',
  // Authenticate user first
  authenticateToken,
  // Basic security for read operations
  securityMiddleware.basic,
  // Controller implementation
  getUserInfo
);

/**
 * PUT /api/auth/profile
 * Update user profile
 */
router.put(
  '/profile',
  // Authenticate user first
  authenticateToken,
  // Validate profile update data
  validateBody(validationSchemas.userProfileUpdate),
  // CSRF protection for state-changing operations
  csrfProtection(),
  // Controller implementation
  updateProfile
);

/**
 * POST /api/auth/change-password
 * Change user password
 */
router.post(
  '/change-password',
  // Authenticate user first
  authenticateToken,
  // Validate password change request
  validateBody(validationSchemas.passwordChange),
  // CSRF protection for state-changing operations
  csrfProtection(),
  // Controller implementation
  changePassword
);

/**
 * GET /api/auth/csrf-token
 * Get CSRF token for client-side use
 */
router.get(
  '/csrf-token',
  // Generate CSRF token
  csrfProtection(),
  (req, res) => {
    res.json({
      success: true,
      csrfToken: res.locals.csrfToken
    });
  }
);

/**
 * GET /api/auth/sessions
 * Get user's active sessions
 */
router.get(
  '/sessions',
  // Redis session validation
  redisSessionValidationMiddleware,
  // Enhanced authentication
  enhancedAuthMiddleware,
  // Session security checks
  sessionSecurityMiddleware,
  // Controller implementation
  getUserSessions
);

/**
 * DELETE /api/auth/sessions/:sessionId
 * Revoke a specific session
 */
router.delete(
  '/sessions/:sessionId',
  // Redis session validation
  redisSessionValidationMiddleware,
  // Enhanced authentication
  enhancedAuthMiddleware,
  // Session security checks
  sessionSecurityMiddleware,
  // CSRF protection for state-changing operations
  csrfProtection(),
  // Controller implementation
  revokeSession
);

/**
 * DELETE /api/auth/sessions
 * Revoke all other sessions (except current)
 */
router.delete(
  '/sessions',
  // Redis session validation
  redisSessionValidationMiddleware,
  // Enhanced authentication
  enhancedAuthMiddleware,
  // Session security checks
  sessionSecurityMiddleware,
  // CSRF protection for state-changing operations
  csrfProtection(),
  // Controller implementation
  revokeAllOtherSessions
);

/**
 * PUT /api/auth/session/extend
 * Extend current session expiration
 */
router.put(
  '/session/extend',
  // Redis session validation
  redisSessionValidationMiddleware,
  // Enhanced authentication
  enhancedAuthMiddleware,
  // Session security checks
  sessionSecurityMiddleware,
  // CSRF protection for state-changing operations
  csrfProtection(),
  // Controller implementation
  extendSession
);

export default router;

/**
 * Password Reset Routes
 * Defines routes for password reset functionality
 */

import { Router } from 'express';
import { 
  requestPasswordReset,
  verifyPasswordResetToken,
  resetPassword,
  getPasswordResetAttempts,
  revokePasswordResetToken,
  getPasswordResetStats,
  getActiveTokensForUser,
  revokeAllTokensForUser
} from '../controllers/passwordResetController';
import { rateLimiters } from '../middleware/rateLimiter';
import { 
  validateBody,
  validateParams,
  validationSchemas
} from '../middleware/validation';
import { xssProtection } from '../middleware/xssProtection';
import { sqlInjectionPrevention } from '../middleware/sqlInjectionPrevention';
import { csrfProtection } from '../middleware/csrfProtection';
import { requireAdmin, requireAuth } from '../middleware/rbac';

const router = Router();

// Apply security middleware to all routes
router.use(xssProtection());
router.use(sqlInjectionPrevention());

/**
 * POST /api/password-reset/request
 * Request password reset
 */
router.post(
  '/request',
  rateLimiters.passwordReset,
  csrfProtection(),
  validateBody(validationSchemas.passwordResetRequest),
  requestPasswordReset
);

/**
 * GET /api/password-reset/verify/:token
 * Verify password reset token
 */
router.get(
  '/verify/:token',
  rateLimiters.general,
  validateParams(validationSchemas.idParam.keys({
    token: validationSchemas.idParam.extract('id').required()
  })),
  verifyPasswordResetToken
);

/**
 * POST /api/password-reset/reset
 * Reset password with token
 */
router.post(
  '/reset',
  rateLimiters.passwordReset,
  csrfProtection(),
  validateBody(validationSchemas.passwordReset),
  resetPassword
);

/**
 * GET /api/password-reset/attempts/:email
 * Get password reset attempts for an email
 */
router.get(
  '/attempts/:email',
  rateLimiters.general,
  requireAuth,
  requireAdmin,
  validateParams(validationSchemas.emailParam),
  getPasswordResetAttempts
);

/**
 * DELETE /api/password-reset/revoke/:token
 * Revoke a password reset token
 */
router.delete(
  '/revoke/:token',
  rateLimiters.general,
  csrfProtection(),
  validateParams(validationSchemas.idParam.keys({
    token: validationSchemas.idParam.extract('id').required()
  })),
  revokePasswordResetToken
);

// Admin routes (require authentication and admin role - middleware to be added)
/**
 * GET /api/password-reset/admin/stats
 * Get password reset statistics (admin only)
 */
router.get(
  '/admin/stats',
  rateLimiters.general,
  requireAuth,
  requireAdmin,
  getPasswordResetStats
);

/**
 * GET /api/password-reset/admin/user/:userId/tokens
 * Get active password reset tokens for a user (admin only)
 */
router.get(
  '/admin/user/:userId/tokens',
  rateLimiters.general,
  requireAuth,
  requireAdmin,
  validateParams(validationSchemas.idParam.keys({
    userId: validationSchemas.idParam.extract('id').required()
  })),
  getActiveTokensForUser
);

/**
 * DELETE /api/password-reset/admin/user/:userId/tokens
 * Revoke all password reset tokens for a user (admin only)
 */
router.delete(
  '/admin/user/:userId/tokens',
  rateLimiters.general,
  requireAuth,
  requireAdmin,
  csrfProtection(),
  validateParams(validationSchemas.idParam.keys({
    userId: validationSchemas.idParam.extract('id').required()
  })),
  revokeAllTokensForUser
);

export default router;

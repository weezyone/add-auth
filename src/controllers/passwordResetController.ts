/**
 * Password Reset Controller
 * Handles password reset requests and processing
 */

import { Request, Response } from 'express';
import { logger } from '../utils/logger';
import { passwordResetManager } from '../security/passwordReset';
import { emailService } from '../utils/emailService';
import { db } from '../database/connection';

/**
 * Request password reset
 */
export const requestPasswordReset = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const ipAddress = req.ip;
    const userAgent = req.get('user-agent');

    // Check if user exists
    const userQuery = 'SELECT id, email, username FROM users WHERE email = $1 AND is_active = true';
    const userResult = await db.query(userQuery, [email]);

    if (userResult.rows.length === 0) {
      // Don't reveal if user exists or not for security
      logger.warn('Password reset requested for non-existent user', { email, ipAddress });
      return void res.status(200).json({
        success: true,
        message: 'If an account with this email exists, you will receive a password reset link.'
      });
    }

    const user = userResult.rows[0];

    // Create password reset token
    const { token, expiresAt } = await passwordResetManager.createPasswordResetToken(
      user.id,
      user.email,
      ipAddress,
      userAgent
    );

    // Send password reset email
    const emailSent = await emailService.sendPasswordResetEmail(
      user.email,
      token,
      expiresAt
    );

    if (!emailSent) {
      logger.error('Failed to send password reset email', { email, userId: user.id });
      return void res.status(500).json({
        success: false,
        error: 'Failed to send password reset email'
      });
    }

    // Log the password reset request
    const auditQuery = `
      INSERT INTO audit_logs (user_id, action, details, ip_address, user_agent, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `;
    await db.query(auditQuery, [
      user.id,
      'password_reset_requested',
      JSON.stringify({ email, expiresAt }),
      ipAddress,
      userAgent
    ]);

    res.status(200).json({
      success: true,
      message: 'If an account with this email exists, you will receive a password reset link.',
      expiresAt
    });
  } catch (error) {
    logger.error('Password reset request failed:', error);
    
    if (error instanceof Error && error.message.includes('Too many')) {
      return void res.status(429).json({
        success: false,
        error: 'Too many password reset attempts',
        message: error.message
      });
    }

    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Failed to process password reset request'
    });
  }
};

/**
 * Verify password reset token
 */
export const verifyPasswordResetToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.params;

    if (!token) {
      return void res.status(400).json({
        success: false,
        error: 'Token is required'
      });
    }

    // Validate token
    const tokenData = await passwordResetManager.validatePasswordResetToken(token);

    if (!tokenData) {
      return void res.status(400).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }

    // Get user information
    const userQuery = 'SELECT id, email, username FROM users WHERE id = $1';
    const userResult = await db.query(userQuery, [tokenData.userId]);

    if (userResult.rows.length === 0) {
      return void res.status(400).json({
        success: false,
        error: 'Invalid token'
      });
    }

    const user = userResult.rows[0];

    res.status(200).json({
      success: true,
      message: 'Token is valid',
      data: {
        email: user.email,
        expiresAt: tokenData.expiresAt
      }
    });
  } catch (error) {
    logger.error('Token verification failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Failed to verify token'
    });
  }
};

/**
 * Reset password
 */
export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body;
    const ipAddress = req.ip;
    const userAgent = req.get('user-agent');

    if (!token || !password) {
      return void res.status(400).json({
        success: false,
        error: 'Token and password are required'
      });
    }

    // Validate token
    const tokenData = await passwordResetManager.validatePasswordResetToken(token);

    if (!tokenData) {
      return void res.status(400).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }

    // Get user information
    const userQuery = 'SELECT id, email, username FROM users WHERE id = $1';
    const userResult = await db.query(userQuery, [tokenData.userId]);

    if (userResult.rows.length === 0) {
      return void res.status(400).json({
        success: false,
        error: 'Invalid token'
      });
    }

    const user = userResult.rows[0];

    // Use the password reset token (this will validate password strength)
    const hashedPassword = await passwordResetManager.usePasswordResetToken(token, password);

    if (!hashedPassword) {
      return void res.status(400).json({
        success: false,
        error: 'Failed to reset password'
      });
    }

    // Update password in database
    const updateQuery = 'UPDATE users SET password_hash = $1 WHERE id = $2';
    await db.query(updateQuery, [hashedPassword, user.id]);

    // Revoke all active sessions for this user
    const revokeSessionsQuery = 'DELETE FROM sessions WHERE user_id = $1';
    await db.query(revokeSessionsQuery, [user.id]);

    // Send password reset confirmation email
    await emailService.sendPasswordResetConfirmationEmail(user.email);

    // Log the password reset
    const auditQuery = `
      INSERT INTO audit_logs (user_id, action, details, ip_address, user_agent, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `;
    await db.query(auditQuery, [
      user.id,
      'password_reset_completed',
      JSON.stringify({ email: user.email }),
      ipAddress,
      userAgent
    ]);

    res.status(200).json({
      success: true,
      message: 'Password has been reset successfully'
    });
  } catch (error) {
    logger.error('Password reset failed:', error);
    
    if (error instanceof Error && error.message.includes('Password requirements')) {
      return void res.status(400).json({
        success: false,
        error: 'Password validation failed',
        message: error.message
      });
    }

    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Failed to reset password'
    });
  }
};

/**
 * Get password reset attempts for an email
 */
export const getPasswordResetAttempts = async (req: Request, res: Response) => {
  try {
    const { email } = req.params;

    if (!email) {
      return void res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    const attempts = await passwordResetManager.getPasswordResetAttempts(email);

    res.status(200).json({
      success: true,
      data: attempts
    });
  } catch (error) {
    logger.error('Failed to get password reset attempts:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
};

/**
 * Revoke password reset token
 */
export const revokePasswordResetToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.params;

    if (!token) {
      return void res.status(400).json({
        success: false,
        error: 'Token is required'
      });
    }

    const success = await passwordResetManager.revokePasswordResetToken(token);

    if (!success) {
      return void res.status(400).json({
        success: false,
        error: 'Token not found or already revoked'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Token revoked successfully'
    });
  } catch (error) {
    logger.error('Failed to revoke password reset token:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
};

/**
 * Get password reset statistics (admin only)
 */
export const getPasswordResetStats = async (req: Request, res: Response) => {
  try {
    const stats = await passwordResetManager.getPasswordResetStats();

    res.status(200).json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Failed to get password reset stats:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
};

/**
 * Get active password reset tokens for a user (admin only)
 */
export const getActiveTokensForUser = async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return void res.status(400).json({
        success: false,
        error: 'User ID is required'
      });
    }

    const tokens = await passwordResetManager.getActiveTokensForUser(userId);

    res.status(200).json({
      success: true,
      data: tokens.map(token => ({
        id: token.id,
        email: token.email,
        createdAt: token.createdAt,
        expiresAt: token.expiresAt,
        isUsed: token.isUsed,
        ipAddress: token.ipAddress,
        userAgent: token.userAgent
      }))
    });
  } catch (error) {
    logger.error('Failed to get active tokens for user:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
};

/**
 * Revoke all password reset tokens for a user (admin only)
 */
export const revokeAllTokensForUser = async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return void res.status(400).json({
        success: false,
        error: 'User ID is required'
      });
    }

    const revokedCount = await passwordResetManager.revokeAllTokensForUser(userId);

    res.status(200).json({
      success: true,
      message: `Revoked ${revokedCount} password reset tokens`,
      data: { revokedCount }
    });
  } catch (error) {
    logger.error('Failed to revoke all tokens for user:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
};

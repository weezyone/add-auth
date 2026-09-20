import { Request, Response } from 'express';
import { UserModel } from '../models/User';
import { AuthUtils } from '../utils/auth';
import { createAuthenticationTokens, refreshAccessToken } from '../utils/refreshToken';
import { performLogout } from '../utils/tokenBlacklist';
import { extractTokenFromHeader } from '../utils/jwt';
import { UserPayload, JWTPayload } from '../types/jwt';
import { UserStatus } from '../types/user';
import { logger } from '../utils/logger';
import { defaultPasswordSecurity } from '../security/password-security';
import { SessionService } from '../services/sessionService';
import { FingerprintService } from '../utils/fingerprint';
import { RoleModel } from '../models/Role';

/**
 * Register a new user
 */
export async function register(req: Request, res: Response): Promise<void> {
  try {
    // Input is already validated by middleware
    const { email, password, username } = req.body;

    // Additional password validation using password security module
    const passwordValidation = defaultPasswordSecurity.validatePassword(password);
    if (!passwordValidation.isValid) {
      res.status(400).json({
        error: 'Password validation failed',
        message: 'Password does not meet security requirements',
        details: passwordValidation.errors
      });
      return;
    }

    // Check if user already exists
    const existingUser = await UserModel.findByEmail(email);
    if (existingUser) {
      res.status(409).json({
        error: 'User already exists',
        message: 'A user with this email already exists'
      });
      return;
    }

    // Hash password
    const hashedPassword = await AuthUtils.hashPassword(password);

    // Create user
    const user = await UserModel.create({
      email: email.toLowerCase().trim(),
      password: hashedPassword
    });

    // Create Redis session with fingerprinting
    const sessionToken = AuthUtils.generateSecureToken();
    const fingerprint = FingerprintService.generateFingerprint(req);
    
    const redisSession = await SessionService.createSession({
      user_id: user.id,
      token: sessionToken,
      expires_at: AuthUtils.calculateSessionExpiration(),
      ip_address: AuthUtils.getClientIp(req),
      user_agent: AuthUtils.getUserAgent(req) || undefined,
      fingerprint: fingerprint
    });

    // Generate JWT tokens
    const userPayload: UserPayload = {
      id: user.id,
      email: user.email,
      roles: [] // Default roles
    };

    const tokens = await createAuthenticationTokens(userPayload, {
      ipAddress: AuthUtils.getClientIp(req),
      userAgent: AuthUtils.getUserAgent(req) || undefined
    });

    logger.info('User registered successfully', { 
      userId: user.id, 
      email: user.email,
      sessionId: redisSession.id
    });

    // Set session cookie
    res.cookie('sessionId', redisSession.id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at,
        status: user.status
      },
      session: {
        id: redisSession.id,
        expires_at: redisSession.expires_at,
        trust_score: redisSession.trust_score
      },
      tokens
    });
  } catch (error: any) {
    logger.error('Registration error:', error);
    
    res.status(500).json({
      error: 'Registration failed',
      message: 'An error occurred during registration'
    });
  }
}

/**
 * Login user
 */
export async function login(req: Request, res: Response): Promise<void> {
  try {
    // Input is already validated by middleware
    const { email, password, rememberMe } = req.body;

    // Find user with password hash
    const user = await UserModel.findByEmail(email, true);
    if (!user) {
      res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
      return;
    }

    // Check if user is active
    if (user.status !== UserStatus.ACTIVE) {
      res.status(401).json({
        error: 'Account disabled',
        message: 'Your account has been disabled'
      });
      return;
    }

    // Check if account is locked
    if (AuthUtils.isAccountLocked(user.locked_until)) {
      res.status(423).json({
        error: 'Account locked',
        message: 'Account is temporarily locked due to failed login attempts'
      });
      return;
    }

    // Verify password
    const passwordValid = await AuthUtils.verifyPassword(password, (user as any).password_hash);
    if (!passwordValid) {
      // Increment failed attempts
      await UserModel.incrementFailedLoginAttempts(user.id);
      
      res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
      return;
    }

    // Update last login and reset failed attempts
    await UserModel.updateLastLogin(user.id);

    // Create Redis session with fingerprinting
    const sessionToken = AuthUtils.generateSecureToken();
    const fingerprint = FingerprintService.generateFingerprint(req);
    
    const redisSession = await SessionService.createSession({
      user_id: user.id,
      token: sessionToken,
      expires_at: AuthUtils.calculateSessionExpiration(),
      ip_address: AuthUtils.getClientIp(req),
      user_agent: AuthUtils.getUserAgent(req) || undefined,
      fingerprint: fingerprint
    }, rememberMe);

    const roles = await RoleModel.getUserRoles(user.id);
    const roleNames = roles.map(role => role.name);

    // Generate JWT tokens
    const userPayload: UserPayload = {
      id: user.id,
      email: user.email,
      roles: roleNames
    };

    const tokens = await createAuthenticationTokens(userPayload, {
      ipAddress: AuthUtils.getClientIp(req),
      userAgent: AuthUtils.getUserAgent(req) || undefined,
    });

    logger.info('User logged in successfully', { 
      userId: user.id, 
      email: user.email,
      sessionId: redisSession.id,
      rememberMe: !!rememberMe
    });

    // Set session cookie
    const cookieMaxAge = rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000; // 7 days or 24 hours
    res.cookie('sessionId', redisSession.id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: cookieMaxAge,
    });

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        last_login: user.last_login,
        status: user.status,
        email_verified: user.email_verified
      },
      session: {
        id: redisSession.id,
        expires_at: redisSession.expires_at,
        trust_score: redisSession.trust_score,
        concurrent_count: redisSession.concurrent_count
      },
      tokens
    });
  } catch (error: any) {
    logger.error('Login error:', error);
    
    res.status(500).json({
      error: 'Login failed',
      message: 'An error occurred during login'
    });
  }
}

/**
 * Change user password
 */
export async function changePassword(req: Request, res: Response): Promise<void> {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user?.id;

    if (!userId) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    const user = await UserModel.findById(userId, true);
    if (!user) {
      res.status(404).json({
        error: 'User not found',
        message: 'User account not found'
      });
      return;
    }

    const currentValid = await AuthUtils.verifyPassword(
      currentPassword,
      (user as any).password_hash
    );

    if (!currentValid) {
      res.status(400).json({
        error: 'Invalid credentials',
        message: 'Current password is incorrect'
      });
      return;
    }

    const passwordValidation = defaultPasswordSecurity.validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      res.status(400).json({
        error: 'Password validation failed',
        message: 'New password does not meet security requirements',
        details: passwordValidation.errors
      });
      return;
    }

    const isSamePassword = await AuthUtils.verifyPassword(
      newPassword,
      (user as any).password_hash
    );

    if (isSamePassword) {
      res.status(400).json({
        error: 'Invalid password',
        message: 'New password must be different from the current password'
      });
      return;
    }

    const hashedPassword = await AuthUtils.hashPassword(newPassword);
    await UserModel.updatePassword(userId, hashedPassword);

    await SessionService.destroyUserSessions(userId);
    res.clearCookie('sessionId');

    logger.info('User password changed successfully', { userId });

    res.json({
      success: true,
      message: 'Password updated successfully. Please log in again.'
    });
  } catch (error: any) {
    logger.error('Password change failed:', error);
    res.status(500).json({
      error: 'Password change failed',
      message: 'An error occurred while changing the password'
    });
  }
}

/**
 * Logout user
 */
export async function logout(req: Request, res: Response): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);

    // Get session ID from cookie or header
    const sessionId = req.cookies?.sessionId || req.headers['x-session-id'] as string;

    let logoutSuccess = false;

    // Handle JWT token logout
    if (token) {
      // Get refresh token from body if provided
      const refreshToken = req.body.refreshToken;
      
      // Blacklist tokens
      logoutSuccess = await performLogout(token, refreshToken);
    }

    // Handle Redis session logout
    if (sessionId) {
      const sessionDestroyed = await SessionService.destroySession(sessionId);
      logoutSuccess = logoutSuccess || sessionDestroyed;
      
      // Clear session cookie
      res.clearCookie('sessionId');
      
      logger.info('Redis session destroyed during logout', {
        sessionId,
        userId: req.user?.id,
        destroyed: sessionDestroyed
      });
    }

    // If we have a Redis session from middleware, destroy it
    if (req.redisSession) {
      await SessionService.destroySession(req.redisSession.id);
      res.clearCookie('sessionId');
      logoutSuccess = true;
      
      logger.info('Active Redis session destroyed during logout', {
        sessionId: req.redisSession.id,
        userId: req.redisSession.user_id
      });
    }

    if (logoutSuccess || sessionId || req.redisSession) {
      logger.info('User logged out successfully', { 
        userId: req.user?.id,
        sessionId: sessionId || req.redisSession?.id,
        tokenLogout: !!token,
        sessionLogout: !!(sessionId || req.redisSession)
      });
      
      res.json({
        message: 'Logged out successfully'
      });
    } else {
      res.status(400).json({
        error: 'No active session found',
        message: 'No token or session provided for logout'
      });
    }
  } catch (error: any) {
    logger.error('Logout error:', error);
    res.status(500).json({
      error: 'Logout failed',
      message: 'An error occurred during logout'
    });
  }
}

/**
 * Refresh access token
 */
export async function refresh(req: Request, res: Response): Promise<void> {
  try {
    // Input is already validated by middleware (through route validation)
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({
        error: 'Validation error',
        message: 'Refresh token is required'
      });
      return;
    }

    // Refresh tokens
    const tokens = await refreshAccessToken(refreshToken, true);

    logger.info('Tokens refreshed successfully');

    res.json({
      message: 'Tokens refreshed successfully',
      tokens
    });
  } catch (error: any) {
    logger.error('Token refresh error:', error);
    
    if (error.name === 'TokenInvalidError' || error.name === 'TokenExpiredError') {
      res.status(401).json({
        error: 'Invalid refresh token',
        message: 'Please login again'
      });
      return;
    }

    res.status(500).json({
      error: 'Token refresh failed',
      message: 'An error occurred while refreshing tokens'
    });
  }
}

/**
 * Get current user info
 */
export async function getUserInfo(req: Request, res: Response): Promise<void> {
  try {
    const userId = req.user?.id;
    
    if (!userId) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    // Get user from database
    const user = await UserModel.findById(userId);
    
    if (!user) {
      res.status(404).json({
        error: 'User not found',
        message: 'User account not found'
      });
      return;
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at,
        updated_at: user.updated_at,
        status: user.status,
        email_verified: user.email_verified,
        last_login: user.last_login
      }
    });
  } catch (error: any) {
    logger.error('Get user info error:', error);
    res.status(500).json({
      error: 'Failed to get user info',
      message: 'An error occurred while fetching user information'
    });
  }
}

/**
 * Update user profile
 */
export async function updateProfile(req: Request, res: Response): Promise<void> {
  try {
    const userId = req.user?.id;
    
    if (!userId) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    // Input is already validated by middleware
    const updateData = req.body;

    // Check if email already exists if updating email
    if (updateData.email) {
      const existingUser = await UserModel.findByEmail(updateData.email);
      if (existingUser && existingUser.id !== userId) {
        res.status(409).json({
          error: 'Email already exists',
          message: 'A user with this email already exists'
        });
        return;
      }
    }

    // Update user
    const updatedUser = await UserModel.update(userId, updateData);
    
    if (!updatedUser) {
      res.status(404).json({
        error: 'User not found',
        message: 'User account not found'
      });
      return;
    }

    logger.info('User profile updated successfully', { 
      userId: userId 
    });

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        updated_at: updatedUser.updated_at,
        status: updatedUser.status,
        email_verified: updatedUser.email_verified
      }
    });
  } catch (error: any) {
    logger.error('Update profile error:', error);
    
    res.status(500).json({
      error: 'Profile update failed',
      message: 'An error occurred while updating profile'
    });
  }
}

/**
 * Get user's active sessions
 */
export async function getUserSessions(req: Request, res: Response): Promise<void> {
  try {
    const userId = req.user?.id;
    
    if (!userId) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    // Get sessions from Redis
    const sessions = await SessionService.getUserSessions(userId);
    
    // Remove sensitive data before sending to client
    const safeSessions = sessions.map(session => ({
      id: session.id,
      created_at: session.created_at,
      last_accessed: session.last_accessed,
      expires_at: session.expires_at,
      ip_address: session.ip_address,
      user_agent: session.user_agent,
      trust_score: session.trust_score,
      is_current: req.redisSession?.id === session.id
    }));

    logger.info('Retrieved user sessions', {
      userId,
      sessionCount: sessions.length
    });

    res.json({
      sessions: safeSessions,
      total: sessions.length
    });
  } catch (error: any) {
    logger.error('Get user sessions error:', error);
    res.status(500).json({
      error: 'Failed to get sessions',
      message: 'An error occurred while fetching sessions'
    });
  }
}

/**
 * Revoke a specific session
 */
export async function revokeSession(req: Request, res: Response): Promise<void> {
  try {
    const userId = req.user?.id;
    const { sessionId } = req.params;
    
    if (!userId) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    if (!sessionId) {
      res.status(400).json({
        error: 'Session ID required',
        message: 'Session ID is required to revoke session'
      });
      return;
    }

    // Get the session to verify it belongs to the user
    const session = await SessionService.getSession(sessionId);
    
    if (!session || session.user_id !== userId) {
      res.status(404).json({
        error: 'Session not found',
        message: 'Session not found or does not belong to user'
      });
      return;
    }

    // Destroy the session
    const success = await SessionService.destroySession(sessionId);
    
    if (success) {
      logger.info('Session revoked by user', {
        userId,
        sessionId,
        revokedBySessionId: req.redisSession?.id
      });
      
      res.json({
        message: 'Session revoked successfully'
      });
    } else {
      res.status(500).json({
        error: 'Failed to revoke session',
        message: 'An error occurred while revoking the session'
      });
    }
  } catch (error: any) {
    logger.error('Revoke session error:', error);
    res.status(500).json({
      error: 'Failed to revoke session',
      message: 'An error occurred while revoking session'
    });
  }
}

/**
 * Revoke all other sessions (except current)
 */
export async function revokeAllOtherSessions(req: Request, res: Response): Promise<void> {
  try {
    const userId = req.user?.id;
    const currentSessionId = req.redisSession?.id;
    
    if (!userId) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User not authenticated'
      });
      return;
    }

    // Destroy all other sessions
    const revokedCount = await SessionService.destroyUserSessions(userId, currentSessionId);
    
    logger.info('All other sessions revoked by user', {
      userId,
      revokedCount,
      currentSessionId
    });
    
    res.json({
      message: `Successfully revoked ${revokedCount} session(s)`,
      revokedCount
    });
  } catch (error: any) {
    logger.error('Revoke all other sessions error:', error);
    res.status(500).json({
      error: 'Failed to revoke sessions',
      message: 'An error occurred while revoking sessions'
    });
  }
}

/**
 * Extend current session
 */
export async function extendSession(req: Request, res: Response): Promise<void> {
  try {
    const sessionId = req.redisSession?.id;
    
    if (!sessionId) {
      res.status(401).json({
        error: 'No active session',
        message: 'No active session to extend'
      });
      return;
    }

    // Extend session by default duration (24 hours)
    const extendedSession = await SessionService.extendSession(sessionId);
    
    if (extendedSession) {
      logger.info('Session extended', {
        sessionId,
        userId: extendedSession.user_id,
        newExpiresAt: extendedSession.expires_at
      });
      
      res.json({
        message: 'Session extended successfully',
        session: {
          id: extendedSession.id,
          expires_at: extendedSession.expires_at,
          trust_score: extendedSession.trust_score
        }
      });
    } else {
      res.status(404).json({
        error: 'Session not found',
        message: 'Session could not be found or extended'
      });
    }
  } catch (error: any) {
    logger.error('Extend session error:', error);
    res.status(500).json({
      error: 'Failed to extend session',
      message: 'An error occurred while extending session'
    });
  }
}

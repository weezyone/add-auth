import { Router } from 'express';
import passport from '../config/passport';
import { SessionModel } from '../models/Session';
import { AuditLogModel } from '../models/AuditLog';
import { FingerprintService } from '../utils/fingerprint';
import { logger } from '../utils/logger';
import { appConfig } from '../config';

const router = Router();

// Google OAuth routes
router.get('/google', 
  passport.authenticate('google', { 
    scope: ['profile', 'email'] 
  })
);

// The provider redirects to `${OAUTH_CALLBACK_URL}/google` (config/passport.ts),
// i.e. /auth/callback/google by default and in ADVANCED_AUTH_SETUP.md, but only
// /auth/google/callback was mounted, so every real callback 404'd. Serve both.
router.get(['/callback/google', '/google/callback'],
  passport.authenticate('google', { failureRedirect: '/login?error=oauth_failed' }),
  async (req, res) => {
    try {
      const user = req.user as any;
      
      if (!user) {
        logger.warn('OAuth callback received without user data');
        return void res.redirect('/login?error=oauth_failed');
      }

      // Generate device fingerprint
      const fingerprint = FingerprintService.generateFingerprint(req);
      
      // Create session in database
      const expiresAt = new Date(Date.now() + appConfig.security.sessionTimeout);
      const session = await SessionModel.create({
        user_id: user.id,
        token: req.sessionID,
        expires_at: expiresAt,
        ip_address: fingerprint.ip,
        user_agent: fingerprint.userAgent,
      });

      // Set session data
      req.session.userId = user.id;
      req.session.isAuthenticated = true;
      req.session.fingerprint = fingerprint;
      req.session.trustScore = 0.8; // Higher trust for OAuth
      req.session.lastActivity = new Date();

      // Log successful OAuth login
      await AuditLogModel.create({
        user_id: user.id,
        action: 'oauth_login',
        resource_type: 'user',
        resource_id: user.id,
        ip_address: fingerprint.ip,
        success: true,
        details: {
          provider: 'google',
          ip_address: fingerprint.ip,
          user_agent: fingerprint.userAgent,
          session_id: req.sessionID,
        },
      });

      logger.info('Google OAuth login successful', {
        userId: user.id,
        email: user.email,
        sessionId: req.sessionID,
      });

      // Redirect to dashboard or intended page
      const redirectTo = req.session.returnTo || '/dashboard';
      delete req.session.returnTo;
      res.redirect(redirectTo);
    } catch (error) {
      logger.error('Error in Google OAuth callback', { error });
      res.redirect('/login?error=oauth_callback_error');
    }
  }
);

// GitHub OAuth routes
router.get('/github', 
  passport.authenticate('github', { 
    scope: ['user:email'] 
  })
);

router.get(['/callback/github', '/github/callback'],
  passport.authenticate('github', { failureRedirect: '/login?error=oauth_failed' }),
  async (req, res) => {
    try {
      const user = req.user as any;
      
      if (!user) {
        logger.warn('OAuth callback received without user data');
        return void res.redirect('/login?error=oauth_failed');
      }

      // Generate device fingerprint
      const fingerprint = FingerprintService.generateFingerprint(req);
      
      // Create session in database
      const expiresAt = new Date(Date.now() + appConfig.security.sessionTimeout);
      const session = await SessionModel.create({
        user_id: user.id,
        token: req.sessionID,
        expires_at: expiresAt,
        ip_address: fingerprint.ip,
        user_agent: fingerprint.userAgent,
      });

      // Set session data
      req.session.userId = user.id;
      req.session.isAuthenticated = true;
      req.session.fingerprint = fingerprint;
      req.session.trustScore = 0.8; // Higher trust for OAuth
      req.session.lastActivity = new Date();

      // Log successful OAuth login
      await AuditLogModel.create({
        user_id: user.id,
        action: 'oauth_login',
        resource_type: 'user',
        resource_id: user.id,
        ip_address: fingerprint.ip,
        success: true,
        details: {
          provider: 'github',
          ip_address: fingerprint.ip,
          user_agent: fingerprint.userAgent,
          session_id: req.sessionID,
        },
      });

      logger.info('GitHub OAuth login successful', {
        userId: user.id,
        email: user.email,
        sessionId: req.sessionID,
      });

      // Redirect to dashboard or intended page
      const redirectTo = req.session.returnTo || '/dashboard';
      delete req.session.returnTo;
      res.redirect(redirectTo);
    } catch (error) {
      logger.error('Error in GitHub OAuth callback', { error });
      res.redirect('/login?error=oauth_callback_error');
    }
  }
);

// OAuth account linking routes (for authenticated users)
router.get('/link/google', 
  (req, res, next) => {
    if (!req.session.isAuthenticated) {
      return void res.status(401).json({ error: 'Authentication required' });
    }
    next();
  },
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    state: 'link_account',
  })
);

router.get('/link/github', 
  (req, res, next) => {
    if (!req.session.isAuthenticated) {
      return void res.status(401).json({ error: 'Authentication required' });
    }
    next();
  },
  passport.authenticate('github', { 
    scope: ['user:email'],
    state: 'link_account',
  })
);

// OAuth account unlinking routes
router.post('/unlink/:provider', async (req, res) => {
  try {
    if (!req.session.isAuthenticated || !req.session.userId) {
      return void res.status(401).json({ error: 'Authentication required' });
    }

    const { provider } = req.params;
    const userId = req.session.userId;

    if (!['google', 'github'].includes(provider)) {
      return void res.status(400).json({ error: 'Invalid OAuth provider' });
    }

    // Import UserModel dynamically to avoid circular dependency
    const { UserModel } = await import('../models/User');
    
    const unlinked = await UserModel.unlinkOAuthAccount(userId, provider);

    if (unlinked) {
      const fingerprint = FingerprintService.generateFingerprint(req);
      await AuditLogModel.create({
        user_id: userId,
        action: 'oauth_unlink',
        resource_type: 'user',
        resource_id: userId,
        ip_address: fingerprint.ip,
        success: true,
        details: {
          provider,
          ip_address: fingerprint.ip,
        },
      });

      logger.info('OAuth account unlinked', { userId, provider });
      res.json({ message: 'Account unlinked successfully' });
    } else {
      res.status(404).json({ error: 'OAuth account not found' });
    }
  } catch (error) {
    logger.error('Error unlinking OAuth account', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's OAuth accounts
router.get('/accounts', async (req, res) => {
  try {
    if (!req.session.isAuthenticated || !req.session.userId) {
      return void res.status(401).json({ error: 'Authentication required' });
    }

    const userId = req.session.userId;
    
    // Import UserModel dynamically to avoid circular dependency
    const { UserModel } = await import('../models/User');
    
    const oauthAccounts = await UserModel.getOAuthAccounts(userId);

    // Remove sensitive data before sending
    const sanitizedAccounts = oauthAccounts.map(account => ({
      provider: account.provider,
      provider_id: account.provider_id,
      created_at: account.created_at,
      profile_data: {
        displayName: account.profile_data.displayName,
        username: account.profile_data.username,
        email: account.profile_data.emails?.[0]?.value,
      },
    }));

    res.json({ accounts: sanitizedAccounts });
  } catch (error) {
    logger.error('Error getting OAuth accounts', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OAuth status endpoint
router.get('/status', (req, res) => {
  const isConfigured = {
    google: !!(appConfig.oauth.google.clientId && appConfig.oauth.google.clientSecret),
    github: !!(appConfig.oauth.github.clientId && appConfig.oauth.github.clientSecret),
  };

  res.json({
    configured: isConfigured,
    available: Object.keys(isConfigured).filter(provider => isConfigured[provider as keyof typeof isConfigured]),
  });
});

export default router;
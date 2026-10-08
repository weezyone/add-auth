import express from 'express';
import passport from './config/passport';
import { createRedisClient, getRedisClient } from './utils/redis';
import { sessionMiddleware, fingerprintMiddleware, sessionActivityMiddleware } from './middleware/session';
import { requireAuth, requireRole, requirePermission, requireAdmin } from './middleware/rbac';
import oauthRoutes from './routes/oauth';
import { appConfig } from './config';
import { logger } from './utils/logger';
import { PERMISSIONS } from './utils/permissions';

const app = express();

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Initialize Redis connection
let redisInitialized = false;

async function initializeRedis() {
  try {
    await createRedisClient();
    redisInitialized = true;
    logger.info('Redis connection initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize Redis connection', { error });
    // Continue without Redis for development
  }
}

// Session + Passport middleware (requires Redis).
//
// These used to be app.use()'d from initializeApp(), i.e. *after* every route
// and the 404 handler had been registered, so they never ran; and
// passport.session() was registered before any session existed, so every
// request that reached it failed with "Login sessions require session
// support". Register them here, in order, and skip them (rather than 500)
// while no Redis client is connected.
function redisReady(): boolean {
  try {
    getRedisClient();
    return true;
  } catch {
    return false;
  }
}

const sessionChain: express.RequestHandler[] = [
  sessionMiddleware,
  fingerprintMiddleware,
  sessionActivityMiddleware,
  passport.session(),
];

app.use(passport.initialize());
app.use((req, res, next) => {
  if (!redisReady()) {
    return next();
  }
  let i = 0;
  const run = (err?: any): void => {
    if (err || i >= sessionChain.length) return next(err);
    sessionChain[i++](req, res, run);
  };
  run();
});

async function setupSessionMiddleware() {
  if (redisInitialized) {
    logger.info('Session middleware initialized with Redis');
  } else {
    logger.warn('Session middleware not initialized - Redis connection failed');
  }
}

// OAuth routes
app.use('/auth', oauthRoutes);

// Public routes
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    redis: redisInitialized ? 'connected' : 'disconnected',
  });
});

app.get('/login', (req, res) => {
  res.json({ 
    message: 'Login page',
    oauth: {
      google: '/auth/google',
      github: '/auth/github',
    },
  });
});

// Protected routes examples

// Basic authentication required
app.get('/dashboard', requireAuth, (req, res) => {
  res.json({
    message: 'Welcome to your dashboard',
    userId: req.session?.userId,
    sessionId: req.sessionID,
    trustScore: req.session?.trustScore,
  });
});

// Role-based access control examples
app.get('/admin', requireAdmin, (req, res) => {
  res.json({
    message: 'Admin panel',
    userRoles: req.userRoles,
    userPermissions: req.userPermissions,
  });
});

app.get('/moderator', requireRole(['admin', 'moderator']), (req, res) => {
  res.json({
    message: 'Moderator panel',
    userRoles: req.userRoles,
  });
});

// Permission-based access control examples
app.get('/users', requirePermission(PERMISSIONS.USER_READ), async (req, res) => {
  try {
    // Example: Get users list (would normally fetch from database)
    res.json({
      message: 'Users list',
      userPermissions: req.userPermissions,
      // users: await UserModel.findAll(),
    });
  } catch (error) {
    logger.error('Error getting users', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/users', requirePermission(PERMISSIONS.USER_WRITE), async (req, res) => {
  try {
    // Example: Create user (would normally create in database)
    res.json({
      message: 'User created',
      // user: await UserModel.create(req.body),
    });
  } catch (error) {
    logger.error('Error creating user', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/users/:id', requirePermission(PERMISSIONS.USER_DELETE), async (req, res) => {
  try {
    // Example: Delete user (would normally delete from database)
    res.json({
      message: 'User deleted',
      userId: req.params.id,
    });
  } catch (error) {
    logger.error('Error deleting user', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Multiple permission requirements
app.get('/audit-logs', 
  requirePermission([PERMISSIONS.AUDIT_READ, PERMISSIONS.SYSTEM_MONITORING], { requireAll: false }),
  async (req, res) => {
    try {
      res.json({
        message: 'Audit logs',
        // logs: await AuditLogModel.findAll(),
      });
    } catch (error) {
      logger.error('Error getting audit logs', { error });
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Profile routes (user can access their own data)
app.get('/profile', requireAuth, async (req, res) => {
  try {
    const userId = req.session?.userId;
    
    if (!userId) {
      return void res.status(401).json({ error: 'Authentication required' });
    }

    // Example: Get user profile
    res.json({
      message: 'User profile',
      userId,
      // profile: await UserModel.findById(userId),
      // oauthAccounts: await UserModel.getOAuthAccounts(userId),
    });
  } catch (error) {
    logger.error('Error getting profile', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Session management routes
app.get('/sessions', requireAuth, async (req, res) => {
  try {
    const userId = req.session?.userId;
    
    if (!userId) {
      return void res.status(401).json({ error: 'Authentication required' });
    }

    // Example: Get user sessions
    res.json({
      message: 'User sessions',
      currentSessionId: req.sessionID,
      // sessions: await SessionModel.findByUserId(userId),
    });
  } catch (error) {
    logger.error('Error getting sessions', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/sessions/:sessionId', requireAuth, async (req, res) => {
  try {
    const userId = req.session?.userId;
    const { sessionId } = req.params;
    
    if (!userId) {
      return void res.status(401).json({ error: 'Authentication required' });
    }

    // Example: Invalidate session
    res.json({
      message: 'Session invalidated',
      sessionId,
      // result: await SessionModel.invalidateByToken(sessionId),
    });
  } catch (error) {
    logger.error('Error invalidating session', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout route
app.post('/logout', requireAuth, async (req, res) => {
  try {
    const userId = req.session?.userId;
    const sessionId = req.sessionID;

    // Invalidate session in database
    // await SessionModel.invalidateByToken(sessionId);

    // Destroy Express session
    req.session.destroy((err) => {
      if (err) {
        logger.error('Error destroying session', { error: err });
        return void res.status(500).json({ error: 'Error logging out' });
      }

      logger.info('User logged out successfully', { userId, sessionId });
      res.json({ message: 'Logged out successfully' });
    });
  } catch (error) {
    logger.error('Error during logout', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((error: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error('Unhandled error', { 
    error: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method,
  });

  res.status(500).json({
    error: 'Internal server error',
    message: appConfig.server.nodeEnv === 'development' ? error.message : 'Something went wrong',
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: `Route ${req.method} ${req.path} not found`,
  });
});

// Initialize the application
async function initializeApp() {
  try {
    await initializeRedis();
    await setupSessionMiddleware();
    
    const port = appConfig.server.port;
    app.listen(port, () => {
      logger.info(`Server started on port ${port}`, {
        port,
        nodeEnv: appConfig.server.nodeEnv,
        redis: redisInitialized ? 'enabled' : 'disabled',
      });
    });
  } catch (error) {
    logger.error('Failed to initialize application', { error });
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Received SIGINT, shutting down gracefully');
  
  try {
    if (redisInitialized) {
      const { closeRedisConnection } = await import('./utils/redis');
      await closeRedisConnection();
    }
    
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown', { error });
    process.exit(1);
  }
});

process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, shutting down gracefully');
  
  try {
    if (redisInitialized) {
      const { closeRedisConnection } = await import('./utils/redis');
      await closeRedisConnection();
    }
    
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown', { error });
    process.exit(1);
  }
});

// Start the application
if (require.main === module) {
  initializeApp();
}

export default app;
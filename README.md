# @paulweezydesign/add-auth

A comprehensive authentication and authorization library for Node.js applications with TypeScript support. Features include RBAC (Role-Based Access Control), OAuth integration, session management, security middleware, and much more.

## Features

- 🔐 **Authentication & Authorization**
  - JWT-based authentication with access and refresh tokens
  - Role-Based Access Control (RBAC)
  - Permission-based authorization
  - Session management with Redis
  - OAuth 2.0 integration (Google, GitHub)

- 🛡️ **Security Middleware**
  - CSRF protection
  - XSS protection
  - SQL injection prevention
  - Rate limiting (general, auth, password reset, registration)
  - Input validation and sanitization
  - Token blacklisting

- 👤 **User Management**
  - User registration and login
  - Password hashing with bcrypt
  - Password reset functionality
  - Email verification
  - Device fingerprinting

- 📊 **Audit & Monitoring**
  - Comprehensive audit logging
  - Session tracking
  - Security event monitoring
  - Health check endpoints

- 🌐 **Internationalization**
  - Multi-language support
  - Localized validation messages
  - Translation helpers

## Installation

```bash
npm install @paulweezydesign/add-auth
```

### Peer Dependencies

The following packages are required:

```bash
npm install express pg redis
```

## Quick Start

### Basic Setup

```typescript
import express from 'express';
import { 
  applySecurityMiddleware,
  requireAuth,
  UserModel,
  db
} from '@paulweezydesign/add-auth';

const app = express();

// Apply security middleware
app.use(express.json());
app.use(applySecurityMiddleware('production'));

// Protected route example
app.get('/api/profile', requireAuth, async (req, res) => {
  const userId = req.session?.userId;
  const user = await UserModel.findById(userId);
  res.json({ user });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### Environment Configuration

Copy [`.env.example`](./.env.example) and set secrets. Names below match `src/config/index.ts` and `src/index.ts` (not `DATABASE_HOST` / `JWT_ACCESS_EXPIRY`).

```env
# Database (or set DATABASE_URL)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=add_auth
DB_USER=postgres
DB_PASSWORD=password
# Leave DB_SSL unset. The string "false" is coerced to true.

# JWT / session (both secrets must be at least 32 characters)
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d
SESSION_SECRET=your-session-secret-at-least-32-characters
SESSION_TIMEOUT=86400000

# Redis (CSRF, rate limits, sessions, password-reset tokens)
REDIS_HOST=localhost
REDIS_PORT=6379

# Password-reset mailer (src/utils/emailService.ts)
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your-email@example.com
EMAIL_PASS=your-email-password
EMAIL_FROM=noreply@example.com

# CORS allowlist for browser clients (comma-separated)
FRONTEND_URL=http://localhost:3000,http://localhost:5173

NODE_ENV=development
PORT=3000
```

Full variable list and pitfalls: [docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md#environment-configuration).

## Usage Examples

### User Authentication

```typescript
import { UserModel, AuthUtils } from '@paulweezydesign/add-auth';

// Register a new user
const user = await UserModel.create({
  email: 'user@example.com',
  username: 'johndoe',
  password: 'SecurePassword123!'
});

// Login
const loginUser = await UserModel.findByEmail('user@example.com');
if (loginUser && await AuthUtils.verifyPassword('SecurePassword123!', loginUser.password_hash)) {
  const tokens = await createAuthenticationTokens({
    userId: loginUser.id,
    email: loginUser.email,
    roles: ['user']
  });
  console.log('Access Token:', tokens.accessToken);
}
```

### Role-Based Access Control

```typescript
import { requireRole, requirePermission, requireAuth } from '@paulweezydesign/add-auth';

// Require specific role
app.get('/admin/dashboard', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin Dashboard' });
});

// Require specific permission
app.post('/posts/create', requireAuth, requirePermission('posts:create'), (req, res) => {
  // Create post logic
});

// Require any of multiple roles
app.get('/moderation', requireAuth, requireRole(['admin', 'moderator']), (req, res) => {
  res.json({ message: 'Moderation Panel' });
});
```

### Security Middleware Stacks

```typescript
import { securityMiddleware } from '@paulweezydesign/add-auth';

// Use pre-configured security stacks
app.post('/auth/login', securityMiddleware.auth, loginController);
app.post('/auth/register', securityMiddleware.registration, registerController);
app.post('/auth/forgot-password', securityMiddleware.passwordReset, forgotPasswordController);
app.use('/admin', securityMiddleware.admin, adminRoutes);
```

### Custom Rate Limiting

```typescript
import { createCustomRateLimiter } from '@paulweezydesign/add-auth';

// Create custom rate limiter
const apiLimiter = createCustomRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many requests from this IP'
});

app.use('/api/', apiLimiter);
```

### Session Management

```typescript
import { SessionService, sessionMiddleware } from '@paulweezydesign/add-auth';

// Apply session middleware
app.use(sessionMiddleware);

// Get user sessions
const sessions = await SessionService.getUserSessions(userId);

// Revoke a session
await SessionService.revokeSession(sessionId);

// Revoke all user sessions
await SessionService.revokeAllUserSessions(userId);
```

### Password Reset

```typescript
import { PasswordResetManager, emailService } from '@paulweezydesign/add-auth';

// Request password reset
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await UserModel.findByEmail(email);
  
  if (user) {
    const resetToken = await PasswordResetManager.createResetToken(user.id);
    await emailService.sendPasswordResetEmail(email, resetToken, user.username);
  }
  
  res.json({ message: 'If email exists, reset link has been sent' });
});

// Reset password with token
app.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  await PasswordResetManager.resetPassword(token, newPassword);
  res.json({ message: 'Password reset successful' });
});
```

### Token Management

```typescript
import { 
  generateAccessToken, 
  validateAccessToken,
  isTokenBlacklisted,
  addToBlacklist 
} from '@paulweezydesign/add-auth';

// Generate token
const accessToken = await generateAccessToken({ 
  userId: user.id, 
  email: user.email 
});

// Validate token
const validation = await validateAccessToken(token);
if (validation.valid) {
  console.log('Token payload:', validation.payload);
}

// Blacklist a token (e.g., on logout)
await addToBlacklist(token, user.id, 'User logout');

// Check if token is blacklisted
const isBlacklisted = await isTokenBlacklisted(token);
```

### Input Validation & Sanitization

```typescript
import { 
  validate, 
  validationSchemas,
  sanitizeInput,
  xssProtection 
} from '@paulweezydesign/add-auth';

// Use built-in validation schemas
app.post('/register', 
  validate(validationSchemas.registration),
  registerController
);

// Apply XSS protection
app.use(xssProtection());

// Sanitize specific input
app.use(sanitizeInput('body'));
app.use(sanitizeInput('query'));
```

### Audit Logging

```typescript
import { AuditLogModel } from '@paulweezydesign/add-auth';

// Create audit log
await AuditLogModel.create({
  user_id: userId,
  action: 'user.login',
  resource_type: 'authentication',
  resource_id: sessionId,
  ip_address: req.ip,
  user_agent: req.headers['user-agent'],
  details: {
    success: true,
    method: '2fa'
  }
});

// Query audit logs
const logs = await AuditLogModel.findByUser(userId, { limit: 50 });
```

## Documentation

- [docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md) — local setup, env, migrations, pitfalls
- [docs/API.md](./docs/API.md) — HTTP contract for `src/index.ts`
- [docs/SECURITY.md](./docs/SECURITY.md) — verified security snapshot
- [example-apps/](./example-apps/) — browser demos

## API Reference

### Middleware

- `requireAuth` - Require authentication
- `optionalAuth` - Optional authentication
- `requireRole(roles)` - Require specific role(s)
- `requirePermission(permissions)` - Require specific permission(s)
- `requireOwnership(field)` - Require resource ownership
- `applySecurityMiddleware(env)` - Apply security stack based on environment
- `sessionMiddleware` - Session management middleware
- `rateLimiters` - Pre-configured rate limiters
- `csrfProtection()` - CSRF protection middleware
- `xssProtection()` - XSS protection middleware
- `sqlInjectionPrevention()` - SQL injection prevention

### Models

- `UserModel` - User database operations
- `RoleModel` - Role management
- `SessionModel` - Session management
- `AuditLogModel` - Audit logging

### Utilities

- `AuthUtils` - Authentication utilities
- `generateAccessToken(payload)` - Generate JWT access token
- `validateAccessToken(token)` - Validate access token
- `createRefreshToken(payload)` - Create refresh token
- `validateRefreshToken(token)` - Validate refresh token
- `PermissionService` - Permission management service
- `EmailService` - Email sending service
- `FingerprintService` - Device fingerprinting
- `logger` - Winston logger instance

### Security

- `PasswordResetManager` - Password reset functionality
- `addToBlacklist(token, userId, reason)` - Blacklist a token
- `isTokenBlacklisted(token)` - Check if token is blacklisted
- `performLogout(userId, token)` - Complete logout process
- `performSecurityRevocation(userId, reason)` - Revoke all user tokens

## Database Setup

The library uses PostgreSQL via `pg` (no Prisma). SQL files are in `src/database/migrations/`. From this repo:

```bash
npx ts-node src/database/migrate.ts migrate
```

`npm run migrate` does not pass the `migrate` subcommand and will only print usage.

## Configuration Options

### Security Middleware Configuration

```typescript
import { securityConfigs, applySecurityMiddleware } from '@paulweezydesign/add-auth';

// Use environment-based presets
app.use(applySecurityMiddleware('production')); // or 'development', 'testing'

// Custom configuration
const customConfig = {
  csrf: {
    saltLength: 32,
    secretLength: 64,
    tokenExpiry: 3600000 // 1 hour
  },
  xss: {
    stripIgnoreTag: true,
    css: false
  },
  sqlInjection: {
    strict: true,
    logAttempts: true
  }
};
```

## TypeScript Support

This library is written in TypeScript and includes type definitions. All types are exported:

```typescript
import type { 
  User, 
  Role, 
  JWTPayload, 
  TokenValidationResult,
  DeviceFingerprint,
  AuditLog 
} from '@paulweezydesign/add-auth';
```

## Error Handling

```typescript
import { 
  globalErrorHandler, 
  notFoundHandler,
  asyncHandler 
} from '@paulweezydesign/add-auth';

// Wrap async route handlers
app.get('/api/data', asyncHandler(async (req, res) => {
  const data = await fetchData();
  res.json(data);
}));

// Apply global error handler (should be last middleware)
app.use(notFoundHandler);
app.use(globalErrorHandler);
```

## Health Checks

```typescript
import { securityHealthCheck } from '@paulweezydesign/add-auth';

app.get('/health', async (req, res) => {
  const health = await securityHealthCheck();
  res.json({
    status: 'ok',
    security: health
  });
});
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT

## Support

For issues and questions, please open an issue on [GitHub](https://github.com/paulweezydesign/add-auth/issues).

## Changelog

### 1.0.0
- Initial release
- Complete authentication and authorization system
- RBAC support
- OAuth integration
- Comprehensive security middleware
- Session management
- Audit logging
- Role-Based Access Control (RBAC)
- OAuth Integration (Google, GitHub)
- Session Management with Redis
- Password Recovery
- JWT Authentication
- Rate Limiting
- Input Validation
- Security Middleware
- Audit Logging

## 🚀 Quick Start

### Running the Main Application

```bash
# Install dependencies
npm install

# Set up environment
cp .env.example .env
# Edit .env — JWT_SECRET and SESSION_SECRET must be ≥ 32 characters

# Run database migrations (npm run migrate does not pass a subcommand)
npx ts-node src/database/migrate.ts migrate

# Start development server (src/index.ts, port 3000)
npm run dev
```

Mutating `/api/auth/*` and `/api/password-reset/*` calls need a CSRF token (`GET /api/auth/csrf-token` + `X-CSRF-Token`). See [docs/API.md](./docs/API.md).

## 📚 Examples & Learning

**Browser clients for this API** (register/login/dashboard against port 3000): [example-apps/](./example-apps/).

**Standalone tutorial backends** (their own servers and ports):

### [View tutorial examples →](./examples/)

| Example | Description | Port | Complexity |
|---------|-------------|------|------------|
| [**JWT Auth**](./examples/jwt-auth/) | Token-based authentication with access/refresh tokens | 3000 | ⭐ Beginner |
| [**Session Auth**](./examples/session-auth/) | Cookie-based sessions with Redis storage | 3001 | ⭐⭐ Intermediate |
| [**OAuth Social**](./examples/oauth-social/) | Google & GitHub social login integration | 3002 | ⭐⭐ Intermediate |
| [**RBAC**](./examples/rbac/) | Role-based access control with permissions | 3003 | ⭐⭐⭐ Advanced |
| [**Password Recovery**](./examples/password-recovery/) | Forgot/reset password with email tokens | 3004 | ⭐⭐ Intermediate |

Each example includes:
- ✅ Complete, working source code
- ✅ Detailed documentation
- ✅ API endpoint examples (cURL commands)
- ✅ Environment configuration templates
- ✅ Step-by-step setup instructions

**[Quick Start Guide →](./examples/QUICKSTART.md)** | **[Browse Examples →](./examples/)**


# Security Documentation

This document outlines security measures in the authentication system and production guidance.

**Read the snapshot below first.** Sections after [Security Architecture](#security-architecture) mix implemented behavior with generic / target-state advice (for example RS256 key pairs). When they disagree, trust the snapshot and the cited source files.

## Table of Contents

- [Verified implementation snapshot](#verified-implementation-snapshot)
- [Security Architecture](#security-architecture)
- [Authentication Security](#authentication-security)
- [Password Security](#password-security)
- [Session Security](#session-security)
- [Data Protection](#data-protection)
- [Network Security](#network-security)
- [Input Validation](#input-validation)
- [Rate Limiting](#rate-limiting)
- [Audit and Logging](#audit-and-logging)
- [Security Headers](#security-headers)
- [Vulnerability Management](#vulnerability-management)
- [Security Best Practices](#security-best-practices)
- [Compliance](#compliance)

## Verified implementation snapshot

Checked against `src/utils/jwt.ts`, `src/middleware/csrfProtection.ts`, `src/middleware/index.ts`, `src/security/password-security.ts`, `src/security/passwordReset.ts`, and `src/index.ts`.

### JWT

- Algorithm is **HMAC** (`jsonwebtoken.sign` with `JWT_SECRET`), not RS256 / RSA files.
- Default access expiry env is `JWT_EXPIRES_IN=24h`. Response `tokens.expiresIn` is hardcoded to `900` in `createAuthenticationTokens`.
- Refresh token **JWT** uses `JWT_REFRESH_EXPIRES_IN` (default `7d`). Revocation metadata is an in-memory `Map` in `src/utils/refreshToken.ts` (lost on process restart).
- Logout blacklisting: `src/utils/tokenBlacklist.ts` (`performLogout`).

### CSRF

- Applied globally via `applySecurityMiddleware` and again on `/api/auth` (`securityMiddleware.auth`).
- Tokens stored in Redis (`csrf:<sessionId>`). Header `X-CSRF-Token`.
- Development skips validation when `Sec-Fetch-Site: same-origin`. Production config sets `skipOnSameSite: false`.
- Fetch token: `GET /api/auth/csrf-token` with a cookie jar. Details: [API.md](./API.md#csrf).

### Passwords

- bcrypt via `AuthUtils.hashPassword` / `BCRYPT_ROUNDS` (default 12).
- Joi on register: min 8, upper, lower, digit, one of `!@#$%^&*`.
- `PasswordSecurityManager` uses a wider special-character set and runs again in register / change-password.
- Password-reset tokens: 64-byte hex, SHA-256 at rest, Redis TTL 1 hour, 3 attempts / email / hour.

### Transport and headers

- `helmet` CSP + `cors` + `trust proxy` in `src/index.ts`.
- CORS origins from `FRONTEND_URL` (comma-separated). Credentialed browsers must be listed.

### Rate limits

Hardcoded in `src/middleware/rateLimiter.ts` (Redis). Auth router: 10 / 15 min. Register: 5 / hour. Password reset: 3 / hour. See [API.md](./API.md#rate-limits).

### Operational gaps (do not assume they are “secure by docs”)

- Password-reset SQL expects `users.username` and `users.is_active`; migrations use `status` and have no `username`.
- Password-reset audit inserts do not match `004_create_audit_logs_table.sql` (`resource_type` required; `timestamp` vs `created_at`).
- OAuth routes are only mounted from `src/app.ts`, which `npm run dev` does not start.

HTTP details: [API.md](./API.md). Local pitfalls: [DEVELOPMENT.md](./DEVELOPMENT.md#troubleshooting).

## Security Architecture

### Defense in Depth

The authentication system implements multiple layers of security:

1. **Network Layer**: HTTPS/TLS encryption, firewall rules
2. **Application Layer**: Input validation, output encoding, security headers
3. **Authentication Layer**: Multi-factor authentication, JWT tokens
4. **Authorization Layer**: Role-based access control, permission checks
5. **Data Layer**: Encryption at rest, secure database connections
6. **Monitoring Layer**: Audit logging, anomaly detection

### Security Principles

- **Principle of Least Privilege**: Users and processes have minimum necessary permissions
- **Defense in Depth**: Multiple security layers provide redundancy
- **Fail Securely**: System fails to a secure state when errors occur
- **Complete Mediation**: All access attempts are checked
- **Open Design**: Security through design, not obscurity

## Authentication Security

### JWT Token Security

#### Token Structure

The system uses JWT tokens with the following structure:

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-id"
  },
  "payload": {
    "iss": "auth-system",
    "sub": "user-id",
    "aud": "api-audience",
    "exp": 1640995200,
    "iat": 1640908800,
    "jti": "token-id",
    "tokenType": "access",
    "user": {
      "id": "user-id",
      "email": "user@example.com",
      "roles": ["user"]
    }
  },
  "signature": "RS256-signature"
}
```

#### Token Security Features

- **RS256 Algorithm**: Asymmetric encryption with RSA key pairs
- **Short Expiration**: Access tokens expire in 15 minutes
- **Refresh Tokens**: Longer-lived tokens for obtaining new access tokens
- **Token Blacklisting**: Revoked tokens are blacklisted
- **Token Rotation**: Refresh tokens are rotated on each use

#### Key Management

```typescript
// RSA key generation
const keyPair = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// Key rotation every 90 days
const keyRotationSchedule = {
  rotationInterval: 90 * 24 * 60 * 60 * 1000, // 90 days
  gracePeriod: 7 * 24 * 60 * 60 * 1000 // 7 days
};
```

### Multi-Factor Authentication (MFA)

#### TOTP (Time-based One-Time Password)

```typescript
import { authenticator } from 'otplib';

// Generate secret for user
const secret = authenticator.generateSecret();

// Verify TOTP token
const isValid = authenticator.verify({
  token: userToken,
  secret: userSecret
});
```

#### SMS/Email Verification

```typescript
// Generate verification code
const generateVerificationCode = (): string => {
  return crypto.randomInt(100000, 999999).toString();
};

// Verify code with timing attack protection
const verifyCode = async (inputCode: string, storedCode: string): Promise<boolean> => {
  const start = Date.now();
  const isValid = crypto.timingSafeEqual(
    Buffer.from(inputCode),
    Buffer.from(storedCode)
  );
  
  // Ensure minimum comparison time
  const elapsed = Date.now() - start;
  if (elapsed < 100) {
    await new Promise(resolve => setTimeout(resolve, 100 - elapsed));
  }
  
  return isValid;
};
```

## Password Security

### Password Hashing

#### Bcrypt Implementation

```typescript
import bcrypt from 'bcrypt';

export class PasswordService {
  private readonly saltRounds = 12;
  
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }
  
  async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}
```

#### Password Strength Validation

```typescript
export interface PasswordConfig {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  specialChars: string;
  maxLength: number;
  preventCommonPasswords: boolean;
}

export class PasswordValidator {
  private config: PasswordConfig = {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    preventCommonPasswords: true
  };
  
  validate(password: string): PasswordValidationResult {
    const errors: string[] = [];
    
    if (password.length < this.config.minLength) {
      errors.push(`Password must be at least ${this.config.minLength} characters`);
    }
    
    if (password.length > this.config.maxLength) {
      errors.push(`Password must not exceed ${this.config.maxLength} characters`);
    }
    
    if (this.config.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (this.config.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (this.config.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (this.config.requireSpecialChars) {
      const specialCharsRegex = new RegExp(`[${this.config.specialChars.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`);
      if (!specialCharsRegex.test(password)) {
        errors.push('Password must contain at least one special character');
      }
    }
    
    if (this.config.preventCommonPasswords && this.isCommonPassword(password)) {
      errors.push('Password is too common. Please choose a different password');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      strength: this.calculateStrength(password)
    };
  }
  
  private calculateStrength(password: string): PasswordStrength {
    let score = 0;
    
    // Length bonus
    score += Math.min(password.length * 0.5, 10);
    
    // Character variety bonus
    if (/[a-z]/.test(password)) score += 2;
    if (/[A-Z]/.test(password)) score += 2;
    if (/\d/.test(password)) score += 2;
    if (/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) score += 3;
    
    // Patterns penalty
    if (/(.)\1{2,}/.test(password)) score -= 2; // Repeated characters
    if (/012|123|234|345|456|567|678|789/.test(password)) score -= 2; // Sequential numbers
    if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password)) score -= 2; // Sequential letters
    
    if (score < 6) return PasswordStrength.WEAK;
    if (score < 12) return PasswordStrength.MEDIUM;
    if (score < 18) return PasswordStrength.STRONG;
    return PasswordStrength.VERY_STRONG;
  }
  
  private isCommonPassword(password: string): boolean {
    const commonPasswords = [
      'password', '123456', 'password123', 'admin', 'qwerty',
      'letmein', 'welcome', 'monkey', '1234567890', 'abc123'
    ];
    return commonPasswords.some(common => 
      password.toLowerCase().includes(common.toLowerCase())
    );
  }
}
```

### Password History

```typescript
export class PasswordHistoryService {
  private readonly historyCount = 5;
  
  async checkPasswordHistory(userId: string, newPassword: string): Promise<boolean> {
    const history = await this.getPasswordHistory(userId);
    
    for (const historicalHash of history) {
      const isReused = await bcrypt.compare(newPassword, historicalHash);
      if (isReused) {
        return false; // Password was previously used
      }
    }
    
    return true; // Password is not in history
  }
  
  async addToHistory(userId: string, passwordHash: string): Promise<void> {
    await this.db.passwordHistory.create({
      userId,
      passwordHash,
      createdAt: new Date()
    });
    
    // Keep only the last N passwords
    await this.cleanupHistory(userId);
  }
  
  private async cleanupHistory(userId: string): Promise<void> {
    const history = await this.db.passwordHistory.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' }
    });
    
    if (history.length > this.historyCount) {
      const toDelete = history.slice(this.historyCount);
      await this.db.passwordHistory.deleteMany({
        where: {
          id: { in: toDelete.map(h => h.id) }
        }
      });
    }
  }
}
```

## Session Security

### Session Configuration

```typescript
export interface SessionConfig {
  secret: string;
  resave: boolean;
  saveUninitialized: boolean;
  cookie: {
    secure: boolean;
    httpOnly: boolean;
    maxAge: number;
    sameSite: 'strict' | 'lax' | 'none';
    domain?: string;
  };
  store: SessionStore;
}

const sessionConfig: SessionConfig = {
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict',
    domain: process.env.COOKIE_DOMAIN
  },
  store: new RedisStore({
    client: redisClient,
    prefix: 'sess:',
    ttl: 24 * 60 * 60 // 24 hours
  })
};
```

### Session Fingerprinting

```typescript
export class SessionFingerprintService {
  generateFingerprint(req: Request): string {
    const components = [
      req.ip,
      req.headers['user-agent'] || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || ''
    ];
    
    const fingerprint = crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex');
    
    return fingerprint;
  }
  
  validateFingerprint(req: Request, storedFingerprint: string): boolean {
    const currentFingerprint = this.generateFingerprint(req);
    return crypto.timingSafeEqual(
      Buffer.from(currentFingerprint),
      Buffer.from(storedFingerprint)
    );
  }
}
```

### Session Anomaly Detection

```typescript
export class SessionAnomalyDetector {
  async detectAnomalies(session: SessionData): Promise<AnomalyReport> {
    const anomalies: Anomaly[] = [];
    
    // Check for unusual location
    if (await this.isUnusualLocation(session.userId, session.ipAddress)) {
      anomalies.push({
        type: 'unusual_location',
        severity: 'medium',
        details: `Login from unusual location: ${session.location}`
      });
    }
    
    // Check for unusual time
    if (this.isUnusualTime(session.userId, session.createdAt)) {
      anomalies.push({
        type: 'unusual_time',
        severity: 'low',
        details: `Login at unusual time: ${session.createdAt}`
      });
    }
    
    // Check for concurrent sessions
    const activeSessions = await this.getActiveSessions(session.userId);
    if (activeSessions.length > 5) {
      anomalies.push({
        type: 'excessive_sessions',
        severity: 'high',
        details: `User has ${activeSessions.length} active sessions`
      });
    }
    
    return {
      sessionId: session.id,
      userId: session.userId,
      anomalies,
      riskScore: this.calculateRiskScore(anomalies)
    };
  }
  
  private calculateRiskScore(anomalies: Anomaly[]): number {
    const weights = {
      low: 1,
      medium: 3,
      high: 5
    };
    
    return anomalies.reduce((score, anomaly) => {
      return score + weights[anomaly.severity];
    }, 0);
  }
}
```

## Data Protection

### Encryption at Rest

```typescript
export class DataEncryption {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32;
  
  encrypt(data: string, key: Buffer): EncryptedData {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(this.algorithm, key);
    cipher.setAAD(Buffer.from('additional-data'));
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }
  
  decrypt(encryptedData: EncryptedData, key: Buffer): string {
    const decipher = crypto.createDecipher(this.algorithm, key);
    decipher.setAAD(Buffer.from('additional-data'));
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}
```

### Database Security

```typescript
// Database connection with SSL
const dbConfig = {
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync(process.env.DB_SSL_CA_PATH),
    cert: fs.readFileSync(process.env.DB_SSL_CERT_PATH),
    key: fs.readFileSync(process.env.DB_SSL_KEY_PATH)
  },
  pool: {
    min: 2,
    max: 10,
    acquireTimeoutMillis: 30000,
    createTimeoutMillis: 30000,
    destroyTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    reapIntervalMillis: 1000,
    createRetryIntervalMillis: 200
  }
};

// Parameterized queries to prevent SQL injection
const getUserByEmail = async (email: string): Promise<User | null> => {
  const result = await db.query(
    'SELECT id, email, password_hash, created_at FROM users WHERE email = $1',
    [email]
  );
  return result.rows[0] || null;
};
```

## Network Security

### HTTPS Configuration

```typescript
import https from 'https';
import fs from 'fs';

const httpsOptions = {
  key: fs.readFileSync(process.env.SSL_KEY_PATH),
  cert: fs.readFileSync(process.env.SSL_CERT_PATH),
  ca: fs.readFileSync(process.env.SSL_CA_PATH),
  
  // Security options
  secureProtocol: 'TLSv1_2_method',
  ciphers: [
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-SHA256',
    'ECDHE-RSA-AES256-SHA384'
  ].join(':'),
  honorCipherOrder: true,
  
  // HSTS
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
};

const server = https.createServer(httpsOptions, app);
```

### CORS Configuration

```typescript
import cors from 'cors';

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-CSRF-Token'
  ],
  exposedHeaders: [
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset'
  ],
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));
```

## Input Validation

### Validation Schemas

```typescript
import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string()
    .email('Invalid email format')
    .max(255, 'Email too long')
    .transform(email => email.toLowerCase()),
  
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password too long')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
           'Password must contain uppercase, lowercase, number, and special character'),
  
  firstName: z.string()
    .min(1, 'First name is required')
    .max(50, 'First name too long')
    .regex(/^[a-zA-Z\s-']+$/, 'First name contains invalid characters'),
  
  lastName: z.string()
    .min(1, 'Last name is required')
    .max(50, 'Last name too long')
    .regex(/^[a-zA-Z\s-']+$/, 'Last name contains invalid characters'),
  
  acceptTerms: z.boolean()
    .refine(val => val === true, 'You must accept the terms and conditions')
});

export const loginSchema = z.object({
  email: z.string()
    .email('Invalid email format')
    .transform(email => email.toLowerCase()),
  
  password: z.string()
    .min(1, 'Password is required'),
  
  rememberMe: z.boolean().optional()
});
```

### Input Sanitization

```typescript
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const window = new JSDOM('').window;
const purify = DOMPurify(window);

export class InputSanitizer {
  static sanitizeHtml(input: string): string {
    return purify.sanitize(input, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: []
    });
  }
  
  static sanitizeString(input: string): string {
    return input
      .replace(/[<>]/g, '') // Remove potential HTML tags
      .replace(/['"]/g, '') // Remove quotes
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim();
  }
  
  static sanitizeEmail(email: string): string {
    return email
      .toLowerCase()
      .replace(/[^\w@.-]/g, '') // Keep only valid email characters
      .trim();
  }
}
```

## Rate Limiting

### Redis-based Rate Limiting

```typescript
import Redis from 'ioredis';

export class RateLimiter {
  private redis: Redis;
  
  constructor(redis: Redis) {
    this.redis = redis;
  }
  
  async checkLimit(key: string, limit: number, window: number): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - window;
    
    const pipeline = this.redis.pipeline();
    
    // Remove old entries
    pipeline.zremrangebyscore(key, 0, windowStart);
    
    // Count current requests
    pipeline.zcard(key);
    
    // Add current request
    pipeline.zadd(key, now, `${now}-${Math.random()}`);
    
    // Set expiration
    pipeline.expire(key, Math.ceil(window / 1000));
    
    const results = await pipeline.exec();
    const count = results[1][1] as number;
    
    return {
      allowed: count < limit,
      count,
      limit,
      remaining: Math.max(0, limit - count - 1),
      resetTime: now + window
    };
  }
}

// Usage
const rateLimiter = new RateLimiter(redisClient);

const rateLimitMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  const key = `rate_limit:${req.ip}:${req.route.path}`;
  const result = await rateLimiter.checkLimit(key, 100, 15 * 60 * 1000); // 100 requests per 15 minutes
  
  res.set({
    'X-RateLimit-Limit': result.limit.toString(),
    'X-RateLimit-Remaining': result.remaining.toString(),
    'X-RateLimit-Reset': new Date(result.resetTime).toISOString()
  });
  
  if (!result.allowed) {
    return res.status(429).json({
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests. Please try again later.',
        details: [
          {
            field: 'retryAfter',
            message: `Retry after ${Math.ceil((result.resetTime - Date.now()) / 1000)} seconds`
          }
        ]
      }
    });
  }
  
  next();
};
```

## Audit and Logging

### Audit Logging

```typescript
export interface AuditLog {
  id: string;
  userId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
  success: boolean;
  details?: Record<string, any>;
  oldValues?: Record<string, any>;
  newValues?: Record<string, any>;
}

export class AuditLogger {
  private logger: Logger;
  
  constructor(logger: Logger) {
    this.logger = logger;
  }
  
  async logAction(action: AuditLog): Promise<void> {
    // Log to database
    await this.db.auditLog.create({
      data: {
        ...action,
        id: crypto.randomUUID(),
        timestamp: new Date()
      }
    });
    
    // Log to file/external service
    this.logger.info('Audit log', {
      action: action.action,
      userId: action.userId,
      resourceType: action.resourceType,
      resourceId: action.resourceId,
      ipAddress: action.ipAddress,
      success: action.success,
      timestamp: action.timestamp
    });
  }
  
  async logAuthenticationAttempt(
    email: string,
    success: boolean,
    ipAddress: string,
    userAgent: string,
    userId?: string
  ): Promise<void> {
    await this.logAction({
      userId,
      action: 'AUTHENTICATION_ATTEMPT',
      resourceType: 'USER',
      resourceId: userId,
      ipAddress,
      userAgent,
      success,
      details: {
        email,
        attemptTime: new Date().toISOString()
      }
    });
  }
}
```

### Security Monitoring

```typescript
export class SecurityMonitor {
  private auditLogger: AuditLogger;
  private alertService: AlertService;
  
  constructor(auditLogger: AuditLogger, alertService: AlertService) {
    this.auditLogger = auditLogger;
    this.alertService = alertService;
  }
  
  async monitorFailedLogins(email: string, ipAddress: string): Promise<void> {
    const timeWindow = 15 * 60 * 1000; // 15 minutes
    const threshold = 5;
    
    const failedAttempts = await this.getFailedLoginAttempts(email, ipAddress, timeWindow);
    
    if (failedAttempts >= threshold) {
      await this.alertService.sendAlert({
        type: 'SECURITY_ALERT',
        severity: 'HIGH',
        title: 'Multiple Failed Login Attempts',
        message: `${failedAttempts} failed login attempts for ${email} from ${ipAddress}`,
        metadata: {
          email,
          ipAddress,
          attempts: failedAttempts,
          timeWindow
        }
      });
      
      // Block IP temporarily
      await this.blockIP(ipAddress, 60 * 60 * 1000); // 1 hour
    }
  }
  
  async detectBruteForce(ipAddress: string): Promise<void> {
    const timeWindow = 5 * 60 * 1000; // 5 minutes
    const threshold = 50;
    
    const requestCount = await this.getRequestCount(ipAddress, timeWindow);
    
    if (requestCount >= threshold) {
      await this.alertService.sendAlert({
        type: 'SECURITY_ALERT',
        severity: 'CRITICAL',
        title: 'Potential Brute Force Attack',
        message: `${requestCount} requests from ${ipAddress} in ${timeWindow / 1000} seconds`,
        metadata: {
          ipAddress,
          requestCount,
          timeWindow
        }
      });
      
      // Block IP for extended period
      await this.blockIP(ipAddress, 24 * 60 * 60 * 1000); // 24 hours
    }
  }
}
```

## Security Headers

### Comprehensive Security Headers

```typescript
import helmet from 'helmet';

app.use(helmet({
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  
  // HTTP Strict Transport Security
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  
  // X-Frame-Options
  frameguard: {
    action: 'deny'
  },
  
  // X-Content-Type-Options
  noSniff: true,
  
  // X-XSS-Protection
  xssFilter: true,
  
  // Referrer Policy
  referrerPolicy: {
    policy: 'same-origin'
  },
  
  // Permissions Policy
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
    notifications: []
  }
}));

// Additional custom headers
app.use((req, res, next) => {
  res.set({
    'X-API-Version': '1.0',
    'X-Response-Time': Date.now().toString(),
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'Surrogate-Control': 'no-store'
  });
  next();
});
```

## Vulnerability Management

### Dependency Security

```json
{
  "scripts": {
    "audit": "npm audit",
    "audit:fix": "npm audit fix",
    "security:check": "npm audit && snyk test",
    "security:monitor": "snyk monitor"
  },
  "devDependencies": {
    "snyk": "^1.0.0",
    "helmet": "^6.0.0",
    "express-rate-limit": "^6.0.0"
  }
}
```

### Security Testing

```typescript
// Security test examples
describe('Security Tests', () => {
  describe('SQL Injection', () => {
    it('should prevent SQL injection in login', async () => {
      const maliciousEmail = "admin'; DROP TABLE users; --";
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: maliciousEmail,
          password: 'password'
        });
      
      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });
  
  describe('XSS Prevention', () => {
    it('should sanitize HTML in user input', async () => {
      const maliciousName = '<script>alert("XSS")</script>';
      const response = await request(app)
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'Password123!',
          firstName: maliciousName,
          lastName: 'User'
        });
      
      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });
  
  describe('Rate Limiting', () => {
    it('should enforce rate limits', async () => {
      const promises = Array(101).fill(null).map(() =>
        request(app)
          .post('/auth/login')
          .send({
            email: 'test@example.com',
            password: 'password'
          })
      );
      
      const responses = await Promise.all(promises);
      const tooManyRequests = responses.filter(r => r.status === 429);
      
      expect(tooManyRequests.length).toBeGreaterThan(0);
    });
  });
});
```

## Security Best Practices

### Development Security

1. **Code Reviews**: All code must be reviewed for security vulnerabilities
2. **Static Analysis**: Use tools like SonarQube, ESLint security rules
3. **Dependency Management**: Regular updates and vulnerability scanning
4. **Secrets Management**: Use environment variables, never commit secrets
5. **Secure Coding Standards**: Follow OWASP secure coding practices

### Deployment Security

1. **Environment Separation**: Separate development, staging, and production
2. **Access Control**: Limit access to production systems
3. **Configuration Management**: Secure configuration deployment
4. **Monitoring**: Comprehensive security monitoring and alerting
5. **Incident Response**: Defined incident response procedures

### Operational Security

1. **Regular Updates**: Keep all dependencies and systems updated
2. **Security Scans**: Regular vulnerability assessments
3. **Backup Security**: Encrypted backups with access controls
4. **Disaster Recovery**: Tested disaster recovery procedures
5. **Documentation**: Maintain up-to-date security documentation

## Compliance

### Data Protection Regulations

#### GDPR Compliance

```typescript
export class GDPRCompliance {
  async requestDataExport(userId: string): Promise<UserData> {
    const userData = await this.db.user.findUnique({
      where: { id: userId },
      include: {
        sessions: true,
        auditLogs: true,
        passwordHistory: true
      }
    });
    
    return {
      personalData: userData,
      exportDate: new Date(),
      requestedBy: userId
    };
  }
  
  async requestDataDeletion(userId: string): Promise<void> {
    // Anonymize audit logs instead of deleting
    await this.db.auditLog.updateMany({
      where: { userId },
      data: {
        userId: null,
        details: { anonymized: true }
      }
    });
    
    // Delete user data
    await this.db.user.delete({
      where: { id: userId }
    });
  }
}
```

#### SOC 2 Compliance

- **Security**: Access controls, authentication, authorization
- **Availability**: System uptime, disaster recovery
- **Processing Integrity**: Data processing accuracy
- **Confidentiality**: Data encryption, access controls
- **Privacy**: Data collection, usage, retention policies

### Security Frameworks

#### OWASP Top 10 Mitigation

1. **A01:2021 – Broken Access Control**: Role-based access control, proper authorization
2. **A02:2021 – Cryptographic Failures**: Strong encryption, secure key management
3. **A03:2021 – Injection**: Input validation, parameterized queries
4. **A04:2021 – Insecure Design**: Secure architecture, threat modeling
5. **A05:2021 – Security Misconfiguration**: Secure defaults, configuration management
6. **A06:2021 – Vulnerable Components**: Dependency management, security updates
7. **A07:2021 – Identification and Authentication Failures**: Strong authentication, session management
8. **A08:2021 – Software and Data Integrity Failures**: Code signing, secure CI/CD
9. **A09:2021 – Security Logging and Monitoring Failures**: Comprehensive logging, monitoring
10. **A10:2021 – Server-Side Request Forgery**: Input validation, allowlisting

## Incident Response

### Security Incident Response Plan

```typescript
export class IncidentResponse {
  async handleSecurityIncident(incident: SecurityIncident): Promise<void> {
    // 1. Immediate containment
    if (incident.severity === 'CRITICAL') {
      await this.containBreach(incident);
    }
    
    // 2. Assessment and investigation
    const assessment = await this.assessIncident(incident);
    
    // 3. Notification
    await this.notifyStakeholders(incident, assessment);
    
    // 4. Remediation
    await this.remediateIncident(incident);
    
    // 5. Recovery
    await this.recoverFromIncident(incident);
    
    // 6. Post-incident review
    await this.conductPostIncidentReview(incident);
  }
  
  private async containBreach(incident: SecurityIncident): Promise<void> {
    // Block malicious IPs
    if (incident.ipAddress) {
      await this.blockIP(incident.ipAddress);
    }
    
    // Disable compromised accounts
    if (incident.userId) {
      await this.disableUser(incident.userId);
    }
    
    // Revoke tokens
    if (incident.tokenId) {
      await this.revokeToken(incident.tokenId);
    }
  }
}
```

---

This security documentation provides comprehensive coverage of the security measures implemented in the authentication system. Regular updates and reviews ensure the security posture remains strong against evolving threats.
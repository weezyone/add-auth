export interface UserPayload {
  id: string;
  email: string;
  roles?: string[];
}

export type TokenType = 'access' | 'refresh';

export interface JWTPayload extends UserPayload {
  sessionId?: string;
  /** Distinguishes access from refresh tokens; both are signed with the same secret. */
  type?: TokenType;
  iat?: number;
  exp?: number;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface RefreshTokenData {
  userId: string;
  tokenId: string;
  expiresAt: Date;
  createdAt: Date;
  revokedAt?: Date;
  ipAddress?: string;
  userAgent?: string;
}

export interface BlacklistedToken {
  tokenId: string;
  userId: string;
  expiresAt: Date;
  blacklistedAt: Date;
  reason: 'logout' | 'revoked' | 'security';
}

export interface TokenValidationResult {
  valid: boolean;
  error?: string;
  expired?: boolean;
  payload?: JWTPayload;
}

export class JWTError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500
  ) {
    super(message);
    this.name = 'JWTError';
  }
}

export class TokenExpiredError extends JWTError {
  constructor(message: string = 'Token has expired') {
    super(message, 'TOKEN_EXPIRED', 401);
    this.name = 'TokenExpiredError';
  }
}

export class TokenInvalidError extends JWTError {
  constructor(message: string = 'Invalid token') {
    super(message, 'TOKEN_INVALID', 401);
    this.name = 'TokenInvalidError';
  }
}

export class TokenBlacklistedError extends JWTError {
  constructor(message: string = 'Token has been blacklisted') {
    super(message, 'TOKEN_BLACKLISTED', 401);
    this.name = 'TokenBlacklistedError';
  }
}
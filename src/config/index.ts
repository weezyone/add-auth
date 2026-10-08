import { config } from 'dotenv';
import { z } from 'zod';

// Load environment variables
config();

// Environment validation schema
const envSchema = z.object({
  // Database
  DATABASE_URL: z.string().optional(),
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.coerce.number().default(5432),
  DB_NAME: z.string().default('add_auth'),
  DB_USER: z.string().default('postgres'),
  DB_PASSWORD: z.string().default('password'),
  DB_SSL: z.coerce.boolean().default(false),

  // Server
  PORT: z.coerce.number().default(3000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  // Express 'trust proxy' setting. Leave unset when the app is reached directly;
  // set to the number of reverse-proxy hops (e.g. 1) or a subnet list when it
  // sits behind a load balancer. 'true' trusts any client-supplied
  // X-Forwarded-For and lets callers pick their own rate-limit key.
  TRUST_PROXY: z.string().optional(),

  // Security
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default('24h'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),

  // Password
  BCRYPT_ROUNDS: z.coerce.number().default(12),

  // Session
  SESSION_SECRET: z.string().min(32),
  SESSION_TIMEOUT: z.coerce.number().default(86400000), // 24 hours in ms

  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(100),

  // Redis
  REDIS_URL: z.string().optional(),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.coerce.number().default(0),
  REDIS_KEY_PREFIX: z.string().default('auth:'),

  // OAuth
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  OAUTH_CALLBACK_URL: z.string().default('http://localhost:3000/auth/callback'),
});

// Validate environment variables
const env = envSchema.parse(process.env);

function parseTrustProxy(value: string | undefined): boolean | number | string {
  if (value === undefined || value.trim() === '' || value === 'false') return false;
  if (value === 'true') return true;
  if (/^\d+$/.test(value.trim())) return parseInt(value, 10);
  return value; // e.g. 'loopback' or '10.0.0.0/8, 127.0.0.1'
}

export const appConfig = {
  database: {
    url: env.DATABASE_URL,
    host: env.DB_HOST,
    port: env.DB_PORT,
    name: env.DB_NAME,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    ssl: env.DB_SSL,
  },
  server: {
    port: env.PORT,
    nodeEnv: env.NODE_ENV,
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
  },
  security: {
    jwtSecret: env.JWT_SECRET,
    jwtExpiresIn: env.JWT_EXPIRES_IN,
    jwtRefreshExpiresIn: env.JWT_REFRESH_EXPIRES_IN,
    bcryptRounds: env.BCRYPT_ROUNDS,
    sessionSecret: env.SESSION_SECRET,
    sessionTimeout: env.SESSION_TIMEOUT,
  },
  logging: {
    level: env.LOG_LEVEL,
  },
  rateLimiting: {
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
  },
  redis: {
    url: env.REDIS_URL,
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
    password: env.REDIS_PASSWORD,
    db: env.REDIS_DB,
    keyPrefix: env.REDIS_KEY_PREFIX,
  },
  oauth: {
    google: {
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
    },
    github: {
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
    },
    callbackUrl: env.OAUTH_CALLBACK_URL,
  },
};

export default appConfig;
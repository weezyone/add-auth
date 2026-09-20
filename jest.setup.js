// Set required env vars before any test module is imported.
// These are test-only values; they satisfy Zod's .min(32) constraints.
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-for-jest-at-least-32-chars!!';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret-for-jest-32-chars!!';
process.env.NODE_ENV = process.env.NODE_ENV || 'test';

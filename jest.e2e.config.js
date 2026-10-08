// End-to-end / integration suite (PAU-18).
// Runs the real Express app (src/index.ts) against a real PostgreSQL database
// and a real Redis server. External services (SMTP, OAuth providers) are mocked.
//
// Requirements (see tests/e2e/README.md):
//   - PostgreSQL reachable with the DB_* env vars below (default db: add_auth_test)
//   - Redis reachable on REDIS_HOST:REDIS_PORT (default localhost:6390, a
//     dedicated instance because the suite FLUSHes it between tests)
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/tests/e2e'],
  testMatch: ['**/*.e2e.test.ts'],
  setupFiles: ['<rootDir>/tests/e2e/env.js'],
  clearMocks: true,
  forceExit: true,
  testTimeout: 30000,
  transform: {
    '^.+\\.ts$': ['ts-jest', { isolatedModules: true }],
  },
};

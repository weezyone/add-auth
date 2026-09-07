module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
  setupFiles: ['<rootDir>/jest.setup.js'],
  clearMocks: true,
  // Several modules schedule cleanup via module-level setInterval (e.g. session.ts,
  // passwordReset.ts), which keeps the Jest worker alive after tests finish. Force
  // exit so `npm test` terminates deterministically instead of hanging.
  forceExit: true,
  // Transpile-only, matching the dev server (ts-node-dev --transpile-only).
  // The codebase has known pre-existing type errors (see AGENTS.md); type-checking
  // during tests would fail to compile otherwise-correct modules under test.
  transform: {
    '^.+\\.ts$': ['ts-jest', { isolatedModules: true }],
  },
};

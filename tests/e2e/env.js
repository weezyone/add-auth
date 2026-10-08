// Env for the e2e suite. Set before any module (and therefore config/index.ts) loads.
// Anything already set in the environment wins, so CI can point at its own services.
const defaults = {
  NODE_ENV: 'test',
  PORT: '3999',
  JWT_SECRET: 'e2e-jwt-secret-that-is-at-least-32-characters',
  SESSION_SECRET: 'e2e-session-secret-that-is-at-least-32-chars',
  DB_HOST: 'localhost',
  DB_PORT: '5432',
  DB_NAME: 'add_auth_test',
  DB_USER: 'postgres',
  DB_PASSWORD: 'password',
  REDIS_HOST: 'localhost',
  REDIS_PORT: '6390',
  BCRYPT_ROUNDS: '4',
  LOG_LEVEL: 'error',
  FRONTEND_URL: 'http://localhost:5173',
  GOOGLE_CLIENT_ID: 'e2e-google-client-id',
  GOOGLE_CLIENT_SECRET: 'e2e-google-client-secret',
  GITHUB_CLIENT_ID: 'e2e-github-client-id',
  GITHUB_CLIENT_SECRET: 'e2e-github-client-secret',
};
for (const [key, value] of Object.entries(defaults)) {
  if (process.env[key] === undefined) process.env[key] = value;
}
// DB_SSL must be unset: z.coerce.boolean() treats the string "false" as true.
delete process.env.DB_SSL;

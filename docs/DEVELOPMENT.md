# Development Setup Guide

How to run the **main API** (`src/index.ts` via `npm run dev`) locally. This is the server the frontend demos in `example-apps/` talk to.

For library consumers, see the root [README.md](../README.md). For HTTP details, see [API.md](./API.md).

## Table of Contents

- [What you are running](#what-you-are-running)
- [Prerequisites](#prerequisites)
- [Initial setup](#initial-setup)
- [Environment configuration](#environment-configuration)
- [Database migrations](#database-migrations)
- [Run the API](#run-the-api)
- [Frontend example apps](#frontend-example-apps)
- [Tests, lint, and build](#tests-lint-and-build)
- [Troubleshooting](#troubleshooting)

## What you are running

Two Express apps exist in this repo. Only one is started by `npm run dev`.

| Entry | Script | What it exposes |
|-------|--------|-----------------|
| `src/index.ts` | `npm run dev` / `npm start` | Helmet, CORS, security middleware, `GET /health`, `GET /`, `/api/auth/*`, `/api/password-reset/*` |
| `src/app.ts` | **not** wired to npm scripts | OAuth (`/auth/google`, `/auth/github`), session-cookie RBAC demo routes |

`src/routes/index.ts` and `src/routes/roles.ts` define a role-management API, but **those routers are not mounted** on `src/index.ts`. Do not expect `/api/roles` on the default server.

There is no Prisma layer. Persistence is `pg` (`src/database/connection.ts`) plus SQL files in `src/database/migrations/`.

## Prerequisites

- **Node.js** 18+
- **PostgreSQL** 14+ (16 in Cursor Cloud)
- **Redis** 6+ (7 in Cursor Cloud) — the process starts if Redis is down, but CSRF tokens, rate limits, sessions, and password-reset tokens degrade or fail
- **npm** 9+

Start local services (Debian/Ubuntu package install):

```bash
sudo pg_ctlcluster 16 main start   # or: sudo systemctl start postgresql
sudo redis-server --daemonize yes  # or: sudo systemctl start redis-server
```

Confirm Redis:

```bash
redis-cli ping   # PONG
```

## Initial setup

```bash
git clone <repository-url>
cd add-auth
npm install
cp .env.example .env
# Edit .env — JWT_SECRET and SESSION_SECRET must be at least 32 characters
```

Create the database (defaults from `src/config/index.ts` / `.env.example`):

```bash
sudo -u postgres psql -c "CREATE DATABASE add_auth;"
```

Or point `DATABASE_URL` / `DB_*` at an existing database.

## Environment configuration

Validated in `src/config/index.ts` (Zod). Required secrets:

| Variable | Constraint | Default |
|----------|------------|---------|
| `JWT_SECRET` | min 32 chars | **required** |
| `SESSION_SECRET` | min 32 chars | **required** |

Common optional / defaulted values:

| Variable | Default | Notes |
|----------|---------|--------|
| `PORT` | `3000` | API listen port |
| `NODE_ENV` | `development` | `development` \| `production` \| `test` |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `localhost` / `5432` / `add_auth` / `postgres` / `password` | Used when `DATABASE_URL` is unset |
| `DATABASE_URL` | unset | If set, used as the `pg` connection string |
| `DB_SSL` | `false` | **Do not set `DB_SSL=false`**. Zod `z.coerce.boolean()` treats the string `"false"` as `true`. Leave unset or empty. |
| `JWT_EXPIRES_IN` | `24h` | Passed to `jsonwebtoken.sign` |
| `JWT_REFRESH_EXPIRES_IN` | `7d` | Passed to `jsonwebtoken.sign` |
| `BCRYPT_ROUNDS` | `12` | |
| `SESSION_TIMEOUT` | `86400000` | milliseconds |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_URL` | `localhost` / `6379` / unset | Rate limit + CSRF + password-reset tokens use ioredis |
| `FRONTEND_URL` | `http://localhost:3000` | **Not in the Zod schema.** Read in `src/index.ts` as a comma-separated CORS allowlist. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GITHUB_*` | unset | Used by `src/config/passport.ts` (OAuth app in `src/app.ts`) |
| `OAUTH_CALLBACK_URL` | `http://localhost:3000/auth/callback` | Passport callback base |
| `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX_REQUESTS` | `900000` / `100` | Config object; many limiters in `rateLimiter.ts` still use hardcoded windows |
| `LOG_LEVEL` | `info` | `error` \| `warn` \| `info` \| `debug` |

Email (password reset) is **not** in the Zod schema. `src/utils/emailService.ts` reads:

- `EMAIL_HOST` (default `smtp.gmail.com`)
- `EMAIL_PORT` (default `587`)
- `EMAIL_SECURE` (`true` to enable TLS)
- `EMAIL_USER` / `EMAIL_PASS` — if either is empty, the mailer stays unconfigured
- `EMAIL_FROM` / `EMAIL_REPLY_TO`

Generate secrets:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Database migrations

SQL migrations live in `src/database/migrations/` (`000`–`005`: schema_migrations, users, sessions, roles, audit_logs, OAuth columns).

`package.json` `"migrate"` is `ts-node src/database/migrate.ts` with **no subcommand**. The CLI requires one:

```bash
# Apply pending migrations (this is the command that actually migrates)
npx ts-node src/database/migrate.ts migrate

# Status / rollback
npx ts-node src/database/migrate.ts status
npx ts-node src/database/migrate.ts rollback
# or: npm run migrate:rollback   → src/database/rollback.ts
```

`npm run migrate` by itself prints usage and exits `1`.

## Run the API

```bash
npm run dev
```

`ts-node-dev --respawn --transpile-only src/index.ts` — type errors do not block the process.

Expect:

- `GET http://localhost:3000/` → `{ message, version, timestamp }`
- `GET http://localhost:3000/health` → database + Redis + `securityHealthCheck()`

The server still listens if Redis init fails (`startServer` in `src/index.ts`). CSRF generation, rate-limit stores, and password-reset tokens then fail at request time.

## Frontend example apps

Browser clients for **this** API (not the standalone apps under `examples/`):

| App | Directory | Dev URL |
|-----|-----------|---------|
| React + Vite | `example-apps/react-auth-demo` | `http://localhost:5173` |
| Next.js | `example-apps/nextjs-auth-demo` | `http://localhost:3001` |
| Vanilla HTML/JS | `example-apps/vanilla-auth-demo` | static (e.g. port 5500) |

Details: [example-apps/README.md](../example-apps/README.md).

Set CORS before starting the API:

```env
FRONTEND_URL=http://localhost:3000,http://localhost:5173,http://localhost:3001,http://localhost:5500
```

Every mutating `/api/auth` and `/api/password-reset` call needs a CSRF token. Same-origin browser requests can skip validation in **development** (`skipOnSameSite` when `Sec-Fetch-Site: same-origin`). Cross-origin demo apps must send `X-CSRF-Token`. See [API.md](./API.md#csrf).

## Tests, lint, and build

Scripts that actually exist (`package.json`):

```bash
npm test                 # Jest; ts-jest isolatedModules; forceExit
npm run lint             # eslint src/**/*.ts
npm run lint:fix
npm run build            # tsc
npm run build:clean      # rm -rf dist && tsc
npm start                # node dist/index.js (needs a successful build)
```

There is no `type-check`, `test:watch`, `test:coverage`, `db:test`, `seed`, `env:validate`, or `generate:keys` script.

### Known constraints (do not treat as environment bugs)

- **`npm run build`**: the tree has pre-existing TypeScript errors. Dev works because `--transpile-only`. Tests use `isolatedModules` for the same reason.
- **ESLint**: `.eslintrc.json` must extend `plugin:@typescript-eslint/recommended` (not `@typescript-eslint/recommended`).
- **Jest**: suites live under `src/**/__tests__/`. Some suites still fail for pre-existing test/code mismatches. The password-reset unit suite was aligned with `PasswordResetManager.usePasswordResetToken` (Redis `setex` on `password-reset:<hashedToken>`).
- Jest `forceExit` is required because several modules start `setInterval` cleanups (sessions, password reset, CSRF).

## Troubleshooting

### `DB_SSL` / unexpected SSL on Postgres

`z.coerce.boolean()` is true for any non-empty string, including `"false"`. Leave `DB_SSL` unset.

### Migrations appear to do nothing

Use `npx ts-node src/database/migrate.ts migrate`, not `npm run migrate`.

### `403 CSRF token missing` on register/login

1. `GET /api/auth/csrf-token` with a cookie jar (`credentials: 'include'`).
2. Replay the same cookies on the POST.
3. Send `X-CSRF-Token` (or body/query `_csrf`).
4. Redis must be up — tokens are stored as `csrf:<sessionId>` (Express session id if present, otherwise `ip` + truncated user-agent).
5. In development, same-origin (`Sec-Fetch-Site: same-origin`) skips CSRF validation. Different ports are not same-origin.

### CORS / credentialed browser calls fail

`FRONTEND_URL` is a comma-separated allowlist. Include the exact demo origin. Allowed request header: `X-CSRF-Token`.

### Redis disconnected in `/health`

The API still starts. Rate limiting, CSRF, session service, and password-reset tokens use Redis. Start Redis and restart the process.

### Password reset request returns 500 after a valid user

`src/controllers/passwordResetController.ts` selects `username` and filters `is_active` on `users`. Current migrations (`001`, `005`) create `email` / `status` and do **not** add `username` or `is_active`. The mailer also no-ops without `EMAIL_USER` + `EMAIL_PASS`.

### Account lock after failed logins

`login` increments `failed_login_attempts` and can return **423** with `Account locked` when `locked_until` is in the future (`AuthUtils.isAccountLocked`). Inactive `status` returns **401** `Account disabled`.

### `npx tsc --noEmit` / `npm run build` fails

Expected today. Use `npm run dev` for local work.

### Port already in use

`PORT` defaults to 3000. Change it in `.env`. Next.js demo uses 3001; Vite demo uses 5173.

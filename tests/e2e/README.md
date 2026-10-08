# End-to-end auth tests

These tests boot the real Express apps (`src/index.ts` — JWT/Redis-session API,
`src/app.ts` — express-session + Passport OAuth + RBAC) in-process with
supertest, against a real PostgreSQL database and a real Redis. OAuth providers
(Google, GitHub) are mocked with `nock`; no real credentials are needed.
Outgoing email goes to an in-memory mailbox (`mailbox` in `helpers.ts`), so
tests read verification links straight from the "sent" emails.

## Requirements

- PostgreSQL with a database named `add_auth_test`
  (user `postgres`, password `password`, localhost:5432 by default)
- Redis on `localhost:6390` (a dedicated port so the suite never flushes a
  dev Redis — **the suite runs `FLUSHDB` between tests**)

```bash
createdb -U postgres add_auth_test
redis-server --port 6390 --save "" --appendonly no --daemonize yes
```

Override any of these via env vars (see `tests/e2e/env.js`).

## Run

```bash
npm run test:e2e              # all e2e suites (run in band)
npm run test:e2e -- csrf      # one suite
npm test                      # unit tests only (no infra needed)
```

Migrations run automatically at suite start; tables are truncated between tests.

## Coverage

| Suite | Covers |
| --- | --- |
| `app-boot` | both apps import/boot under `NODE_ENV=test` |
| `core-flow` | register → email verification → login → access token → refresh → logout, token-type checks, refresh revocation |
| `email-verification` | unverified login refused (`EMAIL_NOT_VERIFIED`), token hashing/expiry/single use, resend (enumeration-safe, rate limited), refresh for unverified users, migration 006 grandfathering |
| `csrf` | token issue/reuse, missing/forged token, cookie-only token rejected |
| `sessions` | Redis session listing/revocation, multi-device, fingerprint trust score |
| `security-middleware` | XSS sanitising, SQLi blocking, rate limiting, `X-Forwarded-For` spoofing |
| `oauth-rbac` | Google/GitHub sign-up & login, OAuth `state`, verified-email linking, RBAC 401/403 |

Not covered: password reset, the `/api/roles` routes (not mounted).

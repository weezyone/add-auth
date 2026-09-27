# API Documentation

HTTP surface of the **default server** (`src/index.ts`). Verified against `src/routes/auth.ts`, `src/routes/passwordReset.ts`, and the controllers they call.

Base URL for local development:

```
http://localhost:3000
```

There is **no** `/api/v1` prefix. Auth lives under `/api/auth`. Password reset lives under `/api/password-reset`.

## Table of Contents

- [Architecture](#architecture)
- [CORS](#cors)
- [CSRF](#csrf)
- [Authentication](#authentication)
- [Errors](#errors)
- [Health and root](#health-and-root)
- [Auth endpoints](#auth-endpoints)
- [Password-reset endpoints](#password-reset-endpoints)
- [Rate limits](#rate-limits)
- [Not mounted on this server](#not-mounted-on-this-server)

## Architecture

```
Browser / client
    │  credentials: include
    │  X-CSRF-Token on unsafe methods
    ▼
src/index.ts
    helmet + CORS + applySecurityMiddleware(NODE_ENV)
    cookie-parser + JSON body
    GET /health, GET /
    /api/auth              → src/routes/auth.ts
    /api/password-reset    → src/routes/passwordReset.ts
```

`applySecurityMiddleware` (`src/middleware/index.ts`) always stacks: general rate limit, CSRF, XSS, SQL-injection checks, and input sanitization. Auth routes also apply `securityMiddleware.auth` (auth rate limit + another CSRF pass).

Responses are **not** wrapped in a uniform `{ success, data, meta }` envelope. Auth controllers typically return `{ message, user, session, tokens }` or `{ error, message }`. Password-reset controllers use `{ success, message }` / `{ success, error }`.

## CORS

Configured in `src/index.ts`:

- Allowlist: `FRONTEND_URL` split on commas (default `http://localhost:3000`). Requests with no `Origin` are allowed (curl, server-to-server).
- `credentials: true`
- Methods: `GET, POST, PUT, DELETE, OPTIONS`
- Request header allowlist includes `X-CSRF-Token`
- Exposed response header: `X-CSRF-Token`

Example for the React and Next demos:

```env
FRONTEND_URL=http://localhost:5173,http://localhost:3001
```

## CSRF

Implementation: `src/middleware/csrfProtection.ts`.

| | |
|---|---|
| Token header | `X-CSRF-Token` (also `body._csrf`, `query._csrf`, or cookie `csrf-token`) |
| Storage | Redis key `csrf:<sessionId>`, TTL 1 hour (2 hours in development config) |
| Session id | `req.session.id` if Express session exists; otherwise `ip` + base64 user-agent prefix |
| Safe methods | `GET`, `HEAD`, `OPTIONS` **generate** a token (sets `res.locals.csrfToken`, `X-CSRF-Token` header, `csrf-token` cookie) |
| Unsafe methods | **validate** the token |

Development (`securityConfigs.development`): validation is skipped when `Sec-Fetch-Site` is `same-origin`. Cross-origin demo apps (port 5173 → 3000) are not same-origin and must send the header.

Testing preset marks `POST` exempt; the running API uses `development` or `production` from `NODE_ENV` (`test` is not in the `applySecurityMiddleware` union — unexpected values fall through to the development object only if you pass `'development'`). `src/index.ts` casts `NODE_ENV` and defaults to `'development'`.

### Client flow (matches `example-apps/`)

```bash
# 1. Cookie jar + fetch token
curl -c cookies.txt -b cookies.txt http://localhost:3000/api/auth/csrf-token
# → { "success": true, "csrfToken": "..." }

# 2. Mutating call with the same cookies
curl -c cookies.txt -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrfToken>" \
  -d '{"email":"user@example.com","password":"SecurePass1!","username":"johndoe","confirmPassword":"SecurePass1!"}' \
  http://localhost:3000/api/auth/register
```

Redis must be reachable or token generate/validate returns 500 / 403.

## Authentication

Protected routes use `authenticateToken` (`src/middleware/auth.ts`):

```
Authorization: Bearer <accessToken>
```

Tokens are **HMAC JWTs** signed with `JWT_SECRET` (`src/utils/jwt.ts`), not RS256. Payload includes `id`, `email`, optional `roles`, and a generated `sessionId`.

Access-token lifetime is `JWT_EXPIRES_IN` (default **24h**). The JSON field `tokens.expiresIn` from `createAuthenticationTokens` is **hardcoded to 900** (seconds) and can disagree with the actual JWT `exp`.

Refresh-token metadata is an **in-process `Map`** (`src/utils/refreshToken.ts`). Restarting the Node process invalidates stored refresh metadata even if the JWT itself has not expired.

Register/login also create a Redis session (`SessionService`) and set an httpOnly `sessionId` cookie (`SameSite=strict`, `Secure` in production). Cookie max-age is 24h, or 7 days when `rememberMe` is true.

## Errors

Typical auth error:

```json
{
  "error": "Invalid credentials",
  "message": "Email or password is incorrect"
}
```

Typical password-reset error:

```json
{
  "success": false,
  "error": "Invalid or expired token"
}
```

| Status | When |
|--------|------|
| 400 | Validation / weak password / bad reset token / current password wrong |
| 401 | Missing/invalid/revoked JWT; bad login; disabled account |
| 403 | CSRF missing or invalid |
| 404 | User or session not found |
| 409 | Email already registered |
| 423 | Account locked (`locked_until`) |
| 429 | Rate limit |
| 500 | Unexpected failure (including mailer / Redis / schema mismatches) |

Joi validation failures come from `validateBody` (localized messages when `localization` detects a language).

## Health and root

### `GET /health`

Checks `db.testConnection()`, Redis `PING`, and `securityHealthCheck()` (Redis, CSRF generate, Joi, XSS, SQL-injection detect).

```json
{
  "status": "healthy",
  "timestamp": "2026-09-06T00:00:00.000Z",
  "database": "connected",
  "redis": "connected",
  "security": {
    "redis": true,
    "csrf": true,
    "validation": true,
    "xss": true,
    "sqlInjection": true
  },
  "version": "1.0.0"
}
```

### `GET /`

```json
{
  "message": "Add-Auth API",
  "version": "1.0.0",
  "timestamp": "2026-09-06T00:00:00.000Z"
}
```

## Auth endpoints

Unless noted, POSTs need CSRF. `securityMiddleware.auth` applies to the whole `/api/auth` router.

### `GET /api/auth/csrf-token`

Returns `{ "success": true, "csrfToken": "<token>" }` after the GET CSRF generator runs.

### `POST /api/auth/register`

Rate limit: `rateLimiters.registration` (5 / hour / IP) plus the auth stack.

**Body** (Joi `userRegistration`):

| Field | Required | Rules |
|-------|----------|--------|
| `username` | yes | alphanumeric, 3–30 chars. **Validated only** — `UserModel.create` persists `email` + `password_hash`, not username. |
| `email` | yes | email |
| `password` | yes | 8–128 chars; at least one lower, upper, digit, and `!@#$%^&*` |
| `confirmPassword` | yes | must match `password` |
| `firstName` / `lastName` | no | letters/spaces, max 50 |

Controller also runs `defaultPasswordSecurity.validatePassword` (specials include a wider set than Joi).

**201**

```json
{
  "message": "User registered successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "created_at": "...",
    "status": "active"
  },
  "session": {
    "id": "redis-session-id",
    "expires_at": "...",
    "trust_score": 0
  },
  "tokens": {
    "accessToken": "...",
    "refreshToken": "...",
    "expiresIn": 900,
    "tokenType": "Bearer"
  }
}
```

**409** if email exists. **400** if password security module rejects the password.

### `POST /api/auth/login`

Rate limit: `rateLimiters.login` (10 / 15 min / IP).

**Body:** `{ "email", "password", "rememberMe": false }`

**200** includes `user` (`id`, `email`, `last_login`, `status`, `email_verified`), `session` (adds `concurrent_count`), and `tokens`. Roles are loaded into the JWT payload, not the `user` object.

**401** invalid password or missing user (`Invalid credentials`) or `status !== active` (`Account disabled`). **423** locked.

Failed passwords call `UserModel.incrementFailedLoginAttempts`.

### `POST /api/auth/logout`

Requires `Authorization: Bearer`. CSRF required.

Optional body: `{ "refreshToken": "..." }` — passed to `performLogout` for blacklist.

Also destroys Redis session from cookie `sessionId` or header `X-Session-Id`.

**200** `{ "message": "Logged out successfully" }`  
**400** if neither token nor session was present.

### `POST /api/auth/refresh`

Rate limit: 30 / 15 min / IP. Body: `{ "refreshToken": "..." }` (Joi `refreshToken` schema).

**200** `{ "message": "Tokens refreshed successfully", "tokens": { ... } }`  
**401** expired/invalid refresh token.

### `GET /api/auth/me`

Bearer required. **200** `{ "user": { id, email, created_at, updated_at, status, email_verified, last_login } }`.

### `PUT /api/auth/profile`

Bearer + CSRF. Body: Joi `userProfileUpdate` (optional `firstName`, `lastName`, `email`, …). `UserModel.update` accepts `email`, `status`, `email_verified` only (`UpdateUserInput`). Extra fields are ignored or fail at SQL depending on the model implementation.

**409** if the new email is taken.

### `POST /api/auth/change-password`

Bearer + CSRF. Body: `{ "currentPassword", "newPassword", "confirmPassword" }`.

On success, all Redis sessions for the user are destroyed and the `sessionId` cookie is cleared.

**200** `{ "success": true, "message": "Password updated successfully. Please log in again." }`

### Session routes (Redis session middleware)

These handlers live on the same router. They require `redisSessionValidationMiddleware` + `enhancedAuthMiddleware` + `sessionSecurityMiddleware` (`src/middleware/session.ts`), not only a JWT.

| Method | Path | CSRF | Success shape |
|--------|------|------|----------------|
| GET | `/api/auth/sessions` | no | `{ sessions, total }` |
| DELETE | `/api/auth/sessions/:sessionId` | yes | `{ message }` |
| DELETE | `/api/auth/sessions` | yes | `{ message, revokedCount }` |
| PUT | `/api/auth/session/extend` | yes | `{ message, session }` |

`src/index.ts` does **not** mount global `sessionMiddleware`. These routes still run their own Redis session checks; they fail closed if Redis/session state is missing.

## Password-reset endpoints

Router: `src/routes/passwordReset.ts`. XSS + SQL-injection middleware on all routes. CSRF on unsafe methods.

Tokens: 64 random bytes, SHA-256 hashed, Redis `password-reset:<hashedToken>`, TTL **1 hour**. Per-email cap: **3** attempts / hour (`PasswordResetManager`). IP limiter: **3** / hour (`rateLimiters.passwordReset`).

### `POST /api/password-reset/request`

Body: `{ "email": "user@example.com" }`.

Always aims to return the same message whether or not the user exists:

```json
{
  "success": true,
  "message": "If an account with this email exists, you will receive a password reset link.",
  "expiresAt": "..."
}
```

`expiresAt` is included when a token was created.

**Operational constraint:** the handler queries `SELECT id, email, username FROM users WHERE email = $1 AND is_active = true`. Current migrations have `status` and no `username` / `is_active`. That query errors against a schema built only from `001`–`005`. Email send also requires `EMAIL_USER` + `EMAIL_PASS`.

### `GET /api/password-reset/verify/:token`

**200** `{ success, message, data: { email, expiresAt } }` or **400** invalid/expired.

### `POST /api/password-reset/reset`

Body (Joi `passwordReset`): `{ "token", "password", "confirmPassword" }`. Controller reads `token` and `password`.

**200** `{ "success": true, "message": "Password has been reset successfully" }`

On success the controller updates `password_hash`, `DELETE FROM sessions WHERE user_id = $1`, and writes an audit row. The audit insert uses columns `details`, `created_at` and omits `resource_type`; `004_create_audit_logs_table.sql` requires `resource_type` and uses `timestamp` instead of `created_at`. Treat password-reset + audit as a known schema drift until those paths are aligned.

### Admin / authenticated extras

All require `requireAuth` + `requireAdmin` except revoke-by-token (CSRF only):

| Method | Path | Notes |
|--------|------|--------|
| GET | `/api/password-reset/attempts/:email` | Auth + admin |
| DELETE | `/api/password-reset/revoke/:token` | CSRF |
| GET | `/api/password-reset/admin/stats` | Auth + admin |
| GET | `/api/password-reset/admin/user/:userId/tokens` | Auth + admin |
| DELETE | `/api/password-reset/admin/user/:userId/tokens` | Auth + admin + CSRF |

`requireAuth` here is the **session/RBAC** helper from `src/middleware/rbac.ts` (`req.session.userId`), not `authenticateToken`. On the default `src/index.ts` server, Express sessions are not initialized, so these admin routes will not see a session user.

## Rate limits

From `src/middleware/rateLimiter.ts` (Redis store). Values are hardcoded on the limiters (not the Zod `RATE_LIMIT_*` config) unless noted.

| Limiter | Window | Max / IP | Applied to |
|---------|--------|----------|------------|
| `general` | 15 min | 100 | Global security stack + several GET reset routes |
| `auth` | 15 min | 10 | Entire `/api/auth` router |
| `login` | 15 min | 10 | `POST /login` |
| `registration` | 1 hour | 5 | `POST /register` |
| `refresh` | 15 min | 30 | `POST /refresh` |
| `passwordReset` | 1 hour | 3 | request + reset |

429 body: `{ "error", "message", "retryAfter" }`.

## Not mounted on this server

| Path / module | Where it lives | Mounted by |
|---------------|----------------|------------|
| `/api/roles/*` | `src/routes/roles.ts` via `src/routes/index.ts` | **not** `src/index.ts` |
| `/auth/google`, `/auth/github` | `src/routes/oauth.ts` | `src/app.ts` only |
| `/dashboard`, `/admin`, `/moderator` | demo handlers | `src/app.ts` only |
| Standalone tutorial apps | `examples/jwt-auth`, etc. | their own `npm start` |

Library exports (`src/lib.ts`) include middleware, models, JWT helpers, `PasswordResetManager`, and `SessionService` for embedding in another Express app. That is a different integration path than calling this demo server.

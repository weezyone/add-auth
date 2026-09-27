# Frontend example apps

Browser clients that call the **main API** on port 3000 (`npm run dev` in the repo root). These are not the standalone tutorial servers in [`examples/`](../examples/).

## Apps

| App | Stack | Dev URL | Notes |
|-----|-------|---------|--------|
| [react-auth-demo](./react-auth-demo/) | React 19 + Vite | http://localhost:5173 | Fastest end-to-end UI check |
| [nextjs-auth-demo](./nextjs-auth-demo/) | Next.js App Router | http://localhost:3001 | Same CSRF/JWT flow |
| [vanilla-auth-demo](./vanilla-auth-demo/) | HTML + `fetch` | serve static (e.g. :5500) | No bundler |

Each app: register, login, dashboard (`GET /api/auth/me`), logout, CSRF header, `credentials: 'include'`.

## Run

1. Postgres + Redis up; root `.env` valid (`JWT_SECRET`, `SESSION_SECRET` ≥ 32 chars).
2. Allow demo origins (exact scheme/host/port):

   ```env
   FRONTEND_URL=http://localhost:3000,http://localhost:5173,http://localhost:3001,http://localhost:5500
   ```

3. From the **repository root**:

   ```bash
   npx ts-node src/database/migrate.ts migrate
   npm run dev
   ```

4. In another terminal:

   ```bash
   cd example-apps/react-auth-demo
   npm install
   npm run dev
   ```

API clients hard-code `http://localhost:3000` (see `react-auth-demo/src/api/auth.ts`, `nextjs-auth-demo/lib/auth.ts`, `vanilla-auth-demo/app.js`).

## CSRF + cookies

Cross-origin POSTs are not `same-origin`, so development CSRF skip does not apply.

1. `GET /api/auth/csrf-token` with `credentials: 'include'`
2. Send `X-CSRF-Token` and the same cookies on `POST /api/auth/register`, `/login`, `/logout`

Full contract: [docs/API.md](../docs/API.md#csrf).

## Register body

Demos send `username`, `email`, `password`, `confirmPassword`. Joi requires `username`; `UserModel.create` does not persist it.

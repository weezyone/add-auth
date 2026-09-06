# Add-Auth Vanilla HTML/CSS/JS Demo

A plain HTML, CSS, and JavaScript example showing how to integrate with the `@paulweezydesign/add-auth` authentication API — no build tools needed.

## Features

- User registration with validation
- Login with JWT tokens
- Dashboard showing user info
- CSRF token handling
- Zero dependencies — just a browser

## Quick Start

```bash
# 1. From the repository root: allow this origin, then start the API
#    FRONTEND_URL must include http://localhost:5500 (see example-apps/README.md)
npx ts-node src/database/migrate.ts migrate
npm run dev

# 2. Serve the static files (any static server works)
cd example-apps/vanilla-auth-demo
npx serve -l 5500
# Or: python3 -m http.server 5500
```

Open `http://localhost:5500` in your browser. If register/login return 403, fetch CSRF with cookies first (`GET /api/auth/csrf-token`) — details in [example-apps/README.md](../README.md).

## How It Works

All auth logic is in `app.js` using the Fetch API:

1. **CSRF Token**: Fetched before every POST/PUT/DELETE via `GET /api/auth/csrf-token`
2. **Registration**: `POST /api/auth/register` with `X-CSRF-Token` header
3. **Login**: `POST /api/auth/login` with `X-CSRF-Token` header
4. **Auth Header**: JWT token sent as `Authorization: Bearer <token>`
5. **Cookies**: `credentials: 'include'` ensures session cookies are sent

# Add-Auth React + Vite Demo

A React + TypeScript + Vite example showing how to integrate with the `@paulweezydesign/add-auth` authentication API.

## Features

- User registration with validation
- Login with JWT tokens
- Dashboard showing user info
- CSRF token handling
- Session cookie management
- Logout with token cleanup

## Quick Start

```bash
# 1. From the repository root: allow this origin, then start the API
#    FRONTEND_URL must include http://localhost:5173 (see example-apps/README.md)
npx ts-node src/database/migrate.ts migrate
npm run dev

# 2. Install dependencies and start the React app
cd example-apps/react-auth-demo
npm install
npm run dev
```

The app runs on `http://localhost:5173`. If register/login return 403, fetch CSRF with cookies first (`GET /api/auth/csrf-token`) — details in [example-apps/README.md](../README.md).

## How It Works

1. **CSRF Token**: Before any POST request, the app fetches a CSRF token from `GET /api/auth/csrf-token`
2. **Registration**: POST to `/api/auth/register` with username, email, password
3. **Login**: POST to `/api/auth/login` with email and password
4. **Auth Header**: After login, the JWT access token is sent via `Authorization: Bearer <token>`
5. **Cookies**: Session cookies are automatically managed via `credentials: 'include'`

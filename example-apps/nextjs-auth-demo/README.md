# Add-Auth Next.js Demo

A Next.js 15 + Tailwind CSS example showing how to integrate with the `@paulweezydesign/add-auth` authentication API using the App Router.

## Features

- User registration with validation
- Login with JWT tokens
- Dashboard showing user info
- CSRF token handling
- Tailwind CSS styling
- TypeScript throughout

## Quick Start

```bash
# 1. From the repository root: allow this origin, then start the API
#    FRONTEND_URL must include http://localhost:3001 (see example-apps/README.md)
npx ts-node src/database/migrate.ts migrate
npm run dev

# 2. Install dependencies and start the Next.js app
cd example-apps/nextjs-auth-demo
npm install
npm run dev
```

The app runs on `http://localhost:3001`. If register/login return 403, fetch CSRF with cookies first (`GET /api/auth/csrf-token`) — details in [example-apps/README.md](../README.md).

## How It Works

- `lib/auth.ts` — API client with CSRF handling, typed responses
- `app/page.tsx` — Client component with login, register, and dashboard views
- All API calls use `credentials: 'include'` for cookie-based sessions
- CSRF tokens are fetched before every mutating request

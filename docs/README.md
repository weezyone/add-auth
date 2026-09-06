# Documentation Index

Guides for the add-auth library and the demo API in `src/index.ts`. Prefer these files over older root-level completion reports (`IMPLEMENTATION_SUMMARY.md`, `TASK_1_COMPLETION_REPORT.md`, etc.), which are historical.

## Start here

| Audience | Read |
|----------|------|
| First run locally | [DEVELOPMENT.md](./DEVELOPMENT.md) |
| HTTP clients / frontend | [API.md](./API.md) |
| Browser demos against this API | [example-apps/README.md](../example-apps/README.md) |
| Security behavior (verified vs generic) | [SECURITY.md](./SECURITY.md) |
| Library install / exports | [../README.md](../README.md) |
| Standalone tutorial backends | [../examples/README.md](../examples/README.md) |

## What each guide covers

- **DEVELOPMENT.md** — Postgres/Redis, `.env` (including `DB_SSL` and `FRONTEND_URL`), migrations (`ts-node … migrate`), `npm run dev`, test/build caveats.
- **API.md** — Real paths (`/api/auth`, `/api/password-reset`), CSRF/CORS, request bodies, rate limits, and what is **not** mounted on the default server.
- **SECURITY.md** — Starts with a snapshot checked against source. Later sections are broader guidance and may describe target-state designs (for example RS256) that the current HMAC JWT path does not use.
- **DEPLOYMENT.md** — Production-oriented checklist. Treat concrete env names and compose files as examples; confirm against `src/config/index.ts` and `package.json` before copying commands.

## Two “examples” folders

| Folder | Role |
|--------|------|
| `example-apps/` | React, Next.js, and vanilla clients for **this** API on port 3000 |
| `examples/` | Separate tutorial servers (JWT, session, OAuth, RBAC, password recovery) with their own ports and READMEs |

## Contributing to docs

When behavior changes, update the matching guide and keep examples in sync with controllers:

1. New or changed HTTP routes → `API.md` and, if clients break, `example-apps/`
2. Env, scripts, or local pitfalls → `DEVELOPMENT.md` and `.env.example`
3. Authn/authz/crypto behavior → `SECURITY.md` snapshot first
4. Do not invent `/api/v1` prefixes, Prisma, or npm scripts that are not in `package.json`

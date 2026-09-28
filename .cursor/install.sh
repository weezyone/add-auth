#!/usr/bin/env bash
#
# Cloud Agent install phase: idempotent repository bootstrap.
# Runs after the repository is checked out. Installs Node dependencies for the
# library and the React example app, and creates a development .env if missing.
# Must NOT start long-running processes (see start.sh for that).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[install] Installing library dependencies..."
npm install

echo "[install] Installing React demo dependencies..."
( cd example-apps/react-auth-demo && npm install )

if [ ! -f .env ]; then
  echo "[install] Creating development .env..."
  # NOTE: DB_SSL is intentionally left unset. Zod's z.coerce.boolean() treats the
  # string "false" as truthy, so setting DB_SSL=false would enable SSL by mistake.
  cat > .env <<'EOF'
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=add_auth
DB_USER=postgres
DB_PASSWORD=password

# Server
PORT=3000
NODE_ENV=development

# Security (development-only secrets; must be >= 32 chars)
JWT_SECRET=dev-super-secret-jwt-key-at-least-32-characters-long
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d
SESSION_SECRET=dev-super-secret-session-key-at-least-32-characters-long
SESSION_TIMEOUT=86400000

# Password
BCRYPT_ROUNDS=12

# Logging
LOG_LEVEL=info

# Rate limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# CORS allowlist for the example frontend apps
FRONTEND_URL=http://localhost:3000,http://localhost:5173,http://localhost:3001
EOF
else
  echo "[install] .env already exists, leaving it untouched."
fi

echo "[install] Done."

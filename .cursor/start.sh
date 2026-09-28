#!/usr/bin/env bash
#
# Cloud Agent start phase: per-boot runtime reconciliation.
# Starts PostgreSQL and Redis, ensures the database and role exist, and applies
# migrations. Idempotent and safe to run on every boot.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[start] Starting PostgreSQL 16..."
# pg_ctlcluster exits non-zero if the cluster is already running; tolerate that.
sudo pg_ctlcluster 16 main start || true

echo "[start] Waiting for PostgreSQL to accept connections..."
for _ in $(seq 1 30); do
  if pg_isready -q; then break; fi
  sleep 1
done
pg_isready

echo "[start] Starting Redis..."
sudo redis-server --daemonize yes || true
for _ in $(seq 1 15); do
  if redis-cli ping >/dev/null 2>&1; then break; fi
  sleep 1
done
redis-cli ping

echo "[start] Ensuring postgres role password and 'add_auth' database exist..."
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'password';" >/dev/null
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='add_auth'" | grep -q 1; then
  sudo -u postgres createdb add_auth
  echo "[start] Created database 'add_auth'."
else
  echo "[start] Database 'add_auth' already exists."
fi

echo "[start] Applying database migrations..."
npx ts-node src/database/migrate.ts migrate

echo "[start] Environment ready."

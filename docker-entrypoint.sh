#!/bin/sh
set -e

# Allow optional prestart hook for custom logic
if [ -x /app/prestart.sh ]; then
  echo "[entrypoint] Running prestart hook"
  /app/prestart.sh
fi

# Run database migrations before starting the server
if command -v alembic >/dev/null 2>&1; then
  echo "[entrypoint] Applying database migrations"
  alembic upgrade head
else
  echo "[entrypoint][warn] Alembic not found on PATH; skipping migrations" >&2
fi

echo "[entrypoint] Starting gunicorn"
exec "$@"

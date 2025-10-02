#!/bin/sh
set -euxo pipefail

# Allow optional prestart hook for custom logic
if [ -x /app/prestart.sh ]; then
  echo "[entrypoint] Running prestart hook"
  /app/prestart.sh
fi

# Run database migrations before starting the server
if command -v alembic >/dev/null 2>&1; then
  echo "[entrypoint] Applying database migrations (DATABASE_URL=${DATABASE_URL:-unset})"
  if alembic upgrade head; then
    echo "[entrypoint] Database migrations applied"
  else
    status=$?
    echo "[entrypoint][error] Alembic upgrade failed with status ${status}" >&2
    exit ${status}
  fi
else
  echo "[entrypoint][warn] Alembic not found on PATH; skipping migrations" >&2
fi

echo "[entrypoint] Starting gunicorn"
exec "$@"

# Arrivals Backend – Postgres Only Dev Setup

This backend is configured to persist everything in Postgres (data) and on disk (uploads), so you don’t lose data when Docker restarts.

## Folders (persisted on host)
- `arrivals-backend/data/pg` — Postgres data directory (bind‑mounted to container)
- `arrivals-backend/uploads` — uploaded files (bind‑mounted to container)

These folders survive `docker compose down -v` because they are bind‑mounts, not named volumes.

## Compose services (arrivals-backend/docker-compose.yml)
- `backend` (Gunicorn WS worker on 8081)
- `db` (Postgres 16)
- `redis` (Redis 7 for Celery + caching)
- `celery` (background worker processing async jobs)

Key env in `backend`:
- `DATABASE_URL` — Postgres connection, e.g. `postgresql+psycopg://arrivals:supersecretchangeit@db:5432/arrivals`
- `UPLOAD_DIR=/app/uploads`
- `ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173` (Vite dev origin)
- `LOG_HTTP=1` (optional request timing logs)

## Start / Stop / Restart

From this folder (`arrivals-backend/`):

- Start or restart (rebuild if code changed):
```
docker compose up --build
```
- Run in background:
```
docker compose up -d --build
```
- Stop (keep data):
```
docker compose down
```
- Full clean (containers + networks; data stays because of bind‑mounts):
```
docker compose down -v
```
> Note: even with `-v`, bind‑mounted folders `data/pg` and `uploads` remain on host. Your DB/files are preserved.

## Reset the database (danger!)
Delete the host folder and start again:
```
rm -rf data/pg
docker compose up --build
```

## Database migrations (Alembic)

- **Cold start a new database** – create a Postgres database and run:
  ```
  make -C arrivals-backend cold-start DATABASE_URL=postgresql+psycopg://user:pass@host:5432/dbname
  ```
- **Adopt an existing (pre-Alembic) database** – mark it at the initial revision then apply the latest migrations:
  ```
  make -C arrivals-backend adopt-db DATABASE_URL=postgresql+psycopg://user:pass@host:5432/dbname
  ```
- **Show current revision**:
  ```
  make -C arrivals-backend alembic-current DATABASE_URL=postgresql+psycopg://user:pass@host:5432/dbname
  ```

All targets export `AUTO_CREATE_TABLES=0` and `ALEMBIC_SKIP_BOOTSTRAP=1`, so the app never falls back to `db.create_all()` during migrations.

## Backup / Restore (basic)
- Backup (on host):
```
pg_dump -h 127.0.0.1 -p 5432 -U arrivals -d arrivals > arrivals_backup.sql
```
- Restore:
```
psql -h 127.0.0.1 -p 5432 -U arrivals -d arrivals < arrivals_backup.sql
```
(Replace user/password/port if different. When using Docker Desktop, you can exec into the db container and run pg_dump/psql there.)

## Health & Routes
- Health: `GET http://localhost:8081/healthz` — DB connectivity check used by the Docker healthcheck
- Arrivals routes: `GET http://localhost:8081/_debug/arrivals-methods`
- All routes: `GET http://localhost:8081/_debug/routes`

## Common FAQs
- 405 on PATCH/POST/DELETE: make sure you’re hitting the WS‑capable backend on 8081 started by this compose. Check `docker compose ps` and restart with `--build`.
- WebSocket “bad response”: ensure the backend is started with the Gevent WebSocket worker (this compose does that).
- Data missing after restart: don’t worry — with bind‑mounts, DB and uploads persist. If you were using another compose earlier, confirm you’re now running this one.
- Need to flush cached lookups quickly? Call `POST /api/admin/cache/clear` with an admin/API token.
- Background jobs such as the demo bulk email endpoint return a `task_id`. Poll `GET /api/tasks/<task_id>` to track progress.

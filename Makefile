SHELL := /bin/sh
VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
PIP ?= $(VENV)/bin/pip
ALEMBIC ?= $(VENV)/bin/alembic

.PHONY: venv alembic-current cold-start adopt-db

venv:
	@python3 -m venv $(VENV)
	@$(PIP) install -r requirements.txt

alembic-current:
	@if [ -z "$(DATABASE_URL)" ]; then \
		echo "DATABASE_URL is required (e.g. postgresql+psycopg://user:pass@host/db)" >&2; \
		exit 1; \
	fi
	@ALEMBIC_SKIP_BOOTSTRAP=1 AUTO_CREATE_TABLES=0 DATABASE_URL=$(DATABASE_URL) $(ALEMBIC) current

cold-start:
	@if [ -z "$(DATABASE_URL)" ]; then \
		echo "DATABASE_URL is required (e.g. postgresql+psycopg://user:pass@host/db)" >&2; \
		exit 1; \
	fi
	@echo "==> Running initial migrations on blank database"
	@ALEMBIC_SKIP_BOOTSTRAP=1 AUTO_CREATE_TABLES=0 DATABASE_URL=$(DATABASE_URL) $(ALEMBIC) upgrade head

adopt-db:
	@if [ -z "$(DATABASE_URL)" ]; then \
		echo "DATABASE_URL is required (e.g. postgresql+psycopg://user:pass@host/db)" >&2; \
		exit 1; \
	fi
	@echo "==> Stamping existing schema as at revision 0001_initial"
	@ALEMBIC_SKIP_BOOTSTRAP=1 AUTO_CREATE_TABLES=0 DATABASE_URL=$(DATABASE_URL) $(ALEMBIC) stamp 0001_initial
	@echo "==> Applying migrations"
	@ALEMBIC_SKIP_BOOTSTRAP=1 AUTO_CREATE_TABLES=0 DATABASE_URL=$(DATABASE_URL) $(ALEMBIC) upgrade head

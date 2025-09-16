from __future__ import annotations
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from dotenv import load_dotenv

# Učitaj .env kako bi DATABASE_URL bio dostupan tokom alembic komandi
load_dotenv()

# Reci aplikaciji da ne pokreće bootstrap (threadovi, init admin, sl.) tokom Alembic importa
os.environ.setdefault("ALEMBIC_SKIP_BOOTSTRAP", "1")

# Alembic konfiguracija (čita vrijednosti iz alembic.ini)
config = context.config

# Injektuj runtime DB URL iz env-a u Alembic config
_db_url = os.getenv("DATABASE_URL")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

# Logging prema alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# --- Meta podaci iz aplikacije ---
# Koristimo Flask‑SQLAlchemy metadata iz app.py kako bi autogenerate vidio sve modele

from app import db  # db = SQLAlchemy() inicijalizovan u app.py

target_metadata = db.metadata


# Filter used by autogenerate to **avoid dropping** legacy tables/columns.
# We only want additive migrations unless we explicitly code removals.
# This prevents Alembic from generating DROP statements for tables like "user"
# that are still referenced by FKs.
def include_object(object, name, type_, reflected, compare_to):
    # Skip DROP of legacy tables if Alembic thinks they were "removed"
    legacy_tables = {
        "user",
        "users",
        "arrival",
        "arrivals",
        "arrival_file",
        "arrival_files",
        "arrival_update",
        "arrival_updates",
        "container_file",
        "container_files",
    }
    if type_ == "table" and reflected and compare_to is None and name in legacy_tables:
        return False
    # Never auto-drop columns on those legacy tables either
    if (
        type_ == "column"
        and object.table is not None
        and object.table.name in legacy_tables
        and compare_to is None
        and reflected
    ):
        return False
    return True


def run_migrations_offline() -> None:
    """Pokretanje migracija u 'offline' modu."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
        dialect_opts={"paramstyle": "named"},
        include_object=include_object,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Pokretanje migracija u 'online' modu."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_object=include_object,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

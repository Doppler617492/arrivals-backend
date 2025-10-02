"""initial schema

Revision ID: 0001_initial
Revises: 
Create Date: 2025-10-02 21:00:31.231933

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Import application metadata so Alembic can create the full schema.
# We intentionally load the Flask app/db inside the migration rather than at
# module import time to keep Alembic CLI responsive and honour
# ALEMBIC_SKIP_BOOTSTRAP set by migrations/env.py.


def _load_metadata():
    """Return SQLAlchemy metadata with all models registered."""
    # Import inside the helper to avoid side-effects when Alembic only inspects
    # the module (e.g. --autogenerate). The env.py already sets
    # ALEMBIC_SKIP_BOOTSTRAP so app bootstrap hooks (admin seeding, etc.) stay
    # inactive during migrations.
    from app import db  # noqa: F401
    import models  # noqa: F401

    return db.metadata


# revision identifiers, used by Alembic.
revision: str = '0001_initial'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the full application schema on a blank database.

    The metadata.create_all call is safe to run against existing installations
    because SQLAlchemy skips tables that already exist. This allows us to reuse
    the same initial revision for both "cold start" (fresh Postgres) and
    "adopt" scenarios where the legacy schema is already present.
    """

    metadata = _load_metadata()
    bind = op.get_bind()
    metadata.create_all(bind=bind)


def downgrade() -> None:
    """Drop all application tables that belong to this metadata."""

    metadata = _load_metadata()
    bind = op.get_bind()
    metadata.drop_all(bind=bind)

"""add countries table

Revision ID: 0002_add_countries
Revises: 0001_initial
Create Date: 2025-10-02 21:32:53.777552

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


COUNTRIES_TABLE_NAME = "countries"


def _countries_table() -> sa.Table:
    return sa.table(
        COUNTRIES_TABLE_NAME,
        sa.column("code", sa.String(length=2)),
        sa.column("name", sa.String(length=128)),
    )


# revision identifiers, used by Alembic.
revision: str = '0002_add_countries'
down_revision: Union[str, Sequence[str], None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        COUNTRIES_TABLE_NAME,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(length=2), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            server_onupdate=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("uq_countries_code", COUNTRIES_TABLE_NAME, ["code"], unique=True)

    try:
        from countries import EUROPEAN_COUNTRIES  # type: ignore

        rows = [
            {"code": code.strip().upper(), "name": name.strip()}
            for code, name in sorted(EUROPEAN_COUNTRIES.items())
        ]
        if rows:
            op.bulk_insert(_countries_table(), rows)
    except Exception:
        # Seeding is best-effort; schema creation is the primary goal.
        pass


def downgrade() -> None:
    op.drop_index("uq_countries_code", table_name=COUNTRIES_TABLE_NAME)
    op.drop_table(COUNTRIES_TABLE_NAME)

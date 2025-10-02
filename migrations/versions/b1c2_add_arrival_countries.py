"""add arrival countries table

Revision ID: b1c2_add_arrival_countries
Revises: a2c1_arrival_country_suppliers
Create Date: 2025-10-02 00:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision: str = "b1c2_add_arrival_countries"
down_revision: Union[str, Sequence[str], None] = "a2c1_arrival_country_suppliers"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "arrival_countries" not in tables:
        op.create_table(
            "arrival_countries",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("arrival_id", sa.Integer(), sa.ForeignKey("arrivals.id", ondelete="CASCADE"), nullable=False),
            sa.Column("code", sa.String(length=2), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("arrival_id", "code", name="uq_arrival_country"),
        )
        op.create_index("ix_arrival_countries_arrival_id", "arrival_countries", ["arrival_id"], unique=False)
        op.create_index("ix_arrival_countries_code", "arrival_countries", ["code"], unique=False)
        op.create_index("ix_arrival_countries_created_at", "arrival_countries", ["created_at"], unique=False)
        op.execute(
            """
            INSERT INTO arrival_countries (arrival_id, code, created_at, updated_at)
            SELECT id, upper(country), now(), now()
            FROM arrivals
            WHERE country IS NOT NULL AND country <> ''
              AND NOT EXISTS (
                  SELECT 1 FROM arrival_countries ac
                  WHERE ac.arrival_id = arrivals.id AND upper(ac.code) = upper(arrivals.country)
              )
            """
        )


def downgrade() -> None:
    op.drop_index("ix_arrival_countries_created_at", table_name="arrival_countries")
    op.drop_index("ix_arrival_countries_code", table_name="arrival_countries")
    op.drop_index("ix_arrival_countries_arrival_id", table_name="arrival_countries")
    op.drop_table("arrival_countries")


"""add arrival country and supplier tables

Revision ID: a2c1_arrival_country_suppliers
Revises: 8a2f_add_category_to_arrivals
Create Date: 2025-05-02 00:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision: str = "a2c1_arrival_country_suppliers"
down_revision: Union[str, Sequence[str], None] = "8a2f_add_category_to_arrivals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(inspector, table_name: str) -> bool:
    try:
        return table_name in inspector.get_table_names()
    except Exception:
        return False


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)

    if not _has_table(inspector, "suppliers"):
        op.create_table(
            "suppliers",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("default_currency", sa.String(length=8), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("name", name="uq_suppliers_name"),
        )
        try:
            op.create_index("ix_suppliers_name", "suppliers", ["name"], unique=False)
        except Exception:
            pass
        try:
            op.create_index("ix_suppliers_is_active", "suppliers", ["is_active"], unique=False)
        except Exception:
            pass

    if not _has_table(inspector, "arrival_suppliers"):
        op.create_table(
            "arrival_suppliers",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("arrival_id", sa.Integer(), sa.ForeignKey("arrivals.id", ondelete="CASCADE"), nullable=False),
            sa.Column("supplier_id", sa.Integer(), sa.ForeignKey("suppliers.id", ondelete="CASCADE"), nullable=False),
            sa.Column("goods_value", sa.Float(), nullable=True),
            sa.Column("currency", sa.String(length=8), nullable=True),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("arrival_id", "supplier_id", name="uq_arrival_supplier"),
        )
        try:
            op.create_index(
                "ix_arrival_suppliers_arrival_id",
                "arrival_suppliers",
                ["arrival_id"],
                unique=False,
            )
        except Exception:
            pass
        try:
            op.create_index(
                "ix_arrival_suppliers_supplier_id",
                "arrival_suppliers",
                ["supplier_id"],
                unique=False,
            )
        except Exception:
            pass

    try:
        with op.batch_alter_table("arrivals") as batch:
            batch.add_column(sa.Column("country", sa.String(length=2), nullable=True))
    except Exception:
        pass


def downgrade() -> None:
    try:
        with op.batch_alter_table("arrivals") as batch:
            batch.drop_column("country")
    except Exception:
        pass

    for index_name in (
        "ix_arrival_suppliers_supplier_id",
        "ix_arrival_suppliers_arrival_id",
    ):
        try:
            op.drop_index(index_name, table_name="arrival_suppliers")
        except Exception:
            pass
    try:
        op.drop_table("arrival_suppliers")
    except Exception:
        pass

    for index_name in ("ix_suppliers_is_active", "ix_suppliers_name"):
        try:
            op.drop_index(index_name, table_name="suppliers")
        except Exception:
            pass
    try:
        op.drop_table("suppliers")
    except Exception:
        pass


"""extend containers business fields

Revision ID: 9f0a_extend_containers_fields
Revises: 033b50f0825b
Create Date: 2025-09-16 00:00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "9f0a_extend_containers_fields"
down_revision: Union[str, Sequence[str], None] = "033b50f0825b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("containers") as batch_op:
        batch_op.add_column(sa.Column("supplier", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("proforma_no", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("etd", sa.Date(), nullable=True))
        batch_op.add_column(sa.Column("delivery", sa.Date(), nullable=True))
        batch_op.add_column(sa.Column("cargo_qty", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("cargo", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("container_no", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("roba", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("contain_price", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("agent", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("total", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("deposit", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("balance", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("paid", sa.Boolean(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("containers") as batch_op:
        batch_op.drop_column("paid")
        batch_op.drop_column("balance")
        batch_op.drop_column("deposit")
        batch_op.drop_column("total")
        batch_op.drop_column("agent")
        batch_op.drop_column("contain_price")
        batch_op.drop_column("roba")
        batch_op.drop_column("container_no")
        batch_op.drop_column("cargo")
        batch_op.drop_column("cargo_qty")
        batch_op.drop_column("delivery")
        batch_op.drop_column("etd")
        batch_op.drop_column("proforma_no")
        batch_op.drop_column("supplier")


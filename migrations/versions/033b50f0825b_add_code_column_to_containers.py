"""add code/status/note/arrived_at to containers

Revision ID: 033b50f0825b
Revises: d817250d8f52
Create Date: 2025-09-15 00:00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "033b50f0825b"
down_revision: Union[str, Sequence[str], None] = "d817250d8f52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SAMO dodajemo kolone/indexe – ništa se ne briše.
    with op.batch_alter_table("containers") as batch_op:
        batch_op.add_column(sa.Column("code", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("status", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("note", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("arrived_at", sa.DateTime(), nullable=True))

    op.create_index("ix_containers_status", "containers", ["status"])
    op.create_index("ix_containers_created_at", "containers", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_containers_created_at", table_name="containers")
    op.drop_index("ix_containers_status", table_name="containers")
    with op.batch_alter_table("containers") as batch_op:
        batch_op.drop_column("arrived_at")
        batch_op.drop_column("note")
        batch_op.drop_column("status")
        batch_op.drop_column("code")
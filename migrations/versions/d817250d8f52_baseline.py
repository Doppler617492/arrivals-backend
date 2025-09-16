"""baseline

Revision ID: d817250d8f52
Revises: 
Create Date: 2025-09-13 19:04:26.257217
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "d817250d8f52"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    NON-DESTRUCTIVE migration.
    - Adds new columns to the existing `containers` table.
    - Creates helpful indexes.
    - DOES NOT drop or modify any other tables/columns.
    """
    # Add new columns if they don't exist yet (batch_alter_table is safe for PG)
    with op.batch_alter_table("containers") as batch_op:
        batch_op.add_column(sa.Column("code", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("status", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("note", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("arrived_at", sa.DateTime(), nullable=True))

    # Helpful indexes
    op.create_index("ix_containers_status", "containers", ["status"])
    op.create_index("ix_containers_created_at", "containers", ["created_at"])


def downgrade() -> None:
    """
    Revert only what we added in this revision.
    """
    # Drop indexes first
    op.drop_index("ix_containers_created_at", table_name="containers")
    op.drop_index("ix_containers_status", table_name="containers")

    # Then drop the columns we added
    with op.batch_alter_table("containers") as batch_op:
        batch_op.drop_column("arrived_at")
        batch_op.drop_column("note")
        batch_op.drop_column("status")
        batch_op.drop_column("code")
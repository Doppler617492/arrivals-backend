"""add category column to arrivals

Revision ID: 8a2f_add_category_to_arrivals
Revises: 7b1c_users_enterprise
Create Date: 2025-09-22 00:00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "8a2f_add_category_to_arrivals"
down_revision: Union[str, Sequence[str], None] = "7b1c_users_enterprise"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        with op.batch_alter_table("arrivals") as batch:
            batch.add_column(sa.Column("category", sa.String(length=255), nullable=True))
    except Exception:
        # safe if column already exists
        pass


def downgrade() -> None:
    try:
        with op.batch_alter_table("arrivals") as batch:
            batch.drop_column("category")
    except Exception:
        pass


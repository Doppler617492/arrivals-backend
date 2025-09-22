"""add dedup_key and event to notifications

Revision ID: 8b3a_notifications_dedup_event
Revises: 8a2f_add_category_to_arrivals
Create Date: 2025-09-22 09:00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "8b3a_notifications_dedup_event"
down_revision: Union[str, Sequence[str], None] = "8a2f_add_category_to_arrivals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("notifications") as batch:
        try:
            batch.add_column(sa.Column("event", sa.String(length=64), nullable=True))
        except Exception:
            pass
        try:
            batch.add_column(sa.Column("dedup_key", sa.String(length=255), nullable=True))
        except Exception:
            pass
    try:
        op.create_index("ix_notifications_event", "notifications", ["event"])
    except Exception:
        pass
    try:
        op.create_unique_constraint("uq_notifications_dedup_key", "notifications", ["dedup_key"])
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_constraint("uq_notifications_dedup_key", "notifications", type_="unique")
    except Exception:
        pass
    try:
        op.drop_index("ix_notifications_event", table_name="notifications")
    except Exception:
        pass
    with op.batch_alter_table("notifications") as batch:
        try:
            batch.drop_column("dedup_key")
        except Exception:
            pass
        try:
            batch.drop_column("event")
        except Exception:
            pass


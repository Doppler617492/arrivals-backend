"""merge multiple heads

Revision ID: 9f7ccc820fcc
Revises: 8b3a_notifications_dedup_event, 9f0a_extend_containers_fields, b1c2_add_arrival_countries
Create Date: 2025-10-02 19:17:58.865519

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9f7ccc820fcc'
down_revision: Union[str, Sequence[str], None] = ('8b3a_notifications_dedup_event', '9f0a_extend_containers_fields', 'b1c2_add_arrival_countries')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass

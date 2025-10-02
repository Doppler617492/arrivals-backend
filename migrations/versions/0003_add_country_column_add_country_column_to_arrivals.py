"""add country column to arrivals

Revision ID: 0003_add_country_column
Revises: 0002_add_countries
Create Date: 2025-10-02 22:01:53.556578

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


TABLE_NAME = "arrivals"
COLUMN_NAME = "country"
INDEX_NAME = "ix_arrivals_country"


# revision identifiers, used by Alembic.
revision: str = '0003_add_country_column'
down_revision: Union[str, Sequence[str], None] = '0002_add_countries'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_columns = {col["name"] for col in inspector.get_columns(TABLE_NAME)}
    if COLUMN_NAME not in existing_columns:
        op.add_column(TABLE_NAME, sa.Column(COLUMN_NAME, sa.String(length=10), nullable=True))

    existing_indexes = {idx["name"] for idx in inspector.get_indexes(TABLE_NAME)}
    if INDEX_NAME not in existing_indexes:
        op.create_index(INDEX_NAME, TABLE_NAME, [COLUMN_NAME])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_indexes = {idx["name"] for idx in inspector.get_indexes(TABLE_NAME)}
    if INDEX_NAME in existing_indexes:
        op.drop_index(INDEX_NAME, table_name=TABLE_NAME)

    existing_columns = {col["name"] for col in inspector.get_columns(TABLE_NAME)}
    if COLUMN_NAME in existing_columns:
        op.drop_column(TABLE_NAME, COLUMN_NAME)

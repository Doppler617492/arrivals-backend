"""
users enterprise: new columns and tables

Revision ID: 7b1c_users_enterprise
Revises: d817250d8f52_baseline
Create Date: 2025-09-19 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = '7b1c_users_enterprise'
down_revision = 'd817250d8f52_baseline'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # users extra columns (idempotent adds)
    bind = op.get_bind()
    inspector = inspect(bind)
    existing_columns = {col.get('name') for col in inspector.get_columns('users')}
    with op.batch_alter_table('users') as batch:
        if 'username' not in existing_columns:
            batch.add_column(sa.Column('username', sa.String(length=255), nullable=True))
        if 'phone' not in existing_columns:
            batch.add_column(sa.Column('phone', sa.String(length=64), nullable=True))
        if 'status' not in existing_columns:
            batch.add_column(sa.Column('status', sa.String(length=32), nullable=True))
        if 'type' not in existing_columns:
            batch.add_column(sa.Column('type', sa.String(length=32), nullable=True))
        if 'last_activity_at' not in existing_columns:
            batch.add_column(sa.Column('last_activity_at', sa.DateTime(), nullable=True))
        if 'last_login_at' not in existing_columns:
            batch.add_column(sa.Column('last_login_at', sa.DateTime(), nullable=True))
        if 'failed_logins' not in existing_columns:
            batch.add_column(sa.Column('failed_logins', sa.Integer(), nullable=True))
        if 'must_change_password' not in existing_columns:
            batch.add_column(sa.Column('must_change_password', sa.Boolean(), nullable=True))
        if 'require_password_change' not in existing_columns:
            batch.add_column(sa.Column('require_password_change', sa.Boolean(), nullable=True))
        if 'note' not in existing_columns:
            batch.add_column(sa.Column('note', sa.Text(), nullable=True))
        if 'deleted_at' not in existing_columns:
            batch.add_column(sa.Column('deleted_at', sa.DateTime(), nullable=True))

    # roles
    op.create_table('roles',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('key', sa.String(length=64), nullable=True, index=True),
        sa.Column('name', sa.String(length=255), nullable=True),
    )

    op.create_table('user_roles',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False),
        sa.Column('role_id', sa.Integer(), sa.ForeignKey('roles.id', ondelete='CASCADE'), index=True, nullable=False),
        sa.Column('scope_location_ids', sa.Text(), nullable=True),
    )

    op.create_table('user_locations',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False),
        sa.Column('location', sa.String(length=255), index=True),
    )

    # sessions
    op.create_table('sessions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False),
        sa.Column('ip', sa.String(length=64)),
        sa.Column('ua', sa.Text()),
        sa.Column('os', sa.String(length=128)),
        sa.Column('jti', sa.String(length=128), index=True),
        sa.Column('trusted', sa.Boolean(), default=False),
        sa.Column('revoked', sa.Boolean(), default=False),
        sa.Column('last_seen_at', sa.DateTime()),
        sa.Column('created_at', sa.DateTime()),
    )

    # notification prefs
    op.create_table('notification_prefs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False),
        sa.Column('channel', sa.String(length=32)),
        sa.Column('event_key', sa.String(length=64)),
        sa.Column('enabled', sa.Boolean(), default=True),
        sa.Column('frequency', sa.String(length=32)),
    )

    # audit logs
    op.create_table('audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('actor_user_id', sa.Integer(), index=True),
        sa.Column('event', sa.String(length=128)),
        sa.Column('target_type', sa.String(length=64)),
        sa.Column('target_id', sa.Integer()),
        sa.Column('meta', sa.Text()),
        sa.Column('created_at', sa.DateTime()),
    )

    # user notes/files
    op.create_table('user_notes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False),
        sa.Column('author_id', sa.Integer(), index=True),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime()),
    )

    op.create_table('user_files',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), index=True, nullable=False),
        sa.Column('file_path', sa.String(length=512), nullable=False),
        sa.Column('label', sa.String(length=255)),
        sa.Column('created_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('user_files')
    op.drop_table('user_notes')
    op.drop_table('audit_logs')
    op.drop_table('notification_prefs')
    op.drop_table('sessions')
    op.drop_table('user_locations')
    op.drop_table('user_roles')
    op.drop_table('roles')
    # keep user columns; dropping may lose data — optional safe drops commented out

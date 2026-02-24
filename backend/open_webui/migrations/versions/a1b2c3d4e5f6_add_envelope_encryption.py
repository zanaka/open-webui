"""Add envelope encryption columns to auth table

Revision ID: a1b2c3d4e5f6
Revises: c440947495f3
Create Date: 2026-02-15 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "a1b2c3d4e5f6"
down_revision = "c440947495f3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("auth", sa.Column("kdf_salt", sa.LargeBinary(), nullable=False))
    op.add_column("auth", sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False))


def downgrade():
    op.drop_column("auth", "wrapped_dek")
    op.drop_column("auth", "kdf_salt")

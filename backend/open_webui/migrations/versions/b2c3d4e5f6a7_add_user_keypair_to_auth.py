"""Add per-user RSA keypair columns to auth table

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-19 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("auth", sa.Column("public_key", sa.LargeBinary(), nullable=False))
    op.add_column(
        "auth", sa.Column("wrapped_private_key", sa.LargeBinary(), nullable=False)
    )


def downgrade():
    op.drop_column("auth", "wrapped_private_key")
    op.drop_column("auth", "public_key")

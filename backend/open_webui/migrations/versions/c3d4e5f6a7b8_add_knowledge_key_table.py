"""Add knowledge_key table (per-knowledge KDEK wrapped per user public key)

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-21 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f6a7b8"
down_revision = "za0002b3c4d5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "knowledge_key",
        sa.Column("knowledge_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("wrapped_kdek", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["knowledge_id"], ["knowledge.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("knowledge_id", "user_id"),
    )


def downgrade():
    op.drop_table("knowledge_key")

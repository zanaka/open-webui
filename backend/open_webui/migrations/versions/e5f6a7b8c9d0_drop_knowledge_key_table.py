"""Drop the knowledge_key table

Knowledge bases are now keyed through resource_key like every other shared
resource. Leaving knowledge_key behind would leave wrapped keys for content
that is protected by a different key, with nothing reading them.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-29 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table("knowledge_key")


def downgrade():
    op.create_table(
        "knowledge_key",
        sa.Column("knowledge_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("wrapped_kdek", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(["knowledge_id"], ["knowledge.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("knowledge_id", "user_id"),
    )

"""Add the resource_key table

One content key per shared resource, stored once per person who may open it.
Replaces knowledge_key, which was tied to the knowledge table by a foreign key
and so could not be used for anything else. The old table is left in place for
now; nothing reads it once knowledge moves across.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-28 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "resource_key",
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("wrapped_key", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint(
            "resource_type", "resource_id", "user_id", name="pk_resource_key"
        ),
    )
    op.create_index(
        "resource_key_resource_idx",
        "resource_key",
        ["resource_type", "resource_id"],
    )


def downgrade():
    op.drop_index("resource_key_resource_idx", table_name="resource_key")
    op.drop_table("resource_key")

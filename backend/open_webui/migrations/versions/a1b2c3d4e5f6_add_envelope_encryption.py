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


def _column_exists(table_name: str, column_name: str) -> bool:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = inspector.get_columns(table_name)
    return any(col["name"] == column_name for col in columns)


def upgrade():
    if not _column_exists("auth", "kdf_salt"):
        op.add_column("auth", sa.Column("kdf_salt", sa.LargeBinary(), nullable=True))
    if not _column_exists("auth", "wrapped_dek"):
        op.add_column(
            "auth", sa.Column("wrapped_dek", sa.LargeBinary(), nullable=True)
        )


def downgrade():
    if _column_exists("auth", "wrapped_dek"):
        op.drop_column("auth", "wrapped_dek")
    if _column_exists("auth", "kdf_salt"):
        op.drop_column("auth", "kdf_salt")

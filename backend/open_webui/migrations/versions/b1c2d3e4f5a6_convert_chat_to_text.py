"""Convert chat.chat column from JSON to Text for EncryptedJSON

Revision ID: b1c2d3e4f5a6
Revises: a1b2c3d4e5f6
Create Date: 2026-02-15 01:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, select
import json

revision = "b1c2d3e4f5a6"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def _column_exists(table_name: str, column_name: str) -> bool:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = inspector.get_columns(table_name)
    return any(col["name"] == column_name for col in columns)


def _get_column_type(table_name: str, column_name: str):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = inspector.get_columns(table_name)
    for col in columns:
        if col["name"] == column_name:
            return col["type"]
    return None


def _convert_json_column_to_text(table_name: str, column_name: str):
    """Convert a JSON column to Text, preserving data as JSON strings."""
    col_type = _get_column_type(table_name, column_name)
    if col_type is None:
        return

    # Already Text — nothing to do
    if isinstance(col_type, sa.Text):
        return

    old_col = f"old_{column_name}"

    # Clean up any leftover from a previous failed migration
    if _column_exists(table_name, old_col):
        op.drop_column(table_name, old_col)

    # Rename current column
    op.alter_column(
        table_name, column_name, new_column_name=old_col, existing_type=col_type
    )

    # Add new Text column
    op.add_column(table_name, sa.Column(column_name, sa.Text(), nullable=True))

    # Migrate data: JSON → json.dumps() → Text
    tbl = table(
        table_name,
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(old_col, sa.JSON()),
        sa.Column(column_name, sa.Text()),
    )

    conn = op.get_bind()
    rows = conn.execute(select(tbl.c.id, getattr(tbl.c, old_col)))
    for row in rows:
        value = getattr(row, old_col)
        text_value = json.dumps(value) if value is not None else None
        conn.execute(
            sa.update(tbl).where(tbl.c.id == row.id).values(**{column_name: text_value})
        )

    # Drop old column
    op.drop_column(table_name, old_col)


def _convert_text_column_to_json(table_name: str, column_name: str):
    """Convert a Text column back to JSON (downgrade)."""
    col_type = _get_column_type(table_name, column_name)
    if col_type is None:
        return

    if not isinstance(col_type, sa.Text):
        return

    old_col = f"old_{column_name}"

    if _column_exists(table_name, old_col):
        op.drop_column(table_name, old_col)

    op.alter_column(
        table_name, column_name, new_column_name=old_col, existing_type=sa.Text()
    )

    op.add_column(table_name, sa.Column(column_name, sa.JSON(), nullable=True))

    tbl = table(
        table_name,
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(old_col, sa.Text()),
        sa.Column(column_name, sa.JSON()),
    )

    conn = op.get_bind()
    rows = conn.execute(select(tbl.c.id, getattr(tbl.c, old_col)))
    for row in rows:
        value = getattr(row, old_col)
        if value is not None:
            try:
                json_value = json.loads(value)
            except json.JSONDecodeError:
                json_value = None
        else:
            json_value = None
        conn.execute(
            sa.update(tbl)
            .where(tbl.c.id == row.id)
            .values(**{column_name: json_value})
        )

    op.drop_column(table_name, old_col)


def upgrade():
    _convert_json_column_to_text("chat", "chat")


def downgrade():
    _convert_text_column_to_json("chat", "chat")

"""merge fork crypto branch with upstream v0.11.1

Revision ID: za0004merge11
Revises: e5f6a7b8c9d0, d4c1a8e37b62
Create Date: 2026-08-29 00:00:00.000000

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = 'za0004merge11'
down_revision: tuple[str, str] = ('e5f6a7b8c9d0', 'd4c1a8e37b62')
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

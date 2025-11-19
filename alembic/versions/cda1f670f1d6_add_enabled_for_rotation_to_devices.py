"""add_enabled_for_rotation_to_devices

Revision ID: cda1f670f1d6
Revises: af1104902ab1
Create Date: 2025-08-28 17:07:17.450647

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "cda1f670f1d6"
down_revision: Union[str, None] = "af1104902ab1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add enabled_for_rotation column to wvds table
    op.add_column("wvds", sa.Column("enabled_for_rotation", sa.Boolean(), nullable=False, server_default="0"))

    # Add enabled_for_rotation column to prds table
    op.add_column("prds", sa.Column("enabled_for_rotation", sa.Boolean(), nullable=False, server_default="0"))


def downgrade() -> None:
    # Remove enabled_for_rotation column from prds table
    op.drop_column("prds", "enabled_for_rotation")

    # Remove enabled_for_rotation column from wvds table
    op.drop_column("wvds", "enabled_for_rotation")

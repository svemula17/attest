"""Schema v2: questionnaires, notifications, package_exports, and the drafts link
to a questionnaire (questionnaire_id + the customer's own question ref).

Hand-written to match ``attest.db.Base.metadata`` (schema version 2) exactly;
tests/test_migrations.py compares the two through the SQLAlchemy inspector and
checks that a database at 0001 upgrades cleanly.

The ``drafts`` change runs in batch mode: SQLite cannot ALTER a table to add a
foreign key, so the table is recreated with the two new columns appended, which
matches the column order the model declares.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-11

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, Sequence[str], None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA_VERSION = 2

_settings = sa.table("settings", sa.column("key", sa.String(length=64)), sa.column("value", sa.JSON()))


def upgrade() -> None:
    op.create_table(
        "questionnaires",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("source_file", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False),
    )
    op.create_index("ix_questionnaires_created_at", "questionnaires", ["created_at"])

    with op.batch_alter_table("drafts") as batch:
        batch.add_column(sa.Column("questionnaire_id", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("ref", sa.String(length=64), nullable=True))
        batch.create_foreign_key("fk_drafts_questionnaire_id", "questionnaires", ["questionnaire_id"], ["id"])
    op.create_index("ix_drafts_questionnaire_id", "drafts", ["questionnaire_id"])

    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("control_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("dedupe_key", sa.String(length=256), nullable=False),
        sa.Column("target", sa.String(length=16), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=True),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("due", sa.String(length=10), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("sent_at", sa.String(length=32), nullable=False),
    )
    op.create_index("ix_notifications_control_id", "notifications", ["control_id"])
    op.create_index("ix_notifications_dedupe_key", "notifications", ["dedupe_key"], unique=True)
    op.create_index("ix_notifications_sent_at", "notifications", ["sent_at"])

    op.create_table(
        "package_exports",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("framework", sa.String(length=32), nullable=True),
        sa.Column("since", sa.String(length=32), nullable=True),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
    )
    op.create_index("ix_package_exports_created_at", "package_exports", ["created_at"])
    op.create_index("ix_package_exports_sha256", "package_exports", ["sha256"])

    # Same stamp init_db() writes for a fresh v2 database.
    op.execute(_settings.update().where(_settings.c.key == "schema_version").values(value={"version": SCHEMA_VERSION}))


def downgrade() -> None:
    op.execute(_settings.update().where(_settings.c.key == "schema_version").values(value={"version": 1}))
    op.drop_index("ix_package_exports_sha256", table_name="package_exports")
    op.drop_index("ix_package_exports_created_at", table_name="package_exports")
    op.drop_table("package_exports")
    op.drop_index("ix_notifications_sent_at", table_name="notifications")
    op.drop_index("ix_notifications_dedupe_key", table_name="notifications")
    op.drop_index("ix_notifications_control_id", table_name="notifications")
    op.drop_table("notifications")
    op.drop_index("ix_drafts_questionnaire_id", table_name="drafts")
    with op.batch_alter_table("drafts") as batch:
        batch.drop_constraint("fk_drafts_questionnaire_id", type_="foreignkey")
        batch.drop_column("ref")
        batch.drop_column("questionnaire_id")
    op.drop_index("ix_questionnaires_created_at", table_name="questionnaires")
    op.drop_table("questionnaires")

"""Initial schema: evidence, audit, control_snapshots, collector_runs, drafts,
risk_acceptances, users, api_keys, settings.

Hand-written to match ``attest.db.Base.metadata`` (schema version 1) exactly;
tests/test_migrations.py compares the two through the SQLAlchemy inspector.

Revision ID: 0001
Revises:
Create Date: 2026-09-11

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCHEMA_VERSION = 1


def upgrade() -> None:
    op.create_table(
        "collector_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("source_id", sa.String(length=64), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.String(length=32), nullable=False),
        sa.Column("finished_at", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("records", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_by", sa.String(length=128), nullable=True),
    )
    op.create_index("ix_collector_runs_source_id", "collector_runs", ["source_id"])
    op.create_index("ix_collector_runs_started_at", "collector_runs", ["started_at"])

    op.create_table(
        "evidence",
        sa.Column("seq", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=128), nullable=False),
        sa.Column("control_ids", sa.JSON(), nullable=False),
        sa.Column("classification", sa.String(length=16), nullable=False),
        sa.Column("collected_at", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("prev_sha256", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("collector_runs.id"), nullable=True),
    )
    op.create_index("ix_evidence_id", "evidence", ["id"], unique=True)
    op.create_index("ix_evidence_source", "evidence", ["source"])
    op.create_index("ix_evidence_kind", "evidence", ["kind"])
    op.create_index("ix_evidence_classification", "evidence", ["classification"])
    op.create_index("ix_evidence_collected_at", "evidence", ["collected_at"])
    op.create_index("ix_evidence_sha256", "evidence", ["sha256"])

    op.create_table(
        "audit",
        sa.Column("seq", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ts", sa.String(length=32), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("rule", sa.String(length=64), nullable=True),
        sa.Column("model_version", sa.String(length=128), nullable=True),
        sa.Column("approver", sa.String(length=128), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("prev_sha256", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_audit_ts", "audit", ["ts"])
    op.create_index("ix_audit_actor", "audit", ["actor"])
    op.create_index("ix_audit_action", "audit", ["action"])

    op.create_table(
        "control_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("evaluated_at", sa.String(length=32), nullable=False),
        sa.Column("control_id", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
    )
    op.create_index("ix_control_snapshots_evaluated_at", "control_snapshots", ["evaluated_at"])
    op.create_index("ix_control_snapshots_control_id", "control_snapshots", ["control_id"])

    op.create_table(
        "drafts",
        sa.Column("question_id", sa.String(length=32), primary_key=True),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("control_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("answer", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("citations", sa.JSON(), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("model_version", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=True),
        sa.Column("approver", sa.String(length=128), nullable=True),
        sa.Column("decided_at", sa.String(length=32), nullable=True),
        sa.Column("signature", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_drafts_created_at", "drafts", ["created_at"])

    op.create_table(
        "risk_acceptances",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("control_id", sa.String(length=32), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires", sa.String(length=10), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("revoked_at", sa.String(length=32), nullable=True),
    )
    op.create_index("ix_risk_acceptances_control_id", "risk_acceptances", ["control_id"])

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(length=256), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("prefix", sa.String(length=12), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("last_used_at", sa.String(length=32), nullable=True),
        sa.Column("revoked_at", sa.String(length=32), nullable=True),
        sa.UniqueConstraint("key_hash"),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("ix_api_keys_prefix", "api_keys", ["prefix"])

    settings = op.create_table(
        "settings",
        sa.Column("key", sa.String(length=64), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.UniqueConstraint("key"),
    )
    # Same stamp init_db() writes, so code reading settings.schema_version sees one answer.
    op.bulk_insert(settings, [{"key": "schema_version", "value": {"version": SCHEMA_VERSION}}])


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_index("ix_api_keys_prefix", table_name="api_keys")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
    op.drop_index("ix_risk_acceptances_control_id", table_name="risk_acceptances")
    op.drop_table("risk_acceptances")
    op.drop_index("ix_drafts_created_at", table_name="drafts")
    op.drop_table("drafts")
    op.drop_index("ix_control_snapshots_control_id", table_name="control_snapshots")
    op.drop_index("ix_control_snapshots_evaluated_at", table_name="control_snapshots")
    op.drop_table("control_snapshots")
    op.drop_index("ix_audit_action", table_name="audit")
    op.drop_index("ix_audit_actor", table_name="audit")
    op.drop_index("ix_audit_ts", table_name="audit")
    op.drop_table("audit")
    op.drop_index("ix_evidence_sha256", table_name="evidence")
    op.drop_index("ix_evidence_collected_at", table_name="evidence")
    op.drop_index("ix_evidence_classification", table_name="evidence")
    op.drop_index("ix_evidence_kind", table_name="evidence")
    op.drop_index("ix_evidence_source", table_name="evidence")
    op.drop_index("ix_evidence_id", table_name="evidence")
    op.drop_table("evidence")
    op.drop_index("ix_collector_runs_started_at", table_name="collector_runs")
    op.drop_index("ix_collector_runs_source_id", table_name="collector_runs")
    op.drop_table("collector_runs")

"""SQLAlchemy ORM models for the dashboard storage layer."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import (JSON, Boolean, CheckConstraint, Float, Index, Integer,
                        String)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from ai_pr_reviewer import storage_schema as _schema


class Base(DeclarativeBase):
    pass


class ReportRow(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(140), primary_key=True)
    repo: Mapped[str] = mapped_column(String(200), default="", index=True)
    pr_number: Mapped[int] = mapped_column(Integer, default=0)
    pr_title: Mapped[str] = mapped_column(String(300), default="")
    author: Mapped[str] = mapped_column(String(100), default="")
    branch: Mapped[str] = mapped_column(String(200), default="")
    mode: Mapped[str] = mapped_column(String(40), default="")
    model: Mapped[str] = mapped_column(String(100), default="")
    reviewed_at: Mapped[str] = mapped_column(String(32), default="", index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    files: Mapped[int] = mapped_column(Integer, default=0)
    additions: Mapped[int] = mapped_column(Integer, default=0)
    deletions: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    severity_counts: Mapped[dict] = mapped_column(JSON, default=dict)
    categories: Mapped[dict] = mapped_column(JSON, default=dict)
    # V3-E04-T05: light metric columns mirrored from payload at upsert, so
    # metrics() aggregates in SQL without parsing report JSON. Existing
    # databases gain them additively in DbStorage._add_missing_columns and
    # get a one-time payload-derived backfill there.
    engine: Mapped[str] = mapped_column(String(40), default="static")
    fallback_used: Mapped[int] = mapped_column(Integer, default=0)
    health_score: Mapped[float] = mapped_column(Float, default=100.0)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class ReviewStateRow(Base):
    __tablename__ = "review_states"

    id: Mapped[str] = mapped_column(String(220), primary_key=True)  # repo_pr_key(repo, pr_number)
    repo: Mapped[str] = mapped_column(String(200), default="", index=True)
    pr_number: Mapped[int] = mapped_column(Integer, default=0, index=True)
    last_reviewed_sha: Mapped[str] = mapped_column(String(40), default="")
    base_sha: Mapped[str] = mapped_column(String(40), default="")
    updated_at: Mapped[str] = mapped_column(String(32), default="")


class FindingHistoryRow(Base):
    __tablename__ = "finding_histories"
    # V3-E04-T05: composite index for the (repo, pr_number) lookups every
    # get_previous_findings / list_findings(repo=...) performs; declared on
    # the model for fresh databases and created idempotently for legacy
    # databases in DbStorage.init().
    __table_args__ = (
        Index("ix_finding_histories_repo_pr", "repo", "pr_number"),
    )

    id: Mapped[str] = mapped_column(String(300), primary_key=True)  # finding_history_key(repo, pr_number, fingerprint)
    repo: Mapped[str] = mapped_column(String(200), default="", index=True)
    pr_number: Mapped[int] = mapped_column(Integer, default=0, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    state: Mapped[str] = mapped_column(String(32), default="new")
    first_seen_sha: Mapped[str] = mapped_column(String(40), default="")
    last_seen_sha: Mapped[str] = mapped_column(String(40), default="")
    resolved_at: Mapped[str] = mapped_column(String(32), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[str] = mapped_column(String(32), default="")


class RepoMemoryRow(Base):
    __tablename__ = "repo_memories"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    repo: Mapped[str] = mapped_column(String(200), default="", index=True)
    path_pattern: Mapped[str] = mapped_column(String(255), default="*")
    note: Mapped[str] = mapped_column(String(1000), default="")
    created_at: Mapped[str] = mapped_column(String(32), default="")
    # V3 C7: human-authored metadata. ``category`` is one of
    # ai_pr_reviewer.memory.CATEGORIES (anything else reads as the default
    # "project-rule"), ``enabled == 0`` keeps a note on the dashboard
    # without feeding it to the reviewer, ``updated_at`` records edits.
    category: Mapped[str] = mapped_column(String(64), default="project-rule")
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[str] = mapped_column(String(32), default="")


class TelemetryRow(Base):
    """V3-E02-T04 — one row per review run's telemetry (additive table).

    Scalar columns exist so ``/api/metrics`` can aggregate without
    walking every payload; ``payload`` keeps the full allowlisted row
    (``telemetry.to_telemetry_row`` output). Token columns are *NULL*
    when usage was unavailable — absence stays a typed state, never a
    measured 0.
    """

    __tablename__ = "telemetry"

    id: Mapped[str] = mapped_column(String(140), primary_key=True)  # review id
    repo: Mapped[str] = mapped_column(String(200), default="", index=True)
    pr_number: Mapped[int] = mapped_column(Integer, default=0)
    provider: Mapped[str] = mapped_column(String(40), default="")
    model: Mapped[str] = mapped_column(String(100), default="")
    input_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    usage_state: Mapped[str] = mapped_column(String(20), default="n/a")
    batch_count: Mapped[int] = mapped_column(Integer, default=0)
    fallback_used: Mapped[int] = mapped_column(Integer, default=0)
    call_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    updated_at: Mapped[str] = mapped_column(String(32), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class FeedbackEventRow(Base):
    """V4-E09-T01 — one human vote on a finding fingerprint (additive table).

    A *record*: the engine never reads these rows to change behavior.
    Scoped per repository on every row; ``origin`` is CHECK-constrained to
    the two authenticated entry points. Constraints and columns mirror
    ``storage_schema`` (asserted by ``tests/test_feedback.py``).
    """

    __tablename__ = _schema.FEEDBACK_EVENTS_TABLE
    __table_args__ = (
        *(CheckConstraint(sql, name=name)
          for name, sql in _schema.FEEDBACK_EVENT_CHECKS),
        Index("ix_feedback_events_repo_created", "repo", "created_at"),
        Index("ix_feedback_events_repo_fingerprint", "repo", "fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    repo: Mapped[str] = mapped_column(String(200), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    note: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    origin: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)


class SuppressionRuleRow(Base):
    """V4-E09-T01 — one human-authored suppression rule (additive table).

    THE INVARIANT lives partly here: ``origin`` is NOT NULL and CHECKed to
    the authenticated origins, a rule's shape is CHECKed so it can never
    match everything, and ``expires_at`` is NOT NULL (every rule expires).
    A forged row — origin ``model``, ``pr``, ``engine`` — is rejected by the
    database itself, whatever code tried to write it.
    """

    __tablename__ = _schema.SUPPRESSION_RULES_TABLE
    __table_args__ = (
        *(CheckConstraint(sql, name=name)
          for name, sql in _schema.SUPPRESSION_RULE_CHECKS),
        Index("ix_suppression_rules_repo", "repo", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    repo: Mapped[str] = mapped_column(String(200), nullable=False)
    match_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False,
                                             default="")
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False,
                                         default="")
    path_glob: Mapped[str] = mapped_column(String(255), nullable=False,
                                           default="")
    reason: Mapped[str] = mapped_column(String(500), nullable=False,
                                        default="")
    origin: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(32), nullable=False)
    disabled_at: Mapped[str] = mapped_column(String(32), nullable=False,
                                             default="")
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

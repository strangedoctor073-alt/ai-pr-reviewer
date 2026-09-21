"""SQLAlchemy ORM models for the dashboard storage layer."""
from __future__ import annotations

from sqlalchemy import JSON, Boolean, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


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
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class ReviewStateRow(Base):
    __tablename__ = "review_states"

    id: Mapped[str] = mapped_column(String(220), primary_key=True)  # f"{repo}#{pr_number}"
    repo: Mapped[str] = mapped_column(String(200), default="", index=True)
    pr_number: Mapped[int] = mapped_column(Integer, default=0, index=True)
    last_reviewed_sha: Mapped[str] = mapped_column(String(40), default="")
    base_sha: Mapped[str] = mapped_column(String(40), default="")
    updated_at: Mapped[str] = mapped_column(String(32), default="")


class FindingHistoryRow(Base):
    __tablename__ = "finding_histories"

    id: Mapped[str] = mapped_column(String(300), primary_key=True)  # f"{repo}#{pr_number}#{fingerprint}"
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


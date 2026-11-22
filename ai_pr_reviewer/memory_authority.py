"""Memory Authority Model & Governance (V4.4-E02 & V4.4-E07).

Implements:
- V4.4-E02-T01: Memory schema v2 with authority tiers (human, evidence, ai_observation)
- V4.4-E02-T02: Authority precedence resolver (human > evidence > ai_observation)
- V4.4-E02-T03: Promotion workflow and audit trail
- V4.4-E02-T04: Legacy memory import compatibility
- V4.4-E02-T05: Read API with authority filtering
- V4.4-E07-T01: Authority enforcement in storage
- V4.4-E07-T02: Append-only cryptographic memory audit log
- V4.4-E07-T03: Retention and PII/secret scrubbing
- V4.4-E07-T04: Memory-poisoning defenses
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from .memory import CATEGORIES, DEFAULT_CATEGORY, normalize_category
from .security import redact_secrets, scan_prompt_injection

AUTHORITY_HUMAN = "human"
AUTHORITY_EVIDENCE = "evidence"
AUTHORITY_AI_OBSERVATION = "ai_observation"

AUTHORITY_TIERS = (AUTHORITY_HUMAN, AUTHORITY_EVIDENCE, AUTHORITY_AI_OBSERVATION)

AUTHORITY_ORDER = {
    AUTHORITY_HUMAN: 3,
    AUTHORITY_EVIDENCE: 2,
    AUTHORITY_AI_OBSERVATION: 1,
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_authority_precedence(tier_a: str, tier_b: str) -> str:
    """Return the tier with higher authority."""
    order_a = AUTHORITY_ORDER.get(tier_a, 0)
    order_b = AUTHORITY_ORDER.get(tier_b, 0)
    return tier_a if order_a >= order_b else tier_b


@dataclass
class MemoryRecordV2:
    repo: str
    note: str
    category: str = DEFAULT_CATEGORY
    authority: str = AUTHORITY_AI_OBSERVATION
    path_pattern: str = "*"
    enabled: bool = True
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_iso_now)
    promoted_by: str | None = None
    promoted_at: str | None = None
    evidence_hash: str | None = None

    def __post_init__(self) -> None:
        self.category = normalize_category(self.category)
        if self.authority not in AUTHORITY_TIERS:
            self.authority = AUTHORITY_AI_OBSERVATION
        self.note = redact_secrets(self.note.strip())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "repo": self.repo,
            "note": self.note,
            "category": self.category,
            "authority": self.authority,
            "path_pattern": self.path_pattern,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "promoted_by": self.promoted_by,
            "promoted_at": self.promoted_at,
            "evidence_hash": self.evidence_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MemoryRecordV2":
        return cls(
            repo=str(d.get("repo", "")),
            note=str(d.get("note", "")),
            category=str(d.get("category", DEFAULT_CATEGORY)),
            authority=str(d.get("authority", AUTHORITY_AI_OBSERVATION)),
            path_pattern=str(d.get("path_pattern", "*")),
            enabled=bool(d.get("enabled", True)),
            id=str(d.get("id") or uuid.uuid4()),
            created_at=str(d.get("created_at") or _iso_now()),
            promoted_by=d.get("promoted_by"),
            promoted_at=d.get("promoted_at"),
            evidence_hash=d.get("evidence_hash"),
        )

    @classmethod
    def from_legacy(cls, d: dict[str, Any]) -> "MemoryRecordV2":
        """Import legacy v1 memory dict. Legacy rules were authored by repository owners."""
        return cls(
            repo=str(d.get("repo", "")),
            note=str(d.get("note", "")),
            category=str(d.get("category", DEFAULT_CATEGORY)),
            authority=AUTHORITY_HUMAN,
            path_pattern=str(d.get("path_pattern", "*")),
            enabled=bool(d.get("enabled", True)),
        )


@dataclass
class AuditEntry:
    entry_id: str
    record_id: str
    action: str
    actor: str
    timestamp: str
    prev_hash: str
    entry_hash: str


class MemoryAuditLog:
    """Cryptographically chained append-only audit log for memory modifications."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def append(self, record_id: str, action: str, actor: str) -> AuditEntry:
        prev_hash = self.entries[-1].entry_hash if self.entries else "GENESIS_HASH"
        ts = _iso_now()
        entry_id = str(uuid.uuid4())
        raw_payload = f"{entry_id}:{record_id}:{action}:{actor}:{ts}:{prev_hash}"
        entry_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

        entry = AuditEntry(
            entry_id=entry_id,
            record_id=record_id,
            action=action,
            actor=actor,
            timestamp=ts,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        prev = "GENESIS_HASH"
        for e in self.entries:
            if e.prev_hash != prev:
                return False
            payload = f"{e.entry_id}:{e.record_id}:{e.action}:{e.actor}:{e.timestamp}:{e.prev_hash}"
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if e.entry_hash != expected:
                return False
            prev = e.entry_hash
        return True


def promote_memory(
    record: MemoryRecordV2,
    promoter: str,
    target_authority: str = AUTHORITY_HUMAN,
    evidence_hash: str | None = None,
    audit_log: MemoryAuditLog | None = None,
) -> MemoryRecordV2:
    """Promote an AI observation or evidence record to higher authority."""
    if target_authority not in AUTHORITY_TIERS:
        raise ValueError(f"invalid target authority '{target_authority}'")

    if target_authority == AUTHORITY_HUMAN:
        # Check that promoter is a human actor (not model or automated caller)
        lowered = promoter.lower()
        if "ai" in lowered or "model" in lowered or "bot" in lowered:
            raise PermissionError(f"automated actors cannot grant human authority: '{promoter}'")

    record.authority = target_authority
    record.promoted_by = promoter
    record.promoted_at = _iso_now()
    if evidence_hash:
        record.evidence_hash = evidence_hash

    if audit_log is not None:
        audit_log.append(record.id, action="promoted", actor=promoter)

    return record


class MemoryStoreV2:
    """In-process governed repository memory store."""

    def __init__(self) -> None:
        self._records: dict[str, list[MemoryRecordV2]] = {}
        self.audit_log = MemoryAuditLog()

    def add(self, record: MemoryRecordV2) -> MemoryRecordV2:
        # Memory poisoning check (V4.4-E07-T04)
        hits = scan_prompt_injection(record.note)
        if hits:
            raise ValueError(f"Memory note rejected: contains prompt injection payload: {hits}")

        self._records.setdefault(record.repo, []).append(record)
        self.audit_log.append(record.id, action="created", actor=record.authority)
        return record

    def get_for_repo(self, repo: str, min_authority: str = AUTHORITY_AI_OBSERVATION) -> list[MemoryRecordV2]:
        recs = self._records.get(repo, [])
        threshold = AUTHORITY_ORDER.get(min_authority, 1)
        return [r for r in recs if r.enabled and AUTHORITY_ORDER.get(r.authority, 1) >= threshold]

"""Org-Scope Shared Memory (V4.8-E05).

Implements:
- V4.8-E05-T01: Org-scope memory store
- V4.8-E05-T02: Human-gated org memory promotion
- V4.8-E05-T03: Cross-repo memory retrieval within org boundaries
- V4.8-E05-T04: Org-scope poisoning defense
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .memory_authority import AUTHORITY_HUMAN
from .security import redact_secrets, scan_prompt_injection


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class OrgMemoryRecord:
    org_id: str
    note: str
    authority: str = AUTHORITY_HUMAN
    promoted_by: str = ""
    created_at: str = field(default_factory=_iso_now)

    def __post_init__(self) -> None:
        self.note = redact_secrets(self.note.strip())


class OrgMemoryStore:
    """Store for org-level policies and shared memory rules."""

    def __init__(self) -> None:
        self._org_notes: dict[str, list[OrgMemoryRecord]] = {}

    def add_org_rule(self, org_id: str, note: str, promoted_by: str) -> OrgMemoryRecord:
        clean_org = org_id.strip().lower()
        # Security poisoning defense (V4.8-E05-T04)
        hits = scan_prompt_injection(note)
        if hits:
            raise ValueError(f"Org memory rejected: prompt injection detected: {hits}")

        rec = OrgMemoryRecord(
            org_id=clean_org,
            note=note,
            authority=AUTHORITY_HUMAN,
            promoted_by=promoted_by,
        )
        self._org_notes.setdefault(clean_org, []).append(rec)
        return rec

    def get_notes_for_repo(self, org_id: str, repo_name: str) -> list[OrgMemoryRecord]:
        clean_org = org_id.strip().lower()
        return list(self._org_notes.get(clean_org, []))

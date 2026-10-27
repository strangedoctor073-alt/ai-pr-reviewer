"""V4.2-E06-T03 — offline advisory source interface.

Advisories are *external, untrusted data*. This module defines the narrow
read-only interface a source must satisfy and one concrete source: a local
JSON snapshot file. **Nothing here touches the network**: no network
module is imported (a test AST-scans the whole package), the default
source is empty, and :func:`lookup_advisories` refuses any source that
does not declare ``offline = True`` unless the caller passes
``allow_network=True`` explicitly — an opt-in that needs human sign-off
under the V4.0 protocol and that no code in this repository passes.

Honesty rules baked into the result types:

* a dependency pinned to a parseable version is either ``affected`` or
  not matched; an unpinned dependency whose package has advisories on
  record is ``unverified`` (the resolved version is unknown — no claim);
* every lookup carries a *freshness label* derived from the snapshot's
  own ``generated_at`` (informational bands, never a gate);
* all advisory text is redacted, fence-neutralized, single-line and
  bounded before it is stored (it may later reach a prompt or a comment).

Snapshot schema (all keys optional except ``advisories``)::

    {"source": "name", "generated_at": "2026-10-01T00:00:00Z",
     "advisories": [{"id": "ADV-1", "ecosystem": "pip", "package": "flask",
                     "introduced": "0", "fixed": "2.2.5",
                     "severity": "high", "summary": "text"}]}
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, Sequence

from ..index.limits import is_contained, is_excluded
from ..rules import SENSITIVE_EXCLUDE_GLOBS
from ..security import redact_secrets, safe_label
from .manifests import SUPPORTED_ECOSYSTEMS, Dependency, normalize_pip_name

MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_ADVISORIES = 20_000
MAX_ADVISORIES_PER_PACKAGE = 50
MAX_ID_CHARS = 64
MAX_SUMMARY_CHARS = 300
SEVERITIES = ("low", "medium", "high", "critical", "unknown")

MATCH_AFFECTED = "affected"
MATCH_UNVERIFIED = "unverified"

FRESH_DAYS = 1
AGING_DAYS = 30
FRESHNESS_LABELS = ("fresh", "aging", "stale", "unknown")


@dataclass(frozen=True)
class Advisory:
    id: str
    ecosystem: str
    package: str                # normalized like Dependency.name
    introduced: str = "0"       # inclusive lower bound
    fixed: str = ""             # exclusive upper bound; "" = no fix known
    severity: str = "unknown"
    summary: str = ""


@dataclass(frozen=True)
class AdvisoryMatch:
    advisory: Advisory
    dependency: Dependency
    status: str                 # MATCH_AFFECTED | MATCH_UNVERIFIED


@dataclass(frozen=True)
class AdvisoryLookup:
    """Result of one lookup pass — always labelled, never raises."""

    matches: tuple[AdvisoryMatch, ...] = ()
    source: str = "none"
    freshness: str = "unknown"          # one of FRESHNESS_LABELS
    age_days: int | None = None
    available: bool = False             # False => no advisory data consulted
    warnings: tuple[str, ...] = ()


class AdvisorySource(Protocol):
    """Read-only advisory provider. ``offline`` MUST be True for default use."""

    name: str
    offline: bool
    generated_at: str | None

    def advisories_for(self, ecosystem: str, package: str) -> Sequence[Advisory]: ...


class NullAdvisorySource:
    """The default: no advisory data, honestly labelled."""

    name = "none"
    offline = True
    generated_at = None

    def advisories_for(self, ecosystem: str, package: str) -> Sequence[Advisory]:
        return ()


# ------------------------------------------------------------- versions

_NUM = re.compile(r"\d+")


def version_tuple(text: str):
    """Dotted numeric version -> tuple, or ``None`` when not comparable.

    Deliberately conservative: pre-release/epoch/local segments make a
    version *incomparable* (no claim) rather than guessed."""
    t = str(text).strip().lstrip("=v")
    if not t or not re.fullmatch(r"\d+(?:\.\d+)*", t):
        return None
    return tuple(int(x) for x in t.split("."))


def _pinned_version(dep: Dependency):
    if not dep.pinned:
        return None
    return version_tuple(dep.spec.lstrip("="))


def affects(advisory: Advisory, version: tuple[int, ...]) -> bool:
    lo = version_tuple(advisory.introduced) or (0,)
    if _pad(version) < _pad(lo):
        return False
    if advisory.fixed:
        hi = version_tuple(advisory.fixed)
        if hi is None:
            return False            # unparseable bound: no claim
        return _pad(version) < _pad(hi)
    return True


def _pad(v: tuple[int, ...], n: int = 6) -> tuple[int, ...]:
    return (v + (0,) * n)[:max(n, len(v))]


# ------------------------------------------------------- local snapshot

def _clean(value, limit: int) -> str:
    return safe_label(redact_secrets(str(value)), limit).strip()


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def freshness_label(generated_at: str | None, now: datetime | None = None):
    """``(label, age_days)`` — informational bands (≤1 d fresh, ≤30 d
    aging, older stale). ``now`` is injectable so tests need no clock."""
    dt = _parse_time(generated_at)
    if dt is None:
        return "unknown", None
    now = now or datetime.now(timezone.utc)
    age = max(0, (now - dt).days)
    if age <= FRESH_DAYS:
        return "fresh", age
    if age <= AGING_DAYS:
        return "aging", age
    return "stale", age


class SnapshotAdvisorySource:
    """In-memory advisory index built from a validated snapshot dict."""

    offline = True

    def __init__(self, name: str, generated_at: str | None,
                 advisories: Sequence[Advisory], warnings=()):
        self.name = name
        self.generated_at = generated_at
        self.warnings = tuple(warnings)
        self._by_pkg: dict[tuple[str, str], list[Advisory]] = {}
        for adv in advisories:
            bucket = self._by_pkg.setdefault((adv.ecosystem, adv.package), [])
            if len(bucket) < MAX_ADVISORIES_PER_PACKAGE:
                bucket.append(adv)

    def advisories_for(self, ecosystem: str, package: str) -> Sequence[Advisory]:
        return tuple(self._by_pkg.get((ecosystem, package), ()))

    @classmethod
    def from_dict(cls, data, *, default_name: str = "local-snapshot"):
        """Validate untrusted snapshot data. Bad entries are skipped with a
        count-only warning; a structurally invalid snapshot yields an empty
        source plus a warning (never an exception)."""
        warnings: list[str] = []
        if not isinstance(data, dict) or not isinstance(data.get("advisories"), list):
            return cls(default_name, None, (), ("advisory snapshot is malformed — ignored",))
        raw = data["advisories"]
        if len(raw) > MAX_ADVISORIES:
            warnings.append(f"advisory snapshot truncated at {MAX_ADVISORIES} entries")
            raw = raw[:MAX_ADVISORIES]
        out: list[Advisory] = []
        bad = 0
        for item in raw:
            adv = _validate_advisory(item)
            if adv is None:
                bad += 1
            else:
                out.append(adv)
        if bad:
            warnings.append(f"{bad} invalid advisory entr{'y' if bad == 1 else 'ies'} skipped")
        name = _clean(data.get("source") or default_name, 64) or default_name
        gen = data.get("generated_at")
        return cls(name, gen if isinstance(gen, str) else None, out, warnings)


def _validate_advisory(item) -> Advisory | None:
    if not isinstance(item, dict):
        return None
    eco = item.get("ecosystem")
    pkg = item.get("package")
    aid = item.get("id")
    if eco not in SUPPORTED_ECOSYSTEMS or not isinstance(pkg, str) or not pkg.strip() \
            or not isinstance(aid, str) or not aid.strip():
        return None
    pkg = normalize_pip_name(pkg.strip()) if eco == "pip" else pkg.strip()
    intro = item.get("introduced", "0")
    fixed = item.get("fixed", "")
    if not isinstance(intro, str) or not isinstance(fixed, str):
        return None
    if version_tuple(intro) is None:
        return None                     # incomparable bound: unusable
    if fixed and version_tuple(fixed) is None:
        return None
    sev = str(item.get("severity", "unknown")).lower()
    return Advisory(
        id=_clean(aid, MAX_ID_CHARS), ecosystem=eco, package=pkg[:214],
        introduced=intro.strip(), fixed=fixed.strip(),
        severity=sev if sev in SEVERITIES else "unknown",
        summary=_clean(item.get("summary", ""), MAX_SUMMARY_CHARS))


def read_local_json(root: str, relpath: str, *, exclusions=(), what: str = "snapshot",
                    max_bytes: int = MAX_SNAPSHOT_BYTES):
    """Guarded read of a local JSON data file: ``(data, warning)``.

    Guard order matches the manifest reader: privacy baseline + caller
    exclusions, then containment, then a size-capped read. Exactly one of
    the two results is ``None``; the warning is a fixed string and never
    echoes the (possibly excluded) path. Shared by the advisory (T03) and
    package-metadata (T04) snapshot loaders."""
    norm = relpath.replace("\\", "/").strip()
    if is_excluded(norm, [*SENSITIVE_EXCLUDE_GLOBS, *exclusions]):
        return None, f"{what} path is excluded — not read"
    if not is_contained(root, norm):
        return None, f"{what} path rejected (outside checkout)"
    try:
        with open(os.path.join(root, norm), "rb") as fh:
            blob = fh.read(max_bytes + 1)
    except OSError:
        return None, f"{what} could not be read"
    if len(blob) > max_bytes:
        return None, f"{what} too large — ignored"
    try:
        return json.loads(blob.decode("utf-8-sig")), None
    except (ValueError, RecursionError):
        return None, f"{what} is not valid JSON — ignored"


def load_local_snapshot(root: str, relpath: str, *, exclusions=()):
    """Load an advisory snapshot file from the checked-out tree. Failure
    returns an empty :class:`SnapshotAdvisorySource` with one fixed
    warning."""
    data, warning = read_local_json(root, relpath, exclusions=exclusions,
                                    what="advisory snapshot")
    if warning is not None:
        return SnapshotAdvisorySource("local-snapshot", None, (), (warning,))
    return SnapshotAdvisorySource.from_dict(data)


# ------------------------------------------------------------- lookup

def lookup_advisories(dependencies, source: AdvisorySource | None = None, *,
                      now: datetime | None = None,
                      allow_network: bool = False) -> AdvisoryLookup:
    """Match ``dependencies`` against ``source`` (default: no data).

    Refuses non-offline sources unless ``allow_network`` is explicitly
    set. Never raises."""
    source = source or NullAdvisorySource()
    if not getattr(source, "offline", False) and not allow_network:
        return AdvisoryLookup(source=_clean(getattr(source, "name", "?"), 64),
                              warnings=("advisory source is not offline — refused "
                                        "(network access is opt-in only)",))
    label, age = freshness_label(getattr(source, "generated_at", None), now)
    warnings = list(getattr(source, "warnings", ()))
    matches: list[AdvisoryMatch] = []
    try:
        for dep in dependencies:
            if dep.source != "registry":
                continue                # URL/VCS/path deps have no registry identity
            for adv in source.advisories_for(dep.ecosystem, dep.name):
                ver = _pinned_version(dep)
                if ver is None:
                    matches.append(AdvisoryMatch(adv, dep, MATCH_UNVERIFIED))
                elif affects(adv, ver):
                    matches.append(AdvisoryMatch(adv, dep, MATCH_AFFECTED))
    except Exception:                                   # noqa: BLE001
        warnings.append("advisory lookup failed — partial results discarded")
        matches = []
    matches.sort(key=lambda m: (m.dependency.manifest, m.dependency.name,
                                m.advisory.id, m.status))
    is_null = isinstance(source, NullAdvisorySource)
    if is_null:
        warnings.append("no advisory source configured — advisory status unknown")
    return AdvisoryLookup(tuple(matches), _clean(source.name, 64), label, age,
                          available=not is_null, warnings=tuple(warnings))

"""V4.2-E06-T04 — license and staleness signals (offline, evidence-backed).

Signals come from two deterministic places only:

* the parsed manifests themselves (non-registry sources, unconstrained
  specifiers) — no outside data needed;
* an optional **local package-metadata snapshot** (license, latest
  version, last release date, deprecation flag), loaded through the same
  guarded, size-capped, exclusion-respecting reader as advisory snapshots.
  Without a snapshot the module says so once and makes no license or
  staleness claim — "unknown" is a result, not an error.

Wording rule (mirrors the family-wide "no compliance claim" stance):
signals describe a *declared* license and its *class*; they never say a
dependency is "compliant", "approved" or "safe", and every license signal
carries the sentence that this is not a legal determination.

Reads: this module opens nothing itself except via
``advisories.read_local_json`` (privacy baseline enforced) and consumes
manifests through ``manifests.collect_dependencies``/``read_manifest`` —
so excluded paths are never read.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from ..models import EvidenceRecord
from ..security import redact_secrets, safe_label
from .advisories import (MAX_ADVISORIES, freshness_label, read_local_json,
                         version_tuple)
from .manifests import SUPPORTED_ECOSYSTEMS, Dependency, normalize_pip_name

MAX_SIGNALS = 500
DEFAULT_STALE_DAYS = 730            # informational threshold, not a gate
MAX_LICENSE_CHARS = 64

# Explicit SPDX-id -> class table. Anything not listed is "unknown": the
# module refuses to guess a class from a free-text license string.
LICENSE_CLASSES = {
    "permissive": ("mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "isc",
                   "0bsd", "unlicense", "cc0-1.0", "zlib", "python-2.0", "psf-2.0"),
    "weak_copyleft": ("lgpl-2.1", "lgpl-2.1-only", "lgpl-2.1-or-later",
                      "lgpl-3.0", "lgpl-3.0-only", "lgpl-3.0-or-later",
                      "mpl-2.0", "epl-2.0", "epl-1.0", "cddl-1.0"),
    "strong_copyleft": ("gpl-2.0", "gpl-2.0-only", "gpl-2.0-or-later",
                        "gpl-3.0", "gpl-3.0-only", "gpl-3.0-or-later"),
    "network_copyleft": ("agpl-3.0", "agpl-3.0-only", "agpl-3.0-or-later"),
    "proprietary": ("unlicensed", "proprietary", "commercial"),
}
_CLASS_BY_ID = {i: c for c, ids in LICENSE_CLASSES.items() for i in ids}

KIND_COPYLEFT = "copyleft_license"
KIND_PROPRIETARY = "proprietary_license"
KIND_UNKNOWN_LICENSE = "unknown_license"
KIND_STALE = "stale_release"
KIND_DEPRECATED = "deprecated"
KIND_MAJOR_BEHIND = "major_version_behind"
KIND_NON_REGISTRY = "non_registry_source"
KIND_UNCONSTRAINED = "unconstrained_version"
SIGNAL_KINDS = (KIND_COPYLEFT, KIND_PROPRIETARY, KIND_UNKNOWN_LICENSE, KIND_STALE,
                KIND_DEPRECATED, KIND_MAJOR_BEHIND, KIND_NON_REGISTRY,
                KIND_UNCONSTRAINED)

_NOT_LEGAL = "declared license class only; not a legal determination"


def license_class(license_id: str) -> str:
    """Class for a declared SPDX identifier (``unknown`` when unlisted or
    when the string is an expression — no guessing across ``OR``/``AND``)."""
    return _CLASS_BY_ID.get(str(license_id).strip().lower(), "unknown")


@dataclass(frozen=True)
class PackageMetadata:
    ecosystem: str
    package: str
    license: str = ""
    latest_version: str = ""
    last_release: str = ""          # ISO date/datetime
    deprecated: bool = False


@dataclass(frozen=True)
class DependencySignal:
    kind: str                       # one of SIGNAL_KINDS
    severity: str                   # info | low | medium (never above medium)
    dependency: Dependency
    detail: str
    evidence: tuple[EvidenceRecord, ...] = ()


@dataclass(frozen=True)
class SignalReport:
    signals: tuple[DependencySignal, ...] = ()
    metadata_available: bool = False
    metadata_freshness: str = "unknown"
    warnings: tuple[str, ...] = ()
    truncated: bool = False


class MetadataSnapshot:
    """Validated local package-metadata snapshot (offline by construction)."""

    offline = True

    def __init__(self, generated_at, packages: Sequence[PackageMetadata], warnings=()):
        self.generated_at = generated_at
        self.warnings = tuple(warnings)
        self._by_key = {(p.ecosystem, p.package): p for p in packages}

    def get(self, ecosystem: str, package: str) -> PackageMetadata | None:
        return self._by_key.get((ecosystem, package))

    @classmethod
    def from_dict(cls, data) -> "MetadataSnapshot":
        if not isinstance(data, dict) or not isinstance(data.get("packages"), list):
            return cls(None, (), ("package-metadata snapshot is malformed — ignored",))
        warnings: list[str] = []
        raw = data["packages"]
        if len(raw) > MAX_ADVISORIES:
            raw = raw[:MAX_ADVISORIES]
            warnings.append("package-metadata snapshot truncated")
        out, bad = [], 0
        for item in raw:
            md = _validate_metadata(item)
            if md is None:
                bad += 1
            else:
                out.append(md)
        if bad:
            warnings.append(f"{bad} invalid package-metadata entr"
                            f"{'y' if bad == 1 else 'ies'} skipped")
        gen = data.get("generated_at")
        return cls(gen if isinstance(gen, str) else None, out, warnings)


def _clean(value, limit: int) -> str:
    return safe_label(redact_secrets(str(value)), limit).strip()


def _validate_metadata(item) -> PackageMetadata | None:
    if not isinstance(item, dict):
        return None
    eco, pkg = item.get("ecosystem"), item.get("package")
    if eco not in SUPPORTED_ECOSYSTEMS or not isinstance(pkg, str) or not pkg.strip():
        return None
    pkg = normalize_pip_name(pkg.strip()) if eco == "pip" else pkg.strip()
    latest = item.get("latest_version", "")
    return PackageMetadata(
        ecosystem=eco, package=pkg[:214],
        license=_clean(item.get("license", ""), MAX_LICENSE_CHARS),
        latest_version=latest.strip() if isinstance(latest, str) else "",
        last_release=item.get("last_release", "")
        if isinstance(item.get("last_release", ""), str) else "",
        deprecated=item.get("deprecated") is True)


def load_local_metadata(root: str, relpath: str, *, exclusions=()) -> MetadataSnapshot:
    """Guarded load of a local metadata snapshot (privacy baseline and
    exclusions enforced; failure => empty snapshot + one fixed warning)."""
    data, warning = read_local_json(root, relpath, exclusions=exclusions,
                                    what="package-metadata snapshot")
    if warning is not None:
        return MetadataSnapshot(None, (), (warning,))
    return MetadataSnapshot.from_dict(data)


# -------------------------------------------------------------- signals

def _age_days(value: str, now: datetime) -> int | None:
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)


def _evidence(dep: Dependency, summary: str) -> tuple[EvidenceRecord, ...]:
    locator = f"{dep.manifest}:{dep.line}" if dep.line else dep.manifest
    try:
        return (EvidenceRecord.create(kind="file_excerpt", locator=locator,
                                      summary=summary,
                                      check_type="dependency_signal"),)
    except ValueError:
        return ()


def _signal(kind, severity, dep, detail) -> DependencySignal:
    detail = _clean(detail, 300)
    return DependencySignal(kind, severity, dep, detail,
                            _evidence(dep, f"{dep.ecosystem} '{dep.name}': {detail}"))


def build_signals(dependencies, metadata: MetadataSnapshot | None = None, *,
                  now: datetime | None = None,
                  stale_days: int = DEFAULT_STALE_DAYS) -> SignalReport:
    """Signals for ``dependencies`` (typically the added/updated ones).

    Pure and deterministic given ``metadata`` and ``now``. Never raises."""
    now = now or datetime.now(timezone.utc)
    warnings: list[str] = list(getattr(metadata, "warnings", ()))
    available = metadata is not None and bool(getattr(metadata, "_by_key", None))
    label = "unknown"
    if metadata is not None:
        label, _ = freshness_label(metadata.generated_at, now)
    if metadata is None:
        warnings.append("no package-metadata snapshot configured — license and "
                        "staleness signals unavailable")
    signals: list[DependencySignal] = []
    try:
        for dep in dependencies:
            if dep.source != "registry":
                signals.append(_signal(
                    KIND_NON_REGISTRY, "low", dep,
                    f"declared from a {dep.source} source rather than the registry; "
                    f"provenance and version cannot be checked offline"))
                continue
            if not dep.spec:
                signals.append(_signal(KIND_UNCONSTRAINED, "info", dep,
                                       "no version constraint declared"))
            md = metadata.get(dep.ecosystem, dep.name) if metadata is not None else None
            if md is None:
                continue
            if md.license:
                cls = license_class(md.license)
                if cls in ("strong_copyleft", "network_copyleft", "weak_copyleft"):
                    sev = "medium" if cls != "weak_copyleft" else "low"
                    signals.append(_signal(
                        KIND_COPYLEFT, sev, dep,
                        f"declares license '{md.license}' (class: {cls}); {_NOT_LEGAL}"))
                elif cls == "proprietary":
                    signals.append(_signal(
                        KIND_PROPRIETARY, "medium", dep,
                        f"declares license '{md.license}' (class: proprietary); {_NOT_LEGAL}"))
                elif cls == "unknown":
                    signals.append(_signal(
                        KIND_UNKNOWN_LICENSE, "info", dep,
                        f"declares license '{md.license}', which is not in the "
                        f"recognised list; {_NOT_LEGAL}"))
            else:
                signals.append(_signal(KIND_UNKNOWN_LICENSE, "info", dep,
                                       f"no license declared in metadata; {_NOT_LEGAL}"))
            if md.deprecated:
                signals.append(_signal(KIND_DEPRECATED, "medium", dep,
                                       "package is marked deprecated in the metadata snapshot"))
            age = _age_days(md.last_release, now) if md.last_release else None
            if age is not None and age > stale_days:
                signals.append(_signal(
                    KIND_STALE, "low", dep,
                    f"last release was about {age} days before the snapshot "
                    f"reference time (threshold {stale_days}); staleness is "
                    f"informational"))
            have = version_tuple(dep.spec.lstrip("=")) if dep.pinned else None
            latest = version_tuple(md.latest_version) if md.latest_version else None
            if have and latest and latest[0] > have[0]:
                signals.append(_signal(
                    KIND_MAJOR_BEHIND, "info", dep,
                    f"pinned to {'.'.join(map(str, have))}; the snapshot lists "
                    f"{'.'.join(map(str, latest))} as latest"))
    except Exception:                                   # noqa: BLE001
        warnings.append("signal analysis failed — partial results discarded")
        signals = []
    truncated = len(signals) > MAX_SIGNALS
    signals = signals[:MAX_SIGNALS]
    signals.sort(key=lambda s: (s.dependency.manifest, s.dependency.name, s.kind))
    return SignalReport(tuple(signals), available, label, tuple(warnings), truncated)

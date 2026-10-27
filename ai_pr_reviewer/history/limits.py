"""V4.4-E01-T01 — bounds for the git history index.

Every dimension of a history build has an explicit, clamped limit here;
callers never invent their own caps. Configuration may move a knob *down*
(or, within the hard ceiling, up) — a hostile or typo'd value can never
balloon a build past the ``HARD_*`` ceilings, and a non-integer falls back
to the default rather than disabling the bound.

The commit/day windows are the plan's *proposed baselines* (500 commits /
90 days, plan §G.7). They are defaults for a feature that is OFF at baseline,
not enforced gates; promoting them is a human-approval decision.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..index.limits import clamp_int

#: Proposed baseline (plan §G.7): last 500 commits ...
DEFAULT_MAX_COMMITS = 500
HARD_MAX_COMMITS = 5_000
#: ... and at most 90 days back, measured from the HEAD commit's own
#: timestamp (never the wall clock), so a build is reproducible on a fixture.
DEFAULT_MAX_DAYS = 90
HARD_MAX_DAYS = 3_650
#: Commits touching more paths than this are "bulk" (mass reformat, vendor
#: drop, tree move): recorded and counted, but excluded from churn and
#: co-change, where they would drown the signal and make pairing quadratic.
DEFAULT_MAX_FILES_PER_COMMIT = 50
HARD_MAX_FILES_PER_COMMIT = 200
#: Distinct paths tracked for churn.
DEFAULT_MAX_TRACKED_PATHS = 5_000
HARD_MAX_TRACKED_PATHS = 50_000
#: Distinct co-change pairs kept.
DEFAULT_MAX_CO_CHANGE_PAIRS = 20_000
HARD_MAX_CO_CHANGE_PAIRS = 200_000
#: Bytes of ``git`` output read before the process is stopped.
DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
HARD_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
#: Wall-clock seconds for the whole build.
DEFAULT_MAX_SECONDS = 20.0
HARD_MAX_SECONDS = 120.0

#: Longest commit subject kept, and the raw prefix examined before
#: redaction (redaction runs on the longer prefix so a credential cut in
#: half by the display cap can never leak a fragment).
MAX_SUBJECT_CHARS = 200
SUBJECT_REDACTION_WINDOW = 1_000


def _clamp_seconds(value, default: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    if value <= 0:
        return default
    return min(float(value), high)


@dataclass(frozen=True)
class HistoryLimits:
    """Effective, already-clamped limits for one history build."""

    max_commits: int = DEFAULT_MAX_COMMITS
    max_days: int = DEFAULT_MAX_DAYS
    max_files_per_commit: int = DEFAULT_MAX_FILES_PER_COMMIT
    max_tracked_paths: int = DEFAULT_MAX_TRACKED_PATHS
    max_co_change_pairs: int = DEFAULT_MAX_CO_CHANGE_PAIRS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_seconds: float = DEFAULT_MAX_SECONDS
    #: Classify each commit's author as bot/human (a coarse ROLE, never an
    #: identity). Off by default: when off, no author data is requested.
    include_roles: bool = False

    @classmethod
    def from_values(cls, **values) -> HistoryLimits:
        """Clamp arbitrary (possibly untrusted) values into range.

        Unknown keys are ignored; missing/invalid ones fall back to the
        default. Never raises.
        """
        return cls(
            max_commits=clamp_int(values.get("max_commits"),
                                  DEFAULT_MAX_COMMITS, HARD_MAX_COMMITS),
            max_days=clamp_int(values.get("max_days"),
                               DEFAULT_MAX_DAYS, HARD_MAX_DAYS),
            max_files_per_commit=clamp_int(
                values.get("max_files_per_commit"),
                DEFAULT_MAX_FILES_PER_COMMIT, HARD_MAX_FILES_PER_COMMIT),
            max_tracked_paths=clamp_int(
                values.get("max_tracked_paths"),
                DEFAULT_MAX_TRACKED_PATHS, HARD_MAX_TRACKED_PATHS),
            max_co_change_pairs=clamp_int(
                values.get("max_co_change_pairs"),
                DEFAULT_MAX_CO_CHANGE_PAIRS, HARD_MAX_CO_CHANGE_PAIRS),
            max_output_bytes=clamp_int(
                values.get("max_output_bytes"),
                DEFAULT_MAX_OUTPUT_BYTES, HARD_MAX_OUTPUT_BYTES),
            max_seconds=_clamp_seconds(values.get("max_seconds"),
                                       DEFAULT_MAX_SECONDS, HARD_MAX_SECONDS),
            include_roles=values.get("include_roles") is True,
        )

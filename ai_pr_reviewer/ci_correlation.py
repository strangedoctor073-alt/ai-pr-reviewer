"""V4.6-E02-T01 — CI failure ingestion + signature normalization.

Turns a configured file of CI runs into frozen, normalized failure
records so later tickets can compare pre/post windows (T02), assign
correlation confidence (T03) and render evidence (T04). The methodology
is ADR-020 (ratified): deterministic computation over declared windows,
evidence out, never a causal claim.

Read-only contract (test-enforced in T01):

* **no network, no writes, no subprocess** — ingestion reads one
  configured local file and nothing else; there is no outbound path of
  any kind;
* **absent configuration is zero surface** — no file, no records, no
  warnings, byte-identical review output;
* **window labels are configuration-declared, never guessed** — a run
  whose ``window`` is missing or not in the closed set {``pre``,
  ``post``} is skipped with a warning (fail-closed): only CI ingestion
  (a later epic) can derive run↔commit order, and inventing it here
  would fabricate the correlation's foundation;
* **the config is trusted, the data is not** — the file lives in the
  base-revision checkout and its name is containment-checked before any
  byte is read; every field extracted from CI text is secret-redacted,
  control-stripped and bounded at ingest. Identity fields (``run_id``,
  ``test_id``, ``suite``) REFUSE to truncate: an over-long value drops
  the record instead of being cut — a mangled test id would silently
  name the wrong test. Free text (``raw``) truncates at
  ``MAX_RAW_CHARS`` AFTER redaction, so a secret is never cut in half;
* **bounded everywhere** — file size, run count, per-run and total
  failure counts; a hostile file degrades to labeled warnings, never an
  exception.

Config file (default ``.ai-pr-reviewer-ci.json`` in the repo root,
override with the plain env var ``CI_SOURCES_FILE``):

    {"runs": [{"run_id": "ci-4711", "window": "pre",
               "started_at": "2026-10-20T09:00:00Z",
               "failures": [{"raw": "FAILED tests/test_a.py::test_x - "
                                     "AssertionError"},
                            {"test_id": "tests/test_b.py::test_y",
                             "suite": "unit", "error_class": "OSError"}]}]}

Failures are either raw text (the extraction ladder runs over it) or
structured fields; unidentifiable failures are dropped, never guessed.
Within a run, ``(run_id, test_id)`` duplicates keep the first.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .index.limits import is_contained
from .security import redact_secrets

DEFAULT_SOURCES_FILE = ".ai-pr-reviewer-ci.json"

# Bounds: a hostile or accidental export can never flood a review, a
# report row or a prompt. Each cap trip is a labeled degradation.
MAX_RUNS = 50
MAX_FAILURES = 1_000
MAX_FAILURES_PER_RUN = 200
MAX_SOURCE_FILE_BYTES = 262_144          # 256 KiB per config file
MAX_IDENTITY_CHARS = 300                 # refuse-to-truncate fields
MAX_RUN_ID_CHARS = 100
MAX_RAW_CHARS = 2_000                    # free text: truncate at the bound
MAX_TIMESTAMP_CHARS = 40
MAX_WARNINGS = 10
MAX_WARNING_CHARS = 300

WINDOWS = ("pre", "post")
UNKNOWN_ERROR_CLASS = "unknown"

_CONTROL = {c: " " for c in (*range(0x20), 0x7F, *range(0x80, 0xA0),
                              0x2028, 0x2029)}


def _clean(text: object, limit: int,
           scrub: Callable[[str], str] | None = None) -> str:
    """Redact, strip control characters, collapse to one line, bound."""
    out = redact_secrets(str(text if text is not None else ""))
    if scrub is not None:
        out = scrub(out)
    out = " ".join(out.translate(_CONTROL).split())
    return out[:limit].strip()


def _identity(value: object, limit: int,
              scrub: Callable[[str], str] | None = None) -> str | None:
    """Identity field (``run_id``/``test_id``/``suite``): cleaned like
    ``_clean`` but REFUSING to truncate.

    ``None`` means "over long — drop the record" (never mangle: a cut
    test id points at a different test). ``""`` means absent/empty;
    the caller decides whether that is droppable.
    """
    if value is None:
        return ""
    out = redact_secrets(str(value))
    if scrub is not None:
        out = scrub(out)
    out = " ".join(out.translate(_CONTROL).split())
    if len(out) > limit:
        return None
    return out


def _warn(msg: str, warnings: list[str],
          scrub: Callable[[str], str] | None = None) -> None:
    if len(warnings) < MAX_WARNINGS:
        warnings.append(_clean(msg, MAX_WARNING_CHARS, scrub))


def _normalize_ts(value: object) -> str:
    """ISO-8601 text -> normalized UTC ISO text, or ``""``.

    Never raises: an unparseable timestamp is recorded as absent rather
    than dropped — ordering comes from the declared window label, not
    from timestamps, so a bad date costs detail, not the record.
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    text = value.strip()[:MAX_TIMESTAMP_CHARS]
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class FailureSignature:
    """The correlation identity of one failure (ADR-020 decision 1).

    All three fields are already redacted, single-line and bounded;
    ``error_class`` is a suffix-normalized class token or the literal
    ``unknown`` — ``unknown`` never upgrades confidence (T03 enforces).
    """

    test_id: str
    suite: str
    error_class: str = UNKNOWN_ERROR_CLASS


@dataclass(frozen=True)
class FailureRecord:
    """One normalized failure inside one declared-window run."""

    run_id: str
    window: str                     # "pre" | "post" (config-declared)
    signature: FailureSignature
    started_at: str = ""            # normalized ISO or "" (never guessed)
    source: str = ""                # the config file it came from


# ------------------------------------------------- extraction ladders
# ADR-020: rungs are a closed, documented order. Running them is
# deterministic string work over redacted text — never a model call,
# and "no rung matched" means the failure is DROPPED (T04 cannot claim
# anything about a test it cannot name).

_PY_SELECTOR_RE = re.compile(r"\S+\.py::\S+")
_DOTTED_RE = re.compile(r"\b[\w.]+\b")
_BARE_TEST_RE = re.compile(r"\btest_\w+")

_CLASS_TOKEN_RE = re.compile(
    r"\b(?:[A-Za-z_][\w.]*?)?"
    r"(?:Error|Exception|Failure|Failed|Timeout)\b")


def extract_test_id(text: str) -> str | None:
    """Raw CI text -> a test identity, by ladder, or ``None``.

    Rungs (order is the contract):
    1. ``path/to_test.py::selector`` — kept whole so the file part is
       later matchable against the test↔source index;
    2. a dotted unittest id containing a ``test_``-prefixed segment;
    3. a bare ``test_*`` token;
    4. ``None`` — unidentifiable failures are dropped, never guessed.
    """
    if not text:
        return None
    match = _PY_SELECTOR_RE.search(text)
    if match:
        return match.group(0)
    for token in _DOTTED_RE.findall(text):
        if any(segment.startswith("test_")
               for segment in token.split(".")):
            return token
    bare = _BARE_TEST_RE.search(text)
    return bare.group(0) if bare else None


def normalize_error_class(value: object) -> str:
    """Ladder -> a suffix-normalized class token, else ``unknown``.

    Keeps the LAST class-shaped token ending in ``Error``/``Exception``/
    ``Failure``/``Failed``/``Timeout`` (the most recent raise wins),
    reduced to its last dotted segment. Anything unclassifiable
    normalizes to ``unknown`` — honest absence, never a fabricated class.
    """
    if not isinstance(value, str) or not value.strip():
        return UNKNOWN_ERROR_CLASS
    matches = _CLASS_TOKEN_RE.findall(value)
    if not matches:
        return UNKNOWN_ERROR_CLASS
    return matches[-1].split(".")[-1]


def _window_label(value: object) -> str | None:
    """Closed vocabulary {pre, post} (case-folded); anything else is
    ``None`` — the caller skips the run. Never a default, never inferred
    from position in the file."""
    if not isinstance(value, str):
        return None
    label = value.strip().lower()
    return label if label in WINDOWS else None


def _normalize_failure(raw: object, *, run_id: str, window: str,
                       started_at: str, source: str,
                       scrub: Callable[[str], str] | None
                       ) -> FailureRecord | None:
    """One untrusted failure object -> a bounded, redacted record.

    Returns ``None`` (drop) for: non-objects, over-long identities
    (refuse-to-truncate), and failures no ladder rung can identify.
    """
    if not isinstance(raw, dict):
        return None
    raw_text = _clean(raw.get("raw"), MAX_RAW_CHARS, scrub)

    test_id = ""
    if raw.get("test_id") is not None:
        test_id = _identity(raw.get("test_id"), MAX_IDENTITY_CHARS, scrub)
        if test_id is None:             # over-long: never mangled
            return None
    if not test_id:
        test_id = extract_test_id(raw_text)
        if test_id is None or len(test_id) > MAX_IDENTITY_CHARS:
            return None

    suite = ""
    if raw.get("suite") is not None:
        suite = _identity(raw.get("suite"), MAX_IDENTITY_CHARS, scrub)
        if suite is None:               # over-long: never mangled
            return None

    error_class = normalize_error_class(raw.get("error_class"))
    if error_class == UNKNOWN_ERROR_CLASS:
        # structured field unclassifiable -> fall back to the record's
        # own text (same record, same evidence; never another source)
        error_class = normalize_error_class(raw_text)

    return FailureRecord(
        run_id=run_id,
        window=window,
        signature=FailureSignature(test_id=test_id, suite=suite,
                                   error_class=error_class),
        started_at=started_at,
        source=_clean(source, MAX_RUN_ID_CHARS, scrub),
    )


def _sources_filename() -> str:
    return (os.environ.get("CI_SOURCES_FILE", "").strip()
            or DEFAULT_SOURCES_FILE)


def ingest_failures(repo_root: str, *,
                    scrub: Callable[[str], str] | None = None,
                    filename: str = ""
                    ) -> tuple[tuple[FailureRecord, ...], tuple[str, ...]]:
    """Load the configured CI file into normalized failure records.

    Deterministic order (file order, run order, failure order);
    ``(run_id, test_id)`` duplicates keep the first. Never raises:
    every failure mode degrades to a warning that names the config
    path or run id but never echoes file content.
    """
    warnings: list[str] = []
    records: list[FailureRecord] = []
    seen: set[tuple[str, str]] = set()

    def warn(msg: str) -> None:
        _warn(msg, warnings, scrub)

    name = filename or _sources_filename()
    if not is_contained(repo_root, name):
        warn(f"ci source path escapes the repository: {name}")
        return (), tuple(warnings)
    path = Path(repo_root) / name
    try:
        if not path.exists():
            return (), ()               # absent config = zero surface
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            warn(f"ci source exceeds size cap: {name}")
            return (), tuple(warnings)
        data = json.loads(path.read_text(encoding="utf-8",
                                         errors="replace"))
    except OSError:
        warn(f"ci source unreadable: {name}")
        return (), tuple(warnings)
    except ValueError as exc:
        # Type only, never file content: a parse failure cannot echo
        # the file it failed on.
        warn(f"ci source is not valid JSON ({type(exc).__name__}): {name}")
        return (), tuple(warnings)

    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list):
        warn(f"ci source has no runs list: {name}")
        return (), tuple(warnings)

    for index, raw_run in enumerate(runs):
        if index >= MAX_RUNS:
            warn(f"run cap ({MAX_RUNS}) reached; remaining runs skipped")
            break
        if len(records) >= MAX_FAILURES:
            warn(f"failure cap ({MAX_FAILURES}) reached; remaining runs "
                 f"skipped")
            break
        if not isinstance(raw_run, dict):
            continue                    # malformed run entry: skip
        run_id = _identity(raw_run.get("run_id"), MAX_RUN_ID_CHARS, scrub)
        if run_id is None:
            warn("run skipped (over-long run_id)")
            continue
        if not run_id:
            warn("run skipped (missing run_id)")
            continue
        window = _window_label(raw_run.get("window"))
        if window is None:
            warn(f"run skipped (missing or invalid window label): "
                 f"{run_id}")
            continue
        started_at = _normalize_ts(raw_run.get("started_at"))
        failures = raw_run.get("failures", [])
        if not isinstance(failures, list):
            warn(f"run has no failures list: {run_id}")
            failures = []

        processed = 0
        for raw_failure in failures:
            if processed >= MAX_FAILURES_PER_RUN:
                warn(f"failure cap ({MAX_FAILURES_PER_RUN}) reached in "
                     f"run {run_id}")
                break
            if len(records) >= MAX_FAILURES:
                warn(f"failure cap ({MAX_FAILURES}) reached; remaining "
                     f"runs skipped")
                break
            processed += 1
            record = _normalize_failure(raw_failure, run_id=run_id,
                                        window=window,
                                        started_at=started_at,
                                        source=name, scrub=scrub)
            if record is None:
                continue
            key = (record.run_id, record.signature.test_id)
            if key in seen:
                continue                # within-run dup: keep first
            seen.add(key)
            records.append(record)

    return tuple(records), tuple(warnings)


# ------------------------------------------------------ V4.6-E02-T02
# Pre/post change-window comparison (ADR-020 decision 2): SET ALGEBRA
# over normalized signatures — relations, never verdicts. Which exact
# failure signatures are new since the change, which pre-existing ones
# stopped, which continue. No timestamps, no scores, no causation:
# confidence labeling (T03) and wording (T04) happen elsewhere.

@dataclass(frozen=True)
class WindowComparison:
    """The three set relations between the declared windows.

    ``pre_count``/``post_count`` count UNIQUE signatures — the operands
    of the algebra (records may repeat a signature; sets do not). The
    tuples are sorted by ``(test_id, suite, error_class)`` so two runs
    over the same records produce identical output.
    """

    new_in_post: tuple[FailureSignature, ...] = ()
    resolved: tuple[FailureSignature, ...] = ()
    persistent: tuple[FailureSignature, ...] = ()
    pre_count: int = 0
    post_count: int = 0


def _sig_key(signature: FailureSignature) -> tuple[str, str, str]:
    return (signature.test_id, signature.suite, signature.error_class)


def compare_windows(records: Iterable[FailureRecord]) -> WindowComparison:
    """Classify ingested failures into ``pre``/``post`` set relations.

    Signature-level by design: a test failing with a DIFFERENT error
    class after the change is one *resolved* old signature and one
    *new* signature — the relations stay exact instead of pretending
    the failure modes are interchangeable. Records whose window is
    neither ``pre`` nor ``post`` do not participate: ingestion refuses
    such runs, so a foreign window here means a hand-built record, and
    guessing its placement would fabricate the comparison.
    """
    pre: set[FailureSignature] = set()
    post: set[FailureSignature] = set()
    for record in records:
        if record.window == "pre":
            pre.add(record.signature)
        elif record.window == "post":
            post.add(record.signature)
    return WindowComparison(
        new_in_post=tuple(sorted(post - pre, key=_sig_key)),
        resolved=tuple(sorted(pre - post, key=_sig_key)),
        persistent=tuple(sorted(pre & post, key=_sig_key)),
        pre_count=len(pre),
        post_count=len(post),
    )

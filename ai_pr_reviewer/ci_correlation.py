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
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .index.limits import is_contained
from .models import (STATIC_ENGINE_ID, EvidenceRecord, Finding,
                     ProvenanceSource)
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


# ------------------------------------------------------ V4.6-E02-T03
# Confidence model (ADR-020 decision 3): a CLOSED ladder over named
# grounds. Grounds that cite changed code may fire only on a real
# intersection — an index edge from the failing test file to a changed
# module, or a path/stem convention match against the changed set.
# Everything else is window-only or not-assessable.
#
# "No unrelated claims" is structural here: CorrelatedFailure carries
# no field that attributes a failure to a changed file, so the only
# outputs that can support such wording in T04 are the two code-citing
# grounds — and those require the intersections tests pin below.
# Confidence can only move DOWN (unknown error class costs one step),
# never up: missing data never upgrades a claim.

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_UNKNOWN = "unknown"
CONFIDENCE_LADDER = (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW,
                     CONFIDENCE_UNKNOWN)

RELATION_NEW = "new_in_post"
RELATION_RESOLVED = "resolved"
RELATION_PERSISTENT = "persistent"

GROUND_INDEX_EDGE = "index_edge"
GROUND_PATH_CONVENTION = "path_convention"
GROUND_WINDOW_ONLY = "window_only"
GROUND_NOT_ASSESSABLE = "not_assessable"


@dataclass(frozen=True)
class CorrelatedFailure:
    """One signature, its window relation, and its confidence LABEL.

    The fields are deliberately the entire vocabulary: relation,
    signature, confidence, ground. There is no "culprit file" field —
    code attribution is only ever wording over an ``index_edge`` or
    ``path_convention`` ground (tests enforce both directions: the
    grounds fire on real intersections, and the schema cannot express
    a claim on its own).
    """

    relation: str
    signature: FailureSignature
    confidence: str
    ground: str


def _test_file_of(test_id: str) -> str | None:
    """The file path a test_id names, or ``None`` (not assessable).

    Accepts ``path::selector`` ids and path-like ids without a
    selector; rejects dotted unittest ids, bare ``test_*`` names and
    anything whitespace- or path-ambiguous — mapping those to a file
    would be a guess, and guesses cannot ground a confidence label.
    """
    if "::" in test_id:
        candidate = test_id.split("::", 1)[0]
    elif "/" in test_id:
        candidate = test_id
    else:
        return None
    candidate = candidate.replace("\\", "/").removeprefix("./")
    if not candidate or " " in candidate:
        return None
    if "/" not in candidate and "." not in candidate:
        return None
    return candidate


def _path_stem(path: str) -> str:
    """Basename without extension, minus test-file decoration.

    ``tests/test_payments.py`` and ``src/payments.py`` both stem to
    ``payments`` — the same naming convention the test taxonomy uses for
    its ``naming``-basis links, applied here as an independent
    convention ground (it works even when the index is absent).
    """
    base = path.rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    if stem.startswith("test_"):
        stem = stem[5:]
    elif stem.endswith("_test"):
        stem = stem[:-5]
    elif stem.startswith("Test") and len(stem) > 4:
        stem = stem[4:]
    if stem.endswith(".test") or stem.endswith(".spec"):
        stem = stem.rsplit(".", 1)[0]
    return stem


def _downgrade(level: str) -> str:
    """Exactly one step down the ladder; ``unknown`` is the floor."""
    index = CONFIDENCE_LADDER.index(level)
    return CONFIDENCE_LADDER[min(index + 1, len(CONFIDENCE_LADDER) - 1)]


def _assess(signature: FailureSignature, *, edges: dict[str, set[str]],
            changed: frozenset[str], changed_stems: frozenset[str]
            ) -> tuple[str, str]:
    test_file = _test_file_of(signature.test_id)
    if not changed or test_file is None:
        # nothing to relate to, or no path to relate from: the ladder
        # refuses to guess in both directions
        confidence, ground = CONFIDENCE_UNKNOWN, GROUND_NOT_ASSESSABLE
    elif edges.get(test_file, set()) & changed:
        confidence, ground = CONFIDENCE_HIGH, GROUND_INDEX_EDGE
    elif test_file in changed \
            or (len(_path_stem(test_file)) >= 2
                and _path_stem(test_file) in changed_stems):
        confidence, ground = CONFIDENCE_MEDIUM, GROUND_PATH_CONVENTION
    else:
        # the diff is real and the test file is known, but nothing ties
        # them together: relation is timing (window) ONLY
        confidence, ground = CONFIDENCE_LOW, GROUND_WINDOW_ONLY
    if signature.error_class == UNKNOWN_ERROR_CLASS:
        confidence = _downgrade(confidence)
    return confidence, ground


def correlate(comparison: WindowComparison, *,
              taxonomy: object | None = None,
              changed_paths: Iterable[str] = ()
              ) -> tuple[CorrelatedFailure, ...]:
    """Label every compared signature with confidence + ground.

    Deterministic: relation order is new_in_post, resolved, persistent
    (each already sorted by signature), so two runs over the same
    inputs are identical. The taxonomy contributes edges only while it
    reports ``available`` — an absent index caps confidence at medium
    (convention still holds, edge claims do not).
    """
    edges = _build_edges(taxonomy)
    changed = frozenset(_norm(p) for p in changed_paths
                        if isinstance(p, str))
    changed_stems = frozenset(
        stem for stem in (_path_stem(p) for p in changed) if len(stem) >= 2)

    out: list[CorrelatedFailure] = []
    for relation, signatures in ((RELATION_NEW, comparison.new_in_post),
                                 (RELATION_RESOLVED, comparison.resolved),
                                 (RELATION_PERSISTENT,
                                  comparison.persistent)):
        for signature in signatures:
            confidence, ground = _assess(signature, edges=edges,
                                         changed=changed,
                                         changed_stems=changed_stems)
            out.append(CorrelatedFailure(relation=relation,
                                         signature=signature,
                                         confidence=confidence,
                                         ground=ground))
    return tuple(out)


# ------------------------------------------------------ V4.6-E02-T04
# Surfacing (ADR-020 decisions 4+5): evidence findings plus the report
# section, wired behind the CI_CORRELATION flag (default OFF, config.py;
# orchestrator hook joins them before dedup). Wording is test-pinned to
# observed window relations only -- a resolved signature is the absence
# of failures, never proof this change fixed anything; the only grounds
# allowed to name changed code are the two whose intersections the tests
# pin (index edge / path convention), everything else states that no
# changed file is implicated ("no unrelated claims").
#
# Finding.confidence is the frozen low|medium|high set (models.py): the
# four-value ladder folds DOWN onto it (unknown -> low). The true label
# survives verbatim in the finding's explanation text and the report
# rows -- the finding field must not lose the information, only round
# it off.

CORRELATION_RULE_ID = "CI_CORRELATION"
MAX_CORRELATION_FINDINGS = 9
MAX_REPORT_ROWS_PER_RELATION = 20
MAX_TITLE_CHARS = 200
MAX_EXPLANATION_CHARS = 900
MAX_EVIDENCE_SUMMARY_CHARS = 400        # mirrors models.MAX_EVIDENCE_SUMMARY_CHARS
CORRELATION_CONTRACT = (
    "deterministic comparison of configured CI failure signatures "
    "(test_id, suite, error_class) across configuration-declared "
    "pre/post change windows; confidence (high/medium/low/unknown) "
    "labels evidence strength on a closed ladder that missing data can "
    "only lower -- relations are observed co-occurrence, never a causal "
    "claim about this change")

log = logging.getLogger(__name__)

_FINDING_CONFIDENCE = {
    CONFIDENCE_HIGH: "high",
    CONFIDENCE_MEDIUM: "medium",
    CONFIDENCE_LOW: "low",
    CONFIDENCE_UNKNOWN: "low",           # folds DOWN; label kept in evidence
}


def _norm(path: str) -> str:
    """Shared diff-path normalization (windows separators, ``./``)."""
    return path.replace("\\", "/").removeprefix("./")


def _build_edges(taxonomy) -> dict[str, set[str]]:
    """test file -> modules the index maps it to; empty when unavailable."""
    edges: dict[str, set[str]] = {}
    if taxonomy is not None and taxonomy.available:
        for link in taxonomy.links:
            edges.setdefault(link.test, set()).add(link.module)
    return edges


def _changed_view(files) -> tuple[tuple[str, ...], frozenset[str],
                                   dict[str, str]]:
    """Diff paths in review order: (originals, normalized set, norm->orig).

    The norm->orig map keeps anchors and report spelling in the
    reviewer's own form of each path while all matching runs on the
    normalized form.
    """
    ordered: list[str] = []
    related: dict[str, str] = {}
    for fd in files or ():
        raw = str(getattr(fd, "path", "") or "")
        if not raw:
            continue
        ordered.append(raw)
        related.setdefault(_norm(raw), raw)
    return tuple(ordered), frozenset(related), related


_RELATION_TEXT = {
    RELATION_NEW: (
        "The failure signature is new in the post-change window: it "
        "appears in post-change CI runs and in no pre-change run on file."),
    RELATION_RESOLVED: (
        "The failure signature is absent from the post-change window. "
        "That is the absence of failures, not proof this change fixed "
        "it: the test may be flaky, renamed, skipped or deleted."),
    RELATION_PERSISTENT: (
        "The failure signature is present in both windows: it is "
        "pre-existing and predates this change."),
}
_UNKNOWN_CAP = (
    "The failure's error class could not be classified, which caps "
    "confidence one step below what the evidence otherwise supports.")
# The only texts for grounds that must NOT name a changed file. The two
# code-citing grounds double as a bug-guard fallback: should the
# intersection that earned such a ground be gone at render time, the
# finding degrades to window-only wording instead of naming a file it can
# no longer prove.
_NO_GROUND_TEXT = {
    GROUND_WINDOW_ONLY: (
        "Nothing in the test-to-source index or the path conventions "
        "ties this test to the changed files: the relation is timing "
        "(the declared windows) only, and no changed file is implicated."),
    GROUND_NOT_ASSESSABLE: (
        "The test id names no file the index or path conventions can "
        "resolve against this diff, so no changed file can be related "
        "to this failure at all."),
}


def _title_for(item: CorrelatedFailure) -> str:
    test_id = item.signature.test_id
    if item.relation == RELATION_NEW:
        return f"CI failure new in post-change window: {test_id}"
    if item.relation == RELATION_RESOLVED:
        return f"CI failure absent from post-change window: {test_id}"
    return f"CI failure present in both windows: {test_id}"


def _code_ground(item: CorrelatedFailure, *, edges: dict[str, set[str]],
                 changed: frozenset[str], related: dict[str, str]
                 ) -> tuple[str, str | None]:
    """Ground text plus the matched normalized path, for the two grounds
    allowed to name changed code; ``("", None)`` for the two that must not.

    Both grounds recompute their intersection (sorted, first wins) with
    the same set algebra ``_assess`` used -- the finding vocabulary stays
    the closed four fields (T03 schema pin), so the recomputation is the
    only thing that can carry the match into wording.
    """
    test_file = _test_file_of(item.signature.test_id)
    if not test_file:
        return "", None
    if item.ground == GROUND_INDEX_EDGE:
        matched = sorted(edges.get(test_file, set()) & changed)
        if matched:
            named = related.get(matched[0], matched[0])
            return (f"the test-to-source index maps {test_file} to "
                    f"{named}, which this change modifies"), matched[0]
    if item.ground == GROUND_PATH_CONVENTION:
        if test_file in changed:
            return (f"the failing test file {test_file} is itself "
                    f"modified by this change"), test_file
        stem = _path_stem(test_file)
        if len(stem) >= 2:
            matched = sorted(p for p in changed if _path_stem(p) == stem)
            if matched:
                named = related.get(matched[0], matched[0])
                return (f"{test_file} follows the naming convention of "
                        f"changed file {named}"), matched[0]
    return "", None


def _explanation(item: CorrelatedFailure, code_text: str) -> str:
    ground = code_text or _NO_GROUND_TEXT.get(item.ground) \
        or _NO_GROUND_TEXT[GROUND_WINDOW_ONLY]
    parts = [_RELATION_TEXT[item.relation], f"Ground: {ground}",
             f"Confidence {item.confidence}."]
    if item.signature.error_class == UNKNOWN_ERROR_CLASS:
        parts.append(_UNKNOWN_CAP)
    parts.append("Observed CI evidence from the configured sources -- "
                 "co-occurrence, never a causal claim about this change.")
    return " ".join(parts)


# ------------------------------------------------------------ tev1 writer
# Correlation emits observed test-evidence records in the tev1 wire
# format (kind ``test_result``, check type ``test_evidence.v1``; a token
# summary ``tev1 path=… [name=…] origin=… outcome=… [covers=…]
# [covers_n=…] [dur_ms=…] [run=…]`` with percent-encoded values). The
# module that owns that format is an opt-in leaf: a structural invariant
# allows exactly one engine module -- the verification reader -- to
# import it, so correlation cannot ask it to build records and mirrors
# the wire format here instead. This is NOT a new format: the same one,
# written byte-compatibly. The mirror is not taken on trust —
# tests/test_ci_correlation.py pushes every record this writer emits
# through the format's own strict parser and reader, so drift in either
# direction fails the suite immediately.
_TEV1_KIND = "test_result"
_TEV1_CHECK_TYPE = "test_evidence.v1"
_TEV1_TAG = "tev1"
_TEV1_ORIGIN = "ci_ingest"                  # observed: a real CI run
_TEV1_OUTCOME = "failed"                    # correlation finds failures
_TEV1_MAX_PATH, _TEV1_MAX_NAME = 120, 80
_TEV1_MAX_COVER, _TEV1_MAX_COVERS = 80, 3
_TEV1_MAX_RUN = 40
_TEV1_SAFE_CHAR = re.compile(r"[A-Za-z0-9_./:@#+~-]")


def _tev1_encode(value: str) -> str:
    """Percent-encode every character outside the format's safe set
    (uppercase hex per UTF-8 byte, exactly like the canonical encoder)."""
    return "".join(c if _TEV1_SAFE_CHAR.fullmatch(c)
                   else "".join(f"%{b:02X}" for b in c.encode("utf-8"))
                   for c in value)


def _tev1_summary(*, path: str, name: str | None,
                  covers: tuple[str, ...], covers_total: int | None,
                  run_ref: str | None) -> str:
    """The canonical tev1 token string, keys in the format's fixed order.

    ``covers_total`` is emitted only when it differs from
    ``len(covers)`` — the reader reconstructs an equal total from
    ``covers`` itself, and a redundant ``covers_n`` token would break
    the byte-exact round-trip the reader demands. This writer never
    carries a duration, so ``dur_ms`` never appears.
    """
    toks = [_TEV1_TAG, f"path={_tev1_encode(path)}"]
    if name is not None:
        toks.append(f"name={_tev1_encode(name)}")
    toks += [f"origin={_TEV1_ORIGIN}", f"outcome={_TEV1_OUTCOME}"]
    if covers:
        toks.append("covers=" + ",".join(_tev1_encode(c) for c in covers))
    if covers_total is not None and covers_total != len(covers):
        toks.append(f"covers_n={covers_total}")
    if run_ref is not None:
        toks.append(f"run={_tev1_encode(run_ref)}")
    return " ".join(toks)


def _tev1_record(item: CorrelatedFailure, *, test_file: str | None,
                 selector: str, edges: dict[str, set[str]],
                 run_ref: str | None,
                 scrub: Callable[[str], str] | None) -> EvidenceRecord | None:
    """tev1 ``test_result`` record (T2's observed-evidence seam), or None.

    ``covers`` comes ONLY from index edges (never stem guesses), capped at
    the tev1 maximum. Anything the format's strict bounds or redaction
    refuse (over-long path/name, redaction-altered summary) falls back to
    a plain ``test_result`` record; a too-long run id yields NO run_ref
    rather than a truncated one -- a cut reference would name the wrong
    run.
    """
    if test_file and len(test_file) <= _TEV1_MAX_PATH:
        targets = sorted(edges.get(test_file, set()))
        covers = tuple(c for c in targets
                       if len(c) <= _TEV1_MAX_COVER)[:_TEV1_MAX_COVERS]
        name = selector or None
        ref = run_ref if run_ref and len(run_ref) <= _TEV1_MAX_RUN else None
        # the format refuses an empty or over-long name and an empty
        # cover entry; such a record is simply not tev1 (plain fallback)
        if (name is None or 0 < len(name) <= _TEV1_MAX_NAME) \
                and all(c for c in covers):
            summary = _tev1_summary(
                path=test_file, name=name, covers=covers,
                # tev1 drops covers_n from the summary when it equals
                # len(covers), so emitting it there would break the
                # round-trip -- it is only information when the total
                # EXCEEDS the capped covers.
                covers_total=len(targets) if len(targets) > len(covers)
                else None,
                run_ref=ref)
            record = None
            if len(summary) <= MAX_EVIDENCE_SUMMARY_CHARS:
                try:
                    record = EvidenceRecord.create(
                        kind=_TEV1_KIND,
                        locator=test_file + (f"::{name}" if name else ""),
                        summary=summary, check_type=_TEV1_CHECK_TYPE,
                        scrub=scrub)
                except ValueError:
                    record = None
            # A summary the redactor or the bounds altered is never
            # emitted: the mutated token string no longer parses back to
            # these facts, and evidence that cannot round-trip must not
            # be able to confirm anything downstream.
            if record is not None and record.summary == summary:
                return record
    try:
        return EvidenceRecord.create(
            kind="test_result", locator=item.signature.test_id,
            summary=_clean(
                f"ci-failure test={item.signature.test_id} "
                f"outcome=failed origin=ci_ingest "
                f"confidence={item.confidence} relation={item.relation} "
                f"class={item.signature.error_class}",
                MAX_EVIDENCE_SUMMARY_CHARS, scrub),
            check_type="ci_failure.v1", scrub=scrub)
    except ValueError:
        return None


def correlation_findings(correlated: Iterable[CorrelatedFailure], *,
                         records: Iterable[FailureRecord], files,
                         taxonomy: object | None = None,
                         scrub: Callable[[str], str] | None = None
                         ) -> tuple[Finding, ...]:
    """Render correlated failures as info-severity evidence findings.

    Evidence-or-dropped (mirrors incident linkage): a finding whose
    evidence cannot be built under the evidence contract is dropped
    whole, never emitted half-stamped. Deterministic: the correlated
    order (relations in fixed sequence, signatures sorted within).
    """
    edges = _build_edges(taxonomy)
    ordered, changed, related = _changed_view(files)
    first_run: dict[FailureSignature, str] = {}
    for rec in records:
        first_run.setdefault(rec.signature, rec.run_id)

    out: list[Finding] = []
    for item in correlated:
        if len(out) >= MAX_CORRELATION_FINDINGS:
            break
        test_id = item.signature.test_id
        test_file = _test_file_of(test_id)
        selector = test_id.split("::", 1)[1] if "::" in test_id else ""
        code_text, matched = _code_ground(item, edges=edges, changed=changed,
                                          related=related)
        # Anchor: the ground's own matched file, else the first changed
        # file. The latter is PLACEMENT ONLY -- an info row must live
        # somewhere; the wording never claims the fallback anchor is
        # implicated (tests pin that separation).
        anchor = related.get(matched, matched) if matched else (
            ordered[0] if ordered else None)
        if not anchor:
            continue
        try:
            evidence: list[EvidenceRecord] = []
            if matched is not None:
                evidence.append(EvidenceRecord.create(
                    kind="file_excerpt", locator=related.get(matched, matched),
                    summary=_clean(
                        f"correlation ground: {code_text} "
                        f"(confidence: {item.confidence})",
                        MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                    check_type="ci_correlation", scrub=scrub))
            if test_file is not None:
                tev = _tev1_record(
                    item, test_file=test_file, selector=selector, edges=edges,
                    run_ref=first_run.get(item.signature), scrub=scrub)
                if tev is not None:
                    evidence.append(tev)
            evidence.append(EvidenceRecord.create(
                kind="rule_ref", locator=f"rule:{CORRELATION_RULE_ID}",
                summary=_clean(CORRELATION_CONTRACT,
                               MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                check_type="ci_correlation", scrub=scrub))
        except ValueError:
            continue                        # evidence-or-dropped
        finding = Finding(
            file=anchor, line=None, severity="info",
            category="maintainability",
            title=_clean(_title_for(item), MAX_TITLE_CHARS, scrub),
            explanation=_clean(_explanation(item, code_text),
                               MAX_EXPLANATION_CHARS, scrub),
            suggestion=None,
            confidence=_FINDING_CONFIDENCE.get(item.confidence, "low"),
            rule_id=CORRELATION_RULE_ID, evidence=tuple(evidence),
        )
        source = ProvenanceSource(engine=STATIC_ENGINE_ID,
                                  model="ci-correlation-v1", origin="rule")
        finding.provenance_engine = source.engine
        finding.provenance_model = source.model
        finding.provenance_agent = None
        finding.provenance_origin = source.origin
        finding.provenance_sources = (source,)
        out.append(finding)
    return tuple(out)


def _relation_block(row_list: list[dict]) -> dict:
    # ``total`` always states the full count; ``rows`` is capped -- a cap
    # that hid volume would be dishonest.
    return {"total": len(row_list),
            "rows": row_list[:MAX_REPORT_ROWS_PER_RELATION]}


def correlations_section(comparison: WindowComparison,
                         correlated: Iterable[CorrelatedFailure],
                         scrub: Callable[[str], str] | None = None) -> dict:
    """The additive report block (``correlations``): window counts plus
    bounded, deterministically ordered rows per relation.

    Rows are re-scrubbed here (redact-at-store chokepoint: everything a
    finding or report can surface is scrubbed as well). The ``unknown``
    label survives verbatim -- only Finding.confidence folds it to low.
    """
    rows: dict[str, list[dict]] = {RELATION_NEW: [], RELATION_RESOLVED: [],
                                   RELATION_PERSISTENT: []}
    for item in correlated:
        rows[item.relation].append({
            "test_id": _clean(item.signature.test_id, MAX_IDENTITY_CHARS,
                              scrub),
            "suite": _clean(item.signature.suite, MAX_IDENTITY_CHARS, scrub),
            "error_class": item.signature.error_class,
            "confidence": item.confidence,
            "ground": item.ground,
        })
    return {"pre_count": comparison.pre_count,
            "post_count": comparison.post_count,
            RELATION_NEW: _relation_block(rows[RELATION_NEW]),
            RELATION_RESOLVED: _relation_block(rows[RELATION_RESOLVED]),
            RELATION_PERSISTENT: _relation_block(rows[RELATION_PERSISTENT])}


@dataclass(frozen=True)
class CorrelationOutcome:
    """Runner result: findings + warnings + the report section.

    ``correlations is None`` means "no comparison happened" (no records,
    garbage config, or no changed files): the orchestrator then leaves
    the report key off entirely -- features absent => unchanged behavior.
    """

    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    correlations: dict | None = None


NOOP = CorrelationOutcome()


def run_failure_correlation(*, repo_root: str, files,
                            taxonomy: object | None = None,
                            scrub: Callable[[str], str] | None = None
                            ) -> CorrelationOutcome:
    """V4.6-E02 entry point (orchestrator hook; CI_CORRELATION default OFF).

    * no records and no warnings -> ``NOOP`` (byte-identical review);
    * garbage config -> its warnings alone, no section, no findings;
    * no changed files -> nothing to relate to: no findings, no section;
    * any crash -> one labeled warning -- the feature never fails a
      review (mirrors the incident and infra runners).
    """
    try:
        records, warnings = ingest_failures(repo_root, scrub=scrub)
        if not records:
            return NOOP if not warnings else CorrelationOutcome(
                warnings=warnings)
        ordered, _, _ = _changed_view(files)
        if not ordered:
            return CorrelationOutcome(warnings=warnings)
        comparison = compare_windows(records)
        correlated = correlate(comparison, taxonomy=taxonomy,
                               changed_paths=ordered)
        return CorrelationOutcome(
            findings=correlation_findings(
                correlated, records=records, files=files, taxonomy=taxonomy,
                scrub=scrub),
            warnings=warnings,
            correlations=correlations_section(comparison, correlated,
                                              scrub=scrub))
    except Exception as exc:  # noqa: BLE001 -- opt-in feature never fails a review
        log.warning("failure correlation failed: %s", type(exc).__name__)
        return CorrelationOutcome(warnings=(
            f"failure correlation failed ({type(exc).__name__}); skipped",))

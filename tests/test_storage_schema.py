"""V3-E04-T03 tests: the shared storage-schema contract and its ownership.

``ai_pr_reviewer/storage_schema.py`` is the single owner of the mute-row
prefix, ``review_id`` parsing and the cross-store key formats. These
tests pin the helpers' semantics (a behavior-identical refactor) and run
the literal-duplication scan that keeps the C9 duplication from coming
back: inside ``ai_pr_reviewer/`` and ``dashboard/``, the banned literals
may appear only in the owner file.
"""
from __future__ import annotations

import io
import sys
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import storage_schema as schema
from ai_pr_reviewer.memory import MUTE_PREFIX as MEMORY_MUTE_PREFIX
from ai_pr_reviewer.memory import is_mute_row
from ai_pr_reviewer.models import ReviewKey

OWNER = "ai_pr_reviewer/storage_schema.py"
SCAN_DIRS = ("ai_pr_reviewer", "dashboard")


# ----------------------------------------------------------------- mute rows
def test_mute_helpers_round_trip():
    assert schema.MUTE_PREFIX == "fingerprint:"
    assert schema.mute_pattern("abc123") == "fingerprint:abc123"
    assert schema.is_mute_pattern("fingerprint:abc123")
    assert schema.is_mute_pattern("fingerprint:")     # malformed still a mute row
    assert not schema.is_mute_pattern("*.py")
    assert not schema.is_mute_pattern(None)
    assert not schema.is_mute_pattern("")

    assert schema.mute_fingerprint("fingerprint:abc123") == "abc123"
    assert schema.mute_fingerprint("fingerprint:  abc  ") == "abc"
    assert schema.mute_fingerprint("fingerprint:") is None      # never ""
    assert schema.mute_fingerprint("fingerprint:   ") is None   # whitespace only
    assert schema.mute_fingerprint("*.py") is None
    assert schema.mute_fingerprint(None) is None


def test_memory_module_reads_the_single_prefix():
    """memory.py imports the prefix instead of redefining it (no drift)."""
    assert MEMORY_MUTE_PREFIX == schema.MUTE_PREFIX
    assert is_mute_row({"path_pattern": schema.mute_pattern("x")})
    assert not is_mute_row({"path_pattern": "*.py"})


# ---------------------------------------------------------------- review ids
@pytest.mark.parametrize("raw,expected", [
    ("acme/api#42@abcdef012345", ("acme/api", 42)),
    ("acme/api#42@", ("acme/api", 42)),        # sha may be absent/empty
    ("acme/api#0@sha", ("acme/api", 0)),
    ("#42@sha", ("", 42)),                     # empty repo half
    ("acme/api#42", ("", 0)),                  # no @
    ("acme/api@42", ("", 0)),                  # no #
    ("acme/api#x@sha", ("acme/api", 0)),       # int() fails: legacy kept repo
    ("#@", ("", 0)),
    ("", ("", 0)),
    (None, ("", 0)),
])
def test_parse_review_id_matches_legacy_semantics(raw, expected):
    """Byte-for-byte the lenient behavior each backend had pre-refactor."""
    assert schema.parse_review_id(raw) == expected


def test_format_review_id_and_reviewkey_share_one_writer():
    rid = schema.format_review_id("acme/api", 42, "abcdef0123456789")
    assert rid == "acme/api#42@abcdef012345"     # sha truncated to 12
    assert schema.parse_review_id(rid) == ("acme/api", 42)

    key = ReviewKey(repo="acme/api", pr_number=42, head_sha="abcdef0123456789")
    assert key.as_id() == rid
    assert key.as_id() == key.as_id()            # deterministic


# ------------------------------------------------------------ cross-store keys
def test_cross_store_key_builders():
    assert schema.repo_pr_key("acme/api", 42) == "acme/api#42"
    assert schema.finding_history_key("acme/api", 42, "fp1") == "acme/api#42#fp1"

    first = schema.memory_row_key("acme/api")
    second = schema.memory_row_key("acme/api")
    assert first.startswith("acme/api#")
    assert len(first) == len("acme/api#") + 8    # uuid4().hex[:8]
    assert first != second                       # unique per call


# ------------------------------------------------------- literal-ownership scan
def _scan_files():
    for pattern_dir in SCAN_DIRS:
        yield from sorted((ROOT / pattern_dir).rglob("*.py"))


def _string_token_hits(source: str) -> list[str]:
    """Lines whose exact string token is the mute prefix literal."""
    hits: list[str] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok in tokens:
            if tok.type == tokenize.STRING and tok.string in (
                    '"fingerprint:"', "'fingerprint:'"):
                hits.append(str(tok.start[0]))
    except tokenize.TokenError:
        pass
    return hits


def _raw_hits(source: str, needle: str) -> list[str]:
    hits: list[str] = []
    offset = 0
    while True:
        idx = source.find(needle, offset)
        if idx < 0:
            return hits
        hits.append(str(source.count("\n", 0, idx) + 1))
        offset = idx + 1


def test_scan_detects_all_three_patterns_in_the_owner_file():
    """Vacuity guard: the detector must actually fire on the owner file,
    otherwise the ownership scan below could pass while scanning nothing."""
    source = (ROOT / OWNER).read_text(encoding="utf-8")
    assert _string_token_hits(source), "mute prefix literal not detected"
    assert _raw_hits(source, '.split("#", 1)'), "review-id parse not detected"
    assert _raw_hits(source, '}#{'), "key format not detected"


def test_no_duplicated_schema_literals_outside_the_owner():
    """The acceptance grep for V3-E04-T03: the literal ``"fingerprint:"``,
    ``.split("#", 1)`` review-id parsing and ``}#{`` key-building may
    appear only in ``storage_schema.py`` (tests/docs are outside the
    scan scope; production code under both packages is not)."""
    offenders: list[str] = []
    for path in _scan_files():
        rel = path.relative_to(ROOT).as_posix()
        if rel == OWNER:
            continue
        source = path.read_text(encoding="utf-8")
        for line in _string_token_hits(source):
            offenders.append(f'{rel}:{line}: "fingerprint:" literal')
        for line in _raw_hits(source, '.split("#", 1)'):
            offenders.append(f'{rel}:{line}: review-id split parse')
        for line in _raw_hits(source, '}#{'):
            offenders.append(f"{rel}:{line}: key-building f-string")
    assert offenders == [], (
        "schema literals duplicated outside the owner:\n  "
        + "\n  ".join(offenders))

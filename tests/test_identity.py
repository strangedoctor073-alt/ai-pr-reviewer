"""V4-E05 -- layered finding identity: continuity, ownership and migration
proofs (ADR-005, approved 2026-10-07).

What this suite pins, and why it is separate from ``test_findings.py``
(which covers the functions themselves):

* **v1 is frozen.**  ``fingerprint_finding`` stays the storage / lifecycle /
  mute / comment key forever.  A golden file captured from the *pristine*
  pre-hardening tree, an independent re-implementation of the formula, and a
  seeded property test all have to agree with the shipped function.
* **The occurrence key is advisory and pipeline-safe.**  It is computed from
  (file, title) only, never persisted, never a storage key, and nothing a
  model can supply beyond those two strings can move it.
* **Nothing orphans.**  Pre-v2-shaped databases (engine SQLite *and* the
  dashboard store) keep loading, keep their mute rows, keep their comment
  bindings, and gain V4 fields additively -- no new table, no alias, no
  backfill.

Everything here is offline; no network, no model ids, no new dependencies.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
import random
import re
import sqlite3
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import findings as findings_module  # noqa: E402
from ai_pr_reviewer.findings import (apply_lifecycle, deduplicate,  # noqa: E402
                                     fingerprint_finding, mark_dismissed,
                                     occurrence_key)
from ai_pr_reviewer.models import (EvidenceRecord, Finding,  # noqa: E402
                                   ProvenanceSource)
from ai_pr_reviewer.orchestrator import (ReviewOrchestrator,  # noqa: E402
                                         _stamp_provenance)
from ai_pr_reviewer.storage import LocalReviewStorage  # noqa: E402
from ai_pr_reviewer.storage_schema import mute_pattern  # noqa: E402

GOLDEN = ROOT / "tests" / "data" / "identity_v1_golden.json"

# Pre-v2 fingerprints, HARD-CODED (captured from the pristine tree via the
# golden file). The migration tests below never recompute these -- they are
# the "what is already stored on disk" side of the proof.
FP_SQL = "0dc303916d0ea3ea"     # security app/payments.py  "Possible SQL injection in 'users' table"
FP_SHELL = "39d9510f8fb4b70a"   # security src/aaa_creds.py "Shell command built from code without escaping"
FP_XSS = "9eed2c703b0b23ca"     # security src/checkout.js  "Assignment to innerHTML can introduce XSS"
FP_EQ = "b9e1dcad8bdafbf3"      # bug      src/checkout.js  "Loose equality (==) performs type coercion"

_PRE_V2 = {
    "A": dict(fp=FP_SQL, file="app/payments.py", category="security", line=10,
              title="Possible SQL injection in 'users' table", severity="high",
              comment_id=9001),
    "B": dict(fp=FP_SHELL, file="src/aaa_creds.py", category="security", line=4,
              title="Shell command built from code without escaping",
              severity="high", comment_id=9002),
    "C": dict(fp=FP_XSS, file="src/checkout.js", category="security", line=7,
              title="Assignment to innerHTML can introduce XSS",
              severity="high", comment_id=9003),
}
_NEW_D = dict(fp=FP_EQ, file="src/checkout.js", category="bug", line=21,
              title="Loose equality (==) performs type coercion",
              severity="low", comment_id=None)

REPO, PR = "acme/payments", 42
REVIEW_ID = f"{REPO}#{PR}@abcdef123456"

# Keys a V3.0.0 payload never carried: the V4 additions. A "pre-v2-shaped"
# stored payload has none of them.
_V4_KEYS = ("evidence", "provenance_sources", "merged_fingerprints")


def _pre_v2_payload(spec: dict, *, with_scalar_provenance: bool) -> dict:
    """What an older release wrote into ``finding_history.payload``."""
    payload = {
        "file": spec["file"], "line": spec["line"], "end_line": None,
        "severity": spec["severity"], "category": spec["category"],
        "title": spec["title"], "explanation": "stored by an earlier review",
        "suggestion": None, "confidence": "medium", "rule_id": None,
        "fingerprint": spec["fp"], "state": "active",
        "first_seen_sha": "aaa111", "last_seen_sha": "bbb222",
        "resolved_at": None, "github_comment_id": spec["comment_id"],
    }
    if with_scalar_provenance:      # V3.0.0 already shipped the scalars
        payload.update(provenance_engine="claude", provenance_model="m-old",
                       provenance_agent=None, provenance_origin="ai")
    assert not any(k in payload for k in _V4_KEYS)
    return payload


def _seed_local_db(path: Path, mute: tuple[str, ...] = ()) -> LocalReviewStorage:
    """A real engine SQLite database holding pre-v2-shaped rows, written with
    raw SQL (not through ``save_findings``) so the seed cannot be influenced
    by the code under test."""
    storage = LocalReviewStorage(path)
    conn = sqlite3.connect(path)
    try:
        for i, spec in enumerate(_PRE_V2.values()):
            payload = _pre_v2_payload(spec, with_scalar_provenance=bool(i % 2))
            conn.execute(
                "INSERT INTO finding_history(repo, pr_number, fingerprint, "
                "state, first_seen_sha, last_seen_sha, resolved_at, payload, "
                "updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (REPO, PR, spec["fp"], "active", "aaa111", "bbb222", None,
                 json.dumps(payload), "2026-09-01T00:00:00+00:00"))
        for fp in mute:
            conn.execute(
                "INSERT INTO repo_memory(repo, path_pattern, note) "
                "VALUES (?, ?, ?)", (REPO, mute_pattern(fp), f"Muted {fp}"))
        conn.execute("INSERT INTO repo_memory(repo, path_pattern, note) "
                     "VALUES (?, ?, ?)", (REPO, "*.py", "a plain note"))
        conn.commit()
    finally:
        conn.close()
    return storage


def _model_dict(spec: dict) -> dict:
    """What a provider would hand back (untrusted model output)."""
    return {"file": spec["file"], "line": spec["line"],
            "severity": spec["severity"], "category": spec["category"],
            "title": spec["title"], "explanation": "re-reported"}


def _run_review(storage, specs: list[dict], engine: str) -> list[Finding]:
    """One review run through the same pure steps the orchestrator performs
    (untrusted parse -> provenance stamp -> dedup -> lifecycle) and the real
    storage write. Returns the lifecycle findings that were persisted."""
    previous = storage.get_previous_findings(REPO, PR)
    current = [Finding.from_untrusted_dict(_model_dict(s)) for s in specs]
    _stamp_provenance(current, SimpleNamespace(engine=engine, model="test-model"))
    updated = apply_lifecycle(previous, deduplicate(current))
    storage.save_findings(REVIEW_ID, [f.to_dict() for f in updated])
    return updated


def _history_fps(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return sorted(r[0] for r in conn.execute(
            "SELECT fingerprint FROM finding_history WHERE repo=? AND pr_number=?",
            (REPO, PR)))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1. v1 identity is frozen (byte-identical before/after)
# ---------------------------------------------------------------------------

def _golden_rows() -> list[dict]:
    data = json.loads(GOLDEN.read_text(encoding="utf-8"))
    return data["rows"]


def _independent_v1(category, file, title) -> str:
    """A from-scratch re-statement of the v1 formula: if this and the shipped
    function ever disagree, one of them changed identity."""
    norm = re.sub(r"\s+", " ", (title or "").strip().lower())
    basis = "|".join([category or "", file or "", norm])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def test_golden_covers_every_shipped_diff_fixture_and_edge_inputs():
    rows = _golden_rows()
    sources = {r["source"].split(":", 1)[0] for r in rows}
    assert "static-engine" in sources                       # real fixtures
    assert any(s.startswith("edge-") for s in sources)      # hand edge cases
    assert len(rows) >= 50
    # every diff fixture the repo ships contributed at least one row
    fixture_diffs = ({str(p.relative_to(ROOT)).replace("\\", "/")
                      for p in (ROOT / "demo" / "samples").glob("*.diff")}
                     | {str(p.relative_to(ROOT)).replace("\\", "/")
                        for p in (ROOT / "eval" / "corpus").glob("**/pr.diff")})
    covered = {r["source"].split(":", 1)[1] for r in rows
               if r["source"].startswith("static-engine:")}
    # fixtures whose static output is empty legitimately contribute nothing
    assert covered, "no fixture produced a golden row"
    assert covered <= fixture_diffs


def test_v1_fingerprints_are_byte_identical_to_the_pre_change_golden():
    """The headline migration property: every v1 fingerprint produced by the
    pristine tree is produced, byte for byte, by today's code."""
    mismatches = []
    for r in _golden_rows():
        f = Finding(file=r["file"], line=1, category=r["category"],
                    title=r["title"], severity="medium")
        got = fingerprint_finding(f)
        if got != r["v1"]:
            mismatches.append((r["source"], r["title"], r["v1"], got))
    assert not mismatches, f"v1 identity changed: {mismatches}"


def test_shipped_v1_function_equals_the_independent_formula_on_golden_inputs():
    for r in _golden_rows():
        f = Finding(file=r["file"], line=1, category=r["category"],
                    title=r["title"], severity="medium")
        assert fingerprint_finding(f) == _independent_v1(
            r["category"], r["file"], r["title"]) == r["v1"]


def _random_text(rng: random.Random, n: int) -> str:
    alphabet = ("abcXYZ019 _-.'\"`()[]{}<>/\\|:;,!?\t\n"
                "éß漢字—…")
    return "".join(rng.choice(alphabet) for _ in range(n))


def test_v1_property_matches_independent_formula_on_random_inputs():
    """Seeded (deterministic) property test -- no hypothesis dependency."""
    rng = random.Random(20261018)
    for _ in range(400):
        cat = rng.choice(["", "bug", "security", "style", _random_text(rng, 6)])
        file = _random_text(rng, rng.randint(0, 24))
        title = _random_text(rng, rng.randint(0, 80))
        f = Finding(file=file, line=rng.randint(1, 9999), category=cat,
                    title=title, severity=rng.choice(["low", "high"]))
        assert fingerprint_finding(f) == _independent_v1(cat, file, title)


def test_v1_depends_only_on_category_file_and_normalized_title():
    """Mutating any other field -- including every V4 provenance/evidence/
    merge-trail field -- must not move the v1 key (otherwise a stored row,
    mute or comment binding would orphan the moment a field was populated)."""
    base = Finding(file="app/a.py", line=10, category="security",
                   title="Possible SQL injection in 'users' table",
                   severity="high")
    want = fingerprint_finding(base)
    variants = [
        dict(line=99), dict(end_line=120), dict(severity="critical"),
        dict(explanation="x"), dict(suggestion="y"), dict(confidence="low"),
        dict(rule_id="R-1"), dict(state="resolved"), dict(fingerprint="zzzz"),
        dict(first_seen_sha="s1"), dict(last_seen_sha="s2"),
        dict(resolved_at="2026-01-01T00:00:00Z"), dict(github_comment_id=5),
        dict(provenance_engine="static", provenance_model="m",
             provenance_agent="a", provenance_origin="static"),
        dict(provenance_sources=(ProvenanceSource(engine="e", model="m"),)),
        dict(evidence=(EvidenceRecord.create(
            kind="rule_ref", locator="rule:R-1", summary="s"),)),
        dict(merged_fingerprints=("0123456789abcdef",)),
        dict(title="  possible   SQL INJECTION in 'users' table\n"),
    ]
    for v in variants:
        f = Finding(**{**base.__dict__, **v})
        assert fingerprint_finding(f) == want, v


# ---------------------------------------------------------------------------
# 2. occurrence key: advisory, pipeline-safe, computed from (file, title) only
# ---------------------------------------------------------------------------

def _attrs_read(func) -> set[str]:
    """Attributes actually read off the ``finding`` parameter (AST, so prose
    in docstrings/comments cannot confuse it)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    return {n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name) and n.value.id == "finding"}


def test_identity_functions_read_only_the_documented_inputs():
    """Ground rule: identity inputs are pipeline-owned / minimal. This pins
    the attribute surface of both keys so a future edit that starts reading
    (say) ``rule_id`` -- which is NOT pipeline-owned -- fails loudly."""
    assert _attrs_read(fingerprint_finding) == {"category", "file", "title"}
    assert _attrs_read(occurrence_key) == {"title", "file"}


@pytest.mark.parametrize("override", [
    dict(line=999), dict(end_line=5), dict(severity="low"),
    dict(category="bug"),                    # ADR formula: path+symbol+gist
    dict(explanation="different"), dict(suggestion="s"),
    dict(confidence="high"), dict(rule_id="MODEL-SUPPLIED"),
    dict(state="resolved"), dict(fingerprint="forged"),
    dict(github_comment_id=1),
    dict(provenance_engine="static", provenance_model="m",
         provenance_agent="x", provenance_origin="rule"),
    dict(provenance_sources=(ProvenanceSource(engine="e"),)),
    dict(merged_fingerprints=("0123456789abcdef",)),
])
def test_occurrence_key_is_independent_of_every_other_field(override):
    base = Finding(file="app/payments.py", line=10, category="security",
                   title="Possible SQL injection in 'users' table",
                   severity="high")
    want = occurrence_key(base)
    assert want != ""
    assert occurrence_key(Finding(**{**base.__dict__, **override})) == want


def test_occurrence_key_shape_and_determinism_on_random_titles():
    rng = random.Random(7)
    for _ in range(300):
        f = Finding(file=_random_text(rng, 12), line=1, category="bug",
                    title=_random_text(rng, rng.randint(0, 70)))
        k = occurrence_key(f)
        assert k == occurrence_key(f)
        assert k == "" or re.fullmatch(r"[0-9a-f]{16}", k)


def test_occurrence_key_is_whitespace_and_path_separator_tolerant_but_v1_is_not():
    """Documented asymmetry: v1 hashes the path verbatim (frozen), while the
    advisory key normalizes separators so Windows/POSIX renderings of one
    file can still be matched across engines."""
    a = Finding(file="src/win/a.py", line=1, category="bug",
                title="Possible SQL injection in query()")
    b = Finding(file="src\\win\\a.py", line=1, category="bug",
                title="Possible   SQL\tinjection in query()")
    assert fingerprint_finding(a) != fingerprint_finding(b)
    assert occurrence_key(a) == occurrence_key(b) != ""


def test_model_output_cannot_forge_identity_state():
    """Untrusted (model) dicts cannot pre-set the v1 key, lifecycle state,
    provenance, evidence or the merge trail -- the occurrence key and the
    merge audit trail are therefore computed purely by the pipeline."""
    forged = {
        "file": "app/payments.py", "line": 10, "category": "security",
        "severity": "high", "title": "Possible SQL injection in 'users' table",
        "fingerprint": "deadbeefdeadbeef", "state": "muted",
        "github_comment_id": 1, "resolved_at": "2026-01-01T00:00:00Z",
        "provenance_engine": "static", "provenance_model": "forged",
        "provenance_agent": "forged", "provenance_origin": "rule",
        "provenance_sources": [{"engine": "forged", "model": "forged"}],
        "evidence": [{"kind": "rule_ref", "locator": "rule:FORGED",
                      "summary": "forged", "content_hash": "0" * 16}],
        "merged_fingerprints": ["0123456789abcdef"],
    }
    f = Finding.from_untrusted_dict(forged)
    clean = Finding.from_untrusted_dict(
        {k: v for k, v in forged.items()
         if k in ("file", "line", "category", "severity", "title")})
    assert f.fingerprint is None and f.state == "new"
    assert f.provenance_engine is None and f.provenance_sources == ()
    assert f.evidence == () and f.merged_fingerprints == ()
    assert fingerprint_finding(f) == fingerprint_finding(clean) == FP_SQL
    assert occurrence_key(f) == occurrence_key(clean)

    # ...and a forged trail cannot survive a real merge either
    other = Finding.from_untrusted_dict({**forged,
        "title": 'Possible SQL injection in "users" table'})
    out = deduplicate([f, other])
    assert len(out) == 1
    assert out[0].merged_fingerprints == (fingerprint_finding(other),)


def test_no_persisted_occurrence_key_no_alias_table_no_new_column(tmp_path):
    """ADR-005 decision 4: no alias table, no backfill, no cutover -- the
    occurrence key is computed, never stored. Checked on the engine SQLite
    schema and the dashboard ORM metadata (names only, so unrelated
    additive tables from other epics never trip this)."""
    storage = LocalReviewStorage(tmp_path / "s.db")
    del storage
    conn = sqlite3.connect(tmp_path / "s.db")
    try:
        names = {r[0].lower() for r in conn.execute(
            "SELECT name FROM sqlite_master")}
        cols = {c[1].lower() for (t,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")
            for c in conn.execute(f"PRAGMA table_info({t})")}
    finally:
        conn.close()
    for token in ("alias", "occurrence"):
        assert not [n for n in names | cols if token in n], token

    from dashboard.models_db import Base
    dash = {t.lower() for t in Base.metadata.tables} | {
        c.name.lower() for t in Base.metadata.tables.values()
        for c in t.columns}
    for token in ("alias", "occurrence"):
        assert not [n for n in dash if token in n], token


@pytest.mark.parametrize("rel", [
    "ai_pr_reviewer/storage.py", "ai_pr_reviewer/storage_schema.py",
    "ai_pr_reviewer/verification.py", "ai_pr_reviewer/memory.py",
    "ai_pr_reviewer/github_sync.py", "ai_pr_reviewer/reporter.py",
    "dashboard/storage.py", "dashboard/models_db.py", "dashboard/app.py",
])
def test_documented_v1_consumers_never_reference_the_occurrence_key(rel):
    """Storage, mute, verification and comment-sync paths stay on v1: the
    occurrence key is used only by ``findings.deduplicate``."""
    path = ROOT / rel
    if not path.exists():
        pytest.skip(f"{rel} not present in this checkout")
    assert "occurrence_key" not in path.read_text(encoding="utf-8")


def test_findings_module_names_no_model_ids():
    """Never hardcode model ids (also enforced repo-wide by
    test_release_hardening; asserted here for the module this epic owns)."""
    src = Path(findings_module.__file__).read_text(encoding="utf-8")
    assert not re.search(r"claude-(?:opus|sonnet|haiku|fable|mythos)-?\d", src)
    assert not re.search(r"\bgpt-\d|\bgemini-\d", src)


# ---------------------------------------------------------------------------
# 3. cross-engine dedup through the real pipeline steps
# ---------------------------------------------------------------------------

def test_finding_rereported_by_another_engine_dedups_to_one_identity():
    ai = Finding.from_untrusted_dict(_model_dict(_PRE_V2["A"]))
    other_engine = Finding.from_untrusted_dict({
        **_model_dict(_PRE_V2["A"]), "line": 11,          # line churn too
        "title": 'Possible SQL injection in "users" table'})
    _stamp_provenance([ai], SimpleNamespace(engine="claude", model="test-model"))
    _stamp_provenance([other_engine],
                      SimpleNamespace(engine="static", model="static-rules-v1"))
    v1_ai, v1_other = fingerprint_finding(ai), fingerprint_finding(other_engine)
    assert v1_ai == FP_SQL and v1_other != v1_ai            # the C4 gap

    out = deduplicate([ai, other_engine])
    assert len(out) == 1                                     # one identity
    survivor = out[0]
    # v1 untouched everywhere: the survivor keeps the winner's storage key,
    # the loser's key is only an audit trail, and the inputs were not mutated
    assert fingerprint_finding(survivor) == v1_ai == FP_SQL
    assert survivor.merged_fingerprints == (v1_other,)
    assert fingerprint_finding(ai) == v1_ai
    assert fingerprint_finding(other_engine) == v1_other
    # attribution of BOTH engines survives (what dedup used to destroy)
    assert {s.engine for s in survivor.provenance_sources} == {"claude", "static"}
    assert survivor.provenance_engine == "claude"
    # persisted payload round-trips with the trail and both sources intact
    again = Finding.from_dict(json.loads(json.dumps(survivor.to_dict())))
    assert again.merged_fingerprints == survivor.merged_fingerprints
    assert again.provenance_sources == survivor.provenance_sources
    assert fingerprint_finding(again) == FP_SQL


def test_different_issues_stay_distinct_across_engines():
    a = Finding.from_untrusted_dict(_model_dict(_PRE_V2["A"]))
    other_file = Finding.from_untrusted_dict(
        {**_model_dict(_PRE_V2["A"]), "file": "app/other.py",
         "title": 'Possible SQL injection in "users" table'})
    other_target = Finding.from_untrusted_dict(
        {**_model_dict(_PRE_V2["A"]),
         "title": 'Possible SQL injection in "orders" table'})
    assert len(deduplicate([a, other_file, other_target])) == 3


# ---------------------------------------------------------------------------
# 4. migration: a seeded pre-v2 database, nothing orphans
# ---------------------------------------------------------------------------

def test_seeded_pre_v2_rows_load_and_each_stored_key_is_still_its_v1_fingerprint(tmp_path):
    storage = _seed_local_db(tmp_path / "state.db")
    previous = storage.get_previous_findings(REPO, PR)
    assert len(previous) == 3
    stored = {f.fingerprint: f for f in previous}
    assert set(stored) == {FP_SQL, FP_SHELL, FP_XSS}
    for spec in _PRE_V2.values():
        f = stored[spec["fp"]]
        assert fingerprint_finding(f) == spec["fp"]      # recompute == stored
        assert f.github_comment_id == spec["comment_id"]
        # V4 additions default additively; nothing was backfilled
        assert f.evidence == () and f.provenance_sources == ()
        assert f.merged_fingerprints == ()


def test_pre_v2_series_keeps_full_lifecycle_continuity_across_engines(tmp_path):
    """MIGRATION_PLAN 5.3 -- '100% state continuity on a fixture PR series',
    with the engine (hence provenance) changing between runs. Row count and
    the stored primary keys never drift; comment bindings follow the v1 key."""
    db = tmp_path / "state.db"
    storage = _seed_local_db(db)
    A, B, C = _PRE_V2["A"], _PRE_V2["B"], _PRE_V2["C"]
    keys = {FP_SQL, FP_SHELL, FP_XSS}

    # run 1 -- same three findings, now stamped with V4 provenance
    run1 = {f.fingerprint: f for f in _run_review(storage, [A, B, C], "claude")}
    assert {f.state for f in run1.values()} == {"active"}
    assert run1[FP_SQL].github_comment_id == 9001
    assert run1[FP_SHELL].github_comment_id == 9002
    assert _history_fps(db) == sorted(keys)

    # run 2 -- a different engine; C is gone -> resolved, A/B untouched
    run2 = {f.fingerprint: f for f in _run_review(storage, [A, B], "openai")}
    assert run2[FP_SQL].state == run2[FP_SHELL].state == "active"
    assert run2[FP_XSS].state == "resolved"
    assert run2[FP_SQL].github_comment_id == 9001
    assert _history_fps(db) == sorted(keys)

    # run 3 -- yet another engine; C returns -> reopened (comment id kept)
    run3 = {f.fingerprint: f for f in _run_review(storage, [A, B, C], "static")}
    assert run3[FP_XSS].state == "reopened"
    assert run3[FP_XSS].github_comment_id == 9003
    assert run3[FP_SQL].state == run3[FP_SHELL].state == "active"
    assert _history_fps(db) == sorted(keys)

    # run 4 -- B fixed, a genuinely new finding D appears
    run4 = {f.fingerprint: f for f in _run_review(storage, [A, C, _NEW_D], "claude")}
    assert run4[FP_SHELL].state == "resolved"
    assert run4[FP_EQ].state == "new"
    assert run4[FP_SQL].state == "active" and run4[FP_XSS].state == "active"
    assert _history_fps(db) == sorted(keys | {FP_EQ})   # nothing orphaned/duplicated

    # V4 fields arrived additively in the stored payloads; the key columns
    # were never rewritten
    stored = {f.fingerprint: f for f in storage.get_previous_findings(REPO, PR)}
    assert stored[FP_SQL].provenance_engine == "claude"
    assert stored[FP_SQL].provenance_sources
    assert all(fingerprint_finding(f) == fp for fp, f in stored.items())


def test_pre_v2_mute_row_still_mutes_through_the_real_orchestrator_hook(tmp_path):
    storage = _seed_local_db(tmp_path / "state.db", mute=(FP_SHELL,))
    assert storage.get_dismissed_fingerprints(REPO) == {FP_SHELL}  # note row ignored

    current = [Finding.from_untrusted_dict(_model_dict(s))
               for s in _PRE_V2.values()]
    stub = SimpleNamespace(storage=storage, cfg=None)
    warnings: list[str] = []
    out = ReviewOrchestrator._apply_dismissals(
        stub, REPO, apply_lifecycle(storage.get_previous_findings(REPO, PR),
                                    deduplicate(current)), warnings)
    states = {fingerprint_finding(f): f.state for f in out}
    assert states[FP_SHELL] == "muted"
    assert states[FP_SQL] == states[FP_XSS] == "active"
    assert warnings == []


def test_pre_v2_mute_still_applies_when_the_muted_finding_survives_a_cross_engine_merge(tmp_path):
    """The muted v1 key is the merge winner's key, so the mute holds even
    though a second engine re-reported the issue with different wording."""
    storage = _seed_local_db(tmp_path / "state.db", mute=(FP_SQL,))
    ai = Finding.from_untrusted_dict(_model_dict(_PRE_V2["A"]))
    other = Finding.from_untrusted_dict(
        {**_model_dict(_PRE_V2["A"]),
         "title": 'Possible SQL injection in "users" table'})
    merged = deduplicate([ai, other])
    assert len(merged) == 1
    out = mark_dismissed(merged, storage.get_dismissed_fingerprints(REPO))
    assert out[0].state == "muted" and fingerprint_finding(out[0]) == FP_SQL


def test_dashboard_store_keeps_pre_v2_rows_and_mutes_without_orphans(tmp_path):
    """The dashboard's own (SQLAlchemy) store: pre-v2 rows keyed by the v1
    fingerprint survive a V4-shaped re-save as the SAME rows, and its mute
    rows (``fingerprint:<fp>`` memory) still resolve."""
    from dashboard.storage import DbStorage

    db = DbStorage(f"sqlite:///{tmp_path / 'dash.db'}")
    db.init()
    db.save_findings(REVIEW_ID, [
        _pre_v2_payload(spec, with_scalar_provenance=False)
        for spec in _PRE_V2.values()])
    db.add_repo_memory(REPO, mute_pattern(FP_XSS), "Muted via dashboard")

    before = db.get_previous_findings(REPO, PR)
    assert {d["fingerprint"] for d in before} == {FP_SQL, FP_SHELL, FP_XSS}
    assert db.get_dismissed_fingerprints(REPO) == {FP_XSS}

    # a V4-era review re-saves the same findings, now with provenance,
    # evidence and a merge trail in the payload
    v4_rows = []
    for spec in _PRE_V2.values():
        f = Finding.from_untrusted_dict(_model_dict(spec))
        _stamp_provenance([f], SimpleNamespace(engine="claude", model="test-model"))
        f.evidence = (EvidenceRecord.create(
            kind="diff_hunk", locator=f"{spec['file']}:{spec['line']}-{spec['line']}",
            summary="flagged line"),)
        f.merged_fingerprints = ("0123456789abcdef",)
        row = f.to_dict()
        row["fingerprint"] = fingerprint_finding(f)
        v4_rows.append(row)
    db.save_findings(REVIEW_ID, v4_rows)

    after = db.get_previous_findings(REPO, PR)
    assert len(after) == 3                                   # same rows, upserted
    assert {d["fingerprint"] for d in after} == {FP_SQL, FP_SHELL, FP_XSS}
    assert all(d["evidence"] and d["provenance_sources"] for d in after)
    assert db.get_dismissed_fingerprints(REPO) == {FP_XSS}

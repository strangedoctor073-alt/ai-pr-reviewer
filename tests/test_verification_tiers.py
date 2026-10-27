"""V4.2-E05 — verification tiers: model (T01), static re-check (T02),
consumed test-evidence adapter (T03), attribution + wiring (T04).

Tier numbering is the backlog's T0/T1/T2 (plan §B.7 C2 pins it against the
roadmap's 1-based T1/T2/T3): T0 diff-coverage floor, T1 static re-check,
T2 observed test evidence. T01–T03 ship model and handlers without changing
any verification decision — the T01 bit-identity test pins that no tier key
exists until T04 adds the attribution field and the opt-in wiring.
"""
from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from ai_pr_reviewer import models
from ai_pr_reviewer.diff_parser import FileDiff, Hunk, HunkLine
from ai_pr_reviewer.models import (EvidenceRecord, Finding,
                                   VERIFICATION_PRESENT,
                                   VERIFICATION_RESOLVED,
                                   VERIFICATION_TIER_T0, VERIFICATION_TIER_T1,
                                   VERIFICATION_TIER_T2, VERIFICATION_TIERS,
                                   VERIFICATION_UNVERIFIED)
from ai_pr_reviewer.verification import (MAX_TIER_ESCALATIONS, REASON_PRESENT,
                                         REASON_RESOLVED,
                                         REASON_RESOLVED_REMOVED,
                                         TIER_EVIDENCE, VERIFICATION_TIER_RANK,
                                         TierEscalation, escalation_from_config,
                                         observed_test_evidence_confirms,
                                         static_recheck_confirms, stronger_tier,
                                         verify_findings)

PATH = "app/main.py"


def _file(path: str = PATH, start: int = 1, count: int = 10) -> FileDiff:
    lines = [HunkLine(tag=" ", old_no=start + i, new_no=start + i, text="ctx")
             for i in range(count)]
    hunk = Hunk(old_start=start, old_count=count, new_start=start,
                new_count=count, lines=lines)
    return FileDiff(old_path=path, new_path=path, hunks=[hunk])


def _finding(state: str | None = None) -> Finding:
    f = Finding(file=PATH, line=5, severity="high",
                title="SQL injection", explanation="because")
    if state:
        f.state = state
    return f


def _baseline() -> list[Finding]:
    prev = _finding()
    prev.state = "active"
    return [prev]


# ------------------------------------------------------------------ vocabulary

def test_tier_vocabulary_is_the_pinned_c2_set():
    assert VERIFICATION_TIERS == ("t0", "t1", "t2")
    assert (VERIFICATION_TIER_T0, VERIFICATION_TIER_T1, VERIFICATION_TIER_T2) \
        == VERIFICATION_TIERS
    assert set(TIER_EVIDENCE) == set(VERIFICATION_TIERS)
    assert TIER_EVIDENCE == {
        "t0": "diff-coverage", "t1": "static-recheck", "t2": "test-evidence"}


def test_tier_rank_is_strictly_increasing_over_the_vocabulary():
    ranks = [VERIFICATION_TIER_RANK[t] for t in VERIFICATION_TIERS]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks) == len(VERIFICATION_TIERS)


def test_verification_re_exports_the_models_contract_verbatim():
    """One source: models owns the tuple (from_dict validates against it),
    verification re-exports it for consumers of the tier logic."""
    import ai_pr_reviewer.verification as ver

    assert ver.VERIFICATION_TIERS is models.VERIFICATION_TIERS
    assert ver.VERIFICATION_TIER_T0 is models.VERIFICATION_TIER_T0


# --------------------------------------------------------------- stronger_tier

@pytest.mark.parametrize("given,expected", [
    ((), None),
    ((None, None), None),
    ((None, VERIFICATION_TIER_T1), VERIFICATION_TIER_T1),
    ((VERIFICATION_TIER_T0, None), VERIFICATION_TIER_T0),
    ((VERIFICATION_TIER_T0, VERIFICATION_TIER_T2), VERIFICATION_TIER_T2),
    ((VERIFICATION_TIER_T2, VERIFICATION_TIER_T1), VERIFICATION_TIER_T2),
    ((VERIFICATION_TIER_T1, VERIFICATION_TIER_T1), VERIFICATION_TIER_T1),
    ((None, VERIFICATION_TIER_T1, VERIFICATION_TIER_T0, VERIFICATION_TIER_T2),
     VERIFICATION_TIER_T2),
])
def test_stronger_tier_returns_the_strongest_declared_evidence(given, expected):
    assert stronger_tier(*given) == expected


@pytest.mark.parametrize("minted", ["t3", "T1", "t0 ", "", "1", "tier"])
def test_stronger_tier_refuses_to_mint_an_unknown_tier(minted):
    """A caller may not invent evidence kinds — unknown raises, never wins."""
    with pytest.raises(ValueError, match="unknown verification tier"):
        stronger_tier(VERIFICATION_TIER_T0, minted)


def test_stronger_tier_validates_even_when_the_loser_is_unknown():
    with pytest.raises(ValueError, match="unknown verification tier"):
        stronger_tier("t3", VERIFICATION_TIER_T2)


# ------------------------------------------------- T0 stays bit-identical here

def test_t0_decisions_are_unchanged_and_carry_the_t0_tier():
    """E05-T04 stamps attribution on every decision the coverage floor
    makes: the status/reason pair is what it was before tiers existed,
    now labelled ``t0``. Escalation is opt-in — its enabled path lives in
    the T04 section below."""
    resolved = _finding(state="resolved")
    out = verify_findings([resolved], previous=_baseline(), current=[],
                          files=[_file()])
    assert (out[0].verification_status, out[0].verification_reason) == \
        (VERIFICATION_RESOLVED, REASON_RESOLVED)
    assert out[0].verification_tier == VERIFICATION_TIER_T0

    present = _finding()
    out = verify_findings([present], previous=_baseline(), current=[present],
                          files=[_file()])
    assert (out[0].verification_status, out[0].verification_reason) == \
        (VERIFICATION_PRESENT, REASON_PRESENT)
    assert out[0].verification_tier == VERIFICATION_TIER_T0

    partial = _finding(state="resolved")
    out = verify_findings([partial], previous=_baseline(), current=[],
                          files=[_file(count=3)])       # lines 1-3, finding on 5
    assert out[0].verification_status == VERIFICATION_UNVERIFIED
    assert out[0].verification_tier == VERIFICATION_TIER_T0


# ------------------------------------------- T1: static re-check (E05-T02)

def _fd(seq: tuple[tuple[str, str], ...], path: str = PATH,
        *, is_binary: bool = False) -> FileDiff:
    """A one-hunk FileDiff from ``(tag, text)`` pairs — tag is ``+``/``-``/
    a space, exactly as the diff parser produces them."""
    lines = []
    old_no = new_no = 0
    for tag, text in seq:
        if tag == "+":
            new_no += 1
        elif tag == "-":
            old_no += 1
        else:
            old_no += 1
            new_no += 1
        lines.append(HunkLine(tag=tag, old_no=old_no, new_no=new_no, text=text))
    hunk = Hunk(old_start=1, old_count=max(old_no, 1), new_start=1,
                new_count=max(new_no, 1), lines=lines)
    return FileDiff(old_path=path, new_path=path, hunks=[hunk],
                    is_binary=is_binary)


def _rule_finding(rule_id: str | None = "SEC003", path: str = PATH) -> Finding:
    return Finding(file=path, line=5, severity="critical",
                   title="Use of eval() executes arbitrary code",
                   explanation="because", rule_id=rule_id)


def test_static_recheck_confirms_when_the_pattern_left_the_hunks():
    fd = _fd(((" ", "ctx"), ("+", "result = transform(value)")))
    assert static_recheck_confirms(_rule_finding(), fd) is True


def test_static_recheck_refuses_while_the_pattern_is_still_an_added_line():
    fd = _fd(((" ", "ctx"), ("+", "x = eval(user_input)")))
    assert static_recheck_confirms(_rule_finding(), fd) is False


def test_static_recheck_refuses_while_the_pattern_sits_in_a_context_line():
    """The committed-but-unfixed case: the flagged pattern is unchanged in
    the file (context of this hunk) while the engine — which only scans
    added lines — would not re-fire on it. The re-check must see it."""
    fd = _fd(((" ", "x = eval(user_input)"), ("+", "y = transform(v)")))
    assert static_recheck_confirms(_rule_finding(), fd) is False


def test_removed_pre_fix_lines_never_block_the_recheck():
    fd = _fd(((" ", "ctx"),
              ("-", "x = eval(user_input)"),
              ("+", "y = transform(v)")))
    assert static_recheck_confirms(_rule_finding(), fd) is True


def test_a_commented_out_pattern_counts_as_gone_engine_and_recheck_agree():
    fd = _fd(((" ", "ctx"), ("+", "# eval(user_input)")))
    assert static_recheck_confirms(_rule_finding(), fd) is True
    # parity pin: the engine really would not fire on that line
    from ai_pr_reviewer.static.engine import StaticEngine
    fired = {f.rule_id for f in StaticEngine().run([fd])}
    assert "SEC003" not in fired


def test_ai_and_unknown_rule_ids_never_confirm():
    fd = _fd(((" ", "ctx"), ("+", "result = transform(value)")))
    assert static_recheck_confirms(_rule_finding(rule_id=None), fd) is False
    assert static_recheck_confirms(_rule_finding(rule_id="ZZZ999"), fd) is False


def test_a_non_line_rule_finding_cannot_be_rechecked():
    """AST001 comes from a file rule (no regex to rescan) — honest absence,
    never an escalation."""
    fd = _fd(((" ", "ctx"), ("+", "def f(items=None):")))
    assert static_recheck_confirms(_rule_finding(rule_id="AST001"), fd) is False


def test_confirming_against_a_different_files_hunks_is_refused():
    other = _fd(((" ", "ctx"), ("+", "result = transform(value)")),
                path="other.py")
    assert static_recheck_confirms(_rule_finding(), other) is False


def test_missing_binary_and_language_mismatched_files_never_confirm():
    clean = _fd(((" ", "ctx"), ("+", "result = transform(value)")))
    # file not part of the diff at all
    assert static_recheck_confirms(_rule_finding(), None) is False
    # binary files are invisible to the engine, so they cannot confirm
    assert static_recheck_confirms(
        _rule_finding(), _fd(((" ", "ctx"),), is_binary=True)) is False
    # SEC003 is a ("py", "js", "ts") rule: on a shell file it could never
    # fire, so it cannot say the pattern is gone either (clean diff or not)
    sh_clean = _fd(((" ", "ctx"), ("+", "result = transform(value)")),
                   path="deploy.sh")
    assert static_recheck_confirms(_rule_finding(path="deploy.sh"), sh_clean) is False
    # control: the same clean diff on a .py file confirms
    assert static_recheck_confirms(_rule_finding(), clean) is True


def test_the_recheck_is_pure_and_deterministic():
    fd = _fd(((" ", "ctx"), ("+", "result = transform(value)")))
    finding = _rule_finding()
    before = finding.to_dict()
    first = static_recheck_confirms(finding, fd)
    second = static_recheck_confirms(finding, fd)
    assert first is second is True
    assert finding.to_dict() == before      # no mutation of the finding


def test_a_caller_supplied_registry_is_used_verbatim():
    """T04 escalates many findings against ONE built registry — the handler
    must consume what it is handed instead of rebuilding."""
    from ai_pr_reviewer.static.engine import build_default_registry

    reg = build_default_registry()
    count = len(reg.line_rules)
    fd = _fd(((" ", "ctx"), ("+", "result = transform(value)")))
    assert static_recheck_confirms(_rule_finding(), fd, registry=reg) is True
    assert len(reg.line_rules) == count


# --------------------------- T2: consumed test-evidence (E05-T03)

def _tev(*, outcome: str = "passed", origin: str = "ci_ingest",
         covers: tuple[str, ...] = (PATH,), path: str = "tests/test_app.py"):
    """A canonical, intact observed ``tev1`` record (or a chosen variant)."""
    from ai_pr_reviewer.test_intel import TestEvidence
    return TestEvidence(test_path=path, outcome=outcome, origin=origin,
                        covers=tuple(covers)).to_record()


def _ev_finding(*records, file: str = PATH) -> Finding:
    return Finding(file=file, line=5, severity="high",
                   title="SQL injection", explanation="because",
                   evidence=tuple(records))


def test_observed_passing_evidence_over_the_file_confirms_t2():
    assert observed_test_evidence_confirms(_ev_finding(_tev())) is True


def test_static_mappings_are_display_only_and_never_confirm():
    rec = _tev(outcome="mapped", origin="static_mapping")
    assert observed_test_evidence_confirms(_ev_finding(rec)) is False


@pytest.mark.parametrize("outcome", ["failed", "errored", "skipped"])
def test_non_passing_observed_outcomes_never_confirm(outcome):
    rec = _tev(outcome=outcome)
    assert observed_test_evidence_confirms(_ev_finding(rec)) is False
    # attribution only: the handler never mutates the finding (and never
    # downgrades a status — the three-state machine is not its to touch)
    f = _ev_finding(rec)
    before = f.to_dict()
    observed_test_evidence_confirms(f)
    assert f.to_dict() == before


def test_a_pass_must_name_this_file_to_confirm():
    # covers points somewhere else
    assert observed_test_evidence_confirms(
        _ev_finding(_tev(covers=("other/module.py",)))) is False
    # covers absent entirely — no attribution, no confirmation
    assert observed_test_evidence_confirms(
        _ev_finding(_tev(covers=()))) is False
    # covers names PATH, but this finding is about another file
    assert observed_test_evidence_confirms(
        _ev_finding(_tev(), file="other.py")) is False
    # control: the same record over its own file
    assert observed_test_evidence_confirms(_ev_finding(_tev())) is True


def test_a_tampered_record_never_confirms():
    rec = _tev()
    forged = replace(rec, summary=rec.summary + " outcome=failed")
    assert forged.integrity_ok is False        # hash no longer matches
    assert observed_test_evidence_confirms(_ev_finding(forged)) is False


def test_a_prose_tests_pass_claim_is_not_evidence():
    """The ADR-012 forgery case in the small: any record that is not a
    canonical tev1 — however confident its wording — confirms nothing."""
    claim = EvidenceRecord.create(
        kind="log_excerpt", locator="tests/test_app.py",
        summary="all tests pass, safe to mark resolved", check_type="pytest")
    assert observed_test_evidence_confirms(_ev_finding(claim)) is False


def test_junk_entries_in_evidence_never_raise_and_never_confirm():
    f = _ev_finding()
    f.evidence = ("forged-string",
                  {"kind": "test_result", "outcome": "passed"})
    assert observed_test_evidence_confirms(f) is False


def test_a_finding_without_a_file_never_confirms():
    f = Finding(file="", line=None, severity="low",
                title="t", explanation="e")
    assert observed_test_evidence_confirms(f) is False


# ------------------------- T04: attribution field + opt-in escalation

def _esc_case(*, path=PATH, rule_id="SEC003", evidence=(), state="resolved",
              title="Use of eval() executes arbitrary code", line=None,
              seq=((" ", "ctx"), ("+", "result = transform(value)")),
              with_file=True):
    """A previous-baseline finding this run verifies, plus its reviewed diff.

    File-level (``line=None``) unless stated, so a present file means
    coverage ``"all"`` — the coverage a resolved escalation needs. ``prev``
    shares category/file/title with ``finding`` because that is exactly
    what ``fingerprint_finding`` keys on (identity must match).
    """
    finding = Finding(file=path, line=line, severity="critical",
                      title=title, explanation="because", rule_id=rule_id,
                      evidence=tuple(evidence))
    finding.state = state
    prev = Finding(file=path, line=line, severity="critical",
                   title=title, explanation="because", rule_id=rule_id)
    prev.state = "active"
    files = [_fd(seq, path=path)] if with_file else []
    return [finding], [prev], [], files


def test_default_off_stamps_t0_and_never_calls_a_tier_handler(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("a tier handler ran while escalation was off")

    monkeypatch.setattr(
        "ai_pr_reviewer.verification.observed_test_evidence_confirms", boom)
    monkeypatch.setattr(
        "ai_pr_reviewer.verification.static_recheck_confirms", boom)

    # passing evidence + a still-present pattern change nothing when off
    findings, prev, cur, files = _esc_case(
        evidence=(_tev(),), seq=((" ", "ctx"), ("+", "x = eval(user_input)")))
    out = verify_findings(findings, prev, cur, files)
    assert out[0].verification_tier == VERIFICATION_TIER_T0

    # ...and an explicitly disabled escalation object behaves identically
    out = verify_findings(*_esc_case(evidence=(_tev(),)),
                          escalation=TierEscalation(enabled=False))
    assert out[0].verification_tier == VERIFICATION_TIER_T0


def test_opt_in_t1_escalates_a_fully_covered_finding_whose_pattern_is_gone():
    findings, prev, cur, files = _esc_case()   # clean hunk, file reviewed
    out = verify_findings(findings, prev, cur, files,
                          escalation=TierEscalation(enabled=True))
    assert (out[0].verification_status, out[0].verification_reason) == \
        (VERIFICATION_RESOLVED, REASON_RESOLVED)
    assert out[0].verification_tier == VERIFICATION_TIER_T1


def test_opt_in_t1_refuses_while_the_pattern_is_still_in_the_file():
    findings, prev, cur, files = _esc_case(
        seq=((" ", "ctx"), ("+", "x = eval(user_input)")))
    out = verify_findings(findings, prev, cur, files,
                          escalation=TierEscalation(enabled=True))
    assert out[0].verification_tier == VERIFICATION_TIER_T0


def test_observed_evidence_beats_the_static_recheck():
    """T2 outranks T1 when both hold — the handler order, pinned."""
    findings, prev, cur, files = _esc_case(evidence=(_tev(),))
    out = verify_findings(findings, prev, cur, files,
                          escalation=TierEscalation(enabled=True))
    assert out[0].verification_tier == VERIFICATION_TIER_T2


def test_a_file_missing_resolution_can_only_climb_via_t2():
    # no hunks for T1 to re-check — observed evidence is the only way up
    findings, prev, cur, files = _esc_case(with_file=False,
                                           evidence=(_tev(),))
    out = verify_findings(findings, prev, cur, files,
                          escalation=TierEscalation(enabled=True))
    assert out[0].verification_status == VERIFICATION_RESOLVED
    assert out[0].verification_reason == REASON_RESOLVED_REMOVED
    assert out[0].verification_tier == VERIFICATION_TIER_T2

    # without evidence it stays on the floor — never a crash, never a mint
    findings, prev, cur, files = _esc_case(with_file=False)
    out = verify_findings(findings, prev, cur, files,
                          escalation=TierEscalation(enabled=True))
    assert out[0].verification_tier == VERIFICATION_TIER_T0


def test_the_budget_caps_handler_checks_across_the_run():
    # cap = 2: the first finding spends both checks (T2 miss + T1 hit)...
    first, prev1, _, files = _esc_case(title="first finding")
    second, prev2, _, _ = _esc_case(title="second finding")
    out = verify_findings(first + second, prev1 + prev2, [], files,
                          escalation=TierEscalation(enabled=True, max_checks=2))
    assert out[0].verification_tier == VERIFICATION_TIER_T1
    # ...so the second finding never gets one
    assert out[1].verification_tier == VERIFICATION_TIER_T0


def test_a_single_check_goes_to_the_first_finding_in_list_order():
    first, prev1, _, files = _esc_case(title="first finding",
                                       evidence=(_tev(),))
    second, prev2, _, _ = _esc_case(title="second finding",
                                    evidence=(_tev(),))
    out = verify_findings(first + second, prev1 + prev2, [], files,
                          escalation=TierEscalation(enabled=True, max_checks=1))
    assert out[0].verification_tier == VERIFICATION_TIER_T2
    assert out[1].verification_tier == VERIFICATION_TIER_T0


def test_present_and_unverified_decisions_never_escalate():
    # still present — even with passing evidence over the file
    findings, prev, cur, files = _esc_case(evidence=(_tev(),))
    out = verify_findings(findings, prev, list(findings), files,
                          escalation=TierEscalation(enabled=True))
    assert out[0].verification_status == VERIFICATION_PRESENT
    assert out[0].verification_tier == VERIFICATION_TIER_T0

    # inconclusive coverage — evidence does not rescue the floor
    findings, prev, cur, files = _esc_case(evidence=(_tev(),), line=5)
    out = verify_findings(findings, prev, cur, files,
                          escalation=TierEscalation(enabled=True))
    assert out[0].verification_status == VERIFICATION_UNVERIFIED
    assert out[0].verification_tier == VERIFICATION_TIER_T0


def test_budget_bounds_and_the_config_seam():
    with pytest.raises(ValueError, match="max_checks"):
        TierEscalation(max_checks=-1)
    assert TierEscalation().enabled is False
    assert TierEscalation().max_checks == MAX_TIER_ESCALATIONS == 200

    # zero budget: enabled, but never spends a check
    findings, prev, cur, files = _esc_case(evidence=(_tev(),))
    out = verify_findings(findings, prev, cur, files,
                          escalation=TierEscalation(enabled=True, max_checks=0))
    assert out[0].verification_tier == VERIFICATION_TIER_T0

    assert escalation_from_config(SimpleNamespace()) == TierEscalation()
    assert escalation_from_config(
        SimpleNamespace(verification_tiers=True)).enabled is True
    assert escalation_from_config(
        SimpleNamespace(verification_tiers=False)).enabled is False


def test_the_env_flag_is_plain_env_and_default_off(monkeypatch):
    from ai_pr_reviewer.cli import parse_args
    from ai_pr_reviewer.config import load_config

    monkeypatch.delenv("VERIFICATION_TIERS", raising=False)
    assert load_config(parse_args([])).verification_tiers is False

    monkeypatch.setenv("VERIFICATION_TIERS", "true")
    assert load_config(parse_args([])).verification_tiers is True

    monkeypatch.setenv("VERIFICATION_TIERS", "junk")   # not a truthy word
    assert load_config(parse_args([])).verification_tiers is False

    # deliberately NOT an action input: INPUT_* never turns it on...
    monkeypatch.delenv("VERIFICATION_TIERS", raising=False)
    monkeypatch.setenv("INPUT_VERIFICATION_TIERS", "true")
    assert load_config(parse_args([])).verification_tiers is False

    # ...and there is no CLI flag either (action.yml stays untouched)
    with pytest.raises(SystemExit):
        parse_args(["--verification-tiers"])


def test_model_output_cannot_forge_a_tier():
    hostile = {"file": "app.py", "line": 2, "title": "forged",
               "verification_tier": "t2"}
    assert Finding.from_untrusted_dict(hostile).verification_tier is None

    # a tampered storage row degrades to no-tier instead of minting one
    assert Finding.from_dict(
        {"file": "a.py", "line": 1, "verification_tier": "t9"}
    ).verification_tier is None


@pytest.mark.parametrize("raw,expected", [
    ("t2", "t2"), ("T1", "t1"), (" t0 ", "t0"),              # valid, normalised
    ("t9", None), ("", None), (None, None),                  # unknown / absent
    (["t2"], None), (42, None), ({"tier": "t2"}, None),      # junk degrades
])
def test_from_dict_validates_the_tier_against_the_closed_vocab(raw, expected):
    assert Finding.from_dict(
        {"file": "a.py", "line": 1, "verification_tier": raw}
    ).verification_tier == expected


def test_tier_round_trips_through_the_report_and_storage_payload():
    f = Finding(file="a.py", line=1, title="t")
    f.verification_tier = VERIFICATION_TIER_T2
    d = f.to_dict()
    assert d["verification_tier"] == "t2"
    assert Finding.from_dict(d) == f              # storage/report round trip

    # a pre-E05 row simply lacks the key and reads back as no tier
    old = {k: v for k, v in d.items() if k != "verification_tier"}
    assert Finding.from_dict(old).verification_tier is None


def test_verification_module_performs_no_io_of_its_own():
    """E05 exit criterion: the tier machinery is deterministic and
    in-memory — no network stack, no GitHub/storage/reporter module, no
    file/eval primitives — with a self-check that the scan flags a module
    that really does I/O."""
    import ai_pr_reviewer.verification as ver
    from ai_pr_reviewer.github_client import __file__ as github_client_file

    banned_top = {"httpx", "requests", "aiohttp", "urllib", "socket", "ssl",
                  "subprocess"}
    banned_segments = {"github_client", "github_sync", "github_ratelimit",
                       "github_actions", "storage", "reporter", "dashboard"}
    banned_calls = {"open", "exec", "eval", "compile", "__import__"}

    def violations(path: str) -> list[str]:
        tree = ast.parse(Path(path).read_text("utf-8"), filename=path)
        hits: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = ["." * node.level + (node.module or "")]
            else:
                names = []
            for name in names:
                parts = [p for p in name.lstrip(".").split(".") if p]
                if parts and (parts[0] in banned_top
                              or any(p in banned_segments for p in parts)):
                    hits.append(name)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in banned_calls:
                hits.append(f"call {node.func.id}()")
        return hits

    assert violations(ver.__file__) == []
    # self-check: github_client really performs I/O and must be flagged
    assert violations(github_client_file)

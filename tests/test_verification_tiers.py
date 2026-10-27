"""V4.2-E05-T01 — the verification tier model: vocabulary, not behavior.

Tier numbering is the backlog's T0/T1/T2 (plan §B.7 C2 pins it against the
roadmap's 1-based T1/T2/T3): T0 diff-coverage floor, T1 static re-check,
T2 observed test evidence. This ticket changes no verification decision —
the last test pins exactly that (no tier key in the output until E05-T04
adds the attribution field).
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer import models
from ai_pr_reviewer.diff_parser import FileDiff, Hunk, HunkLine
from ai_pr_reviewer.models import (Finding, VERIFICATION_PRESENT,
                                   VERIFICATION_RESOLVED,
                                   VERIFICATION_TIER_T0, VERIFICATION_TIER_T1,
                                   VERIFICATION_TIER_T2, VERIFICATION_TIERS,
                                   VERIFICATION_UNVERIFIED)
from ai_pr_reviewer.verification import (REASON_PRESENT, REASON_RESOLVED,
                                         TIER_EVIDENCE, VERIFICATION_TIER_RANK,
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

def test_t0_decisions_are_unchanged_and_carry_no_tier_key_yet():
    """E05-T01 ships the model only: every status/reason the coverage floor
    produces is what it was before tiers existed, and no tier key has been
    added to the report output (the attribution field arrives in T04)."""
    resolved = _finding(state="resolved")
    out = verify_findings([resolved], previous=_baseline(), current=[],
                          files=[_file()])
    assert (out[0].verification_status, out[0].verification_reason) == \
        (VERIFICATION_RESOLVED, REASON_RESOLVED)
    assert "verification_tier" not in out[0].to_dict()

    present = _finding()
    out = verify_findings([present], previous=_baseline(), current=[present],
                          files=[_file()])
    assert (out[0].verification_status, out[0].verification_reason) == \
        (VERIFICATION_PRESENT, REASON_PRESENT)
    assert "verification_tier" not in out[0].to_dict()

    partial = _finding(state="resolved")
    out = verify_findings([partial], previous=_baseline(), current=[],
                          files=[_file(count=3)])       # lines 1-3, finding on 5
    assert out[0].verification_status == VERIFICATION_UNVERIFIED
    assert "verification_tier" not in out[0].to_dict()


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

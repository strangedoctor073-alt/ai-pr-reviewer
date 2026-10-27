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
                                         stronger_tier, verify_findings)

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

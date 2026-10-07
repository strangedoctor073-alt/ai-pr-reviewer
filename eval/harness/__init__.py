"""V3-E03 harness implementation (runner, matcher, scorer, gate, report).

Public entry points:

* ``python -m eval.harness``            — run the corpus, print results
* ``python -m eval.harness --gate``     — CI regression gate (exit 1 on drop)
* ``python -m eval.harness --json PATH`` — machine-readable results (T05)
* ``load_corpus()`` / ``run_case()``    — imported directly by the tests
* ``score_corpus()``                    — metrics (T02)
"""
from __future__ import annotations

from .loader import Case, CorpusError, Label, load_case, load_corpus
from .report import build_report, dumps_report
from .runner import CaseRun, run_case
from .score import (Scorecard, dumps_scorecard, score_case, score_corpus,
                    scorecard_to_dict)

__all__ = [
    "Case", "CaseRun", "CorpusError", "Label", "Scorecard",
    "build_report", "dumps_report", "dumps_scorecard", "load_case",
    "load_corpus", "run_case", "score_case", "score_corpus",
    "scorecard_to_dict",
]

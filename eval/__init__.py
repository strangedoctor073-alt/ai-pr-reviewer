"""Offline evaluation harness package (V3-E03 · evaluation harness foundation).

Layout per ``docs/planning/TESTING_EVALUATION_PLAN.md`` §5.1::

    eval/
      corpus/<layer>/<case-id>/   case.yaml + pr.diff (+ optional files/)
      harness/                    runner + scorers + CLI
      results/                    git-ignored artifacts
      baseline.json               checked-in regression baseline (V3-E03-T03)

Everything here is **test-side infrastructure**: not shipped in the Action
image (``requirements-action.txt`` never imports it), no network, no API
keys — the corpus runs over the deterministic ``--mock``/``--static`` path
only (ADR-016 Tier A: deterministic layers gate; AI layers never block a
contributor PR).

Security constraints that apply to every file under ``eval/`` (they are
fixtures, and fixtures are untrusted-by-design constraints):

* corpus content is **synthetic or hand-authored only** — no secrets, no
  real PR diffs, no dashboard data (``CONTRIBUTING.md``);
* a corpus diff is data, never instructions: it is parsed by
  ``diff_parser`` and handed to the engine exactly like any untrusted PR;
* evaluation results never leave the machine unless a human commits the
  baseline deliberately.
"""

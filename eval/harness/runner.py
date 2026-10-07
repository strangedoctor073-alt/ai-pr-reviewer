"""V3-E03-T01 — offline deterministic runner for one corpus case.

Runs a case through the **real** review pipeline, not a re-implementation
of it: ``ReviewOrchestrator(cfg, gh=None, storage=..., pr=..., diff_text=...)``
— the same local-``--diff-file`` path ``cli.py`` uses. That matters for
V3-E03-T04: defects D2/D3/D4/D5 live in the orchestrator's wiring
(lifecycle input, ``below_threshold`` retention, report uncapped, final
severity sort), so a harness that staged its own copy of that logic could
never fail when the defect is re-introduced. Every assertion here runs
against production code.

Isolation guarantees (offline + reproducible):

* ``Config`` is constructed field-by-field — ``load_config`` is *not*
  called for pipeline cases, so host ``INPUT_*`` / API-key environment
  variables can never flip the run onto a live provider. With no keys in
  the config the model router falls back to the static rule engine
  (``engine == "static"``), no network, no API keys;
* state (previous findings, persistence) lives in a per-case temp
  directory provided by the caller — never in the repository;
* nothing in a run result depends on wall-clock time, duration, host
  paths or iteration order, so the serialized output is byte-stable for
  a given corpus + code (TESTING_EVALUATION_PLAN.md §5.3).

Failure handling is redacted: engine/config exceptions surface as
``TypeName: message`` through :func:`ai_pr_reviewer.security.redact_secrets`,
because exception text is untrusted output like any other.
"""
from __future__ import annotations

import gc
import os
from dataclasses import dataclass, field
from pathlib import Path

from ai_pr_reviewer.config import Config, load_config
from ai_pr_reviewer.models import Finding, PRContext
from ai_pr_reviewer.orchestrator import ReviewOrchestrator
from ai_pr_reviewer.security import redact_secrets

from .loader import Case

# Fixed identity for corpus runs: same repo/pr every run keeps storage
# seeding and any repo-keyed lookups identical across runs and machines.
EVAL_REPO = "eval/corpus"
EVAL_PR = 0

_MAX_ERROR_CHARS = 300


@dataclass
class CaseRun:
    """Raw (unscored) outcome of running one case.

    ``run_status``:

    * ``"ran"``     — the pipeline completed; expectations scored in T02;
    * ``"error"``   — the run raised where it should not (see ``error``);
    * ``"skipped"`` — the case's ``engine_matrix`` needs a live provider;
                      only the offline static engine runs here.

    ``findings`` holds the **posted** bucket (report findings at/above the
    severity threshold), ``below`` the retained below-threshold bucket —
    both are report-visible (D3), and each entry carries its ``bucket``.
    """

    case_id: str
    layer: str
    run_status: str
    engine: str = ""
    findings: list[dict] = field(default_factory=list)
    below: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    skipped_reason: str | None = None


def _finding_dict(f: Finding, bucket: str) -> dict:
    """The scored projection of a finding — fixed keys, JSON-safe values."""
    return {
        "file": f.file,
        "line": f.line,
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "state": f.state,
        "bucket": bucket,
    }


def _previous_finding(data: dict) -> Finding:
    """Build a seeded prior-review finding from a ``previous:`` label."""
    return Finding(
        file=str(data["file"]),
        line=data.get("line"),
        severity=data.get("severity", "medium"),
        category=data.get("category", "bug"),
        title=str(data["title"]),
        explanation=data.get("explanation",
                             "seeded by evaluation corpus (prior review)"),
        state=data.get("state", "active"),
    )


def _redact_error(exc: Exception) -> str:
    return redact_secrets(f"{type(exc).__name__}: {exc}")[:_MAX_ERROR_CHARS]


def _run_config_error_case(case: Case) -> CaseRun:
    """Run a case whose contract is *how the run fails* (defect D6).

    A garbage numeric ``INPUT_*`` must surface as a clean string
    ``SystemExit`` (exit 1, no traceback); a raw ``ValueError`` escaping
    config parsing means the defect is present. The host ``INPUT_*``
    environment is cleared and restored around the call so the case is
    hermetic on any machine.
    """
    saved = {k: v for k, v in os.environ.items() if k.startswith("INPUT_")}
    try:
        for key in saved:
            del os.environ[key]
        os.environ["INPUT_MAX_COMMENTS"] = "abc"
        try:
            from ai_pr_reviewer.cli import parse_args

            load_config(parse_args([]))
        except SystemExit as exc:
            if isinstance(exc.code, str):
                return CaseRun(case.id, case.layer, "ran", engine="config")
            return CaseRun(
                case.id, case.layer, "error", engine="config",
                error=f"SystemExit with non-string code {exc.code!r}; expected "
                      f"a clean config-error message")
        except Exception as exc:
            return CaseRun(
                case.id, case.layer, "error", engine="config",
                error=f"raw {_redact_error(exc)} escaped config parsing; "
                      f"expected a clean string SystemExit")
        return CaseRun(
            case.id, case.layer, "error", engine="config",
            error="no config error raised for a garbage INPUT_MAX_COMMENTS")
    finally:
        for key in [k for k in os.environ if k.startswith("INPUT_")]:
            del os.environ[key]
        os.environ.update(saved)


def run_case(case: Case, workdir: Path | str) -> CaseRun:
    """Execute ``case`` fully offline and return its raw outcome.

    ``workdir`` must be a scratch directory (pytest ``tmp_path`` /
    ``tempfile``); it receives any per-case state storage and is owned by
    the caller. The function never writes inside the repository.
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    if case.expect.config_error:
        return _run_config_error_case(case)

    if "static" not in case.engine_matrix:
        return CaseRun(
            case.id, case.layer, "skipped",
            skipped_reason=f"engine_matrix {list(case.engine_matrix)} needs a "
                           f"live provider; only the offline static engine "
                           f"runs in this harness")

    diff_text = case.diff_path.read_text(encoding="utf-8")
    cfg = Config(
        repo=EVAL_REPO,
        pr_number=EVAL_PR,
        severity_threshold=case.config.severity_threshold,
        severity_threshold_explicit=True,
        max_comments=case.config.max_comments,
        exclude=list(case.config.exclude),
    )

    storage = None
    if case.previous_findings:
        from ai_pr_reviewer.storage import LocalReviewStorage

        storage = LocalReviewStorage(workdir / f"{case.id}.state.db")
        storage.save_findings(
            f"{EVAL_REPO}#{EVAL_PR}@eval",
            [_previous_finding(d) for d in case.previous_findings],
        )

    orchestrator = ReviewOrchestrator(
        cfg, gh=None, storage=storage,
        pr=PRContext(repo=EVAL_REPO, pr_number=EVAL_PR),
        diff_text=diff_text,
    )
    try:
        result = orchestrator.run()
    except Exception as exc:  # engine/config crash — surfaced, redacted
        return CaseRun(case.id, case.layer, "error",
                       engine="", error=_redact_error(exc))
    finally:
        # LocalReviewStorage's per-call sqlite connections are cyclic
        # (connection <-> statement cache): refcounting alone never closes
        # them, so the .state.db file stays locked on Windows until the
        # next GC pass — which would land after the caller's temp-directory
        # cleanup and raise PermissionError. Collect deterministically
        # here so the caller can delete `workdir` the moment run_case
        # returns. (Production code is untouched: the Action exits right
        # after a run, so this only matters for harness/fixture lifetimes.)
        gc.collect()

    return CaseRun(
        case.id, case.layer, "ran",
        engine=getattr(result, "engine", "") or "",
        findings=[_finding_dict(f, "reported") for f in result.findings],
        below=[_finding_dict(f, "below_threshold")
               for f in result.below_threshold],
        warnings=list(result.warnings),
    )

"""V3-E05-T02 — the D13 hard-coded-cap inventory, machine-checked.

D13 (``CURRENT_ARCHITECTURE.md``) called out "silent quality ceilings" —
caps baked into source as literals, invisible to anyone tuning behaviour.
This suite is the named-constants surface: every documented cap must be an
importable, commented constant with an UNCHANGED value (T02 is a pure
refactor — no value changes), and no literal may creep back in at the
documented sites.

Inventory (D13 row, reconciled against the code):

======================  ==============================================
documented cap          named constant
======================  ==============================================
8 context files         repo_context.MAX_CONTEXT_FILES
4 config probes         repo_context.MAX_CONFIG_CANDIDATES
50 memory entries       memory.MAX_MEMORY_ENTRIES
20 comments             config.DEFAULT_MAX_COMMENTS (default, not a hard
                        cap — inline posting is ``cfg.max_comments``)
500 dashboard findings  dashboard.app.MAX_FINDINGS and (per-report
                        storage cap) dashboard.storage.MAX_FINDINGS_STORED
8 markdown findings     reporter.MAX_MARKDOWN_FINDINGS
======================  ==============================================

D13-adjacent literals found and named during this ticket: the dashboard
sandbox endpoint's diff/finding limits, the saved-rules list/length bounds
and the memory-note write bound shared with ``ai_pr_reviewer.memory``
(``dashboard.app``, ``dashboard.storage``).

Out of scan scope (not quality ceilings — different categories): DB column
widths (``author[:100]``, ``pr_title[:300]``, ``path_pattern[:255]`` …),
id/slug/hash truncation (``uuid.hex[:6]``, ETags), error-echo truncation
(``r.text[:200]``) and input-validation ranges (``1 <= max_comments <= 100``).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Files whose caps the D13 inventory (and this ticket) covers. A
# re-hardcoded cap takes the shape `values[:50]`, so these files are scanned
# for slices using the documented cap values.
SCANNED_FILES = (
    "ai_pr_reviewer/reporter.py",
    "ai_pr_reviewer/orchestrator.py",
    "ai_pr_reviewer/context.py",
    "ai_pr_reviewer/memory.py",
    "ai_pr_reviewer/repo_context.py",
    "ai_pr_reviewer/config.py",
    "dashboard/app.py",
    "dashboard/storage.py",
)

# The documented cap values (D13 inventory + the caps named in this ticket).
# 100 is deliberately absent: `author[:100]` is a DB column width, and no
# way to tell them apart from a slice alone — the settings list cap that
# value guards is named (MAX_SETTINGS_LIST_ENTRIES) and value-frozen above.
_HARDCODED_CAP_SLICE = re.compile(
    r"\[\s*:\s*(?:50_000|50000|12_000|12000|4_000|4000|500|50|20|8|4)\s*\]")
_MAGIC_TOP_N = re.compile(r"top_n\s*:\s*int\s*=\s*\d+")  # ARCH-05: fn default cap
_MAGIC_COMMENTS = re.compile(r'"max_comments"\s*:\s*20')  # comment default literal


def test_documented_caps_are_named_constants_with_unchanged_values():
    """Freeze every documented cap's value (a value change must be a
    deliberate, reviewed edit to this test — not an accident)."""
    from ai_pr_reviewer import config, memory, repo_context, reporter
    import dashboard.app as dashboard_app
    import dashboard.storage as dashboard_storage

    # D13 inventory
    assert repo_context.MAX_CONTEXT_FILES == 8
    assert repo_context.MAX_CONFIG_CANDIDATES == 4
    assert memory.MAX_MEMORY_ENTRIES == 50
    assert config.DEFAULT_MAX_COMMENTS == 20
    assert config.Config().max_comments == 20      # dataclass default shares it
    assert dashboard_app.MAX_FINDINGS == 500
    assert dashboard_storage.MAX_FINDINGS_STORED == 500
    assert reporter.MAX_MARKDOWN_FINDINGS == 8

    # D13-adjacent caps named in this ticket
    assert dashboard_app.MAX_ANALYZE_DIFF_CHARS == 50_000
    assert dashboard_app.MAX_ANALYZE_FINDINGS == 50
    assert dashboard_app.MAX_SETTINGS_ITEM_CHARS == 200
    assert dashboard_app.MAX_SETTINGS_LIST_ENTRIES == 100
    assert dashboard_app.MAX_SETTINGS_FOCUS_ENTRIES == 50

    # The dashboard's default comment cap is the engine's (single value,
    # no second literal to drift): T01's single-sourcing lesson applied.
    assert dashboard_app.SETTINGS_KEYS["max_comments"] == config.DEFAULT_MAX_COMMENTS

    # The memory-note bound has one value across engine and dashboard: the
    # storage helper's engine-less fallback must equal the engine constant
    # (the fallback cannot import it, so this test pins the two together).
    assert dashboard_storage._max_note_chars() == memory.MAX_NOTE_CHARS == 1_000
    assert dashboard_app.MAX_NOTE_CHARS == memory.MAX_NOTE_CHARS


def test_no_hard_coded_caps_remain_at_the_documented_sites():
    """Grep guard: re-introducing a literal slice / magic default at any of
    the documented sites fails here (the D13 defect coming back)."""
    offenders: list[str] = []
    for rel in SCANNED_FILES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            for pattern in (_HARDCODED_CAP_SLICE, _MAGIC_TOP_N, _MAGIC_COMMENTS):
                if pattern.search(line):
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "hard-coded caps crept back in (V3-E05-T02 wants named constants):\n"
        + "\n".join(offenders))


def test_summary_markdown_default_comes_from_the_named_constant():
    """The step-summary cap's default must be the constant, not a literal
    re-stated in the signature (ARCH-05's 'function default' finding)."""
    import inspect

    from ai_pr_reviewer import reporter

    default = inspect.signature(reporter.build_summary_markdown).parameters["top_n"].default
    assert default == reporter.MAX_MARKDOWN_FINDINGS

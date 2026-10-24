# Context engine (V4-E02) and change impact (V4-E03)

How the reviewer decides **which** repository files reach a prompt, **why**,
and **how much** of each. Everything here is deterministic, offline and
bounded: no embeddings, no vector database, no model call deciding relevance
(rejected for V4 in the scope record, ADR-017).

## Pipeline

```
checkout ──► index (E01) ──► impact (E03) ──► selection (E02) ──► fetch ──► prompt
 (base rev)   files/imports    bounded BFS      closed reasons      GitHub     fenced,
                                                                    contents   redacted
```

`context.build_context` orchestrates it. With **no index** (no checkout,
origin mismatch, `repo_context_chars <= 0`) selection and impact are `None`
and the run is byte-identical to pre-V4.

## Selection contract (`selection.py`, ADR-017)

`select_context(index, changed_paths, impact=...)` returns a
`ContextSelection`:

| Field | Meaning |
|---|---|
| `selected_files[]` | `{path, reason, rank, relationship, size}` |
| `excluded_files[]` | `{path, reason}` — `over_cap`, `budget`, `not_indexed` |
| `budget_state` | `ok` \| `truncated` \| `exhausted` |

**Closed reason set** (a new reason is a contract change):

| Reason | Priority | Meaning |
|---|---|---|
| `changed` | 0 | in the diff |
| `import` / `importer` | 1 | imported by / imports a changed file (impact dependents join as `importer` at a deeper rank) |
| `test_of` | 2 | test for a changed module — `test_x.py`, `x_test.go`, `x.test.ts`, `x.spec.ts`, `x_spec.rb`, or under `tests/` / `test/` / `__tests__/` |
| `config_of` | 3 | project configuration (small explicit basename list) |
| `adjacent` | 4 | same directory as a changed file |
| `manual` | 5 | explicitly requested by policy, never inferred |

Order is `reason priority → rank → path`: identical inputs give identical
output regardless of index iteration order. The selected set is capped
(`DEFAULT_MAX_SELECTED = 24`, hard 100) and every drop is listed.

**Contract order vs fetch order.** The contract keeps `changed` first. The
files *fetched* for the prompt put changed files **last**: their hunks are
already in the prompt, so they only fill leftover budget. (Fetching them
first used up all 8 fetch slots on a PR touching 8+ files.)

## Change impact (`impact.py`, E03)

`compute_impact(index, changed_paths, max_hops=2, max_nodes=50)` walks the
**reverse import graph** breadth-first (iterative, no recursion). Caps are
named constants: `DEFAULT_MAX_HOPS = 2` (hard 4), `DEFAULT_MAX_NODES = 50`
(hard 200).

* Each entry has `hop`, `confidence` (`direct` hop 1, `indirect` hop ≥ 2) and
  `via`, the index edge it was reached through.
* A changed file absent from the index is `unknown_seeds` — never guessed.
* **Truncation is never silent.** `truncation` is `"hops"` (dependents exist
  beyond the hop limit) or `"nodes"` (affected-file ceiling hit); `""` means
  the closure is complete within the index.
* Impact is a signal, never a finding.

### Prompt section

`render_impact_section(result, max_chars)` produces a short text block, and
`context.build_untrusted_impact_block(section, warnings)` fences it. It is
treated exactly like index content: each path must be a plain relative,
printable path (anything else is counted, not echoed), the block is
secret-redacted, injection-screened, wrapped in `<untrusted_repo_file>` inside
the `untrusted_diff` fence, and never longer than its allocation. No impact ⇒
empty section ⇒ prompt unchanged.

`ReviewContext.impact_section` carries the text; providers fence it with
`build_untrusted_impact_block`.

## One budget (`context.py`)

`ContextBudget.from_config(cfg)` maps the existing inputs into a single
ledger; **no input was removed or renamed**.

| Allocation | Source | Notes |
|---|---|---|
| `diff_chars` | `INPUT_BATCH_CHARS` (`batch_chars`) | unchanged trim behaviour; `<= 0` still means unlimited |
| `repo_chars` | `INPUT_REPO_CONTEXT_CHARS` | unchanged; `<= 0` is still the master switch (no reads, no index, no impact) |
| `impact_chars` | new, additive | `1_500` chars; own allocation, so repository-file behaviour is unchanged |
| `memory_chars` | `memory.py` bound | 50 notes × 1 000 chars (+ category prefix) |

**Token equivalents** use `CHARS_PER_TOKEN = 4`, an *estimate*; real usage
comes from provider telemetry. `ContextBudgetReport` gives `ceiling_tokens`,
`used_tokens`, and tokens per source (`diff`, `repository_files`, `impact`,
`memory`) — counts only, never content.

> **Deprecation note.** `ReviewContext.token_budget` has always been a
> *character* count despite the name, and still is. It is kept for
> compatibility; prefer `context_budget.ceiling_tokens`.

### Degradation is loud

`ContextBudgetReport.state`:

* `ok` — nothing trimmed, skipped or omitted for budget.
* `truncated` — something was cut (diff hunks, repository files, impact
  entries, or candidates selection itself excluded).
* `exhausted` — a changed file's diff was dropped entirely, or the index ran
  out of room.

When the V4 index is active and a reason owned by this layer applies, one
counts-only line is added to `context_warnings` (merged into the run's
warnings by the orchestrator), e.g. `context budget truncated: est. 3120 of
26,900 tokens used (diff=…); repository files: character budget reached … —
the review continues with partial context`. Degradation inherited from the
index build is recorded in the report (`index:` reasons) but not repeated as a
warning; the index logs it when built.

Truncation order: repository files are cut lowest-ranked first. The diff and
repository memory are never cut by the ledger's repo/impact allocations.
There is no per-file "security-relevant" classification yet.

## Measuring relevance — relevance@10

Defined in `TESTING_EVALUATION_PLAN.md` §8 #5: labeled relevant files inside
the selection contract's top 10 ÷ labeled relevant files, micro-averaged over
corpus cases with a `checkout/` fixture. Gate ≥ 0.70. Implemented in
`eval/harness` and run by `python -m eval.harness --gate`. Because the metric
scores the *contract* order (`changed` first), a PR with ≥ 10 changed files
fills the top 10 with changed files.

## Known limits

* Imports are parsed line-by-line: a multi-line `from pkg import (...)`
  statement records only the `from` target — names on continuation lines do
  not become submodule edges (the one-line forms `from pkg.module import x`,
  `import pkg.module`, `from pkg import mod` and `from . import mod` all
  resolve; CHANGELOG 4.0.0 "Import graph"). Plain symbol imports
  (`from pkg import func`) intentionally resolve to no file.
* Fetch is still bounded by the V3 caps in `repo_context.py` (8 files, 4 000
  chars per file, 16 probes); the selection contract can rank more candidates
  than are fetched.

# Architecture intelligence (V4.2-E04, opt-in)

Declare layers in the trusted `.ai-pr-reviewer.yml` (read from the base
revision only) and the review flags dependencies that point the wrong way.
Off unless `architecture.enabled: true`; absent or disabled ⇒ no change to
any output.

```yaml
architecture:
  enabled: true
  severity: medium        # info | low | medium | high (never critical)
  max_findings: 20        # 1..100
  layers:
    - name: api
      paths: ["src/api/**"]
    - name: domain
      paths: ["src/domain/**"]
  allow:                  # importer layer -> layers it may import
    api: [domain]
```

* Same-layer imports are always fine; cross-layer imports must be listed
  in `allow` (a layer with no entry may import no other layer).
* Globs use the same `fnmatch` semantics as `exclude`; overlapping layers
  resolve by declaration order. Files in no layer are not judged.
* Judged edges: imports on lines the PR adds (anchored inline) and
  base-tree graph edges in files the PR touches (file-level). Privacy
  baseline paths are never read, layered or cited.
* Findings: rule `ARCH001`, category `maintainability`, two evidence
  records (offending edge `file_excerpt`, rule `rule_ref`), provenance
  `static` / `architecture-v1` / `rule`. No suggestion is ever produced.
* If the index or the finding cap truncated the analysis the run says so
  (warning + lower confidence) instead of implying completeness.

## Snapshot / drift contract (v1)

`build_snapshot` / `compute_drift` compare two JSON-safe snapshots
(`version`, `model_digest`, `complete`, `layer_edges`, `violations`,
`digest`). Snapshots built under different `architecture` rules are not
comparable; a partial current snapshot never reports "resolved". The
pipeline supplies no baseline today, so drift is inert until a store (the
V4-E06 twin, when it exists) feeds `previous_snapshot`.

Known limits: only the first line of a multi-line import is seen; edges
resolve only to indexed files (external packages are ignored).

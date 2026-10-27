"""V4.2-E04-T01 — architecture description schema (trusted config).

The ``architecture:`` section of ``.ai-pr-reviewer.yml`` declares layers
(path globs) and which layers may depend on which. Like the rest of that
file it is TRUSTED repository-owner configuration, read from the base
revision only — it never comes from PR content, so it is validated here but
not fenced. Anything *derived from the repository tree* (paths) that ends up
in a finding is redacted at the findings boundary, not here.

Contract points (all tested):

* **opt-in, default OFF** — the section must exist *and* carry
  ``enabled: true``; every other state parses to ``None`` (silent no-op).
* **additive** — a distinct top-level key; v1 configs without it behave
  byte-identically.
* **fail closed to no-op** — any structural problem logs a warning and
  yields ``None``; a malformed section can never crash or alter a review.
* **bounded** — layer/pattern/finding counts and string lengths are capped
  so a hostile or typo'd file cannot balloon matching work.

Glob semantics match ``index.limits.is_excluded`` (``fnmatch`` on the
repository-relative path, ``*`` crosses ``/``) so layer assignment and the
privacy-baseline filter agree on what a pattern means.

Example::

    architecture:
      enabled: true
      severity: medium          # info|low|medium|high (never critical)
      max_findings: 20
      layers:
        - name: api
          paths: ["src/api/**"]
        - name: domain
          paths: ["src/domain/**"]
        - name: shared
          paths: ["src/shared/**"]
      allow:                    # importer layer -> layers it may import
        api: [domain, shared]
        domain: [shared]
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)

SECTION_KEY = "architecture"

MAX_LAYERS = 32
MAX_PATTERNS_PER_LAYER = 20
MAX_PATTERN_CHARS = 200
DEFAULT_MAX_FINDINGS = 20
HARD_MAX_FINDINGS = 100
DEFAULT_SEVERITY = "medium"
# A structural-convention finding must never be able to out-rank a security
# finding or fail a build on its own by configuration.
ALLOWED_SEVERITIES = ("info", "low", "medium", "high")

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")
_KNOWN_KEYS = frozenset({"enabled", "severity", "max_findings", "layers",
                         "allow"})


@dataclass(frozen=True)
class Layer:
    name: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class ArchitectureModel:
    """Validated, immutable architecture description."""

    layers: tuple[Layer, ...]
    # (importer_layer, (allowed imported layers…)) — sorted, deterministic.
    allow: tuple[tuple[str, tuple[str, ...]], ...] = ()
    severity: str = DEFAULT_SEVERITY
    max_findings: int = DEFAULT_MAX_FINDINGS

    def layer_of(self, path: str) -> str | None:
        """First declared layer whose pattern matches ``path`` (declaration
        order is the tie-break, so overlapping globs are deterministic);
        ``None`` for unlayered files — edges touching them are not judged."""
        for layer in self.layers:
            for pat in layer.paths:
                if fnmatch.fnmatch(path, pat):
                    return layer.name
        return None

    def allowed_targets(self, layer: str) -> tuple[str, ...]:
        for name, targets in self.allow:
            if name == layer:
                return targets
        return ()

    def allows(self, importer_layer: str, imported_layer: str) -> bool:
        """Same-layer dependencies are always allowed; cross-layer ones only
        when listed. A layer with no ``allow`` entry may import no other
        layer (explicit allow-list, never an implicit allow-all)."""
        if importer_layer == imported_layer:
            return True
        return imported_layer in self.allowed_targets(importer_layer)

    def digest(self) -> str:
        """Stable fingerprint of the *semantics* of the model (used by drift
        to refuse comparing snapshots built under different rules)."""
        payload = {
            "layers": [[l.name, list(l.paths)] for l in self.layers],
            "allow": [[n, list(t)] for n, t in self.allow],
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ArchitectureParse:
    """Result of parsing one section: ``model`` is ``None`` for every no-op
    state; ``warnings`` are bounded, config-derived strings."""

    model: ArchitectureModel | None
    warnings: tuple[str, ...] = ()


def _warn(out: list[str], source: str, msg: str) -> None:
    text = f"{source}: architecture: {msg}"
    log.warning("%s", text)
    if len(out) < 20:
        out.append(text)


def _parse_layers(raw: object, source: str,
                  warnings: list[str]) -> list[Layer]:
    if not isinstance(raw, list):
        _warn(warnings, source, "'layers' must be a list — section ignored")
        return []
    layers: list[Layer] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        if len(layers) >= MAX_LAYERS:
            _warn(warnings, source,
                  f"more than {MAX_LAYERS} layers — extra layers ignored")
            break
        if not isinstance(item, dict):
            _warn(warnings, source, f"layers[{i}] is not a mapping — skipped")
            continue
        name = item.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            _warn(warnings, source,
                  f"layers[{i}] has an invalid name — skipped "
                  "(letters, digits, '_' or '-'; starts with a letter)")
            continue
        if name in seen:
            _warn(warnings, source,
                  f"duplicate layer name '{name}' — later entry skipped")
            continue
        paths_raw = item.get("paths")
        if not isinstance(paths_raw, list):
            _warn(warnings, source,
                  f"layer '{name}' needs a 'paths' list — skipped")
            continue
        paths: list[str] = []
        for p in paths_raw:
            if not isinstance(p, str) or not p.strip():
                continue
            pat = p.strip().replace("\\", "/")
            if (len(pat) > MAX_PATTERN_CHARS or pat.startswith("/")
                    or ".." in pat.split("/")):
                _warn(warnings, source,
                      f"layer '{name}' has an unusable path pattern — "
                      "skipped (relative, no '..', <= "
                      f"{MAX_PATTERN_CHARS} chars)")
                continue
            if pat not in paths:
                paths.append(pat)
            if len(paths) >= MAX_PATTERNS_PER_LAYER:
                _warn(warnings, source,
                      f"layer '{name}' capped at {MAX_PATTERNS_PER_LAYER} "
                      "path patterns")
                break
        if not paths:
            _warn(warnings, source,
                  f"layer '{name}' has no usable paths — skipped")
            continue
        seen.add(name)
        layers.append(Layer(name=name, paths=tuple(paths)))
    return layers


def _parse_allow(raw: object, names: set[str], source: str,
                 warnings: list[str]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        _warn(warnings, source,
              "'allow' must be a mapping of layer -> [layers] — ignored "
              "(no cross-layer dependency will be allowed)")
        return ()
    out: dict[str, tuple[str, ...]] = {}
    for key, targets in raw.items():
        key = str(key)
        if key not in names:
            _warn(warnings, source,
                  f"allow references unknown layer '{key}' — skipped")
            continue
        if not isinstance(targets, list):
            _warn(warnings, source,
                  f"allow.{key} must be a list — treated as empty")
            out[key] = ()
            continue
        clean: list[str] = []
        for t in targets:
            t = str(t)
            if t not in names:
                _warn(warnings, source,
                      f"allow.{key} references unknown layer '{t}' — skipped")
            elif t != key and t not in clean:
                clean.append(t)
        out[key] = tuple(sorted(clean))
    return tuple(sorted(out.items()))


def parse_architecture_section(raw: object,
                               source: str = ".ai-pr-reviewer.yml"
                               ) -> ArchitectureParse:
    """Validate the raw ``architecture`` value. Never raises."""
    warnings: list[str] = []
    try:
        if raw is None:
            return ArchitectureParse(None)
        if not isinstance(raw, dict):
            _warn(warnings, source, "section must be a mapping — ignored")
            return ArchitectureParse(None, tuple(warnings))
        if raw.get("enabled") is not True:
            # Opt-in: absent or false/any-other-value means off, silently.
            return ArchitectureParse(None)

        unknown = sorted(str(k) for k in raw if k not in _KNOWN_KEYS)
        if unknown:
            _warn(warnings, source,
                  f"unknown key(s) ignored: {', '.join(unknown)}")

        sev = raw.get("severity", DEFAULT_SEVERITY)
        if not isinstance(sev, str) or sev.lower() not in ALLOWED_SEVERITIES:
            _warn(warnings, source,
                  f"invalid severity {sev!r} — using '{DEFAULT_SEVERITY}' "
                  f"(allowed: {', '.join(ALLOWED_SEVERITIES)})")
            sev = DEFAULT_SEVERITY
        sev = sev.lower()

        mf = raw.get("max_findings", DEFAULT_MAX_FINDINGS)
        if isinstance(mf, bool) or not isinstance(mf, int) or mf < 1:
            _warn(warnings, source,
                  f"max_findings must be a positive integer — using "
                  f"{DEFAULT_MAX_FINDINGS}")
            mf = DEFAULT_MAX_FINDINGS
        if mf > HARD_MAX_FINDINGS:
            _warn(warnings, source,
                  f"max_findings capped at {HARD_MAX_FINDINGS}")
            mf = HARD_MAX_FINDINGS

        layers = _parse_layers(raw.get("layers"), source, warnings)
        if len(layers) < 2:
            _warn(warnings, source,
                  "at least two valid layers are required — section ignored")
            return ArchitectureParse(None, tuple(warnings))

        allow = _parse_allow(raw.get("allow"), {l.name for l in layers},
                             source, warnings)
        return ArchitectureParse(
            ArchitectureModel(layers=tuple(layers), allow=allow,
                              severity=sev, max_findings=mf),
            tuple(warnings))
    except Exception as exc:  # noqa: BLE001 — config must never crash a review
        _warn(warnings, source, f"unexpected error ({type(exc).__name__}) — "
                                "section ignored")
        return ArchitectureParse(None, tuple(warnings))

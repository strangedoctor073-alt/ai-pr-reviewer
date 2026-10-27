"""Risk features, score and depth decision for one review (V4.0-E04).

Three layers, each a pure function of the one below:

* **T01 features** -- measure the diff, impact and history signals a run
  already has into a fixed, closed set of named integer features.
  ``FEATURE_NAMES`` is pinned by a test and changes only deliberately.
* **T02 score** -- a deterministic, explainable function of *only* those
  features: a table of capped integer rules whose per-feature points sum to
  the score. The contributions are what the report shows, so the score can
  be recomputed by hand from the report alone.
* **T03/T04 depth decision** -- maps the score band to a review depth,
  specialist roles and a budget percentage, then applies the security-depth
  floor last, so no configuration can lower it.

In this release the assessment is *informational*: it is computed and
reported only when the (default-off) risk engine is enabled, and nothing in
the review pipeline acts on the depth decision. The specialist set is a
provisional interface pending V4.0-E02 specialist contracts.

Invariants:

* **Pure function of its inputs.** No I/O, no network, no model, no clock,
  no randomness, no floats. The same inputs in any file order yield an
  identical feature set (a test shuffles and compares).
* **Absent is explicit, never zero.** A feature whose source signal does not
  exist for this run (no repository index, no history) is reported with
  ``available=False`` and a closed-vocabulary ``reason``; it is not folded
  into ``0``. A later scorer must treat unavailable as "no signal", and a
  missing signal can never be read as "low risk".
* **Sensitivity matching is deliberately over-inclusive.** Path hints are
  plain substrings and a strict superset of the V3 ``classify_risk`` hints
  (pinned by a test), so this engine can never call a path insensitive that
  the existing classifier flags. Over-flagging only ever *deepens* a review;
  the unsafe direction is a missed sensitive path.
* **No authorship data, ever.** History enters as per-path change counts
  only. No feature, input or evidence field carries an author, committer or
  any per-person quantity (family-wide invariant; see V4.4-E01-T04).
* **Evidence is untrusted text.** Paths come from the diff or the index, so
  every evidence string is control-stripped, secret-redacted, length-capped
  and count-capped here, at construction, before any consumer sees it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Mapping, Sequence

from .security import redact_secrets

if TYPE_CHECKING:
    from .impact import ImpactResult

FEATURE_SET_VERSION = "risk-features-v1"

GROUP_SIZE = "size"
GROUP_SENSITIVITY = "sensitivity"
GROUP_IMPACT = "impact"
GROUP_HISTORY = "history"

# Why a feature has no value for this run. Closed vocabulary.
REASON_NO_INDEX = "no_index"        # impact signal needs the repository index
REASON_NO_HISTORY = "no_history"    # no history counts were supplied
UNAVAILABLE_REASONS = (REASON_NO_INDEX, REASON_NO_HISTORY)

MAX_EVIDENCE_ITEMS = 5
MAX_EVIDENCE_CHARS = 200
# Inputs that arrive as counts are clamped so a hostile or corrupt value
# cannot dominate any later arithmetic.
COUNT_CEILING = 1_000_000
_MAX_FOCUS_ENTRIES = 50
_MAX_FOCUS_CHARS = 200
# Hard bound on how much of one path is ever scanned (PATH_MAX): redaction
# cost per path must not depend on attacker-chosen length.
_MAX_PATH_SCAN_CHARS = 4096

# (category, lowercase path substrings). The union of the first three
# categories' hints contains every hint of model_router's V3 classifier.
SENSITIVE_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("auth", ("auth", "login", "session", "password", "passwd", "oauth",
              "jwt", "saml", "permission", "rbac")),
    ("payment", ("payment", "billing", "invoice", "checkout", "stripe",
                 "paypal", "refund", "ledger")),
    ("data_store", ("db", "database", "migrat", "sql")),
    ("secrets", ("secret", "credential", "token", "crypto", "keystore",
                 "apikey", "api_key")),
    ("infra", (".github/workflows/", "dockerfile", "docker-compose",
               "terraform", "kubernetes", "k8s", "deploy")),
)
# Extra terms recognised only in the owner's focus list ("security",
# "SQL injection"): free text, not paths.
_FOCUS_EXTRA_HINTS = ("secur", "vulnerab", "inject")

_DOC_EXTENSIONS = (".md", ".rst", ".adoc")
# ``.txt`` is deliberately not a doc extension: requirements.txt is a
# dependency manifest, not documentation.
_DOC_BASENAMES = frozenset({"license", "licence", "changelog", "copying"})


@dataclass(frozen=True)
class RiskFeature:
    """One named measurement.

    ``value`` is a non-negative integer and is ``0`` when ``available`` is
    false -- consumers must check ``available`` rather than the value.
    """

    name: str
    group: str
    value: int
    available: bool = True
    reason: str = ""
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"name": self.name, "group": self.group, "value": self.value,
                "available": self.available, "reason": self.reason,
                "evidence": list(self.evidence)}


@dataclass(frozen=True)
class RiskFeatureSet:
    """The ordered, versioned feature vector for one review."""

    features: tuple[RiskFeature, ...]
    version: str = FEATURE_SET_VERSION

    def get(self, name: str) -> RiskFeature | None:
        for feature in self.features:
            if feature.name == name:
                return feature
        return None

    def to_dict(self) -> dict:
        return {"version": self.version,
                "features": [f.to_dict() for f in self.features]}


# The closed feature vocabulary, in output order. Later tickets key their
# contributions and tests by these names.
FEATURE_NAMES: tuple[str, ...] = (
    "files_changed", "lines_changed", "non_doc_files",
    "sensitive_files",
    *(f"sensitive_{cat}_files" for cat, _ in SENSITIVE_CATEGORIES),
    "focus_sensitive_entries",
    "impact_direct_dependents", "impact_indirect_dependents",
    "impact_truncated", "impact_unknown_seeds",
    "history_max_file_churn", "history_files_with_data",
)


def _count(value: object) -> int:
    """Coerce to an int in ``[0, COUNT_CEILING]``; junk becomes ``0``."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, min(COUNT_CEILING, value))


def _clean_evidence(items: Iterable[object]) -> tuple[str, ...]:
    """Sanitize untrusted path strings for use as evidence.

    Order of operations matters: the scan is bounded, control characters are
    replaced, secrets are redacted, and only then is the text truncated to
    the evidence cap -- truncating before redaction could cut a credential in
    half and leak its prefix. The result is sorted and deduplicated so
    evidence is independent of input order.
    """
    cleaned: set[str] = set()
    for raw in items:
        if not isinstance(raw, str) or not raw:
            continue
        text = "".join(ch if ch.isprintable() else "?"
                       for ch in raw[:_MAX_PATH_SCAN_CHARS])
        text = redact_secrets(text)[:MAX_EVIDENCE_CHARS]
        if text:
            cleaned.add(text)
    return tuple(sorted(cleaned))[:MAX_EVIDENCE_ITEMS]


def _is_doc(path: str) -> bool:
    lowered = path.lower()
    if lowered.endswith(_DOC_EXTENSIONS):
        return True
    return lowered.rsplit("/", 1)[-1] in _DOC_BASENAMES


def _matches(lowered_path: str, hints: Sequence[str]) -> bool:
    return any(hint in lowered_path for hint in hints)


def _file_attr_count(file: object, name: str) -> int:
    # Missing attributes read as 0, but an attribute that *raises* is a bug
    # in the caller's object and propagates: silently counting it as 0 would
    # under-report size, the unsafe direction for a risk signal.
    return _count(getattr(file, name, 0))


def _history_counts(history: object) -> dict[str, int] | None:
    if not isinstance(history, Mapping):
        return None
    return {k: _count(v) for k, v in history.items() if isinstance(k, str)}


def extract_risk_features(
    files: Iterable[object],
    *,
    impact: "ImpactResult | None" = None,
    history: Mapping[str, int] | None = None,
    focus: Sequence[str] = (),
) -> RiskFeatureSet:
    """Measure the v1 risk features.

    ``files``: parsed ``FileDiff`` objects (anything exposing ``path``,
    ``additions`` and ``deletions``). ``impact``: the V4-E03 result, or
    ``None`` when no repository index exists for this run. ``history``:
    ``{path: recent change count}`` or ``None``; counts are per path, never
    per person. ``focus``: the repository owner's trusted focus list; it can
    only add a sensitivity signal.
    """
    file_list = list(files)
    paths = [str(getattr(f, "path", "") or "") for f in file_list]

    lines = sum(_file_attr_count(f, "additions") + _file_attr_count(f, "deletions")
                for f in file_list)
    features: list[RiskFeature] = [
        RiskFeature("files_changed", GROUP_SIZE, _count(len(file_list))),
        RiskFeature("lines_changed", GROUP_SIZE, _count(lines)),
        RiskFeature("non_doc_files", GROUP_SIZE,
                    sum(1 for p in paths if not _is_doc(p))),
    ]

    per_category: list[RiskFeature] = []
    all_sensitive: set[str] = set()
    for category, hints in SENSITIVE_CATEGORIES:
        hit = {p for p in paths if p and _matches(p.lower(), hints)}
        all_sensitive |= hit
        per_category.append(RiskFeature(
            f"sensitive_{category}_files", GROUP_SENSITIVITY, len(hit),
            evidence=_clean_evidence(hit)))
    features.append(RiskFeature("sensitive_files", GROUP_SENSITIVITY,
                                len(all_sensitive),
                                evidence=_clean_evidence(all_sensitive)))
    features.extend(per_category)

    focus_hints = tuple(h for _, hs in SENSITIVE_CATEGORIES for h in hs) \
        + _FOCUS_EXTRA_HINTS
    focus_hits = 0
    for entry in list(focus)[:_MAX_FOCUS_ENTRIES]:
        if isinstance(entry, str) and _matches(
                entry.lower()[:_MAX_FOCUS_CHARS], focus_hints):
            focus_hits += 1
    features.append(RiskFeature("focus_sensitive_entries",
                                GROUP_SENSITIVITY, focus_hits))

    features.extend(_impact_features(impact))
    features.extend(_history_features(paths, history))

    return RiskFeatureSet(features=tuple(features))


def _impact_features(impact: "ImpactResult | None") -> list[RiskFeature]:
    names = ("impact_direct_dependents", "impact_indirect_dependents",
             "impact_truncated", "impact_unknown_seeds")
    if impact is None:
        return [RiskFeature(n, GROUP_IMPACT, 0, available=False,
                            reason=REASON_NO_INDEX) for n in names]
    entries = list(getattr(impact, "entries", ()) or ())
    direct = [e for e in entries
              if getattr(e, "confidence", "") == "direct"]
    indirect = [e for e in entries
                if getattr(e, "confidence", "") == "indirect"]
    return [
        RiskFeature(names[0], GROUP_IMPACT, _count(len(direct)),
                    evidence=_clean_evidence(
                        getattr(e, "path", None) for e in direct)),
        RiskFeature(names[1], GROUP_IMPACT, _count(len(indirect))),
        RiskFeature(names[2], GROUP_IMPACT,
                    1 if getattr(impact, "truncated", False) else 0),
        RiskFeature(names[3], GROUP_IMPACT, _count(
            len(getattr(impact, "unknown_seeds", ()) or ()))),
    ]


def _history_features(paths: Sequence[str],
                      history: object) -> list[RiskFeature]:
    names = ("history_max_file_churn", "history_files_with_data")
    counts = _history_counts(history)
    if counts is None:
        return [RiskFeature(n, GROUP_HISTORY, 0, available=False,
                            reason=REASON_NO_HISTORY) for n in names]
    seen = {p for p in paths if p in counts}
    return [
        RiskFeature(names[0], GROUP_HISTORY,
                    max((counts[p] for p in seen), default=0)),
        RiskFeature(names[1], GROUP_HISTORY, len(seen)),
    ]


# =========================================================================
# V4.0-E04-T02 -- explainable score
# =========================================================================
SCORE_VERSION = "risk-score-v1"

BAND_LOW = "low"
BAND_MEDIUM = "medium"
BAND_HIGH = "high"
BANDS = (BAND_LOW, BAND_MEDIUM, BAND_HIGH)

# Proposed v1 thresholds. They are starting values, not fitted ones: the
# eval corpus has not been used to calibrate them, which is why depth is
# report-only until ADR-018 is accepted.
BAND_MEDIUM_MIN = 3
BAND_HIGH_MIN = 10


@dataclass(frozen=True)
class _Rule:
    """``points = min(cap, (value // step) * points_per_step)``.

    Non-negative integers only, so every rule is monotonic: more of a
    feature never lowers the score.
    """

    feature: str
    step: int
    points_per_step: int
    cap: int

    def points(self, value: int) -> int:
        return min(self.cap, (max(0, value) // self.step) * self.points_per_step)


# Output order of the contributions. Features without a rule (e.g. the
# per-category sensitivity counts, ``non_doc_files``) are measured but not
# scored: they feed the depth floor and later consumers, and scoring them
# too would double-count ``sensitive_files``.
SCORE_RULES: tuple[_Rule, ...] = (
    _Rule("files_changed", 5, 1, 6),
    _Rule("lines_changed", 100, 1, 8),
    _Rule("sensitive_files", 1, 4, 12),
    _Rule("focus_sensitive_entries", 1, 1, 3),
    _Rule("impact_direct_dependents", 2, 1, 6),
    _Rule("impact_indirect_dependents", 5, 1, 3),
    _Rule("impact_truncated", 1, 2, 2),
    _Rule("impact_unknown_seeds", 3, 1, 2),
    _Rule("history_max_file_churn", 10, 1, 5),
)
MAX_SCORE = sum(r.cap for r in SCORE_RULES)


@dataclass(frozen=True)
class RiskContribution:
    """One shown term of the score. ``points`` is ``0`` when the feature is
    unavailable; ``available`` says so explicitly."""

    feature: str
    value: int
    points: int
    available: bool = True

    def to_dict(self) -> dict:
        return {"feature": self.feature, "value": self.value,
                "points": self.points, "available": self.available}


@dataclass(frozen=True)
class RiskScore:
    score: int
    band: str
    contributions: tuple[RiskContribution, ...]
    version: str = SCORE_VERSION

    def __post_init__(self) -> None:
        # The score is *defined* as the sum of what is shown; a RiskScore
        # that disagrees with its own contributions cannot be constructed.
        if self.score != sum(c.points for c in self.contributions):
            raise ValueError("risk score must equal the sum of contributions")
        if self.band != band_for(self.score):
            raise ValueError("risk band must follow the score")


def band_for(score: int) -> str:
    if score >= BAND_HIGH_MIN:
        return BAND_HIGH
    if score >= BAND_MEDIUM_MIN:
        return BAND_MEDIUM
    return BAND_LOW


def score_features(features: RiskFeatureSet) -> RiskScore:
    """Score a feature set. Unavailable features contribute ``0`` points
    and are listed as unavailable -- missing signal is never read as risk
    *or* as safety by this function; the depth floor handles caution."""
    contributions: list[RiskContribution] = []
    for rule in SCORE_RULES:
        feature = features.get(rule.feature)
        if feature is None:
            continue
        points = rule.points(feature.value) if feature.available else 0
        contributions.append(RiskContribution(
            rule.feature, feature.value, points, feature.available))
    total = sum(c.points for c in contributions)
    return RiskScore(total, band_for(total), tuple(contributions))


# =========================================================================
# V4.0-E04-T03 / T04 -- depth routing policy and the security-depth floor
# =========================================================================
DEPTH_LOW = "low"
DEPTH_STANDARD = "standard"
DEPTH_DEEP = "deep"
DEPTH_ORDER = (DEPTH_LOW, DEPTH_STANDARD, DEPTH_DEEP)

# Today's fixed-depth review is the baseline: one full pass at the
# configured budget. Adaptive depth may reduce below it only where the
# floor allows, and may never exceed the configured budget.
BASELINE_DEPTH = DEPTH_STANDARD
BASELINE_BUDGET_PERCENT = 100

_BAND_DEPTH = {BAND_LOW: DEPTH_LOW, BAND_MEDIUM: DEPTH_STANDARD,
               BAND_HIGH: DEPTH_DEEP}
BUDGET_PERCENT = {DEPTH_LOW: 70, DEPTH_STANDARD: 100, DEPTH_DEEP: 100}

ROLE_CORRECTNESS = "correctness"
ROLE_SECURITY = "security"
# Never removable by any depth, cap or configuration.
MANDATORY_ROLES = (ROLE_CORRECTNESS, ROLE_SECURITY)

# Closed vocabulary of why a decision is what it is.
REASON_BAND_LOW = "band_low"
REASON_BAND_MEDIUM = "band_medium"
REASON_BAND_HIGH = "band_high"
REASON_CAP_APPLIED = "depth_cap_applied"
REASON_FLOOR_APPLIED = "security_floor_applied"
REASON_SPECIALIST_CAP = "specialist_cap_applied"
REASON_SPECIALIST_CAP_RAISED = "specialist_cap_raised_to_mandatory"
DEPTH_REASONS = (REASON_BAND_LOW, REASON_BAND_MEDIUM, REASON_BAND_HIGH,
                 REASON_CAP_APPLIED, REASON_FLOOR_APPLIED,
                 REASON_SPECIALIST_CAP, REASON_SPECIALIST_CAP_RAISED)

_PROVISIONAL_ROLES = {
    DEPTH_LOW: MANDATORY_ROLES,
    DEPTH_STANDARD: MANDATORY_ROLES + ("test",),
    DEPTH_DEEP: MANDATORY_ROLES + ("test", "performance", "architecture"),
}


def select_specialists(depth: str) -> tuple[str, ...]:
    """PROVISIONAL specialist-set selection (interface only).

    V4.0-E02 will define real specialist contracts; until then this returns
    role *names* in priority order, mandatory roles first, and nothing in the
    pipeline consumes them. Replace the body, keep the signature's shape:
    mandatory roles must stay first and always present.
    """
    return _PROVISIONAL_ROLES[depth if depth in _PROVISIONAL_ROLES
                              else BASELINE_DEPTH]


@dataclass(frozen=True)
class DepthPolicyConfig:
    """The only knobs that can influence a depth decision.

    Both can only *lower* depth or specialist count, and both are applied
    before the security floor, which always has the last word. The field set
    is pinned by a test: adding a knob is a deliberate, reviewed change.
    """

    depth_cap: str = ""          # "" or one of DEPTH_ORDER; anything else is ignored
    max_specialists: int = 0     # 0 = no cap


@dataclass(frozen=True)
class SecurityFloor:
    depth: str
    budget_percent: int
    reason_sensitive_surface: bool


def security_floor(features: RiskFeatureSet) -> SecurityFloor:
    """The minimum this PR may receive, from the features alone.

    A PR that touches a sensitive path, or whose owner-set focus names a
    sensitive area, never drops below the baseline depth and budget. Other
    PRs may go lower, but even then ``security`` stays a mandatory role.
    """
    def value(name: str) -> int:
        feature = features.get(name)
        return feature.value if feature is not None and feature.available else 0

    sensitive = value("sensitive_files") > 0 or value(
        "focus_sensitive_entries") > 0
    if sensitive:
        return SecurityFloor(BASELINE_DEPTH, BASELINE_BUDGET_PERCENT, True)
    return SecurityFloor(DEPTH_LOW, BUDGET_PERCENT[DEPTH_LOW], False)


@dataclass(frozen=True)
class DepthDecision:
    """A depth decision that cannot be constructed below its own floor."""

    depth: str
    specialists: tuple[str, ...]
    budget_percent: int
    floor_depth: str
    floor_budget_percent: int
    reasons: tuple[str, ...] = ()
    static_rules: bool = True   # the static rule engine is never depth-gated

    def __post_init__(self) -> None:
        if self.depth not in DEPTH_ORDER or self.floor_depth not in DEPTH_ORDER:
            raise ValueError("unknown depth")
        if DEPTH_ORDER.index(self.depth) < DEPTH_ORDER.index(self.floor_depth):
            raise ValueError("depth below the security floor")
        if not all(role in self.specialists for role in MANDATORY_ROLES):
            raise ValueError("mandatory specialist roles missing")
        if not (1 <= self.budget_percent <= BASELINE_BUDGET_PERCENT):
            raise ValueError("budget must be within (0, 100] percent of configured")
        if self.budget_percent < self.floor_budget_percent:
            raise ValueError("budget below the security floor")
        if self.static_rules is not True:
            raise ValueError("static rules cannot be disabled by depth")
        if any(r not in DEPTH_REASONS for r in self.reasons):
            raise ValueError("unknown depth reason")

    def to_dict(self) -> dict:
        return {"level": self.depth, "specialists": list(self.specialists),
                "budget_percent": self.budget_percent,
                "floor_level": self.floor_depth,
                "reasons": list(self.reasons),
                "static_rules": self.static_rules}


def decide_depth(score: RiskScore, features: RiskFeatureSet,
                 policy: DepthPolicyConfig | None = None) -> DepthDecision:
    """Band -> depth, then config caps, then the security floor (last).

    The specialist cap is applied once, to the *final* depth's role list, so
    a floor-lifted PR gets the roles of the depth it actually receives.
    """
    policy = policy or DepthPolicyConfig()
    reasons: list[str] = [{BAND_LOW: REASON_BAND_LOW,
                           BAND_MEDIUM: REASON_BAND_MEDIUM,
                           BAND_HIGH: REASON_BAND_HIGH}[score.band]]
    depth = _BAND_DEPTH[score.band]

    cap = policy.depth_cap
    if cap in DEPTH_ORDER and DEPTH_ORDER.index(cap) < DEPTH_ORDER.index(depth):
        depth = cap
        reasons.append(REASON_CAP_APPLIED)

    floor = security_floor(features)
    if DEPTH_ORDER.index(depth) < DEPTH_ORDER.index(floor.depth):
        depth = floor.depth
        reasons.append(REASON_FLOOR_APPLIED)

    specialists = select_specialists(depth)
    limit = policy.max_specialists
    if isinstance(limit, int) and not isinstance(limit, bool) \
            and 0 < limit < len(specialists):
        specialists = specialists[:max(limit, len(MANDATORY_ROLES))]
        reasons.append(REASON_SPECIALIST_CAP if limit >= len(MANDATORY_ROLES)
                       else REASON_SPECIALIST_CAP_RAISED)

    budget = max(BUDGET_PERCENT[depth], floor.budget_percent)
    return DepthDecision(depth, specialists, budget, floor.depth,
                         floor.budget_percent, tuple(reasons))


# =========================================================================
# V4.0-E04 -- the assessment the orchestrator attaches (flag-gated)
# =========================================================================
ENGINE_VERSION = "risk-v1"


@dataclass(frozen=True)
class RiskAssessment:
    features: RiskFeatureSet
    score: RiskScore
    depth: DepthDecision

    def to_report_dict(self) -> dict:
        """The additive fields merged into the report's existing ``risk``
        block. Closed vocabulary and integers only -- no diff text, no
        paths -- so this adds no untrusted surface to the report."""
        return {
            "engine_version": ENGINE_VERSION,
            "informational": True,
            "score": self.score.score,
            "band": self.score.band,
            "contributions": [c.to_dict() for c in self.score.contributions],
            "depth": self.depth.to_dict(),
        }


REPORT_RISK_KEYS = frozenset({"engine_version", "informational", "score",
                              "band", "contributions", "depth"})


def assess_risk(files: Iterable[object], *,
                impact: "ImpactResult | None" = None,
                history: Mapping[str, int] | None = None,
                focus: Sequence[str] = (),
                policy: DepthPolicyConfig | None = None) -> RiskAssessment:
    features = extract_risk_features(files, impact=impact, history=history,
                                     focus=focus)
    score = score_features(features)
    return RiskAssessment(features, score, decide_depth(score, features, policy))

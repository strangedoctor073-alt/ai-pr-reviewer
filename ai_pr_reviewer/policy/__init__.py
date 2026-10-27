"""Policy engine v1 (V4.2-E07): structured clauses, deterministic evaluation.

Public interface (stable; reused by V4.6-E05 and V4.8-E02):

* ``schema``   -- ``PolicyConfig``/``PolicyClause``, ``parse_policy_section``,
                  ``load_policy_config`` (trusted base-revision YAML).
* ``evaluate`` -- ``evaluate_policy`` -> ``PolicyEvaluation`` of three-valued
                  ``ClauseResult`` (pass / fail / unknown) with clause locator.
* ``findings`` -- ``policy_findings`` / ``review_policy``: failed clauses ->
                  ``Finding`` objects (reported only, never remediated).

``rules.py`` keeps loading the v1 schema unchanged; this package reads only
the additive ``policy:`` key. See each module docstring for invariants.
"""
from .evaluate import (STATUS_FAIL, STATUS_PASS, STATUS_UNKNOWN, ClauseResult,
                       PolicyEvaluation, clause_locator, evaluate_policy)
from .findings import policy_findings, review_policy
from .schema import (CLAUSE_TYPES, PolicyClause, PolicyConfig,
                     load_policy_config, parse_policy_section)

__all__ = [
    "CLAUSE_TYPES", "ClauseResult", "PolicyClause", "PolicyConfig",
    "PolicyEvaluation", "STATUS_FAIL", "STATUS_PASS", "STATUS_UNKNOWN",
    "clause_locator", "evaluate_policy", "load_policy_config",
    "parse_policy_section", "policy_findings", "review_policy",
]

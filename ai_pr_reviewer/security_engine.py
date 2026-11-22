"""Security Engine v2 (V4.2-E01).

Implements:
- V4.2-E01-T01: Security analyzers module + rule registry extension (SEC009-SEC012)
- V4.2-E01-T02: Severity model + CWE-style classification
- V4.2-E01-T03: Dataflow-lite checks over diff + index (deterministic taint tracking)
- V4.2-E01-T04: Cross-file security signals via retrieval (budgeted)
- V4.2-E01-T05: Security findings rendering + false-positive controls
"""
from __future__ import annotations

import re
from typing import Callable, Sequence

from .diff_parser import FileDiff
from .models import EvidenceRecord, Finding
from .static import security_rules
from .static.registry import Rule, RuleRegistry, lang_of

CWE_MAP: dict[str, str] = {
    "SEC001": "CWE-89",   # SQL Injection
    "SEC002": "CWE-798",  # Hardcoded Credentials
    "SEC003": "CWE-95",   # Improper Neutralization of Directives in Dynamically Evaluated Code (Eval RCE)
    "SEC004": "CWE-78",   # OS Command Injection
    "SEC005": "CWE-79",   # Cross-site Scripting (XSS)
    "SEC006": "CWE-312",  # Cleartext Storage of Sensitive Information
    "SEC007": "CWE-295",  # Improper Certificate Validation
    "SEC008": "CWE-732",  # Incorrect Permission Assignment
    "SEC009": "CWE-22",   # Path Traversal
    "SEC010": "CWE-918",  # Server-Side Request Forgery (SSRF)
    "SEC011": "CWE-502",  # Deserialization of Untrusted Data
    "SEC012": "CWE-208",  # Observable Timing Discrepancy
}

CWE_DEFINITIONS: dict[str, dict[str, str]] = {
    "CWE-22": {
        "cwe_id": "CWE-22",
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "default_severity": "high",
    },
    "CWE-78": {
        "cwe_id": "CWE-78",
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "default_severity": "critical",
    },
    "CWE-79": {
        "cwe_id": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "default_severity": "high",
    },
    "CWE-89": {
        "cwe_id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "default_severity": "critical",
    },
    "CWE-95": {
        "cwe_id": "CWE-95",
        "name": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "default_severity": "critical",
    },
    "CWE-208": {
        "cwe_id": "CWE-208",
        "name": "Observable Timing Discrepancy",
        "default_severity": "medium",
    },
    "CWE-295": {
        "cwe_id": "CWE-295",
        "name": "Improper Certificate Validation",
        "default_severity": "critical",
    },
    "CWE-312": {
        "cwe_id": "CWE-312",
        "name": "Cleartext Storage of Sensitive Information",
        "default_severity": "high",
    },
    "CWE-502": {
        "cwe_id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "default_severity": "critical",
    },
    "CWE-732": {
        "cwe_id": "CWE-732",
        "name": "Incorrect Permission Assignment for Critical Resource",
        "default_severity": "medium",
    },
    "CWE-798": {
        "cwe_id": "CWE-798",
        "name": "Use of Hard-coded Credentials",
        "default_severity": "critical",
    },
    "CWE-918": {
        "cwe_id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "default_severity": "high",
    },
}

EXPANDED_SEC_RULES: list[Rule] = [
    Rule(
        "SEC009",
        re.compile(r"open\s*\([^)]*(\+|format|\%|\$|f[\"']).*\)", re.I),
        ("py", "js", "ts"),
        "high",
        "security",
        "Potential path traversal via dynamic path concatenation",
        "[CWE-22] File path is constructed dynamically. Ensure path is validated and sanitized against directory traversal (e.g. os.path.abspath and os.path.commonpath).",
        "Use safe path resolution: secure_path = os.path.basename(user_path)",
    ),
    Rule(
        "SEC010",
        re.compile(r"(requests|httpx|urllib|fetch|axios)\.(get|post|put|delete|patch)\s*\(\s*(url|target_url|req\.|request\.)", re.I),
        ("py", "js", "ts"),
        "high",
        "security",
        "Potential Server-Side Request Forgery (SSRF)",
        "[CWE-918] HTTP request initiated with user-controlled URL. Restrict destinations with an IP/domain allowlist and avoid internal network access.",
        "Validate destination against allowlist before making outbound request.",
    ),
    Rule(
        "SEC011",
        re.compile(r"\b(pickle\.loads?|yaml\.load\([^)]*Loader\s*=\s*(yaml\.)?(Unsafe)?Loader|_pickle\.loads?|marshal\.loads?)\b"),
        ("py",),
        "critical",
        "security",
        "Insecure deserialization of untrusted data",
        "[CWE-502] Deserializing untrusted data with pickle or unsafe YAML loader can lead to arbitrary code execution. Use json or safe loaders.",
        "Use json.loads(...) or yaml.safe_load(...)",
    ),
    Rule(
        "SEC012",
        re.compile(r"(secret|token|password|hash|key)\s*==\s*|(==\s*(expected_)?(secret|token|password|hash|key))", re.I),
        ("py",),
        "medium",
        "security",
        "Timing-vulnerable comparison of sensitive token",
        "[CWE-208] Standard equality (==) for secret tokens leaks timing information. Use constant-time comparison like hmac.compare_digest.",
        "import hmac; hmac.compare_digest(user_token, expected_token)",
    ),
]


def get_rule_cwe(rule_id: str) -> str | None:
    return CWE_MAP.get(rule_id)


def classify_cwe(cwe_id: str) -> dict[str, str]:
    if cwe_id in CWE_DEFINITIONS:
        return dict(CWE_DEFINITIONS[cwe_id])
    return {
        "cwe_id": cwe_id,
        "name": f"Classification for {cwe_id}",
        "default_severity": "medium",
    }


class DataflowLiteAnalyzer:
    """Deterministic intra-file taint tracker for diff hunks (V4.2-E01-T03)."""

    SOURCE_PATTERNS = [
        re.compile(r"\b(request\.(GET|POST|args|query|body|params|form)\b|\breq\.(query|body|params)\b|\binput\s*\(|\bsys\.argv\b)"),
    ]
    SINK_PATTERNS = [
        (re.compile(r"\bos\.system\s*\(([^)]+)\)"), "CWE-78", "critical", "Command injection via tainted dataflow"),
        (re.compile(r"\bsubprocess\.\w+\(([^)]*shell\s*=\s*True[^)]*)\)"), "CWE-78", "critical", "Command injection via shell=True dataflow"),
        (re.compile(r"\b(eval|exec)\s*\(([^)]+)\)"), "CWE-95", "critical", "Code injection via tainted eval/exec dataflow"),
        (re.compile(r"\bcursor\.execute\s*\(\s*f[\"']([^\"']+)[\"']"), "CWE-89", "critical", "SQL injection via formatted query dataflow"),
    ]
    SANITIZER_PATTERNS = [
        re.compile(r"\b(shlex\.quote|os\.path\.basename|int\s*\(|float\s*\(|html\.escape|quote_plus)\b"),
    ]

    def analyze_file(self, diff: FileDiff) -> list[Finding]:
        findings: list[Finding] = []
        added_lines = diff.added_lines()

        tainted_vars: dict[str, int] = {}
        sanitized_vars: set[str] = set()

        # Pass 1: Identify tainted assignments and sanitizations
        for line_no, content in added_lines:
            # Check source assignment: var = source...
            assign_match = re.match(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$", content)
            if assign_match:
                var_name = assign_match.group(1)
                rhs = assign_match.group(2)

                # Check if RHS has sanitizers
                if any(san.search(rhs) for san in self.SANITIZER_PATTERNS):
                    sanitized_vars.add(var_name)
                    tainted_vars.pop(var_name, None)
                    continue

                # Check if RHS introduces taint from source or propagates tainted var
                is_source = any(sp.search(rhs) for sp in self.SOURCE_PATTERNS)
                is_taint_prop = any(tv in rhs for tv in tainted_vars)
                if is_source or is_taint_prop:
                    tainted_vars[var_name] = line_no

        # Pass 2: Check sinks for tainted variables that have not been sanitized
        for line_no, content in added_lines:
            for sink_re, cwe, sev, title in self.SINK_PATTERNS:
                m = sink_re.search(content)
                if m:
                    arg_text = m.group(1)
                    # Check if any tainted var is used in sink and not sanitized
                    active_taints = [tv for tv in tainted_vars if re.search(r"\b" + re.escape(tv) + r"\b", arg_text)]
                    active_taints = [tv for tv in active_taints if tv not in sanitized_vars]
                    if active_taints:
                        findings.append(Finding(
                            file=diff.new_path,
                            line=line_no,
                            severity=sev,
                            category="security",
                            title=title,
                            explanation=f"[{cwe}] Untrusted variable '{active_taints[0]}' flows into sensitive sink without sanitization.",
                            rule_id=f"DATAFLOW-{cwe}",
                            cwe_id=cwe,
                        ))

        return findings


class CrossFileSecurityAnalyzer:
    """Budgeted cross-file security signal retrieval (V4.2-E01-T04)."""

    def __init__(self, retriever: Callable[[str], str] | None = None, max_file_lookups: int = 5) -> None:
        self.retriever = retriever or (lambda _: "")
        self.max_file_lookups = max_file_lookups

    def analyze(self, files: Sequence[FileDiff]) -> list[Finding]:
        findings: list[Finding] = []
        lookups = 0

        for file_diff in files:
            if lookups >= self.max_file_lookups:
                break
            for line_no, line_text in file_diff.added_lines():
                # Look for imports of custom modules
                imp_match = re.search(r"(?:from\s+([\w\.]+)\s+import\s+([\w,\s]+)|import\s+([\w\.]+))", line_text)
                if imp_match and lookups < self.max_file_lookups:
                    mod = imp_match.group(1) or imp_match.group(3)
                    target_path = mod.replace(".", "/") + ".py"
                    code = self.retriever(target_path)
                    lookups += 1
                    if code and ("hashlib.md5" in code or "weak" in code):
                        evidence = EvidenceRecord.create(
                            kind="symbol_def",
                            locator=f"{target_path}:1",
                            summary=f"Imported helper '{mod}' contains weak cryptographic construct",
                        )
                        findings.append(Finding(
                            file=file_diff.new_path,
                            line=line_no,
                            severity="high",
                            category="security",
                            title="Cross-file security risk: weak cryptographic dependency",
                            explanation=f"Imported symbol from '{target_path}' utilizes known weak algorithm (MD5).",
                            rule_id="XFILE-SEC-01",
                            cwe_id="CWE-327",
                            evidence=(evidence,),
                        ))
        return findings


class SecurityEngineV2:
    """Integrated Security Engine v2."""

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        if registry is not None:
            self.registry = registry
        else:
            self.registry = RuleRegistry()
            security_rules.register(self.registry)
        self.dataflow_analyzer = DataflowLiteAnalyzer()
        self.cross_file_analyzer = CrossFileSecurityAnalyzer()
        # Register expanded rules
        self.registry.add_line_rules(EXPANDED_SEC_RULES)

    def run(self, files: Sequence[FileDiff]) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Line rules with false-positive controls (V4.2-E01-T05)
        for f in files:
            ext = lang_of(f.new_path)
            for line_no, line_text in f.added_lines():
                # Skip comments
                if not re.match(r"^\s*(#|//|\*|\")", line_text):
                    for rule in self.registry.line_rules:
                        if rule.languages and ext not in rule.languages:
                            continue
                        if rule.pattern.search(line_text):
                            # False positive controls
                            if rule.rule_id == "SEC001" and re.search(r",\s*\([^\)]*\)\s*\)", line_text):
                                continue  # Parameterized SQL
                            if rule.rule_id == "SEC003" and "literal_eval" in line_text:
                                continue  # Safe literal_eval

                            cwe = get_rule_cwe(rule.rule_id)
                            findings.append(Finding(
                                file=f.new_path,
                                line=line_no,
                                severity=rule.severity,
                                category=rule.category,
                                title=rule.title,
                                explanation=rule.explanation,
                                suggestion=rule.suggestion,
                                confidence=rule.confidence,
                                rule_id=rule.rule_id,
                                cwe_id=cwe,
                            ))

            # 2. Dataflow lite
            findings.extend(self.dataflow_analyzer.analyze_file(f))

        return findings

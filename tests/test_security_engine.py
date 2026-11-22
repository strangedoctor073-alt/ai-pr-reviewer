"""Tests for V4.2-E01: Security Engine v2.

Coverage:
- V4.2-E01-T01: Security analyzers module + rule registry extension
- V4.2-E01-T02: Severity model + CWE-style classification
- V4.2-E01-T03: Dataflow-lite checks over diff + index (deterministic)
- V4.2-E01-T04: Cross-file security signals via retrieval (budgeted)
- V4.2-E01-T05: Security findings rendering + false-positive controls
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer.diff_parser import parse_unified_diff
from ai_pr_reviewer.security_engine import (
    CWE_MAP,
    CrossFileSecurityAnalyzer,
    DataflowLiteAnalyzer,
    SecurityEngineV2,
    classify_cwe,
    get_rule_cwe,
)
from ai_pr_reviewer.static.registry import RuleRegistry


def test_rule_registry_extension_and_cwe_classification():
    """V4.2-E01-T01 & T02: Rule registry extension with CWE classification."""
    registry = RuleRegistry()
    engine = SecurityEngineV2(registry=registry)

    # Check CWE classification mappings for base rules
    assert get_rule_cwe("SEC001") == "CWE-89"
    assert get_rule_cwe("SEC002") == "CWE-798"
    assert get_rule_cwe("SEC003") == "CWE-95"
    assert get_rule_cwe("SEC004") == "CWE-78"
    assert get_rule_cwe("SEC005") == "CWE-79"
    assert get_rule_cwe("SEC006") == "CWE-312"
    assert get_rule_cwe("SEC007") == "CWE-295"
    assert get_rule_cwe("SEC008") == "CWE-732"

    # Expanded rules
    assert get_rule_cwe("SEC009") == "CWE-22"   # Path Traversal
    assert get_rule_cwe("SEC010") == "CWE-918"  # SSRF
    assert get_rule_cwe("SEC011") == "CWE-502"  # Insecure Deserialization
    assert get_rule_cwe("SEC012") == "CWE-208"  # Timing attack / unsafe compare

    cwe_info = classify_cwe("CWE-89")
    assert cwe_info["cwe_id"] == "CWE-89"
    assert "SQL" in cwe_info["name"]
    assert cwe_info["default_severity"] == "critical"


def test_expanded_security_line_rules():
    """V4.2-E01-T01: New analyzers detect path traversal, SSRF, insecure deserialization, timing leak."""
    engine = SecurityEngineV2()

    # SEC009: Path traversal
    diff_path_text = """--- a/app.py
+++ b/app.py
@@ -1,1 +1,2 @@
+path = request.args.get('p')
+open('/data/' + path, 'rb')
"""
    diff_path = parse_unified_diff(diff_path_text)
    findings = engine.run(diff_path)
    assert any(f.rule_id == "SEC009" or "traversal" in f.title.lower() for f in findings)

    # SEC011: Insecure deserialization
    diff_pickle_text = """--- a/worker.py
+++ b/worker.py
@@ -1,1 +1,1 @@
+data = pickle.loads(user_payload)
"""
    diff_pickle = parse_unified_diff(diff_pickle_text)
    findings = engine.run(diff_pickle)
    assert any(f.rule_id == "SEC011" or "deserialization" in f.title.lower() for f in findings)

    # SEC012: Insecure secret comparison
    diff_timing_text = """--- a/auth.py
+++ b/auth.py
@@ -1,1 +1,1 @@
+if user_token == expected_secret_token:
"""
    diff_timing = parse_unified_diff(diff_timing_text)
    findings = engine.run(diff_timing)
    assert any(f.rule_id == "SEC012" or "timing" in f.title.lower() for f in findings)


def test_dataflow_lite_deterministic_taint():
    """V4.2-E01-T03: Deterministic dataflow check from untrusted source to sensitive sink."""
    analyzer = DataflowLiteAnalyzer()

    diff_text = """--- a/views.py
+++ b/views.py
@@ -1,1 +1,4 @@
+def handle_ping(request):
+    ip_addr = request.GET.get('ip')
+    cmd = "ping -c 1 " + ip_addr
+    os.system(cmd)
"""
    diff = parse_unified_diff(diff_text)[0]
    findings = analyzer.analyze_file(diff)
    assert len(findings) >= 1
    flow_finding = findings[0]
    assert flow_finding.severity in ("critical", "high")
    assert "dataflow" in flow_finding.title.lower() or "taint" in flow_finding.explanation.lower()
    assert flow_finding.cwe_id in ("CWE-78", "CWE-89", "CWE-95")


def test_dataflow_lite_sanitizer_suppression():
    """V4.2-E01-T05: Sanitized dataflow does NOT flag false positive."""
    analyzer = DataflowLiteAnalyzer()

    diff_text = """--- a/views.py
+++ b/views.py
@@ -1,1 +1,5 @@
+def handle_ping(request):
+    ip_addr = request.GET.get('ip')
+    safe_ip = shlex.quote(ip_addr)
+    cmd = "ping -c 1 " + safe_ip
+    os.system(cmd)
"""
    diff = parse_unified_diff(diff_text)[0]
    findings = analyzer.analyze_file(diff)
    assert len(findings) == 0, f"Expected sanitized code to produce no findings, got {findings}"


def test_cross_file_security_signals_budgeted():
    """V4.2-E01-T04: Cross-file security analysis with strict retrieval budget."""
    repo_files = {
        "utils/crypto.py": "def weak_hash(data):\n    return hashlib.md5(data).hexdigest()\n",
        "handlers/auth.py": "from utils.crypto import weak_hash\ndef verify(pw):\n    return weak_hash(pw)\n",
    }

    retriever = lambda path: repo_files.get(path, "")
    analyzer = CrossFileSecurityAnalyzer(retriever=retriever, max_file_lookups=2)

    diff_text = """--- a/handlers/auth.py
+++ b/handlers/auth.py
@@ -1,1 +1,2 @@
+from utils.crypto import weak_hash
+    return weak_hash(pw)
"""
    diffs = parse_unified_diff(diff_text)
    findings = analyzer.analyze(diffs)
    assert len(findings) >= 1
    f = findings[0]
    assert "cross-file" in f.explanation.lower() or "weak" in f.title.lower() or "md5" in f.explanation.lower()
    assert f.evidence, "Cross-file finding must contain evidence"


def test_false_positive_controls_on_safe_constructs():
    """V4.2-E01-T05: Parameterized queries and safe AST evaluation are not flagged."""
    engine = SecurityEngineV2()

    # Parameterized SQL query is safe
    safe_sql_text = """--- a/db.py
+++ b/db.py
@@ -1,1 +1,1 @@
+cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    findings = engine.run(parse_unified_diff(safe_sql_text))
    assert not any(f.rule_id == "SEC001" for f in findings)

    # ast.literal_eval is safe
    safe_eval_text = """--- a/parse.py
+++ b/parse.py
@@ -1,1 +1,1 @@
+val = ast.literal_eval(untrusted_data)
"""
    findings = engine.run(parse_unified_diff(safe_eval_text))
    assert not any(f.rule_id == "SEC003" for f in findings)

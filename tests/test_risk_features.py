"""Tests for V4.0-E04-T01: the v1 risk feature set (ai_pr_reviewer/risk.py).

Covers the ticket's contract:
  * a closed, ordered, pinned feature vocabulary (size / sensitivity /
    impact / history);
  * absent signals are explicit ``available=False`` + a closed reason,
    never a silent zero;
  * output is a pure function of its inputs -- file order never matters;
  * sensitivity matching is a strict superset of the V3 ``classify_risk``
    path hints (the engine can never call insensitive what V3 flags);
  * untrusted path text is control-stripped, redacted and bounded before it
    can reach any consumer;
  * structural invariants: no I/O / network / clock / randomness imports,
    no floats, no authorship-shaped inputs or features.

Fixtures are synthetic; no real diffs, secrets or repository data.
"""
from __future__ import annotations

import ast
import dataclasses
import inspect
import random
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.diff_parser import FileDiff, Hunk, HunkLine  # noqa: E402
from ai_pr_reviewer.impact import compute_impact  # noqa: E402
from ai_pr_reviewer.index import FileEntry, RepoIndex  # noqa: E402
from ai_pr_reviewer.model_router import (  # noqa: E402
    _SENSITIVE_PATH_HINTS, classify_risk)
from ai_pr_reviewer.risk import (  # noqa: E402
    COUNT_CEILING, FEATURE_NAMES, FEATURE_SET_VERSION, MAX_EVIDENCE_CHARS,
    MAX_EVIDENCE_ITEMS, REASON_NO_HISTORY, REASON_NO_INDEX,
    SENSITIVE_CATEGORIES, UNAVAILABLE_REASONS, RiskFeatureSet,
    extract_risk_features)

RISK_SRC = ROOT / "ai_pr_reviewer" / "risk.py"


def _diff(path, added=1, removed=0, binary=False):
    lines = [HunkLine("+", None, i + 1, "x") for i in range(added)]
    lines += [HunkLine("-", i + 1, None, "y") for i in range(removed)]
    hunks = [] if binary else [Hunk(lines=lines)]
    return FileDiff(old_path=path, new_path=path, is_binary=binary,
                    hunks=hunks)


def _value(fs, name):
    feature = fs.get(name)
    assert feature is not None, name
    return feature.value


def _entry(path):
    return FileEntry(path=path, size=10, language="py", changed=False,
                     imports=())


def _index(paths, edges):
    return RepoIndex(root=".", files=tuple(_entry(p) for p in paths),
                     edges=tuple(edges), budget_state="ok", warnings=())


class TestVocabulary:
    EXPECTED = (
        "files_changed", "lines_changed", "non_doc_files",
        "sensitive_files", "sensitive_auth_files",
        "sensitive_payment_files", "sensitive_data_store_files",
        "sensitive_secrets_files", "sensitive_infra_files",
        "focus_sensitive_entries",
        "impact_direct_dependents", "impact_indirect_dependents",
        "impact_truncated", "impact_unknown_seeds",
        "history_max_file_churn", "history_files_with_data",
    )

    def test_vocabulary_is_pinned(self):
        # Later tickets key contributions by these names: a change here is
        # a deliberate contract change, never an accident.
        assert FEATURE_NAMES == self.EXPECTED
        assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)

    def test_output_order_and_names_match_vocabulary(self):
        for fs in (extract_risk_features([]),
                   extract_risk_features(
                       [_diff("src/auth.py")],
                       impact=compute_impact(_index(["a.py"], []), ["a.py"]),
                       history={"src/auth.py": 3}, focus=["security"])):
            assert tuple(f.name for f in fs.features) == FEATURE_NAMES
            assert fs.version == FEATURE_SET_VERSION

    def test_groups_are_closed(self):
        fs = extract_risk_features([_diff("a.py")])
        assert {f.group for f in fs.features} == {
            "size", "sensitivity", "impact", "history"}

    def test_get_returns_none_for_an_unknown_name(self):
        fs = extract_risk_features([])
        assert fs.get("files_changed") is not None
        assert fs.get("not_a_feature") is None

    def test_serialization_shape(self):
        d = extract_risk_features([_diff("a.py")]).to_dict()
        assert set(d) == {"version", "features"}
        assert set(d["features"][0]) == {
            "name", "group", "value", "available", "reason", "evidence"}


class TestSize:
    def test_counts_files_and_changed_lines(self):
        fs = extract_risk_features([_diff("a.py", 3, 2), _diff("b.py", 1, 0)])
        assert _value(fs, "files_changed") == 2
        assert _value(fs, "lines_changed") == 6

    def test_empty_input_is_all_zero_and_does_not_raise(self):
        fs = extract_risk_features([])
        assert _value(fs, "files_changed") == 0
        assert _value(fs, "lines_changed") == 0
        assert _value(fs, "non_doc_files") == 0

    def test_binary_file_counts_as_a_file_with_no_lines(self):
        fs = extract_risk_features([_diff("logo.png", binary=True)])
        assert _value(fs, "files_changed") == 1
        assert _value(fs, "lines_changed") == 0

    def test_doc_only_change_has_zero_non_doc_files(self):
        fs = extract_risk_features([
            _diff("README.md"), _diff("docs/guide.rst"),
            _diff("docs/Intro.ADOC"), _diff("LICENSE"),
            _diff("CHANGELOG")])
        assert _value(fs, "non_doc_files") == 0

    def test_txt_and_manifests_are_not_docs(self):
        # requirements.txt is a dependency manifest, not documentation.
        fs = extract_risk_features([
            _diff("requirements.txt"), _diff("notes.txt"),
            _diff("docs/build.py"), _diff("README.md")])
        assert _value(fs, "non_doc_files") == 3

    def test_missing_attributes_degrade_to_zero(self):
        fs = extract_risk_features([SimpleNamespace(path="x.py")])
        assert _value(fs, "files_changed") == 1
        assert _value(fs, "lines_changed") == 0

    def test_a_raising_attribute_is_not_swallowed_into_a_zero(self):
        class Broken:
            path = "x.py"

            @property
            def additions(self):
                raise RuntimeError("corrupt diff object")

        try:
            extract_risk_features([Broken()])
        except RuntimeError:
            return
        raise AssertionError("a broken file object must surface, not read as 0")


class TestSensitivity:
    def test_each_category_counts_its_own_files(self):
        fs = extract_risk_features([
            _diff("app/auth/login.py"), _diff("billing/invoice.py"),
            _diff("db/migrations/001.sql"), _diff("config/secrets.yml"),
            _diff(".github/workflows/ci.yml"), _diff("src/render.py")])
        assert _value(fs, "sensitive_auth_files") == 1
        assert _value(fs, "sensitive_payment_files") == 1
        assert _value(fs, "sensitive_data_store_files") == 1
        assert _value(fs, "sensitive_secrets_files") == 1
        assert _value(fs, "sensitive_infra_files") == 1
        assert _value(fs, "sensitive_files") == 5

    def test_a_file_in_two_categories_counts_once_overall(self):
        fs = extract_risk_features([_diff("auth/token_store_db.py")])
        assert _value(fs, "sensitive_auth_files") == 1
        assert _value(fs, "sensitive_secrets_files") == 1
        assert _value(fs, "sensitive_data_store_files") == 1
        assert _value(fs, "sensitive_files") == 1

    def test_matching_is_case_insensitive(self):
        fs = extract_risk_features([_diff("Src/AUTH/Login.PY")])
        assert _value(fs, "sensitive_auth_files") == 1

    def test_no_sensitive_paths_is_available_zero_not_unavailable(self):
        fs = extract_risk_features([_diff("src/render.py")])
        feature = fs.get("sensitive_files")
        assert feature.value == 0 and feature.available is True

    def test_every_v3_hint_is_still_flagged(self):
        # Strict-superset guarantee against model_router's classifier.
        for hint in _SENSITIVE_PATH_HINTS:
            path = f"src/{hint}/handler.py"
            fs = extract_risk_features([_diff(path)])
            assert _value(fs, "sensitive_files") == 1, hint

    def test_never_lower_than_v3_classifier_on_sample_paths(self):
        samples = [
            "src/feedback.py",            # 'db' substring: V3 over-flags it
            "app/tokenizer.py", "lib/Migrations/0002.py", "x/Stripe.js",
            "web/session_store.ts", "ops/credential_rotation.sh",
            "src/render.py", "docs/guide.md", "tests/test_math.py"]
        for path in samples:
            v3_high = classify_risk(
                SimpleNamespace(files=[SimpleNamespace(path=path)])
            ).level == "high"
            if v3_high:
                fs = extract_risk_features([_diff(path)])
                assert _value(fs, "sensitive_files") >= 1, path

    def test_evidence_lists_sorted_paths_and_is_capped(self):
        paths = [f"src/auth/m{i:02d}.py" for i in range(12)]
        fs = extract_risk_features([_diff(p) for p in reversed(paths)])
        feature = fs.get("sensitive_auth_files")
        assert feature.value == 12
        assert feature.evidence == tuple(sorted(paths))[:MAX_EVIDENCE_ITEMS]

    def test_focus_entries_only_add_signal(self):
        assert _value(extract_risk_features([], focus=[]),
                      "focus_sensitive_entries") == 0
        fs = extract_risk_features(
            [], focus=["Security", "SQL injection", "naming style", "",
                       None, 7])
        assert _value(fs, "focus_sensitive_entries") == 2

    def test_focus_scan_is_bounded(self):
        fs = extract_risk_features([], focus=["security"] * 500)
        assert _value(fs, "focus_sensitive_entries") <= 50

    def test_categories_are_lowercase_and_nonempty(self):
        for category, hints in SENSITIVE_CATEGORIES:
            assert category and hints
            assert all(h == h.lower() and h for h in hints)


class TestImpact:
    def test_no_index_is_unavailable_with_reason_not_zero_risk(self):
        fs = extract_risk_features([_diff("a.py")], impact=None)
        for name in ("impact_direct_dependents", "impact_indirect_dependents",
                     "impact_truncated", "impact_unknown_seeds"):
            feature = fs.get(name)
            assert feature.available is False
            assert feature.reason == REASON_NO_INDEX
            assert feature.value == 0

    def test_direct_and_indirect_dependents_are_counted(self):
        # a imports b imports c imports d; x imports a.
        idx = _index(["a.py", "b.py", "c.py", "d.py", "x.py"],
                     [("a.py", "b.py"), ("b.py", "c.py"),
                      ("c.py", "d.py"), ("x.py", "a.py")])
        impact = compute_impact(idx, ["d.py"])         # c direct, b indirect
        fs = extract_risk_features([_diff("d.py")], impact=impact)
        assert _value(fs, "impact_direct_dependents") == 1
        assert _value(fs, "impact_indirect_dependents") == 1
        assert fs.get("impact_direct_dependents").evidence == ("c.py",)
        assert fs.get("impact_direct_dependents").available is True

    def test_truncation_flag_is_carried(self):
        idx = _index(["a.py", "b.py", "c.py", "d.py", "x.py"],
                     [("a.py", "b.py"), ("b.py", "c.py"),
                      ("c.py", "d.py"), ("x.py", "a.py")])
        truncated = compute_impact(idx, ["d.py"])        # stops at hop 2
        assert truncated.truncated is True
        assert _value(extract_risk_features(
            [_diff("d.py")], impact=truncated), "impact_truncated") == 1
        complete = compute_impact(idx, ["a.py"])
        assert _value(extract_risk_features(
            [_diff("a.py")], impact=complete), "impact_truncated") == 0

    def test_malformed_dependent_paths_are_skipped_in_evidence_only(self):
        entries = [SimpleNamespace(path=p, confidence="direct")
                   for p in (None, "", 5, "ok.py")]
        impact = SimpleNamespace(entries=entries, truncated=False,
                                 unknown_seeds=())
        feature = extract_risk_features(
            [_diff("a.py")], impact=impact).get("impact_direct_dependents")
        assert feature.value == 4                  # the count is not hidden
        assert feature.evidence == ("ok.py",)      # junk never becomes evidence

    def test_unknown_seeds_are_counted(self):
        idx = _index(["a.py"], [])
        impact = compute_impact(idx, ["a.py", "brand_new.py"])
        fs = extract_risk_features([_diff("a.py"), _diff("brand_new.py")],
                                   impact=impact)
        assert _value(fs, "impact_unknown_seeds") == 1


class TestHistory:
    def test_none_is_unavailable_with_reason(self):
        fs = extract_risk_features([_diff("a.py")], history=None)
        for name in ("history_max_file_churn", "history_files_with_data"):
            feature = fs.get(name)
            assert feature.available is False
            assert feature.reason == REASON_NO_HISTORY

    def test_empty_mapping_is_available_zero(self):
        fs = extract_risk_features([_diff("a.py")], history={})
        feature = fs.get("history_max_file_churn")
        assert feature.available is True and feature.value == 0

    def test_only_changed_paths_are_considered(self):
        fs = extract_risk_features(
            [_diff("a.py"), _diff("b.py")],
            history={"a.py": 4, "b.py": 9, "other.py": 500})
        assert _value(fs, "history_max_file_churn") == 9
        assert _value(fs, "history_files_with_data") == 2

    def test_junk_values_are_neutralised_and_huge_values_clamped(self):
        fs = extract_risk_features(
            [_diff("a.py"), _diff("b.py"), _diff("c.py"), _diff("d.py")],
            history={"a.py": True, "b.py": -5, "c.py": "9", "d.py": 10 ** 12})
        assert _value(fs, "history_max_file_churn") == COUNT_CEILING

    def test_non_mapping_history_is_treated_as_absent(self):
        fs = extract_risk_features([_diff("a.py")], history=[("a.py", 3)])
        assert fs.get("history_max_file_churn").available is False

    def test_history_features_carry_no_evidence(self):
        fs = extract_risk_features([_diff("a.py")], history={"a.py": 3})
        assert fs.get("history_max_file_churn").evidence == ()
        assert fs.get("history_files_with_data").evidence == ()


class TestDeterminism:
    def _inputs(self):
        files = [_diff(p, i + 1, i) for i, p in enumerate([
            "src/auth/login.py", "billing/invoice.py", "README.md",
            "db/migrate/1.sql", "src/util.py", "ops/deploy.sh"])]
        idx = _index(["src/util.py", "src/auth/login.py", "app.py"],
                     [("app.py", "src/util.py")])
        return files, compute_impact(idx, ["src/util.py"])

    def test_file_order_never_changes_the_result(self):
        files, impact = self._inputs()
        history = {"src/util.py": 7, "billing/invoice.py": 2}
        baseline = extract_risk_features(
            files, impact=impact, history=history, focus=["auth"]).to_dict()
        rng = random.Random(1234)
        for _ in range(25):
            shuffled = list(files)
            rng.shuffle(shuffled)
            assert extract_risk_features(
                shuffled, impact=impact, history=history,
                focus=["auth"]).to_dict() == baseline

    def test_repeated_calls_are_identical(self):
        files, impact = self._inputs()
        first = extract_risk_features(files, impact=impact).to_dict()
        assert extract_risk_features(files, impact=impact).to_dict() == first

    def test_inputs_are_not_mutated(self):
        files, impact = self._inputs()
        history = {"src/util.py": 7}
        focus = ["auth"]
        before = [(f.path, f.additions, f.deletions) for f in files]
        extract_risk_features(files, impact=impact, history=history,
                              focus=focus)
        assert [(f.path, f.additions, f.deletions) for f in files] == before
        assert history == {"src/util.py": 7} and focus == ["auth"]

    def test_feature_objects_are_immutable(self):
        fs = extract_risk_features([_diff("a.py")])
        for obj in (fs, fs.features[0]):
            try:
                setattr(obj, "version" if obj is fs else "value", 99)
            except dataclasses.FrozenInstanceError:
                continue
            raise AssertionError("risk features must be frozen")


class TestUnavailableIsNeverSilent:
    def test_available_features_have_no_reason_and_unavailable_always_do(self):
        for fs in (extract_risk_features([_diff("a.py")]),
                   extract_risk_features(
                       [_diff("a.py")],
                       impact=compute_impact(_index(["a.py"], []), ["a.py"]),
                       history={})):
            for f in fs.features:
                if f.available:
                    assert f.reason == ""
                else:
                    assert f.reason in UNAVAILABLE_REASONS
                    assert f.value == 0


class TestUntrustedEvidenceHardening:
    def test_secret_in_a_path_is_redacted_from_evidence(self):
        secret = "ghp_" + "a" * 36
        fs = extract_risk_features([_diff(f"src/auth/{secret}.py")])
        blob = repr(fs.to_dict())
        assert secret not in blob
        assert "[REDACTED]" in blob

    def test_control_characters_never_reach_evidence(self):
        nasty = "src/auth/x\n\x1b[31m\x00y\r.py"
        fs = extract_risk_features([_diff(nasty)])
        for f in fs.features:
            for item in f.evidence:
                assert item.isprintable()

    def test_long_paths_and_many_files_stay_bounded(self):
        files = [_diff("auth/" + "a" * 5000 + str(i) + ".py")
                 for i in range(300)]
        fs = extract_risk_features(files)
        assert _value(fs, "sensitive_auth_files") == 300
        for f in fs.features:
            assert len(f.evidence) <= MAX_EVIDENCE_ITEMS
            assert all(len(e) <= MAX_EVIDENCE_CHARS for e in f.evidence)

    def test_evidence_is_deterministic_after_sanitising(self):
        a = extract_risk_features([_diff("auth/b\n.py"), _diff("auth/a.py")])
        b = extract_risk_features([_diff("auth/a.py"), _diff("auth/b\n.py")])
        assert a.to_dict() == b.to_dict()


class TestStructuralInvariants:
    def _tree(self):
        return ast.parse(RISK_SRC.read_text("utf-8"))

    def test_module_imports_no_io_network_clock_or_randomness(self):
        tree = self._tree()
        imports = {
            a.name.split(".")[0]
            for n in ast.walk(tree) if isinstance(n, ast.Import)
            for a in n.names
        } | {
            (n.module or "").split(".")[0]
            for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
            if n.level == 0
        }
        for banned in ("subprocess", "socket", "http", "urllib", "requests",
                       "httpx", "os", "shutil", "pathlib", "random", "time",
                       "datetime", "secrets", "json", "yaml"):
            assert banned not in imports, banned

    def test_module_uses_no_floats(self):
        tree = self._tree()
        floats = [n for n in ast.walk(tree)
                  if isinstance(n, ast.Constant) and isinstance(n.value, float)]
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == "float"]
        assert not floats and not calls

    def test_no_authorship_shaped_inputs_or_features(self):
        banned = ("author", "committer", "developer", "user", "email",
                  "person", "owner", "contributor")
        params = inspect.signature(extract_risk_features).parameters
        for name in list(params) + list(FEATURE_NAMES):
            assert not any(b in name.lower() for b in banned), name

    def test_feature_set_type_is_exported(self):
        assert isinstance(extract_risk_features([]), RiskFeatureSet)

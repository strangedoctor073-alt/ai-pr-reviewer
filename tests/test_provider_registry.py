"""V4.0-E05 — provider capability registry.

T01 (this section): entry schema, validation, in-tree entries, and a
conformance check per backend. The registry *points at* public-contract
surfaces it does not own (``Config`` fields, ``INPUT_*`` env names, Action
inputs, CLI flags, the credential-redaction list, the eval harness engine
table); the pins below fail if an entry names wiring that does not exist or
if that wiring grows a backend the registry does not know about.

Fully offline; no real credentials (synthetic placeholders only).
"""
from __future__ import annotations

import ast
import inspect
import sys
import threading
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import provider_registry as reg  # noqa: E402
from ai_pr_reviewer.provider_registry import (  # noqa: E402
    MODEL_POLICY_BUILTIN, MODEL_POLICY_EXPLICIT, MODEL_POLICY_NONE,
    TASK_REVIEW, TASK_SYNTHESIS, ProviderSpec, RegistryError)

BUILTIN_AI = ("claude", "openai", "gemini")


class _FakeProvider:
    backend = "fake"

    def __init__(self, api_key="", model="", max_tokens=0, batch_chars=0,
                 focus_areas=None, retry=None):
        self.model = model
        self.startup_warnings: list[str] = []


def _fake(**overrides) -> ProviderSpec:
    base = dict(name="fake", display_name="Fake Backend",
                tasks=frozenset({TASK_REVIEW}),
                model_policy=MODEL_POLICY_EXPLICIT, factory=_FakeProvider)
    base.update(overrides)
    return ProviderSpec(**base)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Leave only the built-in entries behind, whatever a test registered."""
    yield
    for name in [s.name for s in reg.specs() if s.name not in reg.BUILTIN_BACKENDS]:
        reg.unregister(name)


# ----------------------------------------------------------- in-tree entries
def test_builtin_entries_and_documented_order():
    assert reg.ai_backend_names() == BUILTIN_AI           # AI_BACKENDS order, unchanged
    assert [s.name for s in reg.specs()] == [*BUILTIN_AI, "static"]
    assert reg.BUILTIN_BACKENDS == frozenset({*BUILTIN_AI, "static"})
    assert [s.ai for s in reg.specs()] == [True, True, True, False]


def test_builtin_entries_all_validate():
    for spec in reg.specs():
        reg.validate_spec(spec)


def test_static_is_never_an_ai_backend():
    static = reg.get_spec(reg.STATIC_BACKEND)
    assert static is not None and static.ai is False
    assert reg.STATIC_BACKEND not in reg.ai_backend_names()
    assert static.factory is None and static.credential_field is None
    assert static.model_policy == MODEL_POLICY_NONE


def test_model_policy_matches_the_documented_defaults():
    # Only Claude ships a default model; OpenAI/Gemini must be told one.
    assert reg.get_spec("claude").model_policy == MODEL_POLICY_BUILTIN
    assert reg.get_spec("claude").default_model == "claude-sonnet-4-6"
    for name in ("openai", "gemini"):
        assert reg.get_spec(name).model_policy == MODEL_POLICY_EXPLICIT
        assert reg.get_spec(name).default_model is None


def test_exactly_one_default_backend_and_it_is_claude():
    assert [s.name for s in reg.specs() if s.default_backend] == ["claude"]


def test_capability_claims_use_the_closed_vocabulary_only():
    for spec in reg.specs():
        assert spec.tasks and spec.tasks <= set(reg.TASK_TYPES)
        assert TASK_REVIEW in spec.tasks
    # Nothing declares a task whose consumer does not exist yet.
    assert all(TASK_SYNTHESIS not in s.tasks for s in reg.specs())
    # The rule engine has no test/architecture rules.
    assert reg.supports("static", "security-review")
    assert not reg.supports("static", "test-review")
    assert not reg.supports("static", "arch-review")
    assert reg.supports("gemini", "arch-review")
    assert not reg.supports("not-a-backend", TASK_REVIEW)


def test_unknown_facts_are_declared_unknown_not_assumed():
    for spec in reg.specs():
        assert spec.context_window_tokens is None
        assert spec.tool_support is False


# ------------------------------------------------- per-backend conformance
@pytest.mark.parametrize("name", BUILTIN_AI)
def test_factory_builds_the_class_whose_backend_matches_the_entry(name):
    spec = reg.get_spec(name)
    cls = reg.resolve_factory(spec)
    assert cls.backend == spec.name


@pytest.mark.parametrize("name", BUILTIN_AI)
def test_factory_accepts_every_keyword_the_router_will_pass(name):
    spec = reg.get_spec(name)
    params = set(inspect.signature(reg.resolve_factory(spec)).parameters)
    expected = {"api_key", "model", "max_tokens", "batch_chars", "focus_areas", "retry"}
    if spec.endpoint_field:
        expected.add("base_url")
    assert expected <= params, f"{name}: constructor lacks {sorted(expected - params)}"


def test_string_factories_can_only_name_modules_inside_the_package():
    spec = _fake(factory="os:system")
    reg.validate_spec(spec)                      # shape is legal ...
    with pytest.raises(ImportError):             # ... but it cannot escape the package
        reg.resolve_factory(spec)


# ------------------------------------- public wiring the registry points at
def _credential_fields() -> list[tuple[str, str]]:
    out = []
    for spec in reg.specs():
        for field in (spec.credential_field, spec.endpoint_field):
            if field:
                out.append((spec.name, field))
    return out


def test_every_registry_field_exists_on_config():
    from ai_pr_reviewer.config import Config
    cfg = Config()
    for name, field in _credential_fields():
        assert hasattr(cfg, field), f"{name}: Config has no {field!r}"


def test_every_registry_field_has_a_known_input_env_var():
    from ai_pr_reviewer.config import KNOWN_INPUT_ENV_VARS
    for name, field in _credential_fields():
        assert f"INPUT_{field.upper()}" in KNOWN_INPUT_ENV_VARS, (name, field)


def test_every_registry_field_is_a_declared_action_input_and_env_export():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    inputs = set(action["inputs"])
    run_text = yaml.safe_dump(action["runs"])
    for name, field in _credential_fields():
        assert field in inputs, f"{name}: action.yml has no input {field!r}"
        assert f"INPUT_{field.upper()}" in run_text, f"{name}: input not exported"


def test_every_registry_field_has_a_cli_flag():
    from ai_pr_reviewer.cli import parse_args
    for name, field in _credential_fields():
        flag = "--" + field.replace("_", "-")
        args = parse_args([flag, "synthetic-value"])
        assert getattr(args, field) == "synthetic-value", (name, flag)


def test_configured_credentials_are_redacted_for_every_registry_credential():
    """``security.scrub_with_config`` keeps its own credential-name list (it
    imports nothing from the package by design); this pins that list to the
    registry so a new credential field cannot leak through a warning."""
    from ai_pr_reviewer.config import Config
    from ai_pr_reviewer.security import scrub_with_config
    for name, field in _credential_fields():
        if field.endswith("_url"):
            continue                                  # endpoints are not secrets
        secret = f"synthetic-{name}-credential-0123456789"
        cfg = Config(**{field: secret})
        assert secret not in scrub_with_config(f"failed with {secret}", cfg), (
            f"{name}: {field} is not covered by scrub_with_config")


def test_eval_harness_engine_table_matches_the_registry():
    """``eval/harness/tier_b.py`` carries its own engine/credential tables;
    keep them in step with the in-tree backends."""
    from eval.harness import tier_b
    assert tier_b.ENGINES == BUILTIN_AI
    for name in BUILTIN_AI:
        assert tier_b._KEY_FIELD[name] == reg.get_spec(name).credential_field


# ---------------------------------------------------------- schema validation
@pytest.mark.parametrize("overrides", [
    {"name": "Fake"}, {"name": "a b"}, {"name": "x+static"}, {"name": ""},
    {"name": "1fake"}, {"name": "f" * 33},
    {"display_name": ""}, {"display_name": "Bad\nName"},
    {"display_name": "<script>x</script>"}, {"display_name": "[link](http://x)"},
    {"display_name": "N" * 41}, {"review_by_name": "Bad|Name"},
    {"tasks": frozenset()}, {"tasks": frozenset({"deploy"})},
    {"tasks": frozenset({TASK_REVIEW, "nonsense"})},
    {"model_policy": "whatever"}, {"billing_class": "free"},
    {"model_policy": MODEL_POLICY_NONE},                 # AI needs a model policy
    {"model_policy": MODEL_POLICY_BUILTIN},              # builtin needs default_model
    {"model_policy": MODEL_POLICY_BUILTIN, "default_model": "bad model"},
    {"default_model": "some-model"},                     # explicit must not ship one
    {"factory": None}, {"factory": "no-colon"}, {"factory": ".rel:Cls"},
    {"factory": "pkg.mod:bad-name"}, {"factory": 123},
    {"credential_field": "__class__"}, {"credential_field": "A-B"},
    {"endpoint_field": "x.y"},
    {"model_prefixes": ("",)}, {"model_prefixes": ("GPT-",)}, {"model_prefixes": (3,)},
    {"precedence": -1}, {"precedence": 1001}, {"precedence": True},
    {"context_window_tokens": 0}, {"context_window_tokens": -5},
    {"context_window_tokens": True}, {"context_window_tokens": "big"},
    {"tool_support": "yes"}, {"ai": "yes"}, {"placeholder_key": "k" * 33},
])
def test_invalid_entries_are_rejected(overrides):
    with pytest.raises(RegistryError):
        reg.validate_spec(_fake(**overrides))


def test_registering_something_that_is_not_a_spec_is_rejected():
    with pytest.raises(RegistryError):
        reg.register({"name": "fake"})                   # type: ignore[arg-type]


@pytest.mark.parametrize("overrides", [
    {"factory": _FakeProvider},                           # non-AI takes no factory
    {"credential_field": "anthropic_api_key"},
    {"endpoint_field": "openai_base_url"},
    {"model_policy": MODEL_POLICY_EXPLICIT},              # must be not_applicable
    {"default_backend": True}, {"model_prefixes": ("x-",)},
])
def test_non_ai_engines_cannot_carry_ai_wiring(overrides):
    base = dict(name="rules", display_name="Rules", ai=False, factory=None,
                model_policy=MODEL_POLICY_NONE)
    base.update(overrides)
    with pytest.raises(RegistryError):
        reg.validate_spec(_fake(**base))


def test_a_well_formed_entry_validates_and_normalises_collections():
    spec = _fake(tasks=[TASK_REVIEW, "security-review"], model_prefixes=["fk-"],
                 review_by_name="Fake Corp")
    reg.validate_spec(spec)
    assert isinstance(spec.tasks, frozenset) and spec.model_prefixes == ("fk-",)
    assert spec.review_label == "Fake Corp"
    assert _fake().review_label == "Fake Backend"
    assert hash(spec) == hash(spec)                      # frozen + hashable


# -------------------------------------------------- registration lifecycle
def test_register_adds_one_ai_backend_and_unregister_removes_it():
    spec = reg.register(_fake())
    assert reg.get_spec("fake") is spec
    assert reg.ai_backend_names() == (*BUILTIN_AI, "fake")
    reg.unregister("fake")
    assert reg.get_spec("fake") is None
    assert reg.ai_backend_names() == BUILTIN_AI
    reg.unregister("fake")                               # idempotent


@pytest.mark.parametrize("name", sorted(reg.BUILTIN_BACKENDS))
def test_builtin_entries_cannot_be_shadowed_replaced_or_removed(name):
    before = reg.get_spec(name)
    with pytest.raises(RegistryError):
        reg.register(_fake(name=name))
    with pytest.raises(RegistryError):
        reg.unregister(name)
    assert reg.get_spec(name) is before


def test_duplicate_registration_is_rejected():
    reg.register(_fake())
    with pytest.raises(RegistryError):
        reg.register(_fake())


def test_a_second_default_backend_is_rejected():
    with pytest.raises(RegistryError, match="default_backend"):
        reg.register(_fake(default_backend=True))
    assert reg.get_spec("fake") is None                  # nothing half-registered


def test_failed_registration_leaves_the_registry_untouched():
    before = reg.specs()
    with pytest.raises(RegistryError):
        reg.register(_fake(tasks=frozenset({"bogus"})))
    assert reg.specs() == before


def test_concurrent_registration_is_safe():
    names = [f"fake{i}" for i in range(16)]
    errors: list[BaseException] = []

    def work(name: str) -> None:
        try:
            reg.register(_fake(name=name))
        except BaseException as exc:                     # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert set(names) <= set(reg.ai_backend_names())


# ------------------------------------------------------- module invariants
def _source() -> str:
    return Path(reg.__file__).read_text(encoding="utf-8")


def test_registry_module_imports_nothing_from_the_package_at_import_time():
    """reporter, cli and model_router all import this module; it must not
    import any of them (cycle-free by construction)."""
    tree = ast.parse(_source())
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import at module level"
            assert not (node.module or "").startswith("ai_pr_reviewer")
        elif isinstance(node, ast.Import):
            assert not any(a.name.startswith("ai_pr_reviewer") for a in node.names)


def test_billing_class_is_descriptive_metadata_only():
    """No registry code other than the validator reads ``billing_class``:
    there is no billing- or latency-based routing."""
    tree = ast.parse(_source())
    readers: set[str] = set()
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(fn):
            if isinstance(node, ast.Attribute) and node.attr == "billing_class":
                readers.add(fn.name)
    assert readers <= {"validate_spec"}, readers


# =========================================================================
# T02 — registry-driven routing replaces the hard-coded wiring sites
# =========================================================================
import itertools  # noqa: E402
import logging  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from ai_pr_reviewer import model_router as router  # noqa: E402
from ai_pr_reviewer import reporter  # noqa: E402
from ai_pr_reviewer.config import Config  # noqa: E402


def _legacy_select_backend(cfg) -> str:
    """Verbatim copy of ``select_backend`` as it was before the registry —
    the behavioural reference the data-driven version must reproduce."""
    if getattr(cfg, "mock", False):
        return "static"
    model = getattr(cfg, "model", "") or ""
    anthropic_key = getattr(cfg, "anthropic_api_key", "")
    openai_key = getattr(cfg, "openai_api_key", "")
    gemini_key = getattr(cfg, "gemini_api_key", "")
    openai_base_url = getattr(cfg, "openai_base_url", "")
    use_openai = (model.startswith(("gpt-", "o1", "o3", "o4")) or
                  bool(openai_base_url) or
                  (openai_key and not anthropic_key and not gemini_key))
    use_gemini = (model.startswith("gemini-") or
                  (gemini_key and not anthropic_key and not openai_key and not use_openai))
    use_claude = (model.startswith("claude-") or
                  (anthropic_key and not use_openai and not use_gemini))
    if use_openai and (openai_key or openai_base_url):
        return "openai"
    if use_gemini and gemini_key:
        return "gemini"
    if use_claude and anthropic_key:
        return "claude"
    return "static"


_MODELS = ("", "gpt-4o", "GPT-4o", "o1-mini", "o3", "o4-x", "gemini-x", "claude-x",
           "mistral-large", "  gpt-4o")


def test_select_backend_matches_the_pre_registry_rule_for_every_combination():
    cases = 0
    for model, a, o, g, url, mock in itertools.product(
            _MODELS, (0, 1), (0, 1), (0, 1), (0, 1), (False, True)):
        cfg = Config(model=model, mock=mock,
                     anthropic_api_key="a" * a, openai_api_key="o" * o,
                     gemini_api_key="g" * g,
                     openai_base_url="http://localhost:1/v1" if url else "")
        assert router.select_backend(cfg) == _legacy_select_backend(cfg), cfg
        cases += 1
    assert cases == len(_MODELS) * 32


def test_select_backend_tolerates_configs_missing_fields():
    assert router.select_backend(SimpleNamespace()) == "static"
    assert router.select_backend(SimpleNamespace(anthropic_api_key="k")) == "claude"


def _legacy_has_credentials(cfg) -> bool:
    return bool(cfg.anthropic_api_key or cfg.openai_api_key or cfg.gemini_api_key
                or cfg.openai_base_url)


def test_has_ai_credentials_matches_the_pre_registry_cli_check():
    for a, o, g, url in itertools.product(("", "k"), repeat=4):
        cfg = Config(anthropic_api_key=a, openai_api_key=o, gemini_api_key=g,
                     openai_base_url=url)
        assert reg.has_ai_credentials(cfg) == _legacy_has_credentials(cfg)


def test_ai_backends_attribute_tracks_the_registry():
    from ai_pr_reviewer.model_router import AI_BACKENDS      # module __getattr__
    assert AI_BACKENDS == BUILTIN_AI
    reg.register(_fake())
    assert router.AI_BACKENDS == (*BUILTIN_AI, "fake")
    with pytest.raises(AttributeError):
        router.NOT_A_REAL_NAME


def test_parse_provider_order_semantics_are_unchanged(caplog):
    assert router.parse_provider_order("Claude, openai") == ["claude", "openai"]
    assert router.parse_provider_order("claude claude gemini") == ["claude", "gemini"]
    assert router.parse_provider_order("static,claude") == ["claude"]
    assert router.parse_provider_order("") == [] == router.parse_provider_order(None)
    with caplog.at_level(logging.WARNING, logger=router.log.name):
        assert router.parse_provider_order("Typo, claude") == ["claude"]
    assert any("ignoring unknown backend 'Typo'" in r.getMessage() for r in caplog.records)


# ------------------------------------------------------------- build_provider
_CTX = SimpleNamespace(files=[], focus_areas=[], project_rules=None)


def test_build_provider_passes_the_same_arguments_as_before():
    claude = router.build_provider(Config(anthropic_api_key="ak"), _CTX, "claude")
    assert (claude.backend, claude.model, claude.api_key) == ("claude", "claude-sonnet-4-6", "ak")
    claude = router.build_provider(Config(anthropic_api_key="ak", model="claude-x"),
                                   _CTX, "claude")
    assert claude.model == "claude-x"

    openai = router.build_provider(
        Config(openai_api_key="ok", model="gpt-x", openai_base_url="http://h/v1",
               batch_chars=1234, focus_areas=["sql"]), _CTX, "openai")
    assert (openai.backend, openai.model, openai.api_key, openai.base_url) == (
        "openai", "gpt-x", "ok", "http://h/v1")
    assert (openai.batch_chars, openai.focus_areas) == (1234, ["sql"])
    keyless = router.build_provider(
        Config(model="local", openai_base_url="http://h/v1"), _CTX, "openai")
    assert keyless.api_key == "unused"

    gemini = router.build_provider(Config(gemini_api_key="gk", model="gemini-x"),
                                   _CTX, "gemini")
    assert (gemini.backend, gemini.model, gemini.api_key) == ("gemini", "gemini-x", "gk")


@pytest.mark.parametrize("mode,tokens", [("economy", 2048), ("balanced", 4096),
                                         ("maximum", 8192), ("automatic", 4096)])
def test_build_provider_keeps_review_mode_token_budgets(mode, tokens):
    provider = router.build_provider(
        Config(anthropic_api_key="k", review_mode=mode), _CTX, "claude")
    assert provider.max_tokens == tokens


def test_build_provider_static_and_unknown():
    assert isinstance(router.build_provider(Config(), _CTX, "static"), router.StaticProvider)
    with pytest.raises(ValueError, match="unknown provider backend 'nope'"):
        router.build_provider(Config(), _CTX, "nope")


def test_build_provider_still_adds_the_high_risk_startup_note():
    ctx = SimpleNamespace(files=[SimpleNamespace(path="app/payment/charge.py")],
                          focus_areas=[], project_rules=None)
    provider = router.build_provider(Config(anthropic_api_key="k"), ctx, "claude")
    assert any(w.startswith("high-risk PR") for w in provider.startup_warnings)


def test_explicit_model_error_text_is_unchanged():
    expected = ("the {b} provider needs an explicit model id \u2014 set the `model` "
               "input (or --model) to a model your account can call.")
    for name in ("openai", "gemini"):
        assert router._backend_config_error(Config(), name) == expected.format(b=name)
        assert router._backend_config_error(Config(model="m"), name) is None
    assert router._backend_config_error(Config(), "claude") is None
    assert router._backend_config_error(Config(), "static") is None


# -------------------------------------------------------------- report labels
_LEGACY_TITLES = {
    "claude": "Claude", "openai": "OpenAI", "gemini": "Gemini",
    "static": "Static Fallback",
    "claude+static": "Claude + Static Fallback",
    "openai+static": "OpenAI + Static Fallback",
    "gemini+static": "Gemini + Static Fallback",
}
_LEGACY_FOOTERS = {
    "claude": "review by Claude (AI)",
    "openai": "review by OpenAI (AI)",
    "gemini": "review by Google Gemini (AI)",
    "static": "rule-based static analysis \u2014 not an AI review",
    "claude+static": ("review by Claude (AI); batches Claude could not review "
                      "were covered by rule-based static analysis (not AI)"),
    "openai+static": ("review by OpenAI (AI); batches OpenAI could not review "
                      "were covered by rule-based static analysis (not AI)"),
    "gemini+static": ("review by Google Gemini (AI); batches Gemini could not review "
                      "were covered by rule-based static analysis (not AI)"),
}


def test_report_labels_are_byte_identical_to_the_hard_coded_tables():
    assert dict(reporter._ENGINE_TITLE) == _LEGACY_TITLES
    assert dict(reporter._ENGINE_FOOTER) == _LEGACY_FOOTERS


def test_static_output_is_never_labelled_as_ai():
    assert "AI" not in reporter._ENGINE_TITLE["static"].split()
    assert reporter._ENGINE_FOOTER["static"].endswith("not an AI review")
    assert "(not AI)" in reporter._ENGINE_FOOTER["claude+static"]


def test_resolve_engine_semantics_are_unchanged():
    assert reporter.resolve_engine(SimpleNamespace(engine="claude+static")) == "claude+static"
    assert reporter.resolve_engine(SimpleNamespace(engine="", mode="openai")) == "openai"
    assert reporter.resolve_engine(SimpleNamespace(engine="weird", mode="mock")) == "static"
    assert reporter.resolve_engine(SimpleNamespace()) == "static"


# ------------------------------------------- "adding a backend is one entry"
def test_a_registered_backend_works_end_to_end_with_no_other_production_edit():
    """Exit criterion: a fake backend needs exactly one registry entry. It is
    named in ``provider_order``, parsed, validated, built, labelled and counted
    as configured — through the production functions, unpatched."""
    reg.register(_fake(model_prefixes=("fk-",), review_by_name="Fake Corp"))
    cfg = Config(provider_order="fake, claude", model="fk-1")

    assert router.parse_provider_order(cfg.provider_order) == ["fake", "claude"]
    assert router.provider_order(cfg) == ["fake", "claude"]
    assert router.provider_config_error(cfg) is None
    provider = router.get_provider(cfg, _CTX)
    assert isinstance(provider, _FakeProvider) and provider.model == "fk-1"
    assert reg.has_ai_credentials(cfg)                       # named, needs no key
    assert reporter._ENGINE_TITLE["fake"] == "Fake Backend"
    assert reporter._ENGINE_TITLE["fake+static"] == "Fake Backend + Static Fallback"
    assert reporter._ENGINE_FOOTER["fake"] == "review by Fake Corp (AI)"
    assert reporter.resolve_engine(SimpleNamespace(engine="fake+static")) == "fake+static"
    assert reporter.resolve_engine(SimpleNamespace(mode="fake")) == "fake"
    assert router.select_backend(Config(model="fk-9")) == "static"   # no credential/endpoint

    reg.unregister("fake")
    assert "fake" not in reporter._ENGINE_TITLE
    assert router.parse_provider_order("fake, claude") == ["claude"]


def test_a_registered_credentialed_backend_is_selected_by_prefix_and_key():
    reg.register(_fake(credential_field="gemini_api_key", model_prefixes=("fk-",)))
    assert router.select_backend(Config(model="fk-1", gemini_api_key="k")) == "fake"
    assert router.select_backend(Config(model="fk-1")) == "static"   # prefix alone is not usable


def test_an_unusable_secondary_backend_is_skipped_not_fatal():
    reg.register(_fake(name="needsmodel"))
    cfg = Config(anthropic_api_key="k", provider_order="claude,needsmodel")
    assert router.provider_config_error(cfg) is None         # primary (claude) is fine
    assert router._backend_config_error(cfg, "needsmodel") is not None


def _string_constants(path: Path) -> set[str]:
    """String literals that are code, not docstrings."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    return {n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in docstrings}


@pytest.mark.parametrize("module", ["model_router.py", "reporter.py"])
def test_no_hard_coded_ai_backend_names_remain_in_routing_code(module):
    """Wiring guard: backend names live in the registry only."""
    literals = _string_constants(ROOT / "ai_pr_reviewer" / module)
    leaked = sorted(l for l in literals
                    if any(l == n or l.startswith(n + "+") or l.startswith(n + "-")
                           for n in BUILTIN_AI))
    assert not leaked, f"{module} hard-codes backend wiring: {leaked}"


def test_routing_modules_do_not_reach_for_backend_specific_config_fields():
    fields = {f for _, f in _credential_fields()}
    for module in ("model_router.py", "reporter.py"):
        literals = _string_constants(ROOT / "ai_pr_reviewer" / module)
        assert not (literals & fields), module
        tree = ast.parse((ROOT / "ai_pr_reviewer" / module).read_text(encoding="utf-8"))
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert not (attrs & fields), (module, attrs & fields)


def test_cli_no_longer_hard_codes_credential_fields():
    tree = ast.parse((ROOT / "ai_pr_reviewer" / "cli.py").read_text(encoding="utf-8"))
    main = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "main")
    attrs = {n.attr for n in ast.walk(main) if isinstance(n, ast.Attribute)}
    assert not (attrs & {f for _, f in _credential_fields()})


# =========================================================================
# T03 — configuration validation through the registry
# =========================================================================
from ai_pr_reviewer.provider_registry import ProviderRoutingError  # noqa: E402


@pytest.fixture
def _circuits():
    router.reset_circuits()
    yield
    router.reset_circuits()


def _legacy_config_error_exists(cfg) -> bool:
    """Pre-registry rule: the first backend of the effective order needs an
    explicit model if it is openai or gemini."""
    order = router.provider_order(cfg)
    return bool(order and order[0] in ("openai", "gemini")
                and not (cfg.model or "").strip())


def test_config_errors_for_the_review_task_are_unchanged():
    for order, model, a, o, g, url in itertools.product(
            ("", "claude", "openai", "gemini", "openai,claude", "gemini,openai",
             "claude,openai", "static", "typo"),
            ("", "gpt-x", "gemini-x", "claude-x"),
            (0, 1), (0, 1), (0, 1), (0, 1)):
        cfg = Config(provider_order=order, model=model, anthropic_api_key="a" * a,
                     openai_api_key="o" * o, gemini_api_key="g" * g,
                     openai_base_url="http://h/v1" if url else "")
        assert (router.provider_config_error(cfg) is not None) == \
            _legacy_config_error_exists(cfg), cfg


@pytest.mark.parametrize("task", ["test-review", "arch-review", "synthesis"])
def test_static_only_run_rejects_tasks_the_rule_engine_cannot_run(task):
    for cfg in (Config(), Config(mock=True, anthropic_api_key="k")):
        message = router.provider_config_error(cfg, task)
        assert message and repr(task) in message and "static rule engine" in message
        with pytest.raises(ProviderRoutingError):
            router.route_task(cfg, task)
        with pytest.raises(ProviderRoutingError):
            router.get_provider(cfg, _CTX, task=task)


def test_static_only_run_accepts_tasks_the_rule_engine_declares():
    for task in ("review", "security-review"):
        assert router.provider_config_error(Config(mock=True), task) is None
        assert router.route_task(Config(mock=True), task) == "static"
        assert isinstance(router.get_provider(Config(), _CTX, task=task),
                          router.StaticProvider)


def test_impossible_task_provider_pair_is_an_actionable_config_error():
    reg.register(_fake(tasks=frozenset({"security-review"}), model_prefixes=("fk-",)))
    cfg = Config(provider_order="fake", model="fk-1")
    message = router.provider_config_error(cfg)                 # task=review
    assert "fake provider cannot run the 'review' task" in message
    assert "it supports: security-review" in message
    assert "provider_order" in message                          # tells the user what to change
    with pytest.raises(ProviderRoutingError, match="cannot run the 'review' task"):
        router.get_provider(cfg, _CTX)
    with pytest.raises(ValueError):                             # still a ValueError for old callers
        router.get_provider(cfg, _CTX)
    assert router.route_task(cfg, "security-review") == "fake"


def test_routing_picks_the_first_backend_that_can_run_the_task(monkeypatch):
    reg.register(_fake(tasks=frozenset({"security-review"})))
    cfg = Config(provider_order="fake, claude", model="m", anthropic_api_key="k")
    assert router.route_task(cfg, "security-review") == "fake"
    assert router.route_task(cfg, "test-review") == "claude"    # fake does not claim it
    with pytest.raises(ProviderRoutingError):
        router.route_task(cfg, "synthesis")                     # nobody claims it
    # An unusable (secondary) backend is skipped, not fatal.
    cfg2 = Config(provider_order="claude, fake", anthropic_api_key="k")
    assert router.provider_config_error(cfg2) is None
    assert isinstance(router.get_provider(cfg2, _CTX), reg.resolve_factory(reg.get_spec("claude")))


def test_unknown_tasks_are_rejected_not_guessed():
    with pytest.raises(ProviderRoutingError, match="unknown task 'deploy'"):
        router.route_task(Config(anthropic_api_key="k"), "deploy")
    assert "unknown task" in router.provider_config_error(Config(), "deploy")


def test_open_circuits_cannot_degrade_a_task_the_fallback_cannot_run(_circuits):
    cfg = Config(anthropic_api_key="k")
    for _ in range(2):
        router.breaker_for("claude").record_failure()
    assert isinstance(router.get_provider(cfg, _CTX), router.StaticProvider)   # review: unchanged
    with pytest.raises(ProviderRoutingError, match="circuit-open"):
        router.get_provider(cfg, _CTX, task="test-review")


def test_no_credentials_review_run_is_still_static():
    assert isinstance(router.get_provider(Config(), _CTX), router.StaticProvider)
    assert router.route_task(Config(), "review") == "static"


def _local_diff(tmp_path) -> str:
    path = tmp_path / "change.diff"
    path.write_text("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n"
                    "-x = 1\n+x = 2\n", encoding="utf-8")
    return str(path)


def test_cli_exits_1_with_the_registry_error_for_an_impossible_pair(
        tmp_path, capsys, monkeypatch):
    from ai_pr_reviewer import cli
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OPENAI_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    reg.register(_fake(tasks=frozenset({"security-review"})))
    code = cli.main(["--diff-file", _local_diff(tmp_path), "--repo", "a/b", "--pr", "1",
                     "--provider-order", "fake", "--model", "m", "--no-comment",
                     "--output", str(tmp_path / "r.json")])
    assert code == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "cannot run the 'review' task" in err
    assert not (tmp_path / "r.json").exists()                   # nothing was reviewed


def test_cli_exit_1_for_a_missing_explicit_model_is_unchanged(tmp_path, capsys, monkeypatch):
    from ai_pr_reviewer import cli
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OPENAI_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    code = cli.main(["--diff-file", _local_diff(tmp_path), "--repo", "a/b", "--pr", "1",
                     "--openai-api-key", "synthetic-key-123456", "--no-comment"])
    assert code == 1
    assert "needs an explicit model id" in capsys.readouterr().err


# =========================================================================
# T04 — retired-model-ID scan covers registry data
# =========================================================================
_RETIRED_MARKERS = ("gemini-2.0", "gemini-1.5", "claude-3-5", "claude-3-7")


def _existing_scan_markers() -> tuple[str, ...]:
    """The deny-list the source-level release scan uses, read from that test so
    the two cannot drift apart."""
    tree = ast.parse((ROOT / "tests" / "test_release_hardening.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
              and n.name == "test_no_retired_model_ids_are_hardcoded_in_the_engine")
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "banned" for t in node.targets):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError("release-hardening scan no longer defines `banned`")


def _strings_in(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (tuple, list, set, frozenset)):
        return [s for item in value for s in _strings_in(item)]
    return []


def _retired_hits(spec_list) -> list[tuple[str, str, str]]:
    """``(entry, field, marker)`` for every retired model id in registry data."""
    hits = []
    for spec in spec_list:
        for field in spec.__dataclass_fields__:
            for text in _strings_in(getattr(spec, field)):
                for marker in _RETIRED_MARKERS:
                    if marker in text.lower():
                        hits.append((spec.name, field, marker))
    return hits


def test_registry_scan_uses_the_same_deny_list_as_the_source_scan():
    assert set(_RETIRED_MARKERS) == set(_existing_scan_markers())


def test_no_registry_entry_carries_a_retired_model_id():
    assert _retired_hits(reg.specs()) == []


def test_registry_scan_negative_control_it_can_fail():
    for marker in _RETIRED_MARKERS:
        bad = _fake(model_policy=MODEL_POLICY_BUILTIN, default_model=f"{marker}-sonnet",
                    model_prefixes=(marker,))
        assert {h[1] for h in _retired_hits([bad])} >= {"default_model", "model_prefixes"}


def test_source_level_release_scan_walks_the_registry_module():
    import ai_pr_reviewer.cli as cli
    walked = {p.name for p in Path(cli.__file__).parent.rglob("*.py")}
    assert "provider_registry.py" in walked


def test_the_only_default_model_is_claudes_and_it_is_current():
    defaults = {s.name: s.default_model for s in reg.specs() if s.default_model}
    assert defaults == {"claude": "claude-sonnet-4-6"}

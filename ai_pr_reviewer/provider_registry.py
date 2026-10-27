"""Provider capability registry (V4.0-E05, ADR-007).

One declarative entry per review backend: what it can be asked to do, how it
is selected from configuration, how it is constructed and how it is labelled.
Everything that used to be hard-coded per backend in ``model_router`` and
``reporter`` is read from here, so adding a backend is one :func:`register`
call (or one entry in ``_BUILTIN_SPECS``) and no other production edit.

Boundaries this module keeps on purpose:

* Stdlib only, and no import of any other ``ai_pr_reviewer`` module at import
  time. ``reporter``, ``cli`` and ``model_router`` all depend on it, so it must
  not depend on them. Provider classes are imported lazily by
  :func:`resolve_factory`.
* The registry maps existing configuration onto backends; it does not own
  configuration. The credential/endpoint *attribute names* an entry points at
  must already exist on ``Config`` (pinned by ``tests/test_provider_registry``).
  The Action inputs, CLI flags and ``Config`` fields are public contract and
  stay additive-only.
* Capability and label data is validated, never assumed
  (:func:`validate_spec`): an entry is configuration-adjacent data, and its
  display strings end up in pull-request comments.
* No billing- or latency-based routing exists. ``billing_class`` is descriptive
  metadata only; nothing here branches on it.
* A string ``factory`` can only name a module inside this package, so registry
  data can never cause an arbitrary import.
"""
from __future__ import annotations

import importlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterable

#: Name of the deterministic rule engine. It is a registry entry (so reports can
#: label it) but never an AI backend and never listed in ``provider_order``.
STATIC_BACKEND = "static"

# --------------------------------------------------------------------- tasks
TASK_REVIEW = "review"
TASK_SECURITY_REVIEW = "security-review"
TASK_TEST_REVIEW = "test-review"
TASK_ARCH_REVIEW = "arch-review"
TASK_SYNTHESIS = "synthesis"

#: Closed vocabulary a capability claim may draw from. Adding a task type is a
#: registry-data change here; an entry claiming anything else is rejected.
TASK_TYPES = (TASK_REVIEW, TASK_SECURITY_REVIEW, TASK_TEST_REVIEW,
              TASK_ARCH_REVIEW, TASK_SYNTHESIS)

# ------------------------------------------------------------ model policies
#: ``builtin_default`` — the entry ships a default model id and may run without
#: ``model``. ``explicit_required`` — no default: model ids turn over quickly
#: and a stale default would silently fail every review. ``not_applicable`` —
#: the engine has no model (the static rule engine).
MODEL_POLICY_BUILTIN = "builtin_default"
MODEL_POLICY_EXPLICIT = "explicit_required"
MODEL_POLICY_NONE = "not_applicable"
MODEL_POLICIES = (MODEL_POLICY_BUILTIN, MODEL_POLICY_EXPLICIT, MODEL_POLICY_NONE)

BILLING_METERED = "metered"
BILLING_UNMETERED = "unmetered"
BILLING_CLASSES = (BILLING_METERED, BILLING_UNMETERED)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
# Rendered into PR comment headers/footers: no markup, newlines or control
# characters can survive this pattern.
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FACTORY_RE = re.compile(r"^[a-z_][a-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")

#: Package every string ``factory`` is resolved against.
_PACKAGE = __name__.rpartition(".")[0] or "ai_pr_reviewer"


class RegistryError(ValueError):
    """A registry entry (or a registration) is invalid."""


class ProviderRoutingError(ValueError):
    """No configured backend can run the requested task. A configuration
    error: the CLI reports it and exits 1 rather than degrading silently."""


@dataclass(frozen=True)
class ProviderSpec:
    """Declarative description of one review backend.

    ``tasks`` is the capability claim; the remaining fields say how the backend
    is selected (``credential_field``, ``endpoint_field``, ``model_prefixes``,
    ``precedence``, ``default_backend``), constructed (``factory``,
    ``placeholder_key``, ``default_model``) and labelled (``display_name``,
    ``review_by_name``).
    """

    name: str
    display_name: str
    tasks: frozenset = frozenset()
    model_policy: str = MODEL_POLICY_EXPLICIT
    #: ``False`` only for the static rule engine.
    ai: bool = True
    #: ``"module:Class"`` inside this package, or a callable
    #: ``(**kwargs) -> provider``. ``None`` for the static engine.
    factory: Any = None
    #: ``Config`` attribute holding the API key, or ``None`` for a backend that
    #: needs none (it is then only reachable through ``provider_order``).
    credential_field: str | None = None
    #: ``Config`` attribute holding a custom endpoint URL. A set endpoint both
    #: selects this backend and stands in for a missing key (local endpoints).
    endpoint_field: str | None = None
    #: API key handed to the factory when the configured one is empty.
    placeholder_key: str = ""
    #: A configured ``model`` starting with any of these selects this backend.
    model_prefixes: tuple = ()
    default_model: str | None = None
    #: Evaluation order when several backends match one configuration; lower
    #: is evaluated first and suppresses the later ones.
    precedence: int = 100
    #: Selected on its own credential even when other backends' credentials are
    #: also present. At most one registered backend may set this.
    default_backend: bool = False
    #: Name used in "review by <name>"; defaults to ``display_name``.
    review_by_name: str = ""
    #: Not declared for the in-tree entries: it depends on the model, which the
    #: user chooses. ``None`` means unknown, never "unlimited".
    context_window_tokens: int | None = None
    billing_class: str = BILLING_METERED
    tool_support: bool = False

    def __post_init__(self) -> None:
        # Frozen dataclass: normalise the two collection fields in place so
        # callers may pass any iterable.
        object.__setattr__(self, "tasks", frozenset(self.tasks))
        object.__setattr__(self, "model_prefixes", tuple(self.model_prefixes))

    @property
    def review_label(self) -> str:
        return self.review_by_name or self.display_name

    def matches_model(self, model: str) -> bool:
        return bool(self.model_prefixes) and model.startswith(self.model_prefixes)


def _bad(spec_name: object, message: str) -> RegistryError:
    return RegistryError(f"provider registry entry {spec_name!r}: {message}")


def validate_spec(spec: ProviderSpec) -> None:
    """Raise :class:`RegistryError` unless ``spec`` is well formed.

    Capability claims and label strings are treated as untrusted
    configuration-adjacent data: every field is checked against a closed
    vocabulary or a restrictive pattern.
    """
    if not isinstance(spec, ProviderSpec):
        raise RegistryError(f"expected a ProviderSpec, got {type(spec).__name__}")
    name = spec.name
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise _bad(name, "name must match [a-z][a-z0-9_-]{0,31}")
    if not isinstance(spec.display_name, str) or not _LABEL_RE.match(spec.display_name):
        raise _bad(name, "display_name must be plain text (letters, digits, "
                         "space, '.', '_', '-'; at most 40 characters)")
    if spec.review_by_name and not _LABEL_RE.match(spec.review_by_name):
        raise _bad(name, "review_by_name must be plain text (same rules as display_name)")

    if not spec.tasks:
        raise _bad(name, "tasks must declare at least one task type")
    unknown = sorted(str(t) for t in spec.tasks if t not in TASK_TYPES)
    if unknown:
        raise _bad(name, f"unknown task type(s) {unknown}; known: {list(TASK_TYPES)}")

    if spec.model_policy not in MODEL_POLICIES:
        raise _bad(name, f"model_policy must be one of {list(MODEL_POLICIES)}")
    if spec.billing_class not in BILLING_CLASSES:
        raise _bad(name, f"billing_class must be one of {list(BILLING_CLASSES)}")
    if not isinstance(spec.tool_support, bool):
        raise _bad(name, "tool_support must be a bool")
    if not isinstance(spec.ai, bool) or not isinstance(spec.default_backend, bool):
        raise _bad(name, "ai and default_backend must be bools")
    window = spec.context_window_tokens
    if window is not None and (isinstance(window, bool) or not isinstance(window, int)
                               or window <= 0):
        raise _bad(name, "context_window_tokens must be a positive int or None")
    if (isinstance(spec.precedence, bool) or not isinstance(spec.precedence, int)
            or not 0 <= spec.precedence <= 1000):
        raise _bad(name, "precedence must be an int in 0..1000")

    for label, value in (("credential_field", spec.credential_field),
                         ("endpoint_field", spec.endpoint_field)):
        if value is not None and (not isinstance(value, str) or not _FIELD_RE.match(value)):
            raise _bad(name, f"{label} must be a plain attribute name or None")
    for prefix in spec.model_prefixes:
        if not isinstance(prefix, str) or not _PREFIX_RE.match(prefix):
            raise _bad(name, f"model_prefixes entry {prefix!r} is not a plain lowercase prefix")
    if not isinstance(spec.placeholder_key, str) or len(spec.placeholder_key) > 32:
        raise _bad(name, "placeholder_key must be a short string")

    default = spec.default_model
    if spec.model_policy == MODEL_POLICY_BUILTIN:
        if not isinstance(default, str) or not _MODEL_ID_RE.match(default):
            raise _bad(name, "model_policy 'builtin_default' needs a default_model id")
    elif default is not None:
        raise _bad(name, f"default_model must be None under model_policy "
                         f"{spec.model_policy!r}")

    if spec.ai:
        if spec.model_policy == MODEL_POLICY_NONE:
            raise _bad(name, "an AI backend needs a model policy other than 'not_applicable'")
        factory = spec.factory
        if isinstance(factory, str):
            if not _FACTORY_RE.match(factory):
                raise _bad(name, "factory must be 'module:Class' or a callable")
        elif not callable(factory):
            raise _bad(name, "an AI backend needs a factory")
    else:
        if spec.factory is not None or spec.credential_field or spec.endpoint_field:
            raise _bad(name, "a non-AI engine takes no factory, credential or endpoint")
        if spec.model_policy != MODEL_POLICY_NONE:
            raise _bad(name, "a non-AI engine must use model_policy 'not_applicable'")
        if spec.default_backend or spec.model_prefixes:
            raise _bad(name, "a non-AI engine is never selected by model or as the default")


# ------------------------------------------------------------ in-tree entries
# The three AI backends run the same shared prompt/parse pipeline, so they
# declare the same task set. ``synthesis`` is deliberately absent: it needs an
# output schema that does not exist yet, and a capability is declared when the
# consumer ships, not before. The scoped review tasks describe the existing
# pipeline run over a narrower scope; the specialist contracts that consume
# them confirm or narrow these claims.
_AI_TASKS = frozenset({TASK_REVIEW, TASK_SECURITY_REVIEW, TASK_TEST_REVIEW,
                       TASK_ARCH_REVIEW})
# The rule engine only has rules for the review and security scopes.
_STATIC_TASKS = frozenset({TASK_REVIEW, TASK_SECURITY_REVIEW})

# Registration order is the documented ``provider_order`` order and must not
# change: ``AI_BACKENDS`` has always been (claude, openai, gemini).
_BUILTIN_SPECS = (
    ProviderSpec(
        name="claude",
        display_name="Claude",
        tasks=_AI_TASKS,
        model_policy=MODEL_POLICY_BUILTIN,
        factory="ai.claude:ClaudeProvider",
        credential_field="anthropic_api_key",
        model_prefixes=("claude-",),
        default_model="claude-sonnet-4-6",
        precedence=20,
        default_backend=True,
    ),
    ProviderSpec(
        name="openai",
        display_name="OpenAI",
        tasks=_AI_TASKS,
        model_policy=MODEL_POLICY_EXPLICIT,
        factory="ai.openai:OpenAIProvider",
        credential_field="openai_api_key",
        endpoint_field="openai_base_url",
        placeholder_key="unused",
        model_prefixes=("gpt-", "o1", "o3", "o4"),
        precedence=0,
    ),
    ProviderSpec(
        name="gemini",
        display_name="Gemini",
        review_by_name="Google Gemini",
        tasks=_AI_TASKS,
        model_policy=MODEL_POLICY_EXPLICIT,
        factory="ai.gemini:GeminiProvider",
        credential_field="gemini_api_key",
        model_prefixes=("gemini-",),
        precedence=10,
    ),
    ProviderSpec(
        name=STATIC_BACKEND,
        display_name="Static Fallback",
        tasks=_STATIC_TASKS,
        model_policy=MODEL_POLICY_NONE,
        ai=False,
        billing_class=BILLING_UNMETERED,
    ),
)

_LOCK = threading.RLock()
_REGISTRY: dict[str, ProviderSpec] = {}
BUILTIN_BACKENDS = frozenset(spec.name for spec in _BUILTIN_SPECS)


def _check_default_backend_unique(spec: ProviderSpec,
                                  existing: Iterable[ProviderSpec]) -> None:
    if spec.default_backend:
        clash = [s.name for s in existing if s.default_backend and s.name != spec.name]
        if clash:
            raise _bad(spec.name, f"default_backend is already claimed by {clash[0]!r}")


def register(spec: ProviderSpec) -> ProviderSpec:
    """Add a validated entry. Built-in entries can never be shadowed or replaced,
    and a name may be registered only once."""
    validate_spec(spec)
    if spec.name in BUILTIN_BACKENDS:
        raise _bad(spec.name, "name is reserved by a built-in backend")
    with _LOCK:
        if spec.name in _REGISTRY:
            raise _bad(spec.name, "already registered")
        _check_default_backend_unique(spec, _REGISTRY.values())
        _REGISTRY[spec.name] = spec
    return spec


def unregister(name: str) -> None:
    """Remove a previously registered entry (tests, future adapter unload).
    Built-in entries cannot be removed."""
    if name in BUILTIN_BACKENDS:
        raise _bad(name, "built-in backends cannot be unregistered")
    with _LOCK:
        _REGISTRY.pop(name, None)


def get_spec(name: str) -> ProviderSpec | None:
    with _LOCK:
        return _REGISTRY.get(name)


def specs() -> tuple[ProviderSpec, ...]:
    """Every entry, in registration order (snapshot)."""
    with _LOCK:
        return tuple(_REGISTRY.values())


def ai_specs() -> tuple[ProviderSpec, ...]:
    return tuple(s for s in specs() if s.ai)


def ai_backend_names() -> tuple[str, ...]:
    """Names a ``provider_order`` may list, in registration order."""
    return tuple(s.name for s in ai_specs())


def supports(name: str, task: str) -> bool:
    spec = get_spec(name)
    return spec is not None and task in spec.tasks


def resolve_factory(spec: ProviderSpec) -> Callable[..., Any]:
    """The callable that builds ``spec``'s provider (lazy import)."""
    factory = spec.factory
    if callable(factory):
        return factory
    if not isinstance(factory, str):
        raise _bad(spec.name, "has no factory")
    module_name, _, attr = factory.partition(":")
    module = importlib.import_module(f"{_PACKAGE}.{module_name}")
    return getattr(module, attr)


# ------------------------------------------------------------ provider_order
_ORDER_SPLIT_RE = re.compile(r"[,\s]+")


def parse_order(raw: str | None) -> tuple[list[str], list[str]]:
    """Split a ``provider_order`` string into ``(names, unknown_tokens)``.

    Names are lower-cased, de-duplicated (first position wins) and limited to
    registered AI backends. ``static`` is dropped silently (it is the implicit
    final fallback); anything else unregistered is returned in ``unknown`` as
    written, so the caller can warn without ever failing the review.
    """
    known = set(ai_backend_names())
    names: list[str] = []
    unknown: list[str] = []
    for part in _ORDER_SPLIT_RE.split(raw or ""):
        name = part.strip().lower()
        if not name or name == STATIC_BACKEND:
            continue
        if name not in known:
            unknown.append(part)
        elif name not in names:
            names.append(name)
    return names, unknown


# ------------------------------------------------------------------ selection
def _present(cfg: Any, field: str | None) -> bool:
    return bool(field and getattr(cfg, field, ""))


def select_backend_name(cfg: Any) -> str:
    """Backend implied by credentials, endpoint and ``model`` — or ``static``.

    Reproduces the historical rule exactly, expressed as data: an explicit
    model prefix or a custom endpoint selects a backend; otherwise a backend is
    implied by its credential when no other backend's credential is set (the
    ``default_backend`` is implied whenever nothing evaluated before it
    matched). A matched backend is only returned if it is usable — it has a
    credential, or a custom endpoint stands in for one.
    """
    model = getattr(cfg, "model", "") or ""
    ordered = sorted(ai_specs(), key=lambda s: s.precedence)
    key = {s.name: _present(cfg, s.credential_field) for s in ordered}
    endpoint = {s.name: _present(cfg, s.endpoint_field) for s in ordered}

    matched: dict[str, bool] = {}
    for spec in ordered:
        earlier = any(matched[e.name] for e in ordered[:ordered.index(spec)])
        if spec.default_backend:
            implied = key[spec.name] and not earlier
        else:
            others = any(key[o.name] for o in ordered if o is not spec)
            implied = key[spec.name] and not others and not earlier
        matched[spec.name] = bool(spec.matches_model(model) or endpoint[spec.name]
                                  or implied)
    for spec in ordered:
        if matched[spec.name] and (key[spec.name] or endpoint[spec.name]):
            return spec.name
    return STATIC_BACKEND


def has_ai_credentials(cfg: Any) -> bool:
    """Is any AI backend configured at all?

    A credential or custom endpoint on any entry counts. A backend that needs
    neither (``credential_field`` and ``endpoint_field`` both ``None``) counts
    when ``provider_order`` names it explicitly.
    """
    for spec in ai_specs():
        if _present(cfg, spec.credential_field) or _present(cfg, spec.endpoint_field):
            return True
    listed, _ = parse_order(getattr(cfg, "provider_order", "") or "")
    for name in listed:
        spec = get_spec(name)
        if spec is not None and not spec.credential_field and not spec.endpoint_field:
            return True
    return False


# --------------------------------------------------------------------- labels
STATIC_FOOTER = "rule-based static analysis \u2014 not an AI review"
_BLEND_SUFFIX = "+static"


def engine_titles() -> dict[str, str]:
    """Report-header label per engine id, including ``<ai>+static`` blends."""
    out: dict[str, str] = {}
    for spec in ai_specs():
        out[spec.name] = spec.display_name
    static = get_spec(STATIC_BACKEND)
    out[STATIC_BACKEND] = static.display_name if static else "Static Fallback"
    for spec in ai_specs():
        out[spec.name + _BLEND_SUFFIX] = f"{spec.display_name} + Static Fallback"
    return out


def engine_footers() -> dict[str, str]:
    """Footer text per engine id. Static-only output is never labelled AI."""
    out: dict[str, str] = {}
    for spec in ai_specs():
        out[spec.name] = f"review by {spec.review_label} (AI)"
    out[STATIC_BACKEND] = STATIC_FOOTER
    for spec in ai_specs():
        out[spec.name + _BLEND_SUFFIX] = (
            f"review by {spec.review_label} (AI); batches {spec.display_name} "
            f"could not review were covered by rule-based static analysis (not AI)")
    return out


def _install_builtins() -> None:
    for spec in _BUILTIN_SPECS:
        validate_spec(spec)
        _check_default_backend_unique(spec, _REGISTRY.values())
        _REGISTRY[spec.name] = spec


_install_builtins()


__all__ = [
    "BILLING_CLASSES", "BILLING_METERED", "BILLING_UNMETERED", "BUILTIN_BACKENDS",
    "MODEL_POLICIES", "MODEL_POLICY_BUILTIN", "MODEL_POLICY_EXPLICIT",
    "MODEL_POLICY_NONE", "ProviderRoutingError", "ProviderSpec", "RegistryError", "STATIC_BACKEND",
    "TASK_ARCH_REVIEW", "TASK_REVIEW", "TASK_SECURITY_REVIEW", "TASK_SYNTHESIS",
    "STATIC_FOOTER", "TASK_TEST_REVIEW", "TASK_TYPES", "ai_backend_names",
    "ai_specs", "engine_footers", "engine_titles", "get_spec",
    "has_ai_credentials", "parse_order", "register", "resolve_factory",
    "select_backend_name", "specs", "supports", "unregister", "validate_spec",
]

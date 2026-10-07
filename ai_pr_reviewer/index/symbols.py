"""V4-E01-T02 — symbol-lite extraction.

Regex-only, line-oriented extraction of *definitions and imports* from
indexed source files: functions, classes, types and import specs, per
language family. Explicitly **not** a parser — no ASTs, no execution, no
model calls (hard rule 2); the result is bounded by
``limits.max_symbols_per_file`` / ``limits.max_imports_per_file`` and
best-effort by design. Unrecognized languages (``unknown``) and
config/data formats yield no symbols — the file still sits in the
inventory with its format tag, so "no symbols here, by design" is
distinguishable downstream from "extraction failed".
"""
from __future__ import annotations

import re

from .limits import IndexLimits

# ------------------------------------------------------------- patterns

# Python
_PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)")
_PY_CLASS = re.compile(r"^\s*class\s+([A-Za-z_]\w*)")
_PY_FROM = re.compile(r"^\s*from\s+([.\w][\w.]*)\s+import\b")
_PY_IMPORT = re.compile(r"^\s*import\s+([.\w][\w.]*)")

# JavaScript / TypeScript
_JS_FUNC = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*"
    r"([A-Za-z_$][\w$]*)")
_JS_CLASS = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+"
    r"([A-Za-z_$][\w$]*)")
_JS_CONST_FUNC = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>")
_JS_CONST_FUNCTION = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s+)?function\b")
_JS_IMPORT = re.compile(
    r"""^\s*import\s+(?:[\w${},*\s]+\s+from\s+)?['"]([^'"]+)['"]""")
_JS_EXPORT_FROM = re.compile(r"""^\s*export\s+[^'"]*from\s+['"]([^'"]+)['"]""")
_JS_REQUIRE = re.compile(r"""^\s*.*\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)""")

# Java / Kotlin / C# (class-shaped languages)
_JAVA_TYPE = re.compile(
    r"^\s*(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+|"
    r"static\s+)*(?:class|interface|enum|record)\s+([A-Za-z_]\w*)")
_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+?)(?:\.\*)?\s*;")

# C / C++
_C_TYPE = re.compile(r"^\s*(?:class|struct|enum|namespace)\s+([A-Za-z_]\w*)")
_C_INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"')

# Go
_GO_FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)")
_GO_TYPE = re.compile(r"^type\s+([A-Za-z_]\w*)\s+(?:struct|interface)")
_GO_IMPORT = re.compile(r'^\s*import\s+(?:\(\s*)?"([^"]+)"')

# Rust
_RS_FN = re.compile(
    r"^\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?"
    r"fn\s+([A-Za-z_]\w*)")
_RS_TYPE = re.compile(r"^\s*(?:pub\s+)?(?:struct|enum|trait)\s+([A-Za-z_]\w*)")
_RS_USE = re.compile(r"^\s*use\s+([\w:]+)")

# Ruby
_RB_DEF = re.compile(r"^\s*def\s+(\w+[?!]?)")
_RB_CLASS = re.compile(r"^\s*(?:class|module)\s+([\w:]+)")

# PHP
_PHP_FUNC = re.compile(
    r"^\s*(?:public\s+|private\s+|protected\s+|static\s+|final\s+)*"
    r"(?:function)\s+&?(\w+)")
_PHP_CLASS = re.compile(
    r"^\s*(?:abstract\s+|final\s+)*(?:class|interface|trait)\s+(\w+)")

# Shell
_SH_FUNC = re.compile(r"^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{")


def _rules(*pairs):
    return tuple(pairs)


# language → ((kind, pattern), ...) for definitions
_SYMBOL_RULES = {
    "python": _rules(("function", _PY_DEF), ("class", _PY_CLASS)),
    "javascript": _rules(("function", _JS_FUNC), ("class", _JS_CLASS),
                         ("function", _JS_CONST_FUNC),
                         ("function", _JS_CONST_FUNCTION)),
    "typescript": _rules(("function", _JS_FUNC), ("class", _JS_CLASS),
                         ("function", _JS_CONST_FUNC),
                         ("function", _JS_CONST_FUNCTION)),
    "java": _rules(("class", _JAVA_TYPE)),
    "kotlin": _rules(("class", _JAVA_TYPE)),
    "csharp": _rules(("class", _JAVA_TYPE)),
    "c": _rules(("type", _C_TYPE)),
    "cpp": _rules(("type", _C_TYPE)),
    "go": _rules(("function", _GO_FUNC), ("type", _GO_TYPE)),
    "rust": _rules(("function", _RS_FN), ("type", _RS_TYPE)),
    "ruby": _rules(("function", _RB_DEF), ("class", _RB_CLASS)),
    "php": _rules(("function", _PHP_FUNC), ("class", _PHP_CLASS)),
    "shell": _rules(("function", _SH_FUNC)),
}

# language → (pattern, ...) for import specs (raw specifiers; the graph
# module resolves them against the inventory)
_IMPORT_RULES = {
    "python": (_PY_FROM, _PY_IMPORT),
    "javascript": (_JS_IMPORT, _JS_EXPORT_FROM, _JS_REQUIRE),
    "typescript": (_JS_IMPORT, _JS_EXPORT_FROM, _JS_REQUIRE),
    "java": (_JAVA_IMPORT,),
    "kotlin": (_JAVA_IMPORT,),
    "csharp": (_JAVA_IMPORT,),
    "c": (_C_INCLUDE,),
    "cpp": (_C_INCLUDE,),
    "go": (_GO_IMPORT,),
    "rust": (_RS_USE,),
}


def extract_symbols(relpath: str, language: str, text: str,
                    limits: IndexLimits) -> tuple[list[tuple[str, str, int]],
                                                  list[str], bool]:
    """Extract ``(kind, name, line)`` symbols and raw import specs.

    Returns ``(symbols, imports, truncated)``: ``truncated`` is True when
    a per-file cap stopped extraction (recorded on the file entry, not as
    a run warning — one giant generated file is data, not an event).
    Bounded and deterministic: caps come from ``limits``, ordering is
    line order, duplicates are dropped first-occurrence-wins.
    """
    symbol_rules = _SYMBOL_RULES.get(language, ())
    import_rules = _IMPORT_RULES.get(language, ())
    if not symbol_rules and not import_rules:
        return [], [], False   # config/data/unknown formats: no symbols, by design
    symbols: list[tuple[str, str, int]] = []
    imports: list[str] = []
    seen_symbols: set[tuple[str, str]] = set()
    seen_imports: set[str] = set()
    symbols_full = imports_full = False
    truncated = False

    for lineno, line in enumerate(text.splitlines(), 1):
        if symbols_full and imports_full:
            truncated = True
            break
        if not symbols_full:
            for kind, pattern in symbol_rules:
                m = pattern.match(line)
                if m:
                    key = (kind, m.group(1))
                    if key in seen_symbols:
                        continue
                    if len(symbols) >= limits.max_symbols_per_file:
                        symbols_full = True
                        truncated = True
                        break
                    seen_symbols.add(key)
                    symbols.append((kind, m.group(1), lineno))
        if not imports_full and import_rules:
            for pattern in import_rules:
                m = pattern.match(line)
                if m:
                    spec = m.group(1)
                    if spec and spec not in seen_imports:
                        if len(imports) >= limits.max_imports_per_file:
                            imports_full = True
                            truncated = True
                            break
                        seen_imports.add(spec)
                        imports.append(spec)
    return symbols, imports, truncated

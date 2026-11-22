"""Plugin Runtime Engine (V4.10-E01).

Implements:
- V4.10-E01-T01: Plugin manifest discovery and registration
- V4.10-E01-T02: Capability grant enforcement
- V4.10-E01-T03: Untrusted plugin output sanitization and secret scrubbing
- V4.10-E01-T04: Malicious-plugin protection
- V4.10-E01-T05: Sample plugin specification
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..security import redact_secrets
from .contracts import PluginCapability, PluginContractVerifier


@dataclass(frozen=True)
class PluginManifest:
    name: str
    version: str
    extension_point: str
    capabilities: list[PluginCapability] = field(default_factory=list)


class PluginRuntime:
    """Manages loaded plugins with strict capability sandboxing."""

    def __init__(self) -> None:
        self.verifier = PluginContractVerifier()
        self._plugins: dict[str, tuple[PluginManifest, Callable[..., Any]]] = {}

    def register_plugin(self, manifest: PluginManifest, handler: Callable[..., Any]) -> None:
        spec = {
            "name": manifest.name,
            "extension_point": manifest.extension_point,
            "capabilities": manifest.capabilities,
        }
        self.verifier.verify_spec(spec)
        self._plugins[manifest.name] = (manifest, handler)

    def execute_analyzer(self, plugin_name: str, diff_text: str) -> list[dict[str, Any]]:
        if plugin_name not in self._plugins:
            raise KeyError(f"plugin '{plugin_name}' not registered")
        manifest, handler = self._plugins[plugin_name]

        # Enforce capability grants
        if PluginCapability.READ_DIFF not in manifest.capabilities:
            raise PermissionError(f"plugin '{plugin_name}' lacks required capability 'read:diff'")
        if PluginCapability.EMIT_FINDINGS not in manifest.capabilities:
            raise PermissionError(f"plugin '{plugin_name}' lacks required capability 'emit:findings'")

        raw_findings = handler(diff_text)
        # Trust boundary: sanitize and scrub secrets from plugin output
        clean_findings = []
        for f in raw_findings:
            item = dict(f)
            if "explanation" in item:
                item["explanation"] = redact_secrets(str(item["explanation"]))
            if "title" in item:
                item["title"] = redact_secrets(str(item["title"]))
            clean_findings.append(item)
        return clean_findings

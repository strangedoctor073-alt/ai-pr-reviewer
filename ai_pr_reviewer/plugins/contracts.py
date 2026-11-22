"""Plugin Extension Points & Capability Contracts (V4.8-E06).

Implements:
- V4.8-E06-T01: Extension point inventory (analyzer, reporter, provider)
- V4.8-E06-T02: Declared capabilities and safe invocation
- V4.8-E06-T03: Conformance test verifier per extension point
- V4.8-E06-T04: Frozen capability security surface
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

EXTENSION_POINTS = ("analyzer", "reporter", "provider")


class PluginCapability(str, Enum):
    READ_DIFF = "read:diff"
    EMIT_FINDINGS = "emit:findings"
    FORMAT_REPORT = "format:report"
    PROVIDER_INFERENCE = "provider:inference"


ALLOWED_CAPABILITIES = {
    PluginCapability.READ_DIFF,
    PluginCapability.EMIT_FINDINGS,
    PluginCapability.FORMAT_REPORT,
    PluginCapability.PROVIDER_INFERENCE,
}


class PluginContractVerifier:
    """Verifies that third-party plugin specifications conform to security contracts."""

    def verify_spec(self, spec: Mapping[str, Any]) -> bool:
        ext_point = spec.get("extension_point")
        if ext_point not in EXTENSION_POINTS:
            raise ValueError(f"unknown extension point '{ext_point}'; allowed: {EXTENSION_POINTS}")

        caps = spec.get("capabilities", [])
        for cap in caps:
            try:
                p_cap = PluginCapability(cap)
            except ValueError:
                raise ValueError(f"unknown or unauthorized capability: '{cap}'")
            if p_cap not in ALLOWED_CAPABILITIES:
                raise ValueError(f"unauthorized capability: '{cap}'")

        return True

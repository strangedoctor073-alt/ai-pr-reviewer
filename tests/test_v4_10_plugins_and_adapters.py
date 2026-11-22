"""Tests for V4.10: Plugin Runtime, Provider Adapters, and Versioned Client.

Coverage:
- V4.10-E01 (T01-T05): Plugin System Runtime, capability grants, output trust handling
- V4.10-E02 (T01-T04): Provider Capability Ecosystem and Adapter SDK
- V4.10-E04-T04: Versioned API Client for CLI/IDE
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer.ai.adapter import BaseProviderAdapter, ProviderAdapterSDK
from ai_pr_reviewer.api_client import VersionedApiClient
from ai_pr_reviewer.plugins.contracts import PluginCapability
from ai_pr_reviewer.plugins.runtime import PluginManifest, PluginRuntime


def test_plugin_runtime_and_capability_grants():
    """V4.10-E01: Plugin loading, capability enforcement, and output sanitization."""
    runtime = PluginRuntime()

    # Sample valid plugin
    manifest = PluginManifest(
        name="style-checker",
        version="1.0.0",
        extension_point="analyzer",
        capabilities=[PluginCapability.READ_DIFF, PluginCapability.EMIT_FINDINGS],
    )

    def dummy_analyzer(diff_text: str) -> list[dict]:
        return [{"file": "main.py", "line": 1, "title": "Style issue", "explanation": "secret=ghp_12345678901234567890"}]

    runtime.register_plugin(manifest, handler=dummy_analyzer)
    findings = runtime.execute_analyzer("style-checker", diff_text="some diff")
    assert len(findings) == 1
    # Secret in output must be redacted
    assert "ghp_12345678901234567890" not in findings[0]["explanation"]
    assert "[REDACTED" in findings[0]["explanation"]

    # Malicious plugin attempting ungranted capability
    hostile_manifest = PluginManifest(
        name="hostile-plugin",
        version="1.0.0",
        extension_point="analyzer",
        capabilities=[PluginCapability.FORMAT_REPORT],  # lacks EMIT_FINDINGS
    )
    runtime.register_plugin(hostile_manifest, handler=dummy_analyzer)
    with pytest.raises(PermissionError, match="lacks required capability"):
        runtime.execute_analyzer("hostile-plugin", diff_text="some diff")


def test_provider_adapter_sdk_and_conformance():
    """V4.10-E02: Provider adapter SDK and conformance contract."""
    sdk = ProviderAdapterSDK()

    class CustomModelAdapter(BaseProviderAdapter):
        def complete(self, prompt: str) -> dict:
            return {"text": "{}", "usage": {"input_tokens": 10, "output_tokens": 5}}

    adapter = CustomModelAdapter(name="custom-model")
    sdk.register_adapter("custom-model", adapter)

    res = sdk.invoke("custom-model", "test prompt")
    assert res["text"] == "{}"
    assert res["usage"]["input_tokens"] == 10


def test_versioned_api_client():
    """V4.10-E04-T04: Versioned client interfacing over /v1 API routes."""
    client = VersionedApiClient(base_url="http://localhost:8000")
    assert client.get_health_endpoint() == "/v1/health"
    assert client.get_query_endpoint() == "/v1/reviews/query"

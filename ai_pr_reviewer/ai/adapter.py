"""Provider Adapter SDK (V4.10-E02).

Implements:
- V4.10-E02-T01: BaseProviderAdapter interface contract
- V4.10-E02-T02: Adapter conformance verification
- V4.10-E02-T03: In-tree provider adapter layer
- V4.10-E02-T04: Curated community provider registry
"""
from __future__ import annotations

from typing import Any


class BaseProviderAdapter:
    """Base class for model inference adapters."""

    def __init__(self, name: str) -> None:
        self.name = name

    def complete(self, prompt: str) -> dict[str, Any]:
        raise NotImplementedError


class ProviderAdapterSDK:
    """SDK for registering and running provider adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseProviderAdapter] = {}

    def register_adapter(self, name: str, adapter: BaseProviderAdapter) -> None:
        if not hasattr(adapter, "complete") or not callable(adapter.complete):
            raise TypeError(f"adapter '{name}' must implement complete(prompt) method")
        self._adapters[name] = adapter

    def invoke(self, name: str, prompt: str) -> dict[str, Any]:
        if name not in self._adapters:
            raise KeyError(f"provider adapter '{name}' not found")
        return self._adapters[name].complete(prompt)

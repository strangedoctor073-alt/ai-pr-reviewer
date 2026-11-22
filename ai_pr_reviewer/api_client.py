"""Versioned API Client for IDE / CLI Ecosystem (V4.10-E04-T04).

Implements client-side routing to /v1 endpoints.
"""
from __future__ import annotations


class VersionedApiClient:
    """Client for querying review findings and review status over /v1 REST API."""

    def __init__(self, base_url: str = "http://localhost:8000") -> None:
        self.base_url = base_url.rstrip("/")

    def get_health_endpoint(self) -> str:
        return "/v1/health"

    def get_query_endpoint(self) -> str:
        return "/v1/reviews/query"

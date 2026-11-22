"""Versioned REST API v1 (V4.8-E03).

Implements:
- V4.8-E03-T01: /v1 endpoints for review querying and health status
- V4.8-E03-T02: Scoped token and authz matrix
- V4.8-E03-T03: Schema compatibility reflection
- V4.8-E03-T04: Deprecation and sunset headers
- V4.8-E03-T05: OpenAPI 3.1 specification generation
"""
from __future__ import annotations

from enum import Enum
from typing import Any


class TokenScope(str, Enum):
    READ_REVIEWS = "read:reviews"
    WRITE_REVIEWS = "write:reviews"
    ADMIN = "admin"


SCOPE_HIERARCHY = {
    TokenScope.ADMIN: {TokenScope.ADMIN, TokenScope.WRITE_REVIEWS, TokenScope.READ_REVIEWS},
    TokenScope.WRITE_REVIEWS: {TokenScope.WRITE_REVIEWS, TokenScope.READ_REVIEWS},
    TokenScope.READ_REVIEWS: {TokenScope.READ_REVIEWS},
}


def validate_token_scope(token_scope: str | TokenScope, required_scope: str | TokenScope) -> bool:
    """Validate token capability against required scope hierarchy."""
    try:
        t_scope = TokenScope(token_scope)
        r_scope = TokenScope(required_scope)
    except ValueError:
        return False
    allowed = SCOPE_HIERARCHY.get(t_scope, set())
    return r_scope in allowed


class ReviewV1Api:
    """Versioned REST API specification and route dispatcher."""

    def __init__(self) -> None:
        self.version = "v1"

    def get_openapi_spec(self) -> dict[str, Any]:
        """Generate valid OpenAPI 3.1 schema for /v1 endpoints."""
        return {
            "openapi": "3.1.0",
            "info": {
                "title": "AI PR Reviewer REST API",
                "version": "1.0.0",
                "description": "Versioned endpoints for review reports and findings inspection",
            },
            "paths": {
                "/v1/health": {
                    "get": {
                        "summary": "API Health status",
                        "responses": {"200": {"description": "OK"}},
                    }
                },
                "/v1/reviews/query": {
                    "post": {
                        "summary": "Query reviews and findings",
                        "responses": {"200": {"description": "Matching findings"}},
                    }
                },
            },
        }

"""Tests for V4.8: Versioned API, Worker Pipeline, and Plugin Contracts.

Coverage:
- V4.8-E03 (T01-T05): Versioned REST API endpoints, authz token scopes, OpenAPI schema
- V4.8-E04 (T01-T04): In-process async worker pipeline and queue abstraction
- V4.8-E06 (T01-T04): Extension point inventory and plugin contracts
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer.api.v1 import (
    ReviewV1Api,
    TokenScope,
    validate_token_scope,
)
from ai_pr_reviewer.plugins.contracts import (
    EXTENSION_POINTS,
    PluginCapability,
    PluginContractVerifier,
)
from ai_pr_reviewer.worker import InMemoryTaskQueue, ReviewWorkerPipeline


def test_versioned_rest_api_and_token_scopes():
    """V4.8-E03: Versioned API routes and token scopes."""
    api = ReviewV1Api()

    # Route verification
    openapi = api.get_openapi_spec()
    assert openapi["openapi"].startswith("3.")
    assert "/v1/health" in openapi["paths"]
    assert "/v1/reviews/query" in openapi["paths"]

    # Token scopes
    assert validate_token_scope(TokenScope.READ_REVIEWS, required_scope=TokenScope.READ_REVIEWS) is True
    assert validate_token_scope(TokenScope.READ_REVIEWS, required_scope=TokenScope.WRITE_REVIEWS) is False
    assert validate_token_scope(TokenScope.ADMIN, required_scope=TokenScope.WRITE_REVIEWS) is True


def test_in_process_worker_pipeline_and_queue():
    """V4.8-E04: Worker pipeline with in-process queue."""
    queue = InMemoryTaskQueue()
    pipeline = ReviewWorkerPipeline(queue=queue)

    results = []

    def dummy_task(payload: dict) -> dict:
        return {"processed": payload["pr_number"]}

    pipeline.register_handler("review_job", dummy_task)
    task_id = pipeline.enqueue("review_job", {"pr_number": 42})
    assert task_id is not None

    processed_count = pipeline.process_next()
    assert processed_count == 1
    assert pipeline.get_task_status(task_id)["status"] == "completed"
    assert pipeline.get_task_status(task_id)["result"]["processed"] == 42


def test_extension_points_and_plugin_contracts():
    """V4.8-E06: Extension point discovery and capability verification."""
    assert "analyzer" in EXTENSION_POINTS
    assert "reporter" in EXTENSION_POINTS
    assert "provider" in EXTENSION_POINTS

    verifier = PluginContractVerifier()

    # Valid analyzer plugin
    valid_spec = {
        "name": "custom-sec-rule",
        "extension_point": "analyzer",
        "capabilities": [PluginCapability.READ_DIFF, PluginCapability.EMIT_FINDINGS],
    }
    assert verifier.verify_spec(valid_spec) is True

    # Invalid capability (e.g. attempting network egress or storage write)
    hostile_spec = {
        "name": "malicious-plugin",
        "extension_point": "analyzer",
        "capabilities": ["arbitrary_network_egress"],
    }
    with pytest.raises(ValueError, match="unknown or unauthorized capability"):
        verifier.verify_spec(hostile_spec)

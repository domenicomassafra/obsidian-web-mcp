"""Per-token read/write rate-limit regression tests."""

import json
import hashlib

from obsidian_vault_mcp import config, context, rate_limit, server
from obsidian_vault_mcp.models import VaultMutationContextInput


def setup_function():
    rate_limit._reset_for_tests()


def teardown_function():
    rate_limit._reset_for_tests()


def _mutation(path):
    return VaultMutationContextInput.model_validate({
        "preflight": {
            "source_input_class": "test-fixture", "entity_area": "01-input/capture",
            "capability": "capture", "canonical_destination": path,
            "candidate_destinations": [path], "file_kind": "atomic-note",
            "operation": "create", "confidence": 0.99, "reason": "rate-limit fixture",
            "preimage_requirement": "absent", "rollback_target": f"delete-if-postimage:{path}",
        }
    })


def test_internal_calls_without_principal_are_not_limited(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_READ", 1)
    assert rate_limit.check_tool_rate_limit("vault_read", now=1.0) is None
    assert rate_limit.check_tool_rate_limit("vault_read", now=1.0) is None


def test_read_limit_is_per_authenticated_token(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_READ", 1)
    first = context.set_request_context(principal="token-a", request_id=None, client=None)
    try:
        assert rate_limit.check_tool_rate_limit("vault_read", now=1.0) is None
        assert rate_limit.check_tool_rate_limit("vault_read", now=1.0) == 60
    finally:
        context.reset_request_context(first)

    second = context.set_request_context(principal="token-b", request_id=None, client=None)
    try:
        assert rate_limit.check_tool_rate_limit("vault_read", now=1.0) is None
    finally:
        context.reset_request_context(second)


def test_read_and_write_buckets_are_independent(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_READ", 1)
    monkeypatch.setattr(config, "RATE_LIMIT_WRITE", 1)
    token = context.set_request_context(principal="token-a", request_id=None, client=None)
    try:
        assert rate_limit.check_tool_rate_limit("vault_read", now=1.0) is None
        assert rate_limit.check_tool_rate_limit("vault_write", now=1.0) is None
        assert rate_limit.check_tool_rate_limit("vault_read", now=1.0) == 60
        assert rate_limit.check_tool_rate_limit("vault_write", now=1.0) == 60
    finally:
        context.reset_request_context(token)


def test_server_rejects_over_limit_without_mutating(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_WRITE", 1)
    token = context.set_request_context(principal="token-a", request_id=None, client=None)
    try:
        first_path = "01-input/capture/first.md"
        second_path = "01-input/capture/second.md"
        first = json.loads(server.vault_write(first_path, "first", _mutation(first_path)))
        blocked = json.loads(server.vault_write(second_path, "second", _mutation(second_path)))
    finally:
        context.reset_request_context(token)

    assert first["created"] is True
    assert blocked["error"] == "Rate limit exceeded"
    assert blocked["retry_after_seconds"] >= 1
    assert not (vault_dir / second_path).exists()

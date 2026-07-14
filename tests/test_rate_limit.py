"""Per-token read/write rate-limit regression tests."""

import json

from obsidian_vault_mcp import config, context, rate_limit, server


def setup_function():
    rate_limit._reset_for_tests()


def teardown_function():
    rate_limit._reset_for_tests()


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
        first = json.loads(server.vault_write("first.md", "first"))
        blocked = json.loads(server.vault_write("second.md", "second"))
    finally:
        context.reset_request_context(token)

    assert first["created"] is True
    assert blocked["error"] == "Rate limit exceeded"
    assert blocked["retry_after_seconds"] >= 1
    assert not (vault_dir / "second.md").exists()

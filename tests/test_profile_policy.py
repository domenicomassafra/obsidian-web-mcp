"""Server-enforced policy for the owner-controlled Signor Studio profile."""

from __future__ import annotations

import json

from obsidian_vault_mcp import context, server
from obsidian_vault_mcp.models import FrontmatterUpdateInput


def _as_signor_studio():
    return context.set_request_context(
        principal="test-token",
        request_id="request-1",
        client="pytest",
        profile="signorstudio",
    )


def _assert_denied(result: str) -> dict:
    payload = json.loads(result)
    assert payload["error"] == "profile_policy_denied"
    assert payload["profile"] == "signorstudio"
    assert payload["forbidden_root"] == "06-life"
    assert payload["write_executed"] is False
    return payload


def test_signor_studio_allows_learning_reads_and_writes(monkeypatch):
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(
        server,
        "_learning_get_today",
        lambda *_args: json.dumps({"status": "pass", "due": []}),
    )
    monkeypatch.setattr(
        server,
        "_learning_set_intent",
        lambda *args: calls.append(("intent", args)) or json.dumps(
            {"status": "applied", "event_id": "intent-1"}
        ),
    )

    token = _as_signor_studio()
    try:
        today = json.loads(server.learning_get_today())
        intent = json.loads(server.learning_set_intent(
            "knowledge-coding",
            "study",
            "Owner chose it",
            "attempt-1",
            "hermes",
        ))
    finally:
        context.reset_request_context(token)

    assert today["status"] == "pass"
    assert intent["status"] == "applied"
    assert calls and calls[0][0] == "intent"


def test_signor_studio_denies_direct_read_and_generic_write(vault_dir):
    knowledge = vault_dir / "05-knowledge"
    knowledge.mkdir()
    allowed = knowledge / "allowed.md"
    allowed.write_text("allowed body", encoding="utf-8")
    life = vault_dir / "06-life"
    life.mkdir()
    private = life / "private.md"
    private.write_text("private body", encoding="utf-8")

    token = _as_signor_studio()
    try:
        allowed_read = json.loads(server.vault_read(
            "05-knowledge/allowed.md"
        ))
        read = _assert_denied(server.vault_read("06-life/private.md"))
        write = _assert_denied(server.vault_write_binary(
            "06-life/private.png",
            "iVBORw0KGgo=",
            "image/png",
        ))
    finally:
        context.reset_request_context(token)

    assert read["operation"] == "vault_read"
    assert write["operation"] == "vault_write_binary"
    assert allowed_read["content"] == "allowed body"
    assert private.read_text(encoding="utf-8") == "private body"
    assert not (life / "private.png").exists()


def test_signor_studio_denies_batch_read_and_batch_write(vault_dir):
    knowledge = vault_dir / "05-knowledge"
    knowledge.mkdir()
    allowed = knowledge / "allowed.md"
    allowed.write_text("---\nstatus: draft\n---\nAllowed", encoding="utf-8")
    life = vault_dir / "06-life"
    life.mkdir()
    private = life / "private.md"
    private.write_text("---\nstatus: private\n---\nPrivate", encoding="utf-8")

    token = _as_signor_studio()
    try:
        batch_read = _assert_denied(server.vault_batch_read([
            "05-knowledge/allowed.md",
            "06-life/private.md",
        ]))
        batch_write = _assert_denied(server.vault_batch_frontmatter_update([
            FrontmatterUpdateInput(
                path="06-life/private.md",
                fields={"status": "changed"},
            ),
        ]))
    finally:
        context.reset_request_context(token)

    assert batch_read["operation"] == "vault_batch_read"
    assert batch_write["operation"] == "vault_batch_frontmatter_update"
    assert "status: private" in private.read_text(encoding="utf-8")


def test_signor_studio_denies_traversal_and_symlink_aliases(vault_dir):
    life = vault_dir / "06-life"
    life.mkdir()
    private = life / "private.md"
    private.write_text("private body", encoding="utf-8")
    knowledge = vault_dir / "05-knowledge"
    knowledge.mkdir()
    (knowledge / "life-alias.md").symlink_to(private)

    token = _as_signor_studio()
    try:
        traversal = _assert_denied(
            server.vault_read("05-knowledge/../06-life/private.md")
        )
        alias = _assert_denied(server.vault_read(
            "05-knowledge/life-alias.md"
        ))
        encoded = _assert_denied(server.vault_read(
            "06%2dlife/private.md"
        ))
    finally:
        context.reset_request_context(token)

    assert traversal["operation"] == "vault_read"
    assert alias["operation"] == "vault_read"
    assert encoded["operation"] == "vault_read"


def test_signor_studio_requires_explicit_safe_scope_for_search_and_list(
    vault_dir,
):
    knowledge = vault_dir / "05-knowledge"
    knowledge.mkdir()
    (knowledge / "allowed.md").write_text("bounded needle", encoding="utf-8")

    token = _as_signor_studio()
    try:
        _assert_denied(server.vault_search("needle"))
        _assert_denied(server.vault_list())
        scoped = json.loads(server.vault_search(
            "needle",
            path_prefix="05-knowledge",
        ))
    finally:
        context.reset_request_context(token)

    assert scoped["total_matches"] == 1
    assert scoped["results"][0]["path"] == "05-knowledge/allowed.md"


def test_signor_studio_denies_context_routes_that_select_life(vault_dir):
    life = vault_dir / "06-life"
    life.mkdir()
    (life / "index.md").write_text("# Life", encoding="utf-8")
    (life / "health.md").write_text("private health", encoding="utf-8")

    token = _as_signor_studio()
    try:
        route = _assert_denied(server.vault_context_route(
            "Come va la mia salute?"
        ))
        read = _assert_denied(server.vault_context_read(
            "Come va la mia salute?"
        ))
    finally:
        context.reset_request_context(token)

    assert route["operation"] == "vault_context_route"
    assert read["operation"] == "vault_context_read"

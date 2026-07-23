"""Fail-closed semantic write routing at the public MCP mutation boundary."""

import hashlib
import json

from obsidian_vault_mcp import audit, config, context, server
from obsidian_vault_mcp.models import VaultMutationContextInput


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _mutation(
    *,
    path: str,
    entity_area: str,
    capability: str,
    file_kind: str,
    operation: str,
    preimage: str,
    rollback: str,
    candidates: list[str] | None = None,
    source_input_class: str = "owner-capture",
    provenance: str | None = None,
) -> VaultMutationContextInput:
    return VaultMutationContextInput.model_validate({
        "reason": "Owner-requested canonical capture",
        "destination": path,
        "preflight": {
            "source_input_class": source_input_class,
            "entity_area": entity_area,
            "capability": capability,
            "canonical_destination": path,
            "candidate_destinations": candidates or [path],
            "file_kind": file_kind,
            "operation": operation,
            "confidence": 0.96,
            "reason": "Entity, owner, capability and local contract resolved",
            "preimage_requirement": preimage,
            "rollback_target": rollback,
            "provenance": provenance,
        },
    })


def _payload(raw: str) -> dict:
    return json.loads(raw)


def _assert_blocked(raw: str) -> dict:
    payload = _payload(raw)
    assert payload["error"] == "write_preflight_blocked"
    assert payload["write_executed"] is False
    assert payload["write_preflight_receipt"]["status"] == "blocked"
    return payload


def test_quick_seed_appends_to_existing_area_register(vault_dir):
    path = "04-areas/creator-spagnolo/content/ideas/README.md"
    initial = "# Ideas\n"
    target = vault_dir / path
    target.parent.mkdir(parents=True)
    target.write_text(initial, encoding="utf-8")
    mutation = _mutation(
        path=path,
        entity_area="04-areas/creator-spagnolo",
        capability="content",
        file_kind="quick-seed-register",
        operation="append",
        preimage=f"sha256:{_sha(initial)}",
        rollback=f"restore-preimage:{path}",
    )

    result = _payload(server.vault_append(path, "- Microfono assurdo", mutation))

    assert result["changed"] is True
    assert result["mutation_receipt"]["write_preflight"]["file_kind"] == "quick-seed-register"
    assert target.read_text(encoding="utf-8").endswith("- Microfono assurdo")


def test_full_brief_creates_atomic_note_and_receipt_can_roll_back(vault_dir, tmp_path, monkeypatch):
    path = "04-areas/creator-spagnolo/content/ideas/escalacion-de-microfono.md"
    content = "# Brief\n\n## Storyboard\n\nProduzione, ricerca e review cycle.\n"
    receipt_log = tmp_path / "audit" / "mutations.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(receipt_log))
    token = context.set_request_context(principal="test", request_id="preflight", client="pytest")
    try:
        mutation = _mutation(
            path=path,
            entity_area="04-areas/creator-spagnolo",
            capability="content",
            file_kind="atomic-note",
            operation="create",
            preimage="absent",
            rollback=f"delete-if-postimage:{path}",
            source_input_class="content-brief",
        )
        result = _payload(server.vault_write(path, content, mutation))
        mutation_id = result["mutation_receipt"]["mutation_id"]
        assert (vault_dir / path).read_text(encoding="utf-8") == content.rstrip()
        assert result["mutation_receipt"]["write_preflight"]["operation"] == "create"

        rolled_back = audit.rollback_mutation(mutation_id, confirm=True)
        assert rolled_back["status"] == "rollback_applied"
        assert not (vault_dir / path).exists()
    finally:
        context.reset_request_context(token)


def test_atomic_brief_is_rejected_from_readme(vault_dir):
    path = "04-areas/creator-spagnolo/content/ideas/README.md"
    initial = "# Ideas\n"
    target = vault_dir / path
    target.parent.mkdir(parents=True)
    target.write_text(initial, encoding="utf-8")
    mutation = _mutation(
        path=path,
        entity_area="04-areas/creator-spagnolo",
        capability="content",
        file_kind="quick-seed-register",
        operation="append",
        preimage=f"sha256:{_sha(initial)}",
        rollback=f"restore-preimage:{path}",
        source_input_class="content-brief",
    )
    before = target.read_bytes()

    blocked = _assert_blocked(server.vault_append(
        path,
        "# Brief\n\n## Storyboard\n\nProduzione e lifecycle completi.",
        mutation,
    ))

    assert any("atomic brief" in error for error in blocked["errors"])
    assert target.read_bytes() == before


def test_wrong_area_is_rejected(vault_dir):
    path = "04-areas/ai-terra-terra/content/ideas/carbonara.md"
    mutation = _mutation(
        path=path,
        entity_area="04-areas/creator-spagnolo",
        capability="content",
        file_kind="atomic-note",
        operation="create",
        preimage="absent",
        rollback=f"delete-if-postimage:{path}",
        source_input_class="content-brief",
    )
    blocked = _assert_blocked(server.vault_write(path, "# Brief\n## Produzione\nDettagli", mutation))
    assert any("outside the resolved entity" in error for error in blocked["errors"])
    assert not (vault_dir / path).exists()


def test_knowledge_cannot_write_life_and_people_cannot_write_business(vault_dir):
    life_path = "06-life/private/reflection.md"
    life_mutation = _mutation(
        path=life_path,
        entity_area="06-life/private",
        capability="knowledge",
        file_kind="knowledge-note",
        operation="create",
        preimage="absent",
        rollback=f"delete-if-postimage:{life_path}",
    )
    life = _assert_blocked(server.vault_write(life_path, "A durable source note", life_mutation))
    assert any("does not own destination root" in error for error in life["errors"])

    people_path = "04-areas/aiconic/people/mario.md"
    people_mutation = _mutation(
        path=people_path,
        entity_area="04-areas/aiconic",
        capability="people",
        file_kind="person-note",
        operation="create",
        preimage="absent",
        rollback=f"delete-if-postimage:{people_path}",
    )
    people = _assert_blocked(server.vault_write(people_path, "Mario — collaborator", people_mutation))
    assert any("People owner" in error for error in people["errors"])


def test_media_requires_provenance(vault_dir):
    path = "04-areas/aiconic/media/reference.jpg.md"
    mutation = _mutation(
        path=path,
        entity_area="04-areas/aiconic",
        capability="media",
        file_kind="media-asset",
        operation="create",
        preimage="absent",
        rollback=f"delete-if-postimage:{path}",
    )
    blocked = _assert_blocked(server.vault_write(path, "Reference asset", mutation))
    assert any("require provenance" in error for error in blocked["errors"])


def test_missing_preimage_and_ambiguous_destination_are_rejected(vault_dir):
    path = "05-knowledge/notes/missing.md"
    mutation = _mutation(
        path=path,
        entity_area="05-knowledge/notes",
        capability="knowledge",
        file_kind="knowledge-note",
        operation="append",
        preimage=f"sha256:{'0' * 64}",
        rollback=f"restore-preimage:{path}",
        candidates=[path, "05-knowledge/notes/other.md"],
    )
    blocked = _assert_blocked(server.vault_append(path, "New fact", mutation))
    assert any("ambiguous" in error for error in blocked["errors"])
    assert any("preimage does not exist" in error for error in blocked["errors"])
    assert not (vault_dir / path).exists()


def test_cross_scope_self_improvement_is_proposal_only(vault_dir):
    path = "00-system/AGENTS.md"
    mutation = _mutation(
        path=path,
        entity_area="00-system",
        capability="self-improvement",
        file_kind="atomic-note",
        operation="create",
        preimage="absent",
        rollback=f"delete-if-postimage:{path}",
        source_input_class="self-improvement-review",
    )
    blocked = _assert_blocked(server.vault_write(path, "Patch a foreign skill", mutation))
    assert any("proposal-only" in error for error in blocked["errors"])
    assert not (vault_dir / path).exists()


def test_context_profile_mutations_require_structured_preflight_in_schema():
    required_fields = {
        "source_input_class",
        "entity_area",
        "capability",
        "canonical_destination",
        "candidate_destinations",
        "file_kind",
        "operation",
        "confidence",
        "reason",
        "preimage_requirement",
        "rollback_target",
    }
    for name in ("vault_write", "vault_edit", "vault_append", "vault_move", "vault_delete"):
        schema = server.mcp._tool_manager.get_tool(name).parameters
        assert "mutation" in schema["required"]
        mutation_ref = schema["properties"]["mutation"]["$ref"].rsplit("/", 1)[-1]
        mutation_schema = schema["$defs"][mutation_ref]
        assert "preflight" in mutation_schema["required"]
        preflight_ref = mutation_schema["properties"]["preflight"]["$ref"].rsplit("/", 1)[-1]
        assert required_fields <= set(schema["$defs"][preflight_ref]["required"])

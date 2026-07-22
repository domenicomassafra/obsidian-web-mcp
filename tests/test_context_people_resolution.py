"""Redacted regressions for named-person routing and guarded writes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from obsidian_vault_mcp import server
from obsidian_vault_mcp.context_engine import clear_bootstrap_cache


def _json(payload: str) -> dict:
    return json.loads(payload)


def _write(vault: Path, path: str, content: str) -> None:
    target = vault / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _seed(vault: Path, *, duplicate_first_name: bool = False) -> str:
    _write(vault, "AGENTS.md", "# Synthetic vault contract\n")
    _write(vault, "00-system/guides/00-vault-operating-model.md", "# Operating model\n")
    _write(vault, "04-areas/README.md", "# Area routing contract\n")
    _write(
        vault,
        "06-life/people/index.md",
        "---\ntype: life\nuid: people-index\n---\n# People\n",
    )
    _write(
        vault,
        "06-life/people/angela-example.md",
        "---\ntype: life-person\ntitle: Angela Example\nuid: person-angela-example\n"
        "visibility: pii\n---\n# Angela Example\nVerified synthetic person fact.",
    )
    if duplicate_first_name:
        _write(
            vault,
            "06-life/people/angela-other.md",
            "---\ntype: life-person\ntitle: Angela Other\nuid: person-angela-other\n"
            "visibility: pii\n---\n# Angela Other\nDifferent synthetic person.\n",
        )
    for path, heading in (
        ("06-life/relationships-and-friends.md", "Relationships"),
        ("06-life/story.md", "Story"),
        ("06-life/dreams.md", "Dreams"),
    ):
        _write(vault, path, f"# {heading}\nAngela Example synthetic context.\n")
    clear_bootstrap_cache()
    server.frontmatter_index.rebuild()
    return (vault / "06-life/people/angela-example.md").read_text(encoding="utf-8")


def test_three_redacted_followups_keep_the_same_resolved_person(vault_dir):
    _seed(vault_dir)
    requests = (
        "Cosa sai di Angela Example?",
        "Mmh, solo questo? Angela Example era una mia coinquilina: verifica la fonte.",
        "Verifica di nuovo Angela Example: sei sicuro che sia tutto?",
    )

    for request in requests:
        route = _json(server.vault_context_route(request))
        receipt = route["receipt"]
        assert receipt["intent"] == "personal_person_context"
        assert receipt["entity_resolution"] == {
            "status": "resolved",
            "uid": "person-angela-example",
            "name": "Angela Example",
            "path": "06-life/people/angela-example.md",
            "matched_name": "Angela Example",
        }
        assert "06-life/people/angela-example.md" in receipt["selected_paths"]
        assert receipt["write_mode"] == "proposal_only"

    result = _json(server.vault_context_read(requests[0], mode="sections"))
    person = next(
        item for item in result["files"] if item["path"].endswith("angela-example.md")
    )
    assert "Verified synthetic person fact" in person["content"]


def test_first_name_collision_fails_closed_without_reading_or_proposing_a_profile(
    vault_dir,
):
    _seed(vault_dir, duplicate_first_name=True)

    route = _json(server.vault_context_route("Cosa sai di Angela?"))["receipt"]
    assert route["intent"] == "personal_person_context"
    assert route["entity_resolution"]["status"] == "ambiguous"
    assert len(route["entity_resolution"]["candidates"]) == 2
    assert route["selected_paths"] == ["06-life/people/index.md"]

    proposal = _json(server.vault_context_proposal("Aggiorna la scheda di Angela"))
    assert proposal["write_executed"] is False
    assert proposal["proposals"] == []


def test_person_proposal_is_no_write_and_cas_apply_replay_rollback_are_exact(vault_dir):
    original = _seed(vault_dir)
    path = "06-life/people/angela-example.md"

    proposal = _json(
        server.vault_context_proposal(
            "Angela Example era una mia coinquilina: prepara un aggiornamento source-bound."
        )
    )
    assert proposal["write_executed"] is False
    target = next(item for item in proposal["proposals"] if item["path"] == path)
    assert target["operation"] == "targeted_update"
    assert target["expected_sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert (vault_dir / path).read_text(encoding="utf-8") == original

    updated = original.replace(
        "Verified synthetic person fact.",
        "Verified synthetic person fact.\nSource-bound synthetic correction.",
    )
    applied = _json(
        server.vault_write(path, updated, expected_sha256=target["expected_sha256"])
    )
    assert applied["created"] is False
    updated_sha = applied["sha256"]

    replay = _json(
        server.vault_write(path, updated, expected_sha256=target["expected_sha256"])
    )
    assert "changed since it was read" in replay["error"]
    assert (vault_dir / path).read_text(encoding="utf-8") == updated

    rolled_back = _json(server.vault_write(path, original, expected_sha256=updated_sha))
    assert rolled_back["sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert (vault_dir / path).read_text(encoding="utf-8") == original

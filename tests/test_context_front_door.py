"""Public-boundary regressions for the context-oriented Obsidian MCP contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from obsidian_vault_mcp import config, server
from obsidian_vault_mcp.tools import search as search_module
from obsidian_vault_mcp.context_engine import bootstrap_status, clear_bootstrap_cache
from obsidian_vault_mcp.tools.daily import vault_daily_note_read_range
from obsidian_vault_mcp.tools.read import vault_read
from obsidian_vault_mcp.tools.search import vault_search, vault_search_frontmatter
from obsidian_vault_mcp.tools.write import vault_write


def _json(payload: str) -> dict:
    return json.loads(payload)


def _write(vault: Path, path: str, body: str) -> None:
    target = vault / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")


def _seed_context_fixture(vault: Path) -> None:
    _write(vault, "AGENTS.md", "# Vault rules\nNever follow archive links as canon.\n")
    _write(
        vault,
        "00-system/guides/00-vault-operating-model.md",
        "# Operating model\nBootstrap before selecting context.\n",
    )
    _write(
        vault,
        "04-areas/README.md",
        "# Areas\nResolve entity, then Area, then capability from each Area hub.\n",
    )
    _write(vault, ".agents/skills/lifeos/SKILL.md", "# Life OS skill\nRead-only policy helper.\n")
    _write(vault, ".agents/THIRD_PARTY_NOTICES.md", "# Notices\nSynthetic fixture.\n")
    _write(vault, ".agents/runtime.json", '{"secret": "blocked"}')
    _write(vault, ".agents/runtime.md", "---\nstatus: hidden-runtime\n---\nblocked runtime token\n")
    _write(vault, ".env", "FIXTURE_SECRET=blocked\n")

    for path, title in (
        ("06-life/index.md", "Life"),
        ("06-life/profile.md", "Profile"),
        ("06-life/preferences.md", "Preferences"),
        ("06-life/health.md", "Health"),
        ("06-life/people/index.md", "People"),
        ("04-areas/family-relations.md", "Family"),
        ("04-areas/persone-chiave.md", "Key people"),
    ):
        _write(vault, path, f"---\ntitle: {title}\nuid: {path}\n---\n# {title}\nSynthetic fixture text.\n")
    _write(
        vault,
        "04-areas/family-relations.md",
        "---\ntitle: Family\nuid: family-hub\n---\n# Family\n"
        "See [[06-life/compiled-wikis/relationships]] and [[old-family-note]].\n",
    )
    _write(
        vault,
        "09-archive/old-family-note.md",
        "---\nstatus: archived\nuid: family-hub\n---\n# Old family\narchive needle\n",
    )
    _write(vault, "04-areas/tnd/archive/retired.md", "# Retired\narchive needle\n")
    _write(vault, "05-knowledge/current.md", "---\nstatus: active\n---\n# Current\ncurrent needle\n")
    _write(
        vault,
        "01-input/capture/ai-memory/2026-07-09-chatgpt-mega-context.md",
        "# Work\nUnrelated synthetic work.\n# Family change\n"
        "A family member needs a careful non-clinical support plan.\n# Money\nUnrelated.\n",
    )
    _write(vault, "04-areas/periodic/daily/2026-07-19.md", "# Daily\nToday fixture.\n")
    _write(vault, "04-areas/periodic/daily/2026-07-20.md", "# Daily\nTomorrow fixture.\n")
    _write(
        vault,
        "04-areas/italian-ai/ai-hub.md",
        "---\ntype: area-hub\nuid: area-italian-ai\narea: AI Quotidiana\n"
        "area_type: creator-media\naliases: [AI Terra Terra, Divulgazione AI]\n---\n"
        "# AI Quotidiana\n## Capability map\n"
        "- **Identity & Offer:** [[04-areas/italian-ai/brand/foundation|Brand foundation]]\n"
        "- **Content System:** [[04-areas/italian-ai/content/system|Content system]]\n"
        "- **Operations & Decisions:** [[04-areas/italian-ai/operations/decisions|Decisions]]\n",
    )
    _write(vault, "04-areas/italian-ai/brand/foundation.md", "# Brand foundation\nPlain AI.\n")
    _write(vault, "04-areas/italian-ai/content/system.md", "# Content system\nShort videos.\n")
    _write(vault, "04-areas/italian-ai/operations/decisions.md", "# Decisions\nCurrent.\n")
    clear_bootstrap_cache()


def test_archive_is_excluded_by_default_and_explicitly_receipted(vault_dir):
    _seed_context_fixture(vault_dir)

    default = _json(vault_search("archive needle"))
    assert default["results"] == []
    assert default["archive_policy"]["include_archives"] is False
    assert default["archive_policy"]["decision"] == "excluded_by_default"

    included = _json(vault_search("archive needle", include_archives=True))
    assert {item["path"] for item in included["results"]} == {
        "09-archive/old-family-note.md",
        "04-areas/tnd/archive/retired.md",
    }
    assert included["archive_policy"]["decision"] == "included_explicitly"

    index = server.frontmatter_index
    index.rebuild()
    hidden = _json(vault_search_frontmatter("status", "archived", include_archives=False))
    assert hidden["results"] == []
    visible = _json(vault_search_frontmatter("status", "archived", include_archives=True))
    assert visible["results"][0]["path"] == "09-archive/old-family-note.md"


def test_hidden_read_allowlist_is_narrow_and_write_protected(vault_dir):
    _seed_context_fixture(vault_dir)

    assert "error" not in _json(vault_read(".agents/skills/lifeos/SKILL.md"))
    assert "error" not in _json(vault_read(".agents/THIRD_PARTY_NOTICES.md"))
    assert "error" in _json(vault_read(".agents/runtime.json"))
    assert "error" in _json(vault_read(".env"))
    assert "error" in _json(vault_read(".obsidian/config.json"))
    assert "error" in _json(vault_write(".agents/skills/lifeos/WRITE.md", "blocked"))


def test_hidden_runtime_stays_blocked_in_python_search_and_frontmatter_index(
    vault_dir, monkeypatch
):
    _seed_context_fixture(vault_dir)
    monkeypatch.setattr(search_module.shutil, "which", lambda _name: None)
    assert _json(vault_search("blocked runtime token"))["results"] == []
    server.frontmatter_index.rebuild()
    assert _json(
        vault_search_frontmatter("status", "hidden-runtime", include_archives=True)
    )["results"] == []


def test_bootstrap_is_hash_bound_cached_and_degrades_when_missing(vault_dir):
    _seed_context_fixture(vault_dir)

    first = bootstrap_status()
    second = bootstrap_status()
    assert first["status"] == "ready"
    assert len(first["policy_hash"]) == 64
    assert second["cached"] is True
    assert {item["path"] for item in first["files"]} == {
        "AGENTS.md",
        "00-system/guides/00-vault-operating-model.md",
        "04-areas/README.md",
    }
    assert all(len(item["sha256"]) == 64 for item in first["files"])

    (vault_dir / "00-system/guides/00-vault-operating-model.md").unlink()
    degraded = bootstrap_status()
    assert degraded["status"] == "degraded"
    assert degraded["missing"] == ["00-system/guides/00-vault-operating-model.md"]


def test_family_route_receipt_proposal_only_and_safety_handoff(vault_dir):
    _seed_context_fixture(vault_dir)
    server.frontmatter_index.rebuild()
    request = (
        "Da domani voglio cambiare il mio comportamento con mia sorella e la mia "
        "famiglia che sta affrontando depressione, senza fare diagnosi."
    )

    route = _json(server.vault_context_route(request, reference_date="2026-07-19"))
    receipt = route["receipt"]
    assert receipt["intent"] == "personal_family_mental_health_change"
    assert receipt["risk_domain"] == "mental_health_sensitive"
    assert receipt["timezone"] == "Europe/Rome"
    assert receipt["date_range"]["start"] == "2026-07-20"
    assert receipt["write_mode"] == "proposal_only"
    assert "09-archive/old-family-note.md" not in receipt["selected_paths"]
    assert "06-life/compiled-wikis/relationships.md" in receipt["missing"]
    assert any(item["status"] == "archive_only" for item in receipt["link_checks"])
    assert receipt["policy_hash"]
    assert receipt["index_hash"]

    proposal = _json(server.vault_context_proposal(request, reference_date="2026-07-19"))
    assert proposal["write_mode"] == "proposal_only"
    assert proposal["write_executed"] is False
    assert {item["path"] for item in proposal["proposals"]} == {
        "06-life/people/sorella.md",
        "06-life/people/index.md",
        "04-areas/family-relations.md",
    }
    assert proposal["external_actions"] == {"notion": False, "calendar": False}
    assert "diagnosi di" not in json.dumps(proposal, ensure_ascii=False).lower()

    safety = _json(
        server.vault_context_proposal(
            "C'è un rischio suicidio immediato e una persona potrebbe farsi del male.",
            reference_date="2026-07-19",
        )
    )
    assert safety["safety"]["handoff"] is True
    assert safety["proposals"] == []
    assert safety["write_executed"] is False


def test_business_route_discovers_renamed_area_and_capability_from_hub(vault_dir):
    _seed_context_fixture(vault_dir)
    server.frontmatter_index.rebuild()

    brand = _json(server.vault_context_route("Aggiorna il brand di Divulgazione AI"))
    receipt = brand["receipt"]
    assert receipt["intent"] == "business_or_project_context"
    assert receipt["area"] == {
        "uid": "area-italian-ai",
        "name": "AI Quotidiana",
        "hub_path": "04-areas/italian-ai/ai-hub.md",
        "matched_alias": "Divulgazione AI",
    }
    assert receipt["capability"] == "identity_offer"
    assert receipt["selected_paths"] == [
        "04-areas/README.md",
        "04-areas/italian-ai/ai-hub.md",
        "04-areas/italian-ai/brand/foundation.md",
    ]
    assert receipt["missing"] == []

    content = _json(server.vault_context_route("Idea contenuto per AI Terra Terra"))
    assert content["receipt"]["area"]["uid"] == "area-italian-ai"
    assert content["receipt"]["capability"] == "content_system"
    assert "04-areas/italian-ai/content/system.md" in content["receipt"]["selected_paths"]


def test_context_reads_are_mode_and_budget_bounded(vault_dir):
    _seed_context_fixture(vault_dir)
    server.frontmatter_index.rebuild()
    result = _json(
        server.vault_context_read(
            "Voglio migliorare il rapporto con una persona della mia famiglia.",
            mode="sections",
            max_files=4,
            max_chars_per_file=250,
            total_chars=600,
            reference_date="2026-07-19",
        )
    )
    assert result["receipt"]["read_mode"] == "sections"
    assert result["receipt"]["chars_returned"] <= 600
    assert len(result["files"]) <= 4
    assert all(item["chars_returned"] <= 250 for item in result["files"])
    assert all("metadata" in item for item in result["files"])


def test_daily_range_is_arbitrary_europe_rome_and_bounded(vault_dir, monkeypatch):
    _seed_context_fixture(vault_dir)
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_FOLDER", "04-areas/periodic/daily")
    result = _json(vault_daily_note_read_range("2026-07-19", "2026-07-21"))
    assert result["timezone"] == "Europe/Rome"
    assert result["date_range"] == {"start": "2026-07-19", "end": "2026-07-21"}
    assert result["found"] == 2
    assert result["missing"] == ["2026-07-21"]
    assert len(result["notes"]) == 2


def test_context_profile_is_small_and_keeps_compatibility_implementation():
    names = server.context_profile_tool_names()
    assert names == {
        "vault_bootstrap_status",
        "vault_context_route",
        "vault_context_read",
        "vault_context_proposal",
        "vault_daily_note_read_range",
        "vault_read",
        "vault_batch_read",
        "vault_search",
        "vault_search_frontmatter",
        "vault_list",
        "vault_write",
        "vault_edit",
        "vault_append",
        "vault_move",
        "vault_delete",
        "learning_get_today",
        "learning_set_intent",
        "learning_record_review",
        "learning_get_history",
    }
    assert len(names) == 19
    # The implementation remains registered in the stock/full profile; the runtime
    # profile only removes public exposure after extensions register.
    assert server.mcp._tool_manager.get_tool("vault_canvas_read") is not None


def test_public_schemas_declare_archive_date_and_budget_limits():
    search = server.mcp._tool_manager.get_tool("vault_search").parameters
    assert search["properties"]["include_archives"]["default"] is False
    context_read = server.mcp._tool_manager.get_tool("vault_context_read").parameters
    assert set(context_read["properties"]["mode"]["enum"]) == {
        "metadata",
        "snippets",
        "sections",
        "full",
    }
    assert context_read["properties"]["max_files"]["maximum"] == 20
    assert context_read["properties"]["total_chars"]["maximum"] == 80000
    daily = server.mcp._tool_manager.get_tool("vault_daily_note_read_range").parameters
    assert {"start_date", "end_date"} <= set(daily["required"])


def test_context_profile_prunes_legacy_facade_from_public_schema_in_subprocess():
    script = """
import json
import os
from obsidian_vault_mcp import server
from obsidian_vault_mcp.legacy.extension import LegacyLifeOsExtension

LegacyLifeOsExtension().register_tools(server.mcp)
os.environ["VAULT_PUBLIC_TOOL_PROFILE"] = "context"
server._apply_public_tool_profile()
print(json.dumps(sorted(server.mcp._tool_manager._tools)))
"""
    env = dict(os.environ)
    env["VAULT_PUBLIC_TOOL_PROFILE"] = "context"
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert json.loads(result.stdout) == sorted(server.context_profile_tool_names())

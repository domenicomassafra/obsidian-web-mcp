"""Read tools for the Obsidian vault MCP server."""

import logging

import frontmatter

from ..serialization import dumps
from ..vault import archive_policy_receipt, is_archive_path, read_file

logger = logging.getLogger(__name__)


def vault_read(path: str, include_archives: bool = False) -> str:
    """Read a file from the vault, returning content, metadata, and parsed frontmatter."""
    try:
        archive_policy = archive_policy_receipt(include_archives)
        if is_archive_path(path) and not include_archives:
            return dumps({
                "error": "Archive path requires include_archives=true",
                "path": path,
                "archive_policy": archive_policy,
            })
        content, metadata = read_file(path, allow_hidden_read=True)

        fm_data = None
        try:
            post = frontmatter.loads(content)
            if post.metadata:
                fm_data = post.metadata
        except Exception:
            pass

        return dumps({
            "path": path,
            "content": content,
            "metadata": metadata,
            "frontmatter": fm_data,
            "archive_policy": archive_policy,
        })
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except FileNotFoundError:
        return dumps({"error": f"File not found: {path}", "path": path})
    except Exception as e:
        logger.error(f"vault_read error for {path}: {e}")
        return dumps({"error": str(e), "path": path})


def vault_batch_read(
    paths: list[str], include_content: bool = True, include_archives: bool = False
) -> str:
    """Read multiple files from the vault in one call."""
    results = []
    found = 0
    missing = 0
    archive_policy = archive_policy_receipt(include_archives)

    for path in paths:
        try:
            if is_archive_path(path) and not include_archives:
                raise ValueError("Archive path requires include_archives=true")
            content, metadata = read_file(path, allow_hidden_read=True)

            fm_data = None
            try:
                post = frontmatter.loads(content)
                if post.metadata:
                    fm_data = post.metadata
            except Exception:
                pass

            entry = {
                "path": path,
                "metadata": metadata,
                "frontmatter": fm_data,
            }
            if include_content:
                entry["content"] = content

            results.append(entry)
            found += 1
        except (ValueError, FileNotFoundError) as e:
            results.append({"path": path, "error": str(e)})
            missing += 1
        except Exception as e:
            results.append({"path": path, "error": str(e)})
            missing += 1

    return dumps({
        "files": results,
        "found": found,
        "missing": missing,
        "archive_policy": archive_policy,
    })

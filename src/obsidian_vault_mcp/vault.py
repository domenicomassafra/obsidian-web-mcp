"""Core filesystem operations for the Obsidian vault."""

import fnmatch
import hashlib
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePath

from . import config


ARCHIVE_PATTERNS = ("09-archive/**", "**/archive/**")
_PROJECTED_HIDDEN_READ_PATHS = frozenset({
    ".agents/NOTICE.md",
    ".agents/NOTICES.md",
    ".agents/THIRD_PARTY_NOTICES.md",
    ".agents/skills/json-canvas/SKILL.md",
    ".agents/skills/lifeos-daily/SKILL.md",
    ".agents/skills/lifeos-harvest/SKILL.md",
    ".agents/skills/lifeos-media/SKILL.md",
    ".agents/skills/lifeos-notion/SKILL.md",
    ".agents/skills/lifeos-wiki/SKILL.md",
    ".agents/skills/lifeos/SKILL.md",
    ".agents/skills/obsidian-bases/SKILL.md",
    ".agents/skills/obsidian-cli/SKILL.md",
    ".agents/skills/obsidian-markdown/SKILL.md",
})


def _clean_relative_path(relative_path: str) -> str:
    return str(PurePath(relative_path)).replace("\\", "/")


def is_archive_path(relative_path: str | Path) -> bool:
    """Return whether a vault-relative path belongs to a non-canonical archive."""
    parts = tuple(part.casefold() for part in Path(str(relative_path)).parts)
    return bool(parts) and (parts[0] == "09-archive" or "archive" in parts)


def archive_policy_receipt(include_archives: bool) -> dict:
    """Return the stable, body-free archive decision attached to read receipts."""
    return {
        "include_archives": include_archives,
        "decision": "included_explicitly" if include_archives else "excluded_by_default",
        "default_exclusions": list(ARCHIVE_PATTERNS),
    }


def is_hidden_read_allowed(relative_path: str) -> bool:
    """Allow only exact projected hidden files; never a hidden directory tree."""
    raw_path = str(relative_path)
    normalized = _clean_relative_path(raw_path).strip("/")
    # The allowlist is a publication contract, not a path-normalization
    # shortcut.  Accept only the canonical spelling that is actually named in
    # that contract, so backslashes, ``./`` prefixes and other aliases cannot
    # inherit authorization from an allowed target.
    return raw_path == normalized and normalized in _PROJECTED_HIDDEN_READ_PATHS


def resolve_vault_path(relative_path: str, *, allow_hidden_read: bool = False) -> Path:
    """Resolve a relative path against the vault root, with safety checks.

    Raises ValueError if the path escapes the vault, contains null bytes,
    or touches dotfile/dot-directory components.
    """
    if "\x00" in relative_path:
        raise ValueError("Path contains null bytes")

    hidden_allowed = allow_hidden_read and is_hidden_read_allowed(relative_path)
    # Check for dot-prefixed components (blocks .obsidian, .trash, dotfiles).
    # The sole exception is the narrow read-only .agents publication surface.
    parts = Path(relative_path).parts
    for part in parts:
        if part.startswith(".") and not hidden_allowed:
            raise ValueError(
                f"Path component '{part}' starts with '.'; dotfiles and hidden directories are not allowed"
            )

    vault_root = config.VAULT_PATH.resolve()
    lexical = vault_root / relative_path
    resolved = lexical.resolve()

    if not str(resolved).startswith(str(vault_root) + os.sep) and resolved != vault_root:
        raise ValueError("Path resolves outside the vault root")

    # A projected hidden read must address the published object itself.  Do
    # not follow an internal symlink or other alias to a different object,
    # even when that object remains inside the vault.
    if hidden_allowed and resolved != lexical:
        raise ValueError("Projected hidden path must not resolve through an alias")

    return resolved


def is_discoverable_vault_path(
    path: Path, *, allow_hidden_read: bool = False
) -> bool:
    """Return whether a filesystem walk may expose this canonical vault path.

    Explicit reads already pass through ``resolve_vault_path``. Directory walks,
    indexes and fallback searches also need to reject symlink aliases, otherwise
    they can disclose names, metadata or content from another tree while still
    presenting a vault-relative path.
    """
    try:
        relative = path.relative_to(config.VAULT_PATH)
        lexical = config.VAULT_PATH.resolve() / relative
        resolved = resolve_vault_path(
            str(relative), allow_hidden_read=allow_hidden_read
        )
    except (OSError, ValueError):
        return False
    return resolved == lexical


def _iso_timestamp(ts: float) -> str:
    """Convert a Unix timestamp to an ISO 8601 string in UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def read_file(relative_path: str, *, allow_hidden_read: bool = False) -> tuple[str, dict]:
    """Read a file and return (content, metadata).

    Metadata keys: size (int), modified (ISO str), created (ISO str).
    """
    path = resolve_vault_path(relative_path, allow_hidden_read=allow_hidden_read)

    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {relative_path}")

    stat = path.stat()
    content = path.read_text(encoding="utf-8")

    metadata = {
        "size": stat.st_size,
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "modified": _iso_timestamp(stat.st_mtime),
        "created": _iso_timestamp(stat.st_birthtime if hasattr(stat, "st_birthtime") else stat.st_ctime),
    }

    return content, metadata


def write_file_atomic(
    relative_path: str,
    content: str,
    create_dirs: bool = True,
    overwrite: bool = True,
    expected_sha256: str | None = None,
) -> tuple[bool, int]:
    """Write content to a file atomically.

    Returns (is_new_file, bytes_written). Writes to a tempfile in the same
    directory then puts it in place, so readers never see a partial write.

    ``overwrite=False`` is a true atomic no-clobber create. ``expected_sha256``
    performs an optimistic version check immediately before atomic replacement;
    it rejects absent or changed targets instead of blindly overwriting them.
    """
    encoded = content.encode("utf-8")
    if len(encoded) > config.MAX_CONTENT_SIZE:
        raise ValueError(
            f"Content size {len(encoded)} bytes exceeds limit of {config.MAX_CONTENT_SIZE} bytes"
        )

    path = resolve_vault_path(relative_path)
    is_new = not path.exists()

    if expected_sha256 is not None:
        if is_new:
            raise FileNotFoundError(
                f"Expected an existing file for SHA-256 check: {relative_path}"
            )
        current_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if current_digest != expected_sha256.lower():
            raise ValueError(
                f"SHA-256 mismatch for {relative_path}: file changed since it was read"
            )

    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the same directory, then atomic-replace.
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
        if expected_sha256 is not None:
            current_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if current_digest != expected_sha256.lower():
                raise ValueError(
                    f"SHA-256 mismatch for {relative_path}: file changed before write"
                )
            os.replace(tmp_path, path)
        elif overwrite:
            os.replace(tmp_path, path)
        else:
            try:
                os.link(tmp_path, path)
            except FileExistsError:
                raise FileExistsError(
                    f"File already exists: {relative_path}. "
                    "Provide expected_sha256 to replace it."
                )
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            is_new = True
    except BaseException:
        # Clean up the temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return is_new, len(encoded)


def write_bytes_atomic(
    relative_path: str, content: bytes, create_dirs: bool = True, overwrite: bool = True
) -> tuple[bool, int]:
    """Write raw bytes to a file atomically.

    The binary counterpart of write_file_atomic: writes to a tempfile in the same
    directory then puts it in place, so readers never see a partial write.
    Returns (is_new_file, bytes_written).

    With overwrite=False the placement is a true no-clobber: it uses os.link, which fails
    atomically if the target already exists, closing the check-then-write race that a plain
    exists()-then-os.replace would leave open. With overwrite=True it os.replace()s.
    """
    if len(content) > config.MAX_BINARY_SIZE:
        raise ValueError(
            f"Content size {len(content)} bytes exceeds limit of {config.MAX_BINARY_SIZE} bytes"
        )

    path = resolve_vault_path(relative_path)
    is_new = not path.exists()

    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the same directory, then put it in place atomically.
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        if overwrite:
            os.replace(tmp_path, path)
        else:
            # Atomic create: os.link fails if the target exists (no clobber, no race).
            try:
                os.link(tmp_path, path)
            except FileExistsError:
                raise FileExistsError(f"File already exists: {relative_path}")
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            is_new = True
    except BaseException:
        # Clean up the temp file on any failure (os.replace consumes it on success).
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return is_new, len(content)


def move_path(
    source: str, destination: str, create_dirs: bool = True
) -> bool:
    """Move a file or directory from source to destination.

    Both paths are relative to the vault root. Raises if the destination
    already exists.
    """
    src = resolve_vault_path(source)
    dst = resolve_vault_path(destination)

    if not src.exists():
        raise FileNotFoundError(f"Source does not exist: {source}")

    if dst.exists():
        raise FileExistsError(f"Destination already exists: {destination}")

    if create_dirs:
        dst.parent.mkdir(parents=True, exist_ok=True)

    shutil.move(str(src), str(dst))
    return True


def delete_path(relative_path: str) -> bool:
    """Soft-delete by moving the path into .trash/ at the vault root.

    Refuses to delete non-empty directories.
    """
    path = resolve_vault_path(relative_path)

    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {relative_path}")

    if path.is_dir() and any(path.iterdir()):
        raise ValueError(f"Refusing to delete non-empty directory: {relative_path}")

    trash_dir = config.VAULT_PATH.resolve() / ".trash"
    trash_dir.mkdir(exist_ok=True)

    dest = trash_dir / path.name

    # Avoid collisions in .trash by appending a timestamp
    if dest.exists():
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
        dest = trash_dir / f"{path.stem}_{ts}{path.suffix}"

    shutil.move(str(path), str(dest))
    return True


def list_directory(
    relative_path: str,
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
    include_archives: bool = False,
) -> list[dict]:
    """List directory contents recursively up to *depth* levels.

    Returns a list of dicts with keys: name, path (relative to vault),
    type ("file" or "dir"), size, modified.
    """
    depth = min(depth, config.MAX_LIST_DEPTH)

    root = resolve_vault_path(relative_path, allow_hidden_read=True)
    if is_archive_path(relative_path) and not include_archives:
        raise ValueError("Archive path requires include_archives=true")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {relative_path}")

    vault_root = config.VAULT_PATH.resolve()
    results: list[dict] = []

    def _walk(dir_path: Path, current_depth: int) -> None:
        if current_depth > depth:
            return

        try:
            entries = sorted(dir_path.iterdir(), key=lambda p: p.name.lower())
        except PermissionError:
            return

        for entry in entries:
            # Skip excluded directories at every level
            if entry.name in config.EXCLUDED_DIRS:
                continue
            if not is_discoverable_vault_path(entry, allow_hidden_read=True):
                continue

            is_dir = entry.is_dir()

            if is_dir and not include_dirs:
                # Still recurse even if we're not listing dirs
                _walk(entry, current_depth + 1)
                continue

            if not is_dir and not include_files:
                continue

            # Apply glob pattern filter
            if pattern and not fnmatch.fnmatch(entry.name, pattern):
                if is_dir:
                    _walk(entry, current_depth + 1)
                continue

            try:
                stat = entry.stat()
            except OSError:
                continue

            rel = str(entry.relative_to(vault_root))
            if is_archive_path(rel) and not include_archives:
                continue

            results.append({
                "name": entry.name,
                "path": rel,
                "type": "dir" if is_dir else "file",
                "size": stat.st_size,
                "modified": _iso_timestamp(stat.st_mtime),
            })

            if is_dir:
                _walk(entry, current_depth + 1)

    _walk(root, 1)
    return results

"""Pydantic input models for obsidian-vault-mcp tool endpoints."""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .config import (
    CONTEXT_LINES,
    DEFAULT_SEARCH_RESULTS,
    MAX_BATCH_SIZE,
    MAX_BINARY_SIZE,
    MAX_CONTENT_SIZE,
    MAX_LIST_DEPTH,
    MAX_SEARCH_RESULTS,
)


FrontmatterMatchType = Literal["exact", "contains", "exists"]
AnalyticsFindingCategory = Literal[
    "frontmatter_missing",
    "required_frontmatter_missing",
    "broken_wikilinks",
    "suspicious_tag_variants",
    "encoding_issues",
    "oversized_files",
]
CanvasNodeType = Literal["text", "file", "link", "group"]
CanvasSide = Literal["top", "right", "bottom", "left"]
ExpectedSha256 = Annotated[str, Field(pattern=r"^[0-9a-fA-F]{64}$")]


class VaultReadInput(BaseModel):
    """Read a single file from the vault."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path from vault root (e.g. 'projects/acme/notes.md')",
        min_length=1,
        max_length=500,
    )
    include_archives: bool = Field(
        default=False,
        description="Allow an explicit read from 09-archive/** or **/archive/**; default false",
    )


class VaultWriteInput(BaseModel):
    """Create a file or explicitly replace a known vault version."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path from vault root",
        min_length=1,
        max_length=500,
    )
    content: str = Field(
        ...,
        description="Full file content to write",
        max_length=MAX_CONTENT_SIZE,
    )
    create_dirs: bool = Field(
        default=True,
        description="Create parent directories if they don't exist",
    )
    merge_frontmatter: bool = Field(
        default=False,
        description="If true, merge YAML frontmatter with existing file's frontmatter instead of replacing",
    )
    overwrite: bool = Field(
        default=False,
        description="Replace an existing file only when expected_sha256 is also provided",
    )
    expected_sha256: ExpectedSha256 | None = Field(
        default=None,
        description=(
            "Replace only when the existing file has this SHA-256 digest; "
            "safer than a blind overwrite"
        ),
    )

    @model_validator(mode="after")
    def reject_blind_overwrite(self):
        """Never let the compatibility flag bypass optimistic concurrency."""
        if self.overwrite and self.expected_sha256 is None:
            raise ValueError(
                "Blind overwrite is disabled; provide expected_sha256"
            )
        return self


class VaultWriteBinaryInput(BaseModel):
    """Write an allowed binary file to the vault from base64-encoded content."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path from vault root",
        min_length=1,
        max_length=500,
    )
    data: str = Field(
        ...,
        description="Base64-encoded file content",
        # base64 expands ~4/3; cap the encoded length so an oversized payload is rejected
        # before it is decoded into memory.
        max_length=((MAX_BINARY_SIZE + 2) // 3) * 4 + 1024,
    )
    media_type: str = Field(
        ...,
        description="MIME type of the binary content; must be in the server's allowlist",
        min_length=3,
        max_length=200,
    )
    overwrite: bool = Field(
        default=False,
        description="Overwrite an existing file at the target path",
    )
    create_dirs: bool = Field(
        default=True,
        description="Create parent directories if they don't exist",
    )


class VaultEditOperationInput(BaseModel):
    """Replace one exact text fragment inside a vault file."""

    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def normalize_str_replace_aliases(cls, data):
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        for canonical, alias in (("old_text", "old_str"), ("new_text", "new_str")):
            if canonical in normalized and alias in normalized:
                raise ValueError(f"Use either '{canonical}' or '{alias}', not both")
            if alias in normalized:
                normalized[canonical] = normalized.pop(alias)

        return normalized

    old_text: str = Field(
        ...,
        description="Exact existing text fragment to replace; must appear exactly once",
        min_length=1,
        max_length=MAX_CONTENT_SIZE,
    )
    new_text: str = Field(
        ...,
        description="Replacement text for old_text",
        max_length=MAX_CONTENT_SIZE,
    )


class VaultEditInput(BaseModel):
    """Patch an existing file with exact text replacements."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path from vault root",
        min_length=1,
        max_length=500,
    )
    edits: list[VaultEditOperationInput] = Field(
        ...,
        description="Ordered exact text replacements to apply without resending the full file",
        min_length=1,
        max_length=MAX_BATCH_SIZE,
    )
    dry_run: bool = Field(
        default=False,
        description="Preview the patch and diff without writing the file",
    )


class VaultAppendInput(BaseModel):
    """Append content to a file without resending the existing body."""

    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path from vault root",
        min_length=1,
        max_length=500,
    )
    content: str = Field(
        ...,
        description="Content to append or write if the file does not exist",
        max_length=MAX_CONTENT_SIZE,
    )
    separator: str = Field(
        default="\n\n",
        description="Text inserted between existing content and appended content",
        max_length=100,
    )
    create_dirs: bool = Field(
        default=True,
        description="Create parent directories if they don't exist",
    )


class VaultListInput(BaseModel):
    """List files and directories under a vault path."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        default="",
        description="Relative directory path from vault root; empty string for root",
        max_length=500,
    )
    depth: int = Field(
        default=1,
        ge=1,
        le=MAX_LIST_DEPTH,
        description="How many levels deep to recurse",
    )
    include_files: bool = Field(
        default=True,
        description="Include files in the listing",
    )
    include_dirs: bool = Field(
        default=True,
        description="Include directories in the listing",
    )
    pattern: str | None = Field(
        default=None,
        description="Optional glob pattern to filter results (e.g. '*.md')",
        max_length=100,
    )
    include_archives: bool = Field(
        default=False,
        description="Include non-canonical archive directories and files; default false",
    )


class VaultMoveInput(BaseModel):
    """Move or rename a file/directory within the vault."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    source: str = Field(
        ...,
        description="Current relative path of the file or directory",
        min_length=1,
        max_length=500,
    )
    destination: str = Field(
        ...,
        description="New relative path for the file or directory",
        min_length=1,
        max_length=500,
    )
    create_dirs: bool = Field(
        default=True,
        description="Create destination parent directories if they don't exist",
    )


class VaultDeleteInput(BaseModel):
    """Delete a file from the vault."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path of the file to delete",
        min_length=1,
        max_length=500,
    )
    confirm: bool = Field(
        ...,
        description="Must be true to execute deletion -- safety gate to prevent accidental deletes",
    )


class VaultSearchInput(BaseModel):
    """Full-text search across vault files."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    query: str = Field(
        ...,
        description="Search string to find in file contents",
        min_length=1,
        max_length=200,
    )
    path_prefix: str | None = Field(
        default=None,
        description="Limit search to files under this directory prefix",
        max_length=500,
    )
    file_pattern: str = Field(
        default="*.md",
        description="Glob pattern for files to search (e.g. '*.md', '*.canvas')",
        max_length=50,
    )
    max_results: int = Field(
        default=DEFAULT_SEARCH_RESULTS,
        ge=1,
        le=MAX_SEARCH_RESULTS,
        description="Maximum number of matching files to return",
    )
    context_lines: int = Field(
        default=CONTEXT_LINES,
        ge=0,
        le=10,
        description="Number of lines of context to show around each match",
    )
    include_archives: bool = Field(
        default=False,
        description="Include matches under 09-archive/** and **/archive/**; default false",
    )


class VaultSearchFrontmatterInput(BaseModel):
    """Search vault files by YAML frontmatter field values."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    field: str = Field(
        ...,
        description="Frontmatter field name to search (e.g. 'status', 'tags', 'publish-date')",
        min_length=1,
        max_length=100,
    )
    value: str = Field(
        default="",
        description="Value to match against; ignored when match_type is 'exists'",
        max_length=200,
    )
    match_type: FrontmatterMatchType = Field(
        default="exact",
        description="How to match: 'exact' for equality, 'contains' for substring, 'exists' to check field presence",
    )
    path_prefix: str | None = Field(
        default=None,
        description="Limit search to files under this directory prefix",
        max_length=500,
    )
    max_results: int = Field(
        default=DEFAULT_SEARCH_RESULTS,
        ge=1,
        le=MAX_SEARCH_RESULTS,
        description="Maximum number of matching files to return",
    )
    include_archives: bool = Field(
        default=False,
        description="Include indexed archive matches; default false",
    )


class VaultBatchReadInput(BaseModel):
    """Read multiple vault files in a single request."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    paths: list[str] = Field(
        ...,
        description="List of relative paths to read",
        min_length=1,
        max_length=MAX_BATCH_SIZE,
    )
    include_content: bool = Field(
        default=True,
        description="If false, return metadata only (frontmatter, size) without file body",
    )
    include_archives: bool = Field(
        default=False,
        description="Allow explicit archive paths in this batch; default false",
    )


class FrontmatterUpdateInput(BaseModel):
    """A frontmatter merge for one vault file."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path from vault root",
        min_length=1,
        max_length=500,
    )
    fields: dict[str, Any] = Field(
        ...,
        description="Frontmatter key-value pairs to merge; values may be YAML scalars, lists, or objects",
        min_length=1,
    )


class VaultBatchFrontmatterUpdateInput(BaseModel):
    """Update YAML frontmatter on multiple files in one request."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    updates: list[FrontmatterUpdateInput] = Field(
        ...,
        description="Per-file frontmatter merges; each item requires path and non-empty fields",
        min_length=1,
        max_length=MAX_BATCH_SIZE,
    )


def _validate_alnum_id(value: str | None) -> str | None:
    if value is not None and not value.isalnum():
        raise ValueError("id must be alphanumeric when provided")
    return value


class CanvasNodeInput(BaseModel):
    """A single Obsidian Canvas node.

    extra='allow' preserves Obsidian-specific fields (text, file, color, label,
    subpath, ...) so appending a node never strips data on the round-trip.
    """

    model_config = ConfigDict(extra="allow")

    id: str | None = Field(default=None, description="Optional alphanumeric node id; generated when omitted")
    type: CanvasNodeType = Field(..., description="Canvas node type: text, file, link, or group")
    x: int | float = Field(..., description="Canvas x coordinate")
    y: int | float = Field(..., description="Canvas y coordinate")
    width: int | float = Field(..., gt=0, description="Node width")
    height: int | float = Field(..., gt=0, description="Node height")
    text: str | None = Field(default=None, description="Text content for a text node")
    file: str | None = Field(default=None, description="Vault-relative file path for a file node")
    url: str | None = Field(default=None, description="URL for a link node")
    label: str | None = Field(default=None, description="Label for a group node")
    color: str | int | None = Field(default=None, description="Optional Obsidian Canvas color")
    subpath: str | None = Field(default=None, description="Optional heading or block subpath for a file node")

    @field_validator("id")
    @classmethod
    def _node_id_alnum(cls, v: str | None) -> str | None:
        return _validate_alnum_id(v)


class CanvasEdgeInput(BaseModel):
    """A single Obsidian Canvas edge. extra='allow' preserves color/label/etc."""

    model_config = ConfigDict(extra="allow")

    id: str | None = Field(default=None, description="Optional alphanumeric edge id; generated when omitted")
    fromNode: str = Field(..., min_length=1, description="Existing source node id")
    fromSide: CanvasSide = Field(..., description="One of: top, right, bottom, left")
    toNode: str = Field(..., min_length=1, description="Existing target node id")
    toSide: CanvasSide = Field(..., description="One of: top, right, bottom, left")
    color: str | int | None = Field(default=None, description="Optional Obsidian Canvas color")
    label: str | None = Field(default=None, description="Optional edge label")

    @field_validator("id")
    @classmethod
    def _edge_id_alnum(cls, v: str | None) -> str | None:
        return _validate_alnum_id(v)


class VaultCanvasReadInput(BaseModel):
    """Read and parse an Obsidian .canvas file."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path to a .canvas file from the vault root",
        min_length=1,
        max_length=500,
    )


class VaultCanvasAddNodeInput(BaseModel):
    """Append a node to a .canvas file."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path to a .canvas file (created if missing)",
        min_length=1,
        max_length=500,
    )
    node: CanvasNodeInput = Field(..., description="Node to append")


class VaultCanvasAddEdgeInput(BaseModel):
    """Append an edge to an existing .canvas file."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path to an existing .canvas file",
        min_length=1,
        max_length=500,
    )
    edge: CanvasEdgeInput = Field(..., description="Edge to append; fromNode/toNode must already exist")


class VaultDailyNoteAppendInput(BaseModel):
    """Append content to today's daily note."""

    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid")

    content: str = Field(
        ...,
        description="Content to append to today's daily note (the note is created from the template if missing)",
        max_length=MAX_CONTENT_SIZE,
    )


class VaultAnalyticsSummaryInput(BaseModel):
    """Build a compact analytics summary for a vault path."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    path_prefix: str | None = Field(
        default=None,
        description="Optional folder prefix to restrict the analysis",
        max_length=500,
    )
    required_frontmatter: list[str] | None = Field(
        default=None,
        description="Optional required frontmatter fields to validate",
        max_length=20,
    )
    max_examples: int = Field(
        default=3,
        ge=1,
        le=20,
        description="Maximum example findings to include per category",
    )


class VaultAnalyticsFindingsInput(BaseModel):
    """Return detailed findings for one analytics category."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    category: AnalyticsFindingCategory = Field(
        ...,
        description="Analytics finding category to return",
    )
    path_prefix: str | None = Field(
        default=None,
        description="Optional folder prefix to restrict the analysis",
        max_length=500,
    )
    required_frontmatter: list[str] | None = Field(
        default=None,
        description="Optional required frontmatter fields to validate",
        max_length=20,
    )
    max_results: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of findings to return",
    )

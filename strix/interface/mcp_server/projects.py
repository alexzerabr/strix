"""Resolve a project name to a directory under one confined root.

An MCP client names a project (``"my-app"``); it never sends a path. This module
turns that name into an absolute directory under ``STRIX_PROJECTS_ROOT`` and
refuses anything that would escape the root, so a caller cannot ask Strix to scan
``/etc`` or ``../../secrets`` by smuggling a path into the name.
"""

from __future__ import annotations

import os
from pathlib import Path


DEFAULT_PROJECTS_ROOT = "/projects"


class ProjectError(ValueError):
    """A project name could not be resolved to a directory under the root."""


def projects_root() -> Path:
    """The confined root every project must live under (``STRIX_PROJECTS_ROOT``)."""
    return Path(os.environ.get("STRIX_PROJECTS_ROOT") or DEFAULT_PROJECTS_ROOT)


def resolve_project(name: str) -> Path:
    """Absolute path of project ``name`` under the root, or raise ``ProjectError``.

    Rejects an empty name, a name with path separators or ``..`` segments, and
    any resolved path that lands outside the root (which also catches a symlink
    inside the root that points out of it, since ``resolve()`` follows links).
    """
    cleaned = (name or "").strip()
    if not cleaned:
        raise ProjectError("project name is empty")
    if "/" in cleaned or "\\" in cleaned or cleaned in {".", ".."}:
        raise ProjectError(
            f"invalid project name {name!r}: it must be a bare directory name under the "
            "projects root, not a path"
        )

    root = projects_root().resolve()
    candidate = (root / cleaned).resolve()
    if candidate != root and root not in candidate.parents:
        raise ProjectError(f"project {name!r} resolves outside the projects root {str(root)!r}")
    if not candidate.is_dir():
        raise ProjectError(
            f"project {name!r} is not a directory under {str(root)!r}; clone or sync it there first"
        )
    return candidate


def list_projects() -> list[str]:
    """Names of the immediate directories under the root, sorted; empty if none."""
    root = projects_root()
    if not root.is_dir():
        return []
    return sorted(entry.name for entry in root.iterdir() if entry.is_dir())

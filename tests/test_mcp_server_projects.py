"""The confined-root resolver is the security boundary: a client names a project,
never a path, and nothing may resolve outside the projects root."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from strix.interface.mcp_server import projects


@pytest.fixture
def _root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("STRIX_PROJECTS_ROOT", str(tmp_path))
    (tmp_path / "my-app").mkdir()
    return tmp_path


def test_resolves_a_project_directory_under_the_root(_root: Path) -> None:
    assert projects.resolve_project("my-app") == (_root / "my-app").resolve()


@pytest.mark.parametrize(
    "name",
    [
        "",
        "   ",
        ".",
        "..",
        "../secrets",
        "sub/dir",
        "a\\b",
        "/etc",
    ],
)
def test_a_name_that_is_a_path_or_escapes_is_rejected(_root: Path, name: str) -> None:
    with pytest.raises(projects.ProjectError):
        projects.resolve_project(name)


def test_a_symlink_pointing_out_of_the_root_is_rejected(_root: Path, tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-tree"
    outside.mkdir()
    (_root / "escape").symlink_to(outside)
    # resolve() follows the link, so the resolved path lands outside the root.
    with pytest.raises(projects.ProjectError, match="outside"):
        projects.resolve_project("escape")


def test_a_missing_project_is_rejected_with_guidance(_root: Path) -> None:
    with pytest.raises(projects.ProjectError, match="clone or sync it there first"):
        projects.resolve_project("not-cloned-yet")


def test_a_file_is_not_a_project(_root: Path) -> None:
    (_root / "readme.txt").write_text("x", encoding="utf-8")
    with pytest.raises(projects.ProjectError):
        projects.resolve_project("readme.txt")


def test_list_projects_returns_only_directories_sorted(_root: Path) -> None:
    (_root / "zebra").mkdir()
    (_root / "alpha").mkdir()
    (_root / "loose.txt").write_text("x", encoding="utf-8")
    assert projects.list_projects() == ["alpha", "my-app", "zebra"]


def test_list_projects_is_empty_when_root_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STRIX_PROJECTS_ROOT", str(tmp_path / "nope"))
    assert projects.list_projects() == []

"""Jobs launch run_strix_scan without waiting, read status back from run.json,
and reject bad arguments before anything is launched."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface.mcp_server import jobs
from strix.interface.mcp_server.projects import ProjectError


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("STRIX_PROJECTS_ROOT", str(tmp_path))
    proj = tmp_path / "my-app"
    proj.mkdir()
    (proj / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)  # run_dir_for reads strix_runs/ under cwd
    return proj


def _write_run_json(cwd: Path, scan_id: str, payload: dict[str, Any]) -> None:
    run_dir = cwd / "strix_runs" / scan_id
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps(payload), encoding="utf-8")


def test_start_launches_a_task_and_returns_at_once(
    _project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched: dict[str, Any] = {}

    async def _fake_run(**kwargs: Any) -> None:
        launched.update(kwargs)
        await asyncio.sleep(0)

    monkeypatch.setattr(jobs, "run_strix_scan", _fake_run)
    monkeypatch.setattr(jobs, "_resolve_sandbox_image", lambda: "img:test")

    async def _go() -> dict[str, str]:
        result = await jobs.start("my-app", scan_mode="quick")
        await jobs._tasks[result["scan_id"]]  # let the launched task run
        return result

    result = asyncio.run(_go())
    assert result["status"] == "started"
    assert result["scan_id"]
    assert launched["scan_id"] == result["scan_id"]
    assert launched["scan_config"]["scan_mode"] == "quick"
    assert launched["scan_config"]["non_interactive"] is True
    assert launched["local_sources"], "a local project must produce a bind-mount source"


def test_unknown_scan_mode_is_rejected_before_launch(_project: Path) -> None:
    with pytest.raises(jobs.JobError, match="unknown scan_mode"):
        asyncio.run(jobs.start("my-app", scan_mode="turbo"))


def test_non_positive_budget_is_rejected(_project: Path) -> None:
    with pytest.raises(jobs.JobError, match="max_budget must be positive"):
        asyncio.run(jobs.start("my-app", max_budget=0))


def test_a_project_name_that_escapes_is_rejected(_project: Path) -> None:
    with pytest.raises(ProjectError):
        asyncio.run(jobs.start("../elsewhere"))


def test_status_reads_from_run_json(_project: Path) -> None:
    _write_run_json(
        _project.parent,
        "run-xyz",
        {
            "status": "completed",
            "vulnerabilities": [{"title": "SQLi"}, {"title": "XSS"}],
            "llm_usage": {"total_tokens": 1_537_209, "cost": 0.0},
        },
    )
    result = jobs.status("run-xyz")
    assert result["status"] == "completed"
    assert result["vulnerabilities"] == 2
    assert result["tokens"] == 1_537_209
    assert result["cost"] == 0.0


def test_status_of_an_unknown_id_is_unknown(_project: Path) -> None:
    assert jobs.status("never-started")["status"] == "unknown"


def test_findings_projects_the_fields_agents_need(_project: Path) -> None:
    _write_run_json(
        _project.parent,
        "run-f",
        {
            "status": "completed",
            "vulnerabilities": [
                {
                    "title": "Command injection",
                    "severity": "critical",
                    "file": "app.py",
                    "proof_of_concept": "GET /ping?host=;id",
                }
            ],
        },
    )
    out = jobs.findings("run-f")
    assert out == [
        {
            "title": "Command injection",
            "severity": "critical",
            "file": "app.py",
            "poc": "GET /ping?host=;id",
        }
    ]


def test_cancel_of_an_untracked_scan_is_not_found(_project: Path) -> None:
    assert asyncio.run(jobs.cancel("nope"))["status"] == "not_found"

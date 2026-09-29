"""Jobs launch run_strix_scan without waiting, read status back from run.json,
and reject bad arguments before anything is launched."""

from __future__ import annotations

import asyncio
import contextlib
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
    # run_strix_scan reads the report state through the global, so start() must
    # register one before launching, or the scan writes no run.json and status
    # stays empty. Proven on the deployment host: without this, a live scan ran
    # for 10 minutes and never wrote run.json.
    run_json = _project.parent / "strix_runs" / result["scan_id"] / "run.json"
    assert run_json.is_file(), "start() must set up ReportState so run.json is written"


def test_url_target_launches_black_box(_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    launched: dict[str, Any] = {}

    async def _fake_run(**kwargs: Any) -> None:
        launched.update(kwargs)
        await asyncio.sleep(0)

    monkeypatch.setattr(jobs, "run_strix_scan", _fake_run)
    monkeypatch.setattr(jobs, "_resolve_sandbox_image", lambda: "img:test")

    async def _go() -> dict[str, str]:
        result = await jobs.start(target="http://10.1.20.199:49374/web", scan_mode="quick")
        await jobs._tasks[result["scan_id"]]
        return result

    result = asyncio.run(_go())
    assert result["status"] == "started"
    targets = launched["scan_config"]["targets"]
    assert targets[0]["type"] == "web_application"
    assert targets[0]["details"]["target_url"] == "http://10.1.20.199:49374/web"
    # A URL has no local source to bind-mount.
    assert launched["local_sources"] == []


def test_exactly_one_of_project_or_target(_project: Path) -> None:
    with pytest.raises(jobs.JobError, match="exactly one of project or target"):
        asyncio.run(jobs.start())
    with pytest.raises(jobs.JobError, match="exactly one of project or target"):
        asyncio.run(jobs.start(project="my-app", target="http://x.test/"))


def test_a_local_path_as_target_is_refused(_project: Path) -> None:
    # A filesystem path must go through `project` (confined to the root); allowing
    # it via `target` would reach the host's disk outside the confinement.
    with pytest.raises(jobs.JobError, match="local path"):
        asyncio.run(jobs.start(target=str(_project)))


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


def test_status_reports_failed_when_the_task_died_before_writing_run_json(
    _project: Path,
) -> None:
    # A scan can fail before ReportState writes any run.json (LLM auth fails at
    # warm-up). Reproduced end to end on the remote: the client polled "running"
    # forever. A finished-with-exception task must read as failed, not running.
    async def _boom() -> None:
        raise RuntimeError("OAuth session expired")

    async def _go() -> str:
        task = asyncio.create_task(_boom())
        with contextlib.suppress(RuntimeError):
            await task
        jobs._tasks["scan-died"] = task
        return str(jobs.status("scan-died")["status"])

    assert asyncio.run(_go()) == "failed"


def test_status_reports_running_only_while_the_task_lives(_project: Path) -> None:
    started = asyncio.Event()

    async def _go() -> str:
        async def _long() -> None:
            started.set()
            await asyncio.sleep(5)

        task = asyncio.create_task(_long())
        await started.wait()
        jobs._tasks["scan-live"] = task
        state = str(jobs.status("scan-live")["status"])
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return state

    assert asyncio.run(_go()) == "running"


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

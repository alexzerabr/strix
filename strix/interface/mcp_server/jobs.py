"""Run Strix scans as background jobs for the MCP server.

An MCP tool call has to return in seconds; a scan runs for minutes to hours. So
:func:`start` launches :func:`strix.core.runner.run_strix_scan` as a task and
returns the ``scan_id`` at once, and :func:`status` reads it back from the
``run.json`` the scan already persists -- which means status survives a restart
of the server, since it is read from disk, not from this process's memory.

One scan runs at a time (a module-level semaphore): a subscription is a single
rate-limit ceiling, so two parallel scans would only contend for the same quota.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import TYPE_CHECKING, Any

from strix.core.paths import run_dir_for
from strix.core.runner import run_strix_scan
from strix.interface.cli import _resolve_sandbox_image
from strix.interface.mcp_server.projects import resolve_project
from strix.interface.scan_setup import build_targets_info
from strix.interface.utils import collect_local_sources, generate_run_name
from strix.report.state import ReportState, set_global_report_state
from strix.report.writer import read_run_record


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_SCAN_MODES = ("lightning", "quick", "standard", "deep")

# Statuses a scan's run.json reports once it has reached an end; anything else
# (or a missing run.json) defers to the launched task's own state.
_TERMINAL_STATUSES = frozenset({"completed", "failed", "crashed", "interrupted"})

_tasks: dict[str, asyncio.Task[Any]] = {}
_semaphore: asyncio.Semaphore | None = None


class JobError(ValueError):
    """A scan could not be started with the given arguments."""


def _slots() -> asyncio.Semaphore:
    # Bound to the server's single event loop, created on first use so import
    # does not need a running loop.
    global _semaphore  # noqa: PLW0603
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(1)
    return _semaphore


def _scan_config(args: argparse.Namespace) -> dict[str, Any]:
    """The scan_config run_strix_scan expects, mirroring the CLI's own builder."""
    return {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
        "diff_scope": {"active": False},
        "scan_mode": args.scan_mode,
        "non_interactive": True,
        "local_sources": args.local_sources,
        "workspace_files": [],
        "scope_mode": "auto",
        "diff_base": None,
        "resume_instruction": "",
    }


def _prepare(
    project: str, scan_mode: str, instruction: str | None, max_budget: float | None
) -> tuple[argparse.Namespace, float | None]:
    if scan_mode not in _SCAN_MODES:
        raise JobError(f"unknown scan_mode {scan_mode!r}: expected one of {', '.join(_SCAN_MODES)}")
    if max_budget is not None and max_budget <= 0:
        raise JobError(f"max_budget must be positive, received {max_budget!r}")

    project_dir = resolve_project(project)  # raises ProjectError on a bad name

    args = argparse.Namespace(
        target=[str(project_dir)],
        target_list=[],
        instruction=instruction,
        scan_mode=scan_mode,
    )
    build_targets_info(args)  # fills args.targets_info; raises ValueError on bad target
    args.local_sources = collect_local_sources(args.targets_info)
    args.run_name = generate_run_name(args.targets_info)
    return args, max_budget


async def start(
    project: str,
    scan_mode: str = "quick",
    instruction: str | None = None,
    max_budget: float | None = None,
) -> dict[str, str]:
    """Launch a scan of ``project`` and return its ``scan_id`` without waiting."""
    args, budget = _prepare(project, scan_mode, instruction, max_budget)
    scan_id = args.run_name
    scan_config = _scan_config(args)

    async def _run() -> None:
        async with _slots():
            # run_strix_scan reads the report state through get_global_report_state,
            # so the caller has to build and register it first, exactly as the CLI
            # does. Without this the scan runs but writes no run.json, so status and
            # findings stay empty. Set inside the semaphore (one scan at a time), so
            # the global always belongs to the scan that is actually running.
            report_state = ReportState(scan_id)
            report_state.hydrate_from_run_dir()
            report_state.set_scan_config(scan_config)
            report_state.save_run_data()
            set_global_report_state(report_state)
            await run_strix_scan(
                scan_config=scan_config,
                scan_id=scan_id,
                image=_resolve_sandbox_image(),
                local_sources=args.local_sources,
                max_budget_usd=budget,
            )

    task = asyncio.create_task(_run())
    _tasks[scan_id] = task
    task.add_done_callback(lambda t: _log_task_result(scan_id, t))
    logger.info("MCP scan launched: scan_id=%s project=%s mode=%s", scan_id, project, scan_mode)
    return {"scan_id": scan_id, "status": "started"}


def _log_task_result(scan_id: str, task: asyncio.Task[Any]) -> None:
    if task.cancelled():
        logger.info("MCP scan cancelled: scan_id=%s", scan_id)
        return
    exc = task.exception()
    if exc is not None:
        logger.error("MCP scan failed: scan_id=%s: %s", scan_id, exc)


def _record(scan_id: str) -> dict[str, Any]:
    run_dir: Path = run_dir_for(scan_id)
    return read_run_record(run_dir)  # {} when the scan has not written yet


def status(scan_id: str) -> dict[str, Any]:
    """Live status of a scan, read from its ``run.json`` on disk.

    ``"unknown"`` when nothing has been written yet and no task is tracked here,
    so a caller can tell a never-started id from one still spinning up.
    """
    record = _record(scan_id)
    usage = record.get("llm_usage") or {}
    reported = record.get("status")
    task_state = _task_state(_tasks.get(scan_id))
    # A finished task overrides a missing or non-terminal run.json status. A scan
    # can fail before ReportState writes any run.json (e.g. LLM auth fails at
    # warm-up), and without this the caller would poll "running" forever on a scan
    # that already ended.
    if reported not in _TERMINAL_STATUSES and task_state is not None:
        reported = task_state
    return {
        "scan_id": scan_id,
        "status": reported or "unknown",
        "vulnerabilities": len(record.get("vulnerabilities") or []),
        "tokens": usage.get("total_tokens", 0),
        "cost": usage.get("cost", 0.0),
    }


def _task_state(task: asyncio.Task[Any] | None) -> str | None:
    """Status derived from the launched task, or None when none is tracked here."""
    if task is None:
        return None
    if not task.done():
        return "running"
    if task.cancelled():
        return "cancelled"
    return "failed" if task.exception() is not None else "completed"


def findings(scan_id: str) -> list[dict[str, Any]]:
    """Reported vulnerabilities for a scan: title, severity, file, and PoC."""
    record = _record(scan_id)
    result: list[dict[str, Any]] = []
    for vuln in record.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        result.append(
            {
                "title": vuln.get("title") or vuln.get("name") or "",
                "severity": vuln.get("severity") or "",
                "file": vuln.get("file") or vuln.get("location") or "",
                "poc": vuln.get("proof_of_concept") or vuln.get("poc") or "",
            }
        )
    return result


async def cancel(scan_id: str) -> dict[str, str]:
    """Cancel a running scan. A no-op reported as ``not_found`` if it is not tracked."""
    task = _tasks.get(scan_id)
    if task is None or task.done():
        return {"scan_id": scan_id, "status": "not_found"}
    task.cancel()
    return {"scan_id": scan_id, "status": "cancelling"}

"""FastMCP app and the ``strix mcp-serve`` entry point.

Five tools front :mod:`strix.interface.mcp_server.jobs`; the bearer gate wraps
the streamable-HTTP ASGI app. This runs as a plain process on the Strix host
(see ``deploy/strix-mcp.service``), talking to the host's Docker, so bind mounts
of ``/projects/<name>`` resolve without any path translation.
"""

from __future__ import annotations

import argparse
import logging
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp import FastMCP

from strix.interface.mcp_server import jobs
from strix.interface.mcp_server.auth import BearerAuthMiddleware, require_token
from strix.interface.mcp_server.projects import list_projects, projects_root


if TYPE_CHECKING:
    from starlette.types import ASGIApp


logger = logging.getLogger(__name__)

_INSTRUCTIONS = (
    "Run autonomous Strix penetration tests against a project already present on "
    "this host under the projects root. Name the project; do not send a path. "
    "strix_scan_start returns a scan_id immediately (a scan runs for minutes to "
    "hours); poll strix_scan_status until it reports completed, then read "
    "strix_scan_findings."
)


def register_tools(mcp: FastMCP) -> None:
    """Register the five Strix tools on ``mcp``. The single source of the tool set."""

    @mcp.tool()
    async def strix_scan_start(
        project: str | None = None,
        scan_mode: str = "quick",
        instruction: str | None = None,
        max_budget: float | None = None,
        target: str | None = None,
    ) -> dict[str, str]:
        """Start a scan and return its scan_id. Pass exactly one of project or target.

        project: bare directory name under the projects root (e.g. "my-app"),
            scanned white-box; the name is confined to the root.
        target: a URL, domain, or IP scanned black-box (e.g.
            "http://10.0.0.5:8080/"); not confined to the projects root, so the
            bearer token is the only gate on what it may reach. A local path is
            refused here -- use project for local code.
        scan_mode: lightning | quick | standard | deep.
        instruction: optional free-text guidance for the agents.
        max_budget: optional USD ceiling (ignored on a $0 subscription backend).
        """
        return await jobs.start(project, scan_mode, instruction, max_budget, target)

    @mcp.tool()
    def strix_scan_status(scan_id: str) -> dict[str, Any]:
        """Live status of a scan: status, vulnerability count, tokens, and cost."""
        return jobs.status(scan_id)

    @mcp.tool()
    def strix_scan_findings(scan_id: str) -> list[dict[str, Any]]:
        """Reported vulnerabilities for a scan: title, severity, file, and PoC."""
        return jobs.findings(scan_id)

    @mcp.tool()
    async def strix_scan_cancel(scan_id: str) -> dict[str, str]:
        """Cancel a running scan."""
        return await jobs.cancel(scan_id)

    @mcp.tool()
    def strix_projects_list() -> list[str]:
        """Project names available to scan under the projects root."""
        return list_projects()


def build_asgi_app(mcp: FastMCP, token: str) -> ASGIApp:
    """Register the tools on ``mcp`` and return the bearer-guarded ASGI app."""
    register_tools(mcp)
    return BearerAuthMiddleware(mcp.streamable_http_app(), token=token)


def serve(argv: list[str]) -> int:
    """Entry point for ``strix mcp-serve``. Returns a process exit code."""
    parser = argparse.ArgumentParser(prog="strix mcp-serve", add_help=True)
    # 0.0.0.0 by default is the point: a LAN server must be reachable from other
    # hosts. The bearer token, not the bind address, is the access gate.
    default_host = "0.0.0.0"  # nosec B104
    parser.add_argument(
        "--host", default=default_host, help="Interface to bind (default: 0.0.0.0)."
    )
    parser.add_argument("--port", type=int, default=8848, help="Port to bind (default: 8848).")
    args = parser.parse_args(argv)

    try:
        token = require_token()  # fail fast before binding; never start open
    except Exception as exc:  # noqa: BLE001
        # Expected, actionable failure (no token): log the message, not a traceback.
        logger.error("%s", exc)  # noqa: TRY400
        return 1

    import uvicorn

    mcp = FastMCP("strix", instructions=_INSTRUCTIONS, host=args.host, port=args.port)
    app = build_asgi_app(mcp, token)

    logger.info(
        "Strix MCP server on %s:%s, projects root %s", args.host, args.port, str(projects_root())
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0

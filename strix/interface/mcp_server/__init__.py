"""Self-hosted MCP server that exposes Strix scans to LAN agents.

Strix is normally driven from the CLI; this package adds a thin MCP front door
so an agent (Claude, Codex, ...) on the same network can start an audit of a
project already present on this host and poll it to completion. It drives
:func:`strix.core.runner.run_strix_scan` -- the same entry point the CLI uses --
and adds nothing to the scan itself.

See ``deploy/strix-mcp.service`` for how it is meant to run (a systemd process
on the host, talking to the host's Docker), and the ``strix mcp-serve``
subcommand for the entry point.
"""

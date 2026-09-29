# Strix as an MCP server (self-hosted)

Strix is normally an MCP *client* — it connects to MCP servers you list and
exposes their tools to the pentest agents (see `mcp.mdx`). This is the other
direction: running Strix itself as an MCP *server*, so agents on your LAN
(Claude, Codex, and others) can start a scan of a project on this host and poll
it to completion.

It drives the same `run_strix_scan` entry point the CLI uses; it adds nothing to
the scan. Think of it as a thin front door on the machine that already runs
Strix and Docker.

## Topology

The agents run on their own machines and hold no Docker. This host runs Strix,
Docker, and the sandbox, and the projects to audit already live here under a
confined root. An agent names a project; it never sends code.

```
[Claude / Codex on the LAN]  --MCP / HTTP + bearer-->  [this host]
                                                        strix mcp-serve
                                                        Docker + sandbox
                                                        /projects/<name>
```

Because the server runs as a plain process on this host talking to this host's
Docker, a bind mount of `/projects/<name>` resolves with no path translation.
That is why it is not itself containerized: Strix is designed to *command* a
Docker daemon (`docker.from_env()`), not to run inside one.

## Setup

1. Put the code to audit under the projects root, one directory per project:

   ```bash
   sudo mkdir -p /projects
   git clone <repo> /projects/my-app     # or sync it however you like
   ```

2. Sign the host in on the LLM backend once. The Claude subscription backend
   needs the `claude` CLI signed in on this host (`claude /login`); its OAuth
   works headless. Or use `anthropic/<model>` + `LLM_API_KEY`.

3. Start the server with a bearer token. It refuses to start without one, so it
   never binds the network unauthenticated:

   ```bash
   export STRIX_MCP_TOKEN="$(openssl rand -hex 32)"
   export STRIX_LLM="claude-code/claude-opus-5"
   export STRIX_PROJECTS_ROOT=/projects
   strix mcp-serve --host 0.0.0.0 --port 8848
   ```

   For a managed service, install `deploy/strix-mcp.service` (systemd) and set
   `STRIX_MCP_TOKEN` in an override.

## Connecting an agent

Point the agent's MCP client at `http://<host>:8848/mcp` (streamable HTTP) with
`Authorization: Bearer <STRIX_MCP_TOKEN>`. For Claude Code, in
`~/.claude/mcp-servers.json`:

```json
[
  {
    "name": "strix",
    "type": "http",
    "url": "http://strix-box.lan:8848/mcp",
    "headers": { "Authorization": "Bearer <STRIX_MCP_TOKEN>" }
  }
]
```

## Tools

| Tool | Returns |
| --- | --- |
| `strix_scan_start(project, scan_mode="quick", instruction=None, max_budget=None)` | `{scan_id, status}` — returns at once; the scan runs in the background |
| `strix_scan_status(scan_id)` | `{status, vulnerabilities, tokens, cost}`, read from `run.json` |
| `strix_scan_findings(scan_id)` | list of `{title, severity, file, poc}` |
| `strix_scan_cancel(scan_id)` | `{scan_id, status}` |
| `strix_projects_list()` | project names available under the root |

A scan runs for minutes (`quick`) to hours (`deep`), so `strix_scan_start`
returns a `scan_id` immediately; poll `strix_scan_status` until it reports
`completed`, then read `strix_scan_findings`. Status is read from the scan's
`run.json` on disk, so it survives a restart of the server.

One scan runs at a time. A subscription is a single rate-limit ceiling, so
running scans in parallel would only make them contend for the same quota.

## Security

- **Bearer token, always.** A LAN is not zero-trust: any host on the network can
  reach the port, so the token is what separates "on the network" from "allowed
  to spend the scan quota". Compared with a constant-time check.
- **Confined project root.** `project` is a bare directory name resolved under
  `STRIX_PROJECTS_ROOT`; a name with path separators, `..`, or a symlink that
  escapes the root is rejected. An agent cannot ask Strix to scan `/etc`.
- **Only scan what you are authorized to test.** The confined root makes that a
  property of what you place under it.
- **TLS** is not built in; put a reverse proxy in front if the traffic ever
  leaves a trusted LAN.

# sentinelx-core

The lightweight agent that runs on the user's server. Maintains a persistent WebSocket connection to [`sentinelx-hub`](https://github.com/pensados/sentinelx-hub) and executes commands on behalf of the user.

## What's different from the legacy core

The legacy `sentinelx-agent.py` (still running on `pensa-orion`) is a self-hosted FastAPI server. **This new core is its successor** — same execution logic, but instead of accepting HTTP requests directly, it opens an outbound WebSocket to the cloud hub. Benefits:

- No port forwarding, no nginx, no SSL setup on the user's side
- Works behind NAT, firewalls, and CGNAT without configuration
- One-line install
- Identity is per-user, managed via OAuth (Google) instead of self-issued bearer tokens

The actual command-execution code (the allowlist, capabilities, edit/upload/script endpoints) is **reused as-is** from the legacy agent. The new layer is just the WS client + protocol marshalling.

## Architecture

```
                        ┌─────────────────────────────┐
                        │  sentinelx-core (this repo) │
                        │                             │
   WSS to mcp.sentinelx │  ┌────────┐  ┌───────────┐  │
   ◀────────────────────┤  │ client │──│ executor  │──┼──▶ shell, files, systemd
                        │  └────────┘  └───────────┘  │
                        │                             │
                        └─────────────────────────────┘
```

- `client.py` — WebSocket client that handles connection, hello/welcome handshake, ping/pong, reconnection with exponential backoff
- `executor.py` — Receives `request` messages, dispatches to the right handler, returns `response`
- `handlers/` — One file per `op` (exec, edit, service, etc.) — these are thin wrappers around the proven legacy code
- `policy.py` — The allowlist: which commands and services this host is allowed to run (configured at install)
- `identity.py` — Loads `/etc/sentinelx/identity.json` (host_id + enrollment token)

## Running

The agent is started by systemd via `sentinelx-core.service` (installed by `sentinelx-installer`):

```bash
sudo systemctl status sentinelx-core
sudo journalctl -u sentinelx-core -f
```

For local development:

```bash
python -m sentinelx_core --hub ws://localhost:8000 --identity /tmp/identity.json
```

## Configuration

Single config file at `/etc/sentinelx/config.yaml`:

```yaml
# Commands the agent will execute. The hub doesn't enforce this — the agent does.
allowed_commands:
  - systemctl
  - docker
  - nginx -t
  - cat
  - tail
  - journalctl

# Service units that the user has explicitly authorized for restart/status
services:
  nginx:
    unit: nginx
    actions: [status, start, stop, restart, reload, validate]
  docker:
    unit: docker
    actions: [status, restart]
```

## Protocol

Speaks the wire protocol defined in [`sentinelx-protocol`](https://github.com/pensados/sentinelx-protocol). The current core ships with `protocol_version = 1.0.0`.

# sentinelx-cloud-core

The SentinelX agent. Runs as a systemd service on a Linux host and connects out to a SentinelX hub via WebSocket. The hub exposes the host as an MCP connector to LLMs like Claude.ai and ChatGPT.

> **Most users don't install this directly.** Use the one-line installer:
> ```bash
> curl -fsSL https://get.sentinelx.app | sudo bash
> ```
> See [`sentinelx-cloud-installer`](https://github.com/pensados/sentinelx-cloud-installer) for details.

This README is for people who want to understand or modify the agent itself.

---

## What it does

When connected, the agent exposes the following operations to the hub (forwarded to the LLM as MCP tools):

| Operation | What it does |
|---|---|
| `ping` | Health check |
| `capabilities` | Lists allowed commands, paths, services, playbooks from `config.yaml` |
| `help` | Returns a human-readable help section |
| `state` | Snapshot of host state (kernel, OS, uptime, hostname) |
| `exec` | Run a command from the allowlist |
| `service` | systemctl wrapper (start/stop/restart/reload/status, allowlisted) |
| `restart` | Restart a service |
| `script_run` | Run a one-off bash or python3 script |
| `edit` | Structured file edit (replace, regex, replace-block, append, prepend, write) with optional validation |
| `upload_file`, `upload_init`, `upload_chunk`, `upload_complete` | Single + chunked file uploads |
| `edit_upload_file`, `edit_upload_init`, `edit_upload_complete` | Edit using files staged via upload (for big content) |

Every operation is gated by the allowlist in `/etc/sentinelx/config.yaml`. The agent refuses anything not explicitly listed.

---

## Architecture

```
                         ┌────────────────────────────────────┐
                         │      sentinelx-cloud-core          │
                         │                                    │
                         │  ┌────────┐    ┌─────────────────┐ │
   wss://mcp.sentinelx   │  │        │    │                 │ │
   ◀─────────────────────┼──┤ client │────│ executor + 16   │─┼──▶ shell / files / systemd
                         │  │  (WS)  │    │ handlers        │ │
                         │  └────────┘    └─────────────────┘ │
                         │       │              │             │
                         │       │              └─ policy ────┼──◀ /etc/sentinelx/config.yaml
                         │       │                            │
                         │       └─ identity ─────────────────┼──◀ /etc/sentinelx/identity.json
                         └────────────────────────────────────┘
```

- **`client.py`** — WebSocket client. Handles hello/welcome handshake, ping/pong heartbeat, exponential-backoff reconnection.
- **`executor.py`** — Receives `request` messages, dispatches to a handler, returns a `response`.
- **`handlers/`** — One module per operation. Each enforces its part of the policy.
- **`policy.py`** — Loads `config.yaml`, exposes the allowlist to handlers.
- **`executor_engine.py`** — Low-level command runner used by handlers (`run_shell`, `run_shell_split`, `safe_path_under`).
- **`identity.py`** — Reads `identity.json` (the per-host enrollment JWT).

The agent depends on [`sentinelx-cloud-protocol`](https://github.com/pensados/sentinelx-cloud-protocol) for the wire format (Hello, Welcome, Request, Response, Pong messages — all Pydantic models).

---

## Configuration

The agent reads two files at startup, both under `/etc/sentinelx/`:

### `identity.json`

Written once by the installer during enrollment. Contents:

```json
{
  "host_id": "host_0f56813c3e894ded",
  "token": "eyJhbGc...",
  "hub": "wss://mcp.sentinelx.app"
}
```

The `token` is a signed JWT issued by the hub during the OAuth flow. It binds this host to a specific `(user_id, host_id)` pair on the hub side.

### `config.yaml`

The allowlist and capabilities of this host. See [`config.example.yaml`](./config.example.yaml) for the minimal set, [`config.orion.example.yaml`](./config.orion.example.yaml) for a richer example with 110+ commands.

Minimal config:

```yaml
agent:
  hostname_label: my-server
allowed_commands:
  - echo
  - whoami
  - hostname
  - df -h
  - free -h
  - uptime
  - cat /etc/os-release
upload_base: /var/lib/sentinelx/uploads
services: {}
```

Richer config can additionally declare:

- **`paths`** — directories the agent is allowed to read/write under
- **`services`** — systemd units the agent is allowed to control (with per-service action lists)
- **`playbooks`** — named sequences of commands the agent can run as a unit
- **`locations`** — symbolic names for paths (e.g. `nginx_conf: /etc/nginx`) that the LLM can reference

The example configs are the source of truth for the schema.

---

## Running manually (for development)

```bash
git clone https://github.com/pensados/sentinelx-cloud-core
cd sentinelx-cloud-core
python -m venv .venv
.venv/bin/pip install -e .

# You'll need an identity.json — get one via the dashboard enrollment flow:
# https://mcp.sentinelx.app/auth/dashboard/enroll?host_id=dev-machine-1

.venv/bin/sentinelx-cloud-core \
    --hub wss://mcp.sentinelx.app \
    --identity ./identity.json \
    --config ./config.example.yaml \
    --log-level DEBUG
```

Logs go to stderr in development. Under systemd they're captured by journald.

---

## Tests

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

53 unit tests cover the engine, policy parser, and each handler.

---

## Security model

- **The agent never exposes a port.** All communication is outbound WSS to the hub.
- **The allowlist is the only authority.** A command not in `config.yaml` is rejected even if the LLM asks for it nicely.
- **The agent runs as the unprivileged `sentinelx` user.** To run commands that need root, configure sudo explicitly:
  ```bash
  # /etc/sudoers.d/sentinelx
  sentinelx ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx
  ```
  And reference it in the config:
  ```yaml
  services:
    nginx:
      sudo: true
      actions: [reload]
  ```
- **Identity is per-host.** Compromising one host's `identity.json` doesn't grant access to other hosts of the same user. The hub enforces this on every tool call.

---

## Related repos

- [`sentinelx-cloud-installer`](https://github.com/pensados/sentinelx-cloud-installer) — the one-line installer
- [`sentinelx-cloud-protocol`](https://github.com/pensados/sentinelx-cloud-protocol) — wire format

---

## License

Apache 2.0. See [`LICENSE`](./LICENSE).

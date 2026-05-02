# sentinelx-cloud-core

The SentinelX agent. Runs as a systemd service on a Linux host, connects out
to a SentinelX hub via WebSocket, and exposes that host's operations as MCP
tools to LLMs like Claude.ai and ChatGPT.

> **Most users don't install this directly.** Use the one-line installer:
> ```bash
> curl -fsSL https://get.sentinelx.app | sudo bash
> ```
> The rest of this README is for developers who want to understand, audit,
> or contribute to the agent.

## Architecture

```
                                        Internet
                                            │
   ┌────────────────┐                       │                  ┌─────────────────┐
   │  Claude.ai or  │   MCP over HTTPS      │   WebSocket      │  Your Linux box │
   │   ChatGPT      │ ◄───────────────────► │ ◄──────────────► │                 │
   │                │   (OAuth via Google)  │                  │  ┌───────────┐  │
   └────────────────┘                       │                  │  │  agent    │  │
                                ┌───────────────────────┐      │  │ (this)    │  │
                                │   mcp.sentinelx.app   │      │  └─────┬─────┘  │
                                │  (SentinelX hub —     │      │        │        │
                                │   closed source)      │      │   shell, edit,  │
                                └───────────────────────┘      │   service mgmt  │
                                                               └─────────────────┘
```

The agent is the box on the right. It opens **one outbound WebSocket** to the
hub at install time (after enrollment) and stays connected. No inbound ports,
no port-forwarding, no reverse tunnel.

## What runs where

| Component | Where | What it does |
|---|---|---|
| `sentinelx-cloud-core` (this repo) | `/opt/sentinelx-cloud-core` on your host | Receives MCP tool calls from the hub, executes them locally, returns output |
| Hub | `mcp.sentinelx.app` (Anthropic-side) | Auth, multi-host routing, MCP transport |
| Config | `/etc/sentinelx/config.yaml` | Allowlist: which commands, services, and paths the agent will accept |
| Identity | `/etc/sentinelx/identity.json` | The agent's enrollment JWT, used to authenticate the WebSocket handshake |

## Tools exposed

The agent exposes 16 MCP tools to your LLM via the hub:

| Tool | What it does |
|---|---|
| `sentinel_exec` | Run an allowlisted shell command |
| `sentinel_script_run` | Run a one-off bash or python3 script |
| `sentinel_edit` | Structured file edit (replace, regex, write, append, prepend) |
| `sentinel_edit_upload_*` | Three-step upload for large file edits |
| `sentinel_service` | systemctl start/stop/restart/reload/status |
| `sentinel_restart` | Shortcut for `sentinel_service` with action=restart |
| `sentinel_upload_file` | Single-shot file upload to the host |
| `sentinel_upload_*` | Three-step chunked upload for large files |
| `sentinel_capabilities` | Returns the host's allowlist + service definitions |
| `sentinel_help` | The help text the operator put in the config |
| `sentinel_state` | Internal agent state, for debugging |
| `sentinel_ping` | Cheap connectivity check |

## Config (`/etc/sentinelx/config.yaml`)

A starter config is generated at install time. Editable. Reloaded when the
service restarts. Schema sketch:

```yaml
exec:
  allow:
    - "df -h"
    - "uptime"
    - "free -m"
    - "systemctl status nginx"
    # ... whatever shell commands you want to allow

services:
  allow:
    - nginx
    - postgresql
    # ... whatever systemd units the agent can touch

paths:
  allow_edit:
    - "/etc/nginx/"
    - "/etc/sentinelx/help.md"
    # ... directories the agent can edit files in

playbooks:
  health:
    description: "Show system health summary"
    commands:
      - "uptime"
      - "df -h /"
      - "free -m"

help: |
  This host runs a Postgres replica and an nginx fronted webapp.
  Don't touch /etc/postgresql/ during business hours.
```

The agent **only** runs what's allowlisted. Out of the box it's restrictive;
expand as you trust the LLM with more.

## Security model

- **No inbound ports.** Only an outbound WebSocket to the hub.
- **JWT-bound identity.** `identity.json` is signed by the hub at enrollment.
  Compromising one host doesn't grant access to others.
- **Allowlist-gated.** Anything not in `config.yaml` returns
  `command_not_allowed`. The agent won't synthesize new commands. **This is
  the actual security boundary** — not the unix user, not sudo policy.
- **Unprivileged user with passwordless sudo.** The agent runs as `sentinelx`,
  not as root. By default the installer grants `sentinelx` passwordless sudo
  so it can manage services and edit system files — but it can still only
  invoke what's in your allowlist. To run with no sudo, set
  `SENTINELX_SKIP_SUDO=1` during install.
- **No telemetry.** The agent reports nothing about your host or activity to
  anyone but the hub you're explicitly connected to.

## Local development

```bash
git clone https://github.com/pensados/sentinelx-cloud-core
cd sentinelx-cloud-core
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest                              # 53 unit tests
```

To run the agent against a hub other than the production one:

```bash
SENTINELX_HUB_URL=wss://localhost:8000/agent/connect \
  python3 -m sentinelx_core --identity-file /tmp/dev-identity.json
```

## Vendored: pensa-safe-edit

`sentinel_edit` shells out to a small Python script called `pensa-safe-edit`
that handles the actual file mutations safely. It's vendored at
`src/sentinelx_core/vendored/pensa_safe_edit.py` and registered as a
`pip` console-script entry point so `pip install` puts it on `$PATH`. It is
stdlib-only and does its work via temp files + atomic rename + optional
validator (json/yaml/python/sh/nginx/systemd presets).

## Related

- [`sentinelx-cloud-installer`](https://github.com/pensados/sentinelx-cloud-installer) — the bash + python installer
- [`sentinelx-cloud-protocol`](https://github.com/pensados/sentinelx-cloud-protocol) — wire format spec

## License

Apache 2.0

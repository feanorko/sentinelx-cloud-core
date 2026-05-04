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
| `sentinel_help` | A short summary of the agent plus counts of allowed commands, services, and playbooks |
| `sentinel_state` | Internal agent state, for debugging |
| `sentinel_ping` | Cheap connectivity check |

## Config (`/etc/sentinelx/config.yaml`)

A starter config is generated at install time. Editable. Reloaded when the
service restarts. Schema:

```yaml
# Commands the agent can execute via the `exec` op. Prefix-matched against
# this list; empty/missing = nothing allowed (deny by default).
allowed_commands:
  - uptime
  - df -h
  - free
  - systemctl
  - sudo systemctl
  - journalctl
  # See config.example.yaml for the full starter list (file inspection,
  # networking, containers, git, etc.) plus opt-in categories
  # (Cloudflare tunnels, WireGuard, Android tooling, firewalling, SSH).

# Service units the agent is allowed to control via `service` / `restart`.
# Each unit explicitly lists which actions are permitted.
services:
  nginx:
    actions: [status, start, stop, restart, reload]
  docker:
    actions: [status, restart]
  # The agent itself, so the LLM can reload policy after editing the
  # config. Restarting re-reads /etc/sentinelx/config.yaml. Conservative
  # actions only — no start/stop, since the agent can't remotely start
  # itself once stopped.
  sentinelx-cloud-core:
    actions: [status, restart, is-active, is-enabled]
  # postgresql:
  #   actions: [status, start, stop, restart, reload]

# Optional: named playbooks the LLM can read or execute. Two shapes are
# supported and can coexist in the same map:
#
# 1) Diagnostic playbook — a fixed sequence of allowlisted commands the
#    agent can run in order. Useful for "give me a quick health snapshot"
#    type prompts where you want one named entry-point.
#
# 2) Procedure playbook — a structured recipe for the LLM to follow,
#    expressed in `description` / `when` / `steps` / `requires` / `notes`
#    fields. Pure documentation: the agent does NOT execute the steps,
#    the LLM reads them via `capabilities` and then calls the regular
#    tools (sentinel_exec, sentinel_edit, sentinel_service) on its own.
#
# See `config.example.yaml` for the full reference.
playbooks:
  # Diagnostic playbook (shape 1)
  health:
    description: "Show system health summary"
    commands:
      - "uptime"
      - "df -h /"
      - "free -m"

  # Procedure playbook (shape 2) — guides the LLM through extending the
  # allowlist itself. Useful so users can ask "let me run htop here" and
  # the LLM knows the exact procedure (edit config, restart service,
  # verify with capabilities).
  add_allowed_command:
    description: "How to add a new command to this host's allowlist"
    when: "User asks to allow a new command on this host"
    steps:
      - "Read /etc/sentinelx/config.yaml with sentinel_exec"
      - "Insert under allowed_commands with sentinel_edit (sudo, validator_preset=yaml)"
      - "Restart the agent: sentinel_service restart sentinelx-cloud-core"
      - "Verify with sentinel_capabilities"

# Logging
log:
  path: /var/log/sentinelx/core.log
  level: INFO
```

The agent **only** runs commands that prefix-match `allowed_commands`. So
allowing `git` lets the LLM run `git status`, `git log`, etc.; allowing
`ls` is enough to cover `ls -lah /var/log`. Out of the box the config is
restrictive — see `config.example.yaml` for the full starter list with
sensible categories.

File edits via `sentinel_edit` are gated by **unix file permissions** (plus
`sudo NOPASSWD` for `pensa-safe-edit` if installed), not by a path
allowlist in `config.yaml`.

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

"""Platform-aware guidance for user-facing error messages and help text.

The agent runs on Linux (systemd, root-owned /etc/sentinelx) and macOS (launchd,
user-owned ~/sentinelx). Messages that tell the operator how to edit the policy
or reload the agent must adapt to the platform, or macOS users get pointed at
/etc/sentinelx and `systemctl` (neither of which exists there). Centralized here
so each message stays a one-liner and there's a single place to update.
"""
from __future__ import annotations

import sys

_DARWIN = sys.platform == "darwin"

# Policy file the operator edits.
CONFIG_PATH = "~/sentinelx/config.yaml" if _DARWIN else "/etc/sentinelx/config.yaml"

# Service key to pass to the service op for a self-restart.
SERVICE_KEY = "sentinelx" if _DARWIN else "sentinelx-cloud-core"

# Manual restart command for a real terminal (when the service op isn't usable).
MANUAL_RESTART = (
    "sudo launchctl kickstart -k system/app.sentinelx.core"
    if _DARWIN
    else "sudo systemctl restart sentinelx-cloud-core"
)

# sentinel_edit sudo hint: Linux config is root-owned (needs sudo=true); macOS
# config is user-owned and file-scoped rw (no sudo).
_EDIT_SUDO = "" if _DARWIN else "sudo=true and "

# Where to look for agent logs.
LOGS_HINT = (
    "~/sentinelx/agent.err (or: log show --predicate 'process == "
    '"sentinelx-cloud-core"' "' --last 5m)"
    if _DARWIN
    else "sudo journalctl -u sentinelx-cloud-core -n 30"
)

HOST_KIND = "macOS host" if _DARWIN else "Linux host"


def edit_config_via() -> str:
    """e.g. "sentinel_edit on ~/sentinelx/config.yaml with validator_preset='yaml'"."""
    return f"sentinel_edit on {CONFIG_PATH} with {_EDIT_SUDO}validator_preset='yaml'"


def reload_agent() -> str:
    """How to reload the policy after editing it."""
    return (
        f"reload the agent (sentinel_service action='restart' service='{SERVICE_KEY}', "
        f"or run '{MANUAL_RESTART}' on a terminal)"
    )


# Diagnostic playbooks that ship by default (differ per platform).
DIAGNOSTIC_PLAYBOOKS = (
    "launchd_debug, network_debug, system_debug"
    if _DARWIN
    else "systemd_debug, nginx_debug, docker_debug, network_debug, ports_debug"
)

# One install command for both platforms - the dispatcher auto-detects the OS.
INSTALL_CMD = "curl -fsSL https://get.sentinelx.app | bash"

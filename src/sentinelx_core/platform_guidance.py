"""Platform-aware guidance for user-facing error messages and help text.

The agent runs on Linux (systemd, root-owned /etc/sentinelx), macOS (launchd,
user-owned ~/sentinelx) and Windows (WinSW service as LocalSystem, config under
C:\\ProgramData\\SentinelX). Messages that tell the operator how to edit the
policy or reload the agent must adapt to the platform, or a user gets pointed at
/etc/sentinelx and `systemctl` (neither of which exists off Linux). Centralized
here so each message stays a one-liner and there's a single place to update.
"""
from __future__ import annotations

import sys

_WINDOWS = sys.platform == "win32"
_DARWIN = sys.platform == "darwin"


def _pick(windows: str, macos: str, linux: str) -> str:
    """Choose the platform-appropriate string (Windows / macOS / Linux)."""
    if _WINDOWS:
        return windows
    if _DARWIN:
        return macos
    return linux


# Policy file the operator edits.
CONFIG_PATH = _pick(
    r"C:\ProgramData\SentinelX\config.yaml",
    "~/sentinelx/config.yaml",
    "/etc/sentinelx/config.yaml",
)

# Service key to pass to the service op for a self-restart.
SERVICE_KEY = _pick("sentinelx", "sentinelx", "sentinelx-cloud-core")

# Manual restart command for a real terminal (when the service op isn't usable).
MANUAL_RESTART = _pick(
    "Restart-Service SentinelX  (in an elevated PowerShell)",
    "sudo launchctl kickstart -k system/app.sentinelx.core",
    "sudo systemctl restart sentinelx-cloud-core",
)

# sentinel_edit sudo hint: Linux config is root-owned (needs sudo=true); macOS
# and Windows configs are exposed file-scoped rw, so no sudo.
_EDIT_SUDO = _pick("", "", "sudo=true and ")

# Where to look for agent logs.
LOGS_HINT = _pick(
    r"Get-Content C:\ProgramData\SentinelX\logs\sentinelx-service.err.log -Tail 30",
    "~/sentinelx/agent.err (or: log show --predicate 'process == "
    '"sentinelx-cloud-core"' "' --last 5m)",
    "sudo journalctl -u sentinelx-cloud-core -n 30",
)

HOST_KIND = _pick("Windows host", "macOS host", "Linux host")


def edit_config_via() -> str:
    """e.g. "sentinel_edit on <config> with validator_preset='yaml'"."""
    return f"sentinel_edit on {CONFIG_PATH} with {_EDIT_SUDO}validator_preset='yaml'"


def reload_agent() -> str:
    """How to reload the policy after editing it."""
    return (
        f"reload the agent (sentinel_service action='restart' service='{SERVICE_KEY}', "
        f"or run '{MANUAL_RESTART}' on a terminal)"
    )


# Diagnostic playbooks that ship by default (differ per platform).
DIAGNOSTIC_PLAYBOOKS = _pick(
    "network_debug, system_debug",
    "launchd_debug, network_debug, system_debug",
    "systemd_debug, nginx_debug, docker_debug, network_debug, ports_debug",
)

# Install command. The get.sentinelx.app dispatcher auto-detects the OS for the
# curl|bash path; Windows uses the PowerShell one-liner.
INSTALL_CMD = _pick(
    'iwr -useb https://get.sentinelx.app/install.ps1 -OutFile "$env:TEMP\\sx.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\\sx.ps1"',
    "curl -fsSL https://get.sentinelx.app | bash",
    "curl -fsSL https://get.sentinelx.app | bash",
)

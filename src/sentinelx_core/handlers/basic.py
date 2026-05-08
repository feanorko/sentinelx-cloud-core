"""Read-only / introspection handlers: ping, capabilities, help, state."""

from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any

from sentinelx_core import AGENT_VERSION
from sentinelx_core.policy import Policy


async def handle_ping(payload: dict[str, Any]) -> dict[str, Any]:
    return {"pong": True, "agent_version": AGENT_VERSION}


def make_capabilities_handler(policy: Policy):
    async def handle_capabilities(payload: dict[str, Any]) -> dict[str, Any]:
        """Return the policy as introspection data + ops supported.

        This is the dynamic equivalent of legacy SentinelX's GET /capabilities.
        Output is shaped to be friendly for an LLM tool: lists, dicts, no fluff.
        """
        return {
            "agent": "sentinelx-cloud-core",
            "version": AGENT_VERSION,
            "host": {
                "hostname": socket.gethostname(),
                "label": policy.hostname_label,
                "kernel": platform.release(),
                "arch": platform.machine(),
            },
            "ops_supported": [
                "ping", "capabilities", "help", "state",
                "exec", "service", "restart",
                "script_run",
                "edit", "edit_upload_init", "edit_upload_file", "edit_upload_complete",
                "upload_file", "upload_init", "upload_chunk", "upload_complete",
            ],
            "allowed_commands": list(policy.allowed_commands),
            "services": {
                name: {
                    "unit": spec.unit,
                    "actions": list(spec.actions),
                    "requires_sudo": spec.requires_sudo,
                    "description": spec.description,
                }
                for name, spec in policy.services.items()
            },
            "locations": {
                label: {"path": spec.path, "description": spec.description}
                for label, spec in policy.locations.items()
            },
            "playbooks": policy.playbooks,
            "limits": {
                "exec_timeout_default": policy.exec_timeout_default,
                "exec_timeout_max": policy.exec_timeout_max,
            },
            "fetch_policy": {
                # Hosts the agent will fetch from when sentinel_upload_file
                # is called with file_url. Empty list means file_url is
                # disabled — the LLM should use content_base64 (inline) or
                # the chunked upload path instead.
                "trusted_fetch_hosts": list(policy.trusted_fetch_hosts),
                "file_url_timeout_seconds": policy.file_url_timeout_seconds,
                # Hard requirements applied to every file_url, regardless
                # of allowlist:
                #   - https only (http blocked)
                #   - hostname in allowlist (above)
                #   - resolved IP must be public-routable
                #     (loopback / RFC1918 / link-local / etc. blocked)
                #   - redirects disabled
                # See SECURITY.md and THREAT_MODEL.md in the source repo
                # for the full threat model.
                "scheme_allowed": ["https"],
                "follow_redirects": False,
            },
        }

    return handle_capabilities


def make_help_handler(policy: Policy):
    async def handle_help(payload: dict[str, Any]) -> dict[str, Any]:
        """Short human-readable help."""
        return {
            "agent": "sentinelx-cloud-core",
            "summary": (
                "SentinelX gives you safe, structured control of this Linux server. "
                "Use 'capabilities' to see what's allowed; 'state' for current host status; "
                "'exec' for inspection commands; 'service' / 'restart' for service control."
            ),
            "host_label": policy.hostname_label,
            "allowed_commands_count": len(policy.allowed_commands),
            "services_count": len(policy.services),
            "playbooks_count": len(policy.playbooks),
        }

    return handle_help


async def handle_state(payload: dict[str, Any]) -> dict[str, Any]:
    """Real-time host status."""
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "platform": platform.platform(),
        "now_utc": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": _read_uptime(),
        "loadavg": _read_loadavg(),
    }


def _read_uptime() -> float | None:
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError):
        return None


def _read_loadavg() -> tuple[float, float, float] | None:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            return (float(parts[0]), float(parts[1]), float(parts[2]))
    except (OSError, ValueError, IndexError):
        return None

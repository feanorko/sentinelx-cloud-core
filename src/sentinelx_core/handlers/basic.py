"""Read-only / introspection handlers."""

from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any

from sentinelx_core import AGENT_VERSION


async def handle_ping(payload: dict[str, Any]) -> dict[str, Any]:
    return {"pong": True, "agent_version": AGENT_VERSION}


async def handle_capabilities(payload: dict[str, Any]) -> dict[str, Any]:
    """Return what this agent can do.

    For now, a static stub. The legacy core has a much richer capabilities map
    (allowed_commands, service_actions, locations, playbooks) — that whole
    structure should be ported here, ideally read from /etc/sentinelx/config.yaml.
    """
    return {
        "agent": "sentinelx-core",
        "version": AGENT_VERSION,
        "ops_supported": [
            "ping", "capabilities", "help", "state",
            "exec", "service", "restart",
        ],
    }


async def handle_help(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "message": (
            "SentinelX agent. Use 'capabilities' to see what's supported, "
            "'state' for current host status."
        ),
    }


async def handle_state(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "now": datetime.now(timezone.utc).isoformat(),
    }

"""Op handlers: one async function per `op`.

Each handler takes a payload dict and returns a result dict (or raises HandlerError).

The registry binds handlers to the Policy at startup. Handlers that need
configuration (allowed commands, allowed services) are built via factories
that close over the policy; stateless handlers (ping) are referenced directly.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from sentinelx_core.handlers.basic import (
    handle_ping,
    handle_state,
    make_capabilities_handler,
    make_help_handler,
)
from sentinelx_core.handlers.exec import make_exec_handler
from sentinelx_core.handlers.service import make_restart_handler, make_service_handler
from sentinelx_core.policy import Policy

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def build_registry(config_path: Path | None = None, policy: Policy | None = None) -> dict[str, Handler]:
    """Build the op → handler registry from a Policy.

    Provide either `config_path` (loaded with Policy.from_file) or `policy`
    directly (useful in tests).
    """
    if policy is None:
        if config_path is None:
            policy = Policy.empty()
        else:
            policy = Policy.from_file(config_path)

    return {
        "ping": handle_ping,
        "capabilities": make_capabilities_handler(policy),
        "help": make_help_handler(policy),
        "state": handle_state,
        "exec": make_exec_handler(policy),
        "service": make_service_handler(policy),
        "restart": make_restart_handler(policy),
        # Pending ports from legacy:
        # "edit", "edit_upload_init", "edit_upload_file", "edit_upload_complete",
        # "script_run", "upload_init", "upload_chunk", "upload_complete", "upload_file",
    }

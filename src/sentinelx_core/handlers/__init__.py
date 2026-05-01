"""Op handlers: one async function per `op`.

Each handler takes a payload dict and returns a result dict (or raises HandlerError).

The registry binds handlers to the Policy at startup. Handlers that need
configuration (allowed commands, allowed services, upload_base) are built via
factories that close over the policy; stateless handlers (ping, state) are
referenced directly.
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
from sentinelx_core.handlers.edit import (
    make_edit_handler,
    make_edit_upload_complete_handler,
    make_edit_upload_file_handler,
    make_edit_upload_init_handler,
)
from sentinelx_core.handlers.exec import make_exec_handler
from sentinelx_core.handlers.script import make_script_run_handler
from sentinelx_core.handlers.service import make_restart_handler, make_service_handler
from sentinelx_core.handlers.upload import (
    make_upload_chunk_handler,
    make_upload_complete_handler,
    make_upload_file_handler,
    make_upload_init_handler,
)
from sentinelx_core.policy import Policy

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def build_registry(
    config_path: Path | None = None,
    policy: Policy | None = None,
) -> dict[str, Handler]:
    """Build the op → handler registry from a Policy.

    Provide either `config_path` (loaded with Policy.from_file) or `policy`
    directly (useful in tests).
    """
    if policy is None:
        if config_path is None:
            policy = Policy.empty()
        else:
            policy = Policy.from_file(config_path)

    upload_base = policy.upload_base

    return {
        # Read-only / introspection
        "ping": handle_ping,
        "capabilities": make_capabilities_handler(policy),
        "help": make_help_handler(policy),
        "state": handle_state,

        # Command execution
        "exec": make_exec_handler(policy),
        "service": make_service_handler(policy),
        "restart": make_restart_handler(policy),
        "script_run": make_script_run_handler(policy, upload_base),

        # File editing
        "edit": make_edit_handler(policy, upload_base),
        "edit_upload_init": make_edit_upload_init_handler(upload_base),
        "edit_upload_file": make_edit_upload_file_handler(upload_base),
        "edit_upload_complete": make_edit_upload_complete_handler(policy, upload_base),

        # File uploads
        "upload_file": make_upload_file_handler(upload_base),
        "upload_init": make_upload_init_handler(upload_base),
        "upload_chunk": make_upload_chunk_handler(upload_base),
        "upload_complete": make_upload_complete_handler(upload_base),
    }

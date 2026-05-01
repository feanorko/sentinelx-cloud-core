"""Op handlers: one async function per `op`.

Each handler takes a payload dict and returns a result dict (or raises HandlerError).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from sentinelx_core.handlers.basic import (
    handle_capabilities,
    handle_help,
    handle_ping,
    handle_state,
)
from sentinelx_core.handlers.exec import handle_exec
from sentinelx_core.handlers.service import handle_restart, handle_service

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def build_registry(config_path: Path) -> dict[str, Handler]:
    """Build the op → handler registry. Load config once, bind into closures."""
    # TODO: real config loading + policy enforcement.
    # For now we accept everything and let the underlying tools enforce.
    return {
        "ping": handle_ping,
        "capabilities": handle_capabilities,
        "help": handle_help,
        "state": handle_state,
        "exec": handle_exec,
        "restart": handle_restart,
        "service": handle_service,
        # The following ops are placeholders — wire them up when porting from legacy:
        # "edit", "edit_upload_init", "edit_upload_file", "edit_upload_complete",
        # "script_run", "upload_init", "upload_chunk", "upload_complete", "upload_file",
    }

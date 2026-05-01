"""exec handler: run a whitelisted command via bash -lc.

Allowlist comes from policy (loaded from /etc/sentinelx/config.yaml). Empty
allowlist = deny-all. Match is by prefix, identical to legacy SentinelX 0.3.5.
"""

from __future__ import annotations

from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.executor_engine import run_shell
from sentinelx_core.policy import Policy


def make_exec_handler(policy: Policy):
    """Return an async handler bound to the given policy."""

    async def handle_exec(payload: dict[str, Any]) -> dict[str, Any]:
        command = payload.get("command")
        timeout = float(payload.get("timeout", policy.exec_timeout_default))

        if not command or not isinstance(command, str):
            raise HandlerError("invalid_payload", "missing or non-string 'command'")

        timeout = min(timeout, policy.exec_timeout_max)

        if not policy.is_command_allowed(command):
            raise HandlerError(
                "command_not_allowed",
                f"command not in allowlist: {command.split()[0] if command else '<empty>'}",
                details={"command": command},
            )

        return await run_shell(command, timeout=timeout)

    return handle_exec

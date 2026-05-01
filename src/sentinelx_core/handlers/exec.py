"""exec handler: run a whitelisted command and return stdout/stderr/exit_code.

This is the seam where we'd port the rich allowlist + capabilities logic from
the legacy core. For now: a minimal placeholder that runs the command in a
subprocess with a timeout. The real version must enforce the allowlist.
"""

from __future__ import annotations

import asyncio
from typing import Any

from sentinelx_core.executor import HandlerError


async def handle_exec(payload: dict[str, Any]) -> dict[str, Any]:
    command = payload.get("command")
    timeout = float(payload.get("timeout", 30))

    if not command or not isinstance(command, str):
        raise HandlerError("invalid_payload", "missing or non-string 'command'")

    # TODO: enforce allowlist from config
    # if not is_allowed(command): raise HandlerError("command_not_allowed", ...)

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        raise HandlerError("command_failed", str(exc)) from exc

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise HandlerError("timeout", f"command exceeded {timeout}s") from exc

    return {
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
        "exit_code": proc.returncode,
    }

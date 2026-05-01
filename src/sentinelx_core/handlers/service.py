"""service / restart handlers: systemctl wrappers."""

from __future__ import annotations

import asyncio
from typing import Any

from sentinelx_core.executor import HandlerError

ALLOWED_ACTIONS = {"start", "stop", "restart", "reload", "status", "is-active", "is-enabled"}


async def _systemctl(args: list[str], timeout: float = 30.0) -> dict[str, Any]:
    proc = await asyncio.create_subprocess_exec(
        "systemctl",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise HandlerError("timeout", "systemctl exceeded timeout") from exc

    return {
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
        "exit_code": proc.returncode,
    }


async def handle_service(payload: dict[str, Any]) -> dict[str, Any]:
    service = payload.get("service")
    action = payload.get("action")

    if not service or not isinstance(service, str):
        raise HandlerError("invalid_payload", "missing 'service'")
    if action not in ALLOWED_ACTIONS:
        raise HandlerError("invalid_payload", f"action must be one of: {sorted(ALLOWED_ACTIONS)}")

    # TODO: enforce per-service allowlist from config
    return await _systemctl([action, service])


async def handle_restart(payload: dict[str, Any]) -> dict[str, Any]:
    service = payload.get("service")
    if not service or not isinstance(service, str):
        raise HandlerError("invalid_payload", "missing 'service'")
    return await _systemctl(["restart", service])

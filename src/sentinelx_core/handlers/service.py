"""service / restart handlers: systemctl wrappers, gated by policy.

Each `service` request specifies the service name (e.g. "nginx") and an action
("start", "restart", "status", etc.). The agent looks up the service in the
policy, checks the action is allowed, then runs systemctl.

Note: the policy stores the SYSTEMD UNIT name (e.g. "nginx.service" or
"sentinelx-core") which may differ from the friendly service name the user
provides. This decoupling lets you alias `core` -> `sentinelx-core.service`.
"""

from __future__ import annotations

from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.executor_engine import run_shell_split
from sentinelx_core.policy import Policy


def _build_systemctl(action: str, unit: str, requires_sudo: bool) -> str:
    prefix = "sudo " if requires_sudo else ""
    return f"{prefix}systemctl {action} {unit}"


def make_service_handler(policy: Policy):
    """Return an async handler bound to the given policy."""

    async def handle_service(payload: dict[str, Any]) -> dict[str, Any]:
        service = payload.get("service")
        action = payload.get("action")

        if not service or not isinstance(service, str):
            raise HandlerError("invalid_payload", "missing 'service'")
        if not action or not isinstance(action, str):
            raise HandlerError("invalid_payload", "missing 'action'")

        spec = policy.get_service(service)
        if spec is None:
            raise HandlerError(
                "service_not_allowed",
                f"service not registered in policy: {service}",
                details={"service": service, "available": sorted(policy.services.keys())},
            )

        if action not in spec.actions:
            raise HandlerError(
                "service_action_not_allowed",
                f"action '{action}' not allowed for service '{service}'",
                details={"allowed_actions": list(spec.actions)},
            )

        cmd = _build_systemctl(action, spec.unit, spec.requires_sudo)
        return await run_shell_split(cmd, timeout=30.0)

    return handle_service


def make_restart_handler(policy: Policy):
    """Return an async handler that maps `restart {service}` to a service action."""

    service_handler = make_service_handler(policy)

    async def handle_restart(payload: dict[str, Any]) -> dict[str, Any]:
        service = payload.get("service")
        if not service or not isinstance(service, str):
            raise HandlerError("invalid_payload", "missing 'service'")
        return await service_handler({"service": service, "action": "restart"})

    return handle_restart

"""Tests for the op handlers — pure unit tests, no real subprocess calls."""

from __future__ import annotations

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy


@pytest.mark.asyncio
async def test_ping() -> None:
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["ping"]({})
    assert result["pong"] is True
    assert "agent_version" in result


@pytest.mark.asyncio
async def test_capabilities_reflects_policy() -> None:
    p = Policy.from_dict({
        "agent": {"hostname_label": "orion"},
        "allowed_commands": ["ls", "cat"],
        "services": {"nginx": {"actions": ["status", "restart"]}},
    })
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({})
    assert result["host"]["label"] == "orion"
    assert "ls" in result["allowed_commands"]
    assert result["services"]["nginx"]["actions"] == ["status", "restart"]


@pytest.mark.asyncio
async def test_exec_rejects_non_allowed_command() -> None:
    p = Policy(allowed_commands=("ls",))
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["exec"]({"command": "rm -rf /"})
    assert exc.value.code == "command_not_allowed"


@pytest.mark.asyncio
async def test_exec_runs_allowed_command() -> None:
    p = Policy(allowed_commands=("echo",))
    handlers = build_registry(policy=p)
    result = await handlers["exec"]({"command": "echo hello"})
    assert result["returncode"] == 0
    assert "hello" in result["output"]


@pytest.mark.asyncio
async def test_exec_missing_command() -> None:
    p = Policy(allowed_commands=("ls",))
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["exec"]({})
    assert exc.value.code == "invalid_payload"


@pytest.mark.asyncio
async def test_service_unknown_service() -> None:
    p = Policy.empty()
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["service"]({"service": "nginx", "action": "status"})
    assert exc.value.code == "service_not_allowed"


@pytest.mark.asyncio
async def test_service_action_not_allowed() -> None:
    p = Policy.from_dict({"services": {"nginx": {"actions": ["status"]}}})
    handlers = build_registry(policy=p)
    with pytest.raises(HandlerError) as exc:
        await handlers["service"]({"service": "nginx", "action": "kill"})
    assert exc.value.code == "service_action_not_allowed"


@pytest.mark.asyncio
async def test_state_returns_host_info() -> None:
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["state"]({})
    assert "hostname" in result
    assert "kernel" in result
    assert "now_utc" in result

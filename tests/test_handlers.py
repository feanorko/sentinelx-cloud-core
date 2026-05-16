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
async def test_capabilities_exposes_fetch_policy_defaults() -> None:
    """Default policy: empty allowlist, https only, no redirects."""
    p = Policy.from_dict({"allowed_commands": ["ls"]})
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({})
    fp = result["fetch_policy"]
    assert fp["trusted_fetch_hosts"] == []
    assert fp["scheme_allowed"] == ["https"]
    assert fp["follow_redirects"] is False
    assert fp["file_url_timeout_seconds"] == 15  # default


@pytest.mark.asyncio
async def test_capabilities_exposes_configured_trusted_hosts() -> None:
    """When the operator configures trusted_fetch_hosts, capabilities
    surfaces them so the LLM knows where it can fetch from."""
    p = Policy.from_dict({
        "allowed_commands": ["ls"],
        "security": {
            "trusted_fetch_hosts": ["drop.pensa.ar", "get.sentinelx.app"],
            "file_url_timeout_seconds": 20,
        },
    })
    handlers = build_registry(policy=p)
    result = await handlers["capabilities"]({})
    fp = result["fetch_policy"]
    assert "drop.pensa.ar" in fp["trusted_fetch_hosts"]
    assert "get.sentinelx.app" in fp["trusted_fetch_hosts"]
    assert fp["file_url_timeout_seconds"] == 20


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



@pytest.mark.asyncio
async def test_ops_supported_matches_registry() -> None:
    """`ops_supported` in capabilities is a hand-maintained list; it
    MUST stay in sync with the actual op registry. This test is the
    guard: it failed (and caught a real bug) when move/copy/delete/
    chmod/chown were registered in build_registry but not added to the
    capabilities list, so a client introspecting ops_supported
    couldn't discover them. If you add an op, add it in BOTH places.
    """
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["capabilities"]({})
    advertised = set(result["ops_supported"])
    registered = set(handlers)
    missing_from_caps = registered - advertised
    phantom_in_caps = advertised - registered
    assert not missing_from_caps, (
        f"ops registered but not advertised in capabilities: "
        f"{sorted(missing_from_caps)}"
    )
    assert not phantom_in_caps, (
        f"ops advertised in capabilities but not registered: "
        f"{sorted(phantom_in_caps)}"
    )


@pytest.mark.asyncio
async def test_capabilities_advertises_mutating_ops() -> None:
    """Explicit check that the five r/rw mutating ops are discoverable
    via capabilities (not just executable)."""
    handlers = build_registry(policy=Policy.empty())
    result = await handlers["capabilities"]({})
    for op in ("move", "copy", "delete", "chmod", "chown"):
        assert op in result["ops_supported"], (
            f"{op!r} missing from ops_supported"
        )
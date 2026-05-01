"""Tests for the Policy loader and its query methods."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sentinelx_core.policy import Policy


def test_empty_policy_denies_everything() -> None:
    p = Policy.empty()
    assert p.is_command_allowed("ls /") is False
    assert p.is_command_allowed("") is False
    assert p.get_service("nginx") is None
    assert p.is_service_action_allowed("nginx", "restart") is False


def test_allowlist_prefix_match() -> None:
    p = Policy(allowed_commands=("ls", "cat", "sudo systemctl status"))
    assert p.is_command_allowed("ls -la /tmp") is True
    assert p.is_command_allowed("cat /etc/hosts") is True
    assert p.is_command_allowed("sudo systemctl status nginx") is True
    assert p.is_command_allowed("rm -rf /") is False
    assert p.is_command_allowed("sudo systemctl restart nginx") is False


def test_allowlist_empty_string_matches_everything() -> None:
    """If someone puts '' in the allowlist they get everything (gotcha to be aware of)."""
    p = Policy(allowed_commands=("",))
    assert p.is_command_allowed("anything") is True


def test_allowlist_truly_empty_blocks_everything() -> None:
    p = Policy(allowed_commands=())
    assert p.is_command_allowed("ls") is False
    assert p.is_command_allowed("") is False


def test_from_dict_basic() -> None:
    data = {
        "agent": {"hostname_label": "test-host"},
        "allowed_commands": ["ls", "cat"],
        "services": {
            "nginx": {
                "unit": "nginx.service",
                "actions": ["status", "restart"],
                "requires_sudo": True,
            },
            "docker": {
                "actions": ["status"],
            },
        },
        "locations": {
            "home": {"path": "/home/test", "description": "test home"},
            "logs": "/var/log",  # short form
        },
    }
    p = Policy.from_dict(data)
    assert p.hostname_label == "test-host"
    assert p.allowed_commands == ("ls", "cat")
    assert p.services["nginx"].unit == "nginx.service"
    assert p.services["docker"].unit == "docker"  # defaults to name
    assert p.is_service_action_allowed("nginx", "restart") is True
    assert p.is_service_action_allowed("nginx", "kill") is False
    assert p.locations["home"].path == "/home/test"
    assert p.locations["logs"].path == "/var/log"
    assert p.locations["logs"].description == ""


def test_from_file(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(textwrap.dedent("""
        allowed_commands:
          - ls
          - tail
        services:
          nginx:
            actions: [status, reload]
    """))
    p = Policy.from_file(config)
    assert p.allowed_commands == ("ls", "tail")
    assert p.is_service_action_allowed("nginx", "reload") is True


def test_from_file_missing_returns_empty(tmp_path: Path) -> None:
    p = Policy.from_file(tmp_path / "does-not-exist.yaml")
    assert p.allowed_commands == ()


def test_from_file_invalid_yaml_returns_empty(tmp_path: Path) -> None:
    config = tmp_path / "bad.yaml"
    config.write_text("not: valid: yaml: with: too: many: colons:")
    p = Policy.from_file(config)
    assert p.allowed_commands == ()


def test_exec_timeout_defaults() -> None:
    p = Policy.empty()
    assert p.exec_timeout_default == 60
    assert p.exec_timeout_max == 600

    p2 = Policy.from_dict({"exec": {"timeout_default": 30, "timeout_max": 120}})
    assert p2.exec_timeout_default == 30
    assert p2.exec_timeout_max == 120

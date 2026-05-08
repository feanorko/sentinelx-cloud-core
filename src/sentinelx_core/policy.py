"""Policy: allowlist + service registry + paths, loaded from /etc/sentinelx/config.yaml.

This is the ONLY place that knows about per-host configuration. Handlers consult
the policy to decide whether a command/service is allowed; they do not hardcode
anything site-specific.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ServiceSpec:
    """Allowed actions for a systemd service."""
    unit: str
    actions: tuple[str, ...]
    requires_sudo: bool = True
    description: str = ""


@dataclass(frozen=True)
class LocationSpec:
    """A known path on this host."""
    path: str
    description: str = ""


@dataclass
class Policy:
    """Loaded policy. Immutable after construction."""

    # Command prefixes the agent will execute via the `exec` op.
    # An exec request matches if cmd.startswith(allowed) for some entry.
    allowed_commands: tuple[str, ...] = field(default_factory=tuple)

    # service name -> ServiceSpec
    services: dict[str, ServiceSpec] = field(default_factory=dict)

    # short label -> LocationSpec
    locations: dict[str, LocationSpec] = field(default_factory=dict)

    # diagnostic playbook name -> ordered list of commands
    playbooks: dict[str, dict[str, Any]] = field(default_factory=dict)

    # optional human-readable label for this host
    hostname_label: str | None = None

    # exec timeout default
    exec_timeout_default: int = 60
    exec_timeout_max: int = 600

    # Where uploads + edit workdirs live. Default mirrors legacy SentinelX.
    upload_base: Path = field(default_factory=lambda: Path("/home/sentinelx/uploads"))

    # ── file_url SSRF defense ──────────────────────────────────────────────
    # When the hub asks the agent to fetch a URL (upload_file with file_url),
    # the URL's hostname must be in this allowlist AND its resolved IP must
    # not be private/loopback/link-local.
    #
    # Default empty = file_url is effectively disabled. Operators must
    # opt-in by listing trusted hosts. This is the principle of least
    # privilege: the agent runs with elevated rights, so a fetch primitive
    # to arbitrary hosts is a SSRF gun pointed at the host's network.
    #
    # Typical configuration for SentinelX:
    #   trusted_fetch_hosts:
    #     - drop.pensa.ar
    #     - get.sentinelx.app
    trusted_fetch_hosts: tuple[str, ...] = ()

    # Tighter timeout than the legacy 60s — fetches that take that long
    # against an attacker-controlled host are tying up agent resources
    # while leaking timing info.
    file_url_timeout_seconds: int = 15

    @classmethod
    def empty(cls) -> "Policy":
        """Used in tests and as the default if no config file exists."""
        return cls()

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        if not path.exists():
            logger.warning("policy_config_missing", extra={"path": str(path)})
            return cls.empty()

        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (yaml.YAMLError, OSError) as exc:
            logger.error("policy_config_invalid", extra={"path": str(path), "error": str(exc)})
            return cls.empty()

        # Schema errors (unknown keys, typos like `allow:` instead of
        # `allowed_commands:`) are reported as ValueError by from_dict. We
        # log them prominently and refuse to fall back to empty — silently
        # loading nothing was the exact bug we're trying to prevent.
        try:
            return cls.from_dict(data)
        except ValueError as exc:
            logger.error(
                "policy_config_schema_error",
                extra={"path": str(path), "error": str(exc)},
            )
            # Re-raise so the agent fails loudly at startup rather than
            # accepting WS connections with an empty allowlist. The systemd
            # unit will restart but journalctl will show this clearly.
            raise

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        # --- Schema validation: detect typos with high-confidence -----------
        # We deliberately use a TWO-TIER approach:
        #
        #   Tier 1: HARD FAIL on keys we know are common typos for required
        #           keys. These produce a ValueError so the agent crashes
        #           loudly at startup (better than silently loading nothing).
        #
        #   Tier 2: SOFT WARN on unknown keys that don't match any known
        #           typo. We just log a warning and continue. This avoids
        #           breaking forward-compatible configs that include keys
        #           we haven't seen yet (e.g. a future version adds a new
        #           top-level key, but the user is still running an older
        #           agent — their config keeps working).
        #
        # The bug we're preventing is the one from May 2 2026: someone
        # writes `allow:` instead of `allowed_commands:` and the agent
        # silently loads zero commands. We hard-fail on that exact typo
        # but stay tolerant of unknowns we don't recognize.
        TYPO_HINTS = {
            "allow": "allowed_commands",
            "allowedCommands": "allowed_commands",
            "commands": "allowed_commands",
            "service": "services",
            "location": "locations",
            "playbook": "playbooks",
            "hub": "hub_url",
        }
        # Hard fail: any key in TYPO_HINTS is a known mistake.
        typos_found = [k for k in data.keys() if k in TYPO_HINTS]
        if typos_found:
            hints = [
                f"  '{k}' is not recognized — did you mean '{TYPO_HINTS[k]}'?"
                for k in sorted(typos_found)
            ]
            raise ValueError(
                "config.yaml contains keys that look like common typos:\n"
                + "\n".join(hints)
                + "\nFix the key name(s) and restart the agent."
            )

        # Soft warn: anything else not in KNOWN_KEYS is just informational.
        # It does NOT block the agent from starting.
        KNOWN_KEYS = {
            "agent", "exec", "allowed_commands", "services", "locations",
            "playbooks", "hub_url", "upload_base", "log", "security",
        }
        unknown = set(data.keys()) - KNOWN_KEYS - set(TYPO_HINTS.keys())
        if unknown:
            logger.warning(
                "policy_unknown_keys",
                extra={
                    "unknown_keys": sorted(unknown),
                    "known_keys": sorted(KNOWN_KEYS),
                },
            )

        agent_block = data.get("agent", {}) or {}
        exec_block = data.get("exec", {}) or {}
        security_block = data.get("security", {}) or {}

        services: dict[str, ServiceSpec] = {}
        for name, meta in (data.get("services") or {}).items():
            actions = tuple(meta.get("actions") or [])
            services[name] = ServiceSpec(
                unit=meta.get("unit", name),
                actions=actions,
                requires_sudo=bool(meta.get("requires_sudo", True)),
                description=meta.get("description", ""),
            )

        locations: dict[str, LocationSpec] = {}
        for label, meta in (data.get("locations") or {}).items():
            if isinstance(meta, str):
                locations[label] = LocationSpec(path=meta)
            else:
                locations[label] = LocationSpec(
                    path=meta["path"],
                    description=meta.get("description", ""),
                )

        policy = cls(
            allowed_commands=tuple(data.get("allowed_commands") or []),
            services=services,
            locations=locations,
            playbooks=dict(data.get("playbooks") or {}),
            hostname_label=agent_block.get("hostname_label"),
            exec_timeout_default=int(exec_block.get("timeout_default", 60)),
            exec_timeout_max=int(exec_block.get("timeout_max", 600)),
            upload_base=Path(
                data.get("upload_base") or "/home/sentinelx/uploads"
            ).resolve(),
            trusted_fetch_hosts=tuple(
                security_block.get("trusted_fetch_hosts") or ()
            ),
            file_url_timeout_seconds=int(
                security_block.get("file_url_timeout_seconds", 15)
            ),
        )

        # --- Fix #7-prevention (part 2): warn on empty allowlist -----------
        # An empty allowed_commands list is technically valid (deny-all) but
        # it almost always means the operator forgot to populate it or used
        # the wrong key name. Loud warning at startup so it surfaces in
        # journalctl rather than only when the first exec attempt fails.
        if not policy.allowed_commands:
            # Note: don't pass `message` in extra — that's a reserved field
            # in stdlib logging.LogRecord and using it raises KeyError.
            logger.warning(
                "Policy loaded with NO allowed_commands. "
                "All `exec` calls will be rejected. "
                "If this is unintentional, check that "
                "/etc/sentinelx/config.yaml contains an "
                "`allowed_commands:` block (with underscore — "
                "`allow:` won't work)."
            )
        else:
            logger.info(
                "policy_loaded",
                extra={
                    "allowed_commands_count": len(policy.allowed_commands),
                    "services_count": len(policy.services),
                    "playbooks_count": len(policy.playbooks),
                },
            )

        return policy

    # --- Query methods --------------------------------------------------------

    def is_command_allowed(self, cmd: str) -> bool:
        """Match by prefix, like the legacy core does.

        Empty allowlist means deny-all.
        """
        cmd = (cmd or "").strip()
        if not cmd:
            return False
        return any(cmd.startswith(allowed) for allowed in self.allowed_commands)

    def get_service(self, name: str) -> ServiceSpec | None:
        return self.services.get(name)

    def is_service_action_allowed(self, name: str, action: str) -> bool:
        spec = self.services.get(name)
        if spec is None:
            return False
        return action in spec.actions

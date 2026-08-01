"""Read-only / introspection handlers: ping, capabilities, help, state."""

from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any

from sentinelx_core import AGENT_VERSION
from sentinelx_core.policy import Policy


async def handle_ping(payload: dict[str, Any]) -> dict[str, Any]:
    return {"pong": True, "agent_version": AGENT_VERSION}


def make_read_audit_handler():
    """Return a handler that reads recent entries from the local audit log.

    Read-only. Returns entries from /var/lib/sentinelx/audit.jsonl (op +
    payload + status), newest first. This is the only path by which the
    on-host payload log leaves the host, and only in response to an explicit
    request routed through the hub to this host's owner.
    """
    from sentinelx_core import local_audit

    async def handle_read_audit(payload: dict[str, Any]) -> dict[str, Any]:
        limit = payload.get("limit", 200)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 200
        entries = local_audit.read_recent(limit=limit)
        return {
            "entries": entries,
            "count": len(entries),
            "source": str(local_audit.AUDIT_PATH),
            "max_retained": local_audit.MAX_LINES,
        }

    return handle_read_audit


def make_capabilities_handler(policy: Policy):
    async def handle_capabilities(payload: dict[str, Any]) -> dict[str, Any]:
        """Return the policy as introspection data + ops supported.

        This is the dynamic equivalent of legacy SentinelX's GET /capabilities.
        Output is shaped to be friendly for an LLM tool: lists, dicts, no fluff.
        """
        return {
            "agent": "sentinelx-cloud-core",
            "version": AGENT_VERSION,
            "host": {
                "hostname": socket.gethostname(),
                "label": policy.hostname_label,
                "kernel": platform.release(),
                "arch": platform.machine(),
            },
            # NOTE: keep this list in sync with build_registry() in
            # handlers/__init__.py. It is intentionally explicit (not
            # derived from the registry) so capabilities output is
            # stable and readable, but that means new ops must be
            # added in BOTH places. The five mutating ops below were
            # added with the unified r/rw file-ops model.
            "ops_supported": [
                "ping", "capabilities", "help", "state",
                "exec", "service", "restart",
                "script_run",
                "edit", "edit_upload_init", "edit_upload_file", "edit_upload_complete",
                "upload_file", "upload_init", "upload_chunk", "upload_complete",
                "read", "list", "search",
                "read_audit",
                "move", "copy", "delete", "chmod", "chown",
            ],
            "allowed_commands": list(policy.allowed_commands),
            "services": {
                name: {
                    "unit": spec.unit,
                    "actions": list(spec.actions),
                    "requires_sudo": spec.requires_sudo,
                    "description": spec.description,
                }
                for name, spec in policy.services.items()
            },
            "locations": {
                label: {"path": spec.path, "description": spec.description}
                for label, spec in policy.locations.items()
            },
            "playbooks": policy.playbooks,
            "limits": {
                "exec_timeout_default": policy.exec_timeout_default,
                "exec_timeout_max": policy.exec_timeout_max,
            },
            "fetch_policy": {
                # Hosts the agent will fetch from when sentinel_upload_file
                # is called with file_url. Empty list means file_url is
                # disabled — the LLM should use content_base64 (inline) or
                # the chunked upload path instead.
                "trusted_fetch_hosts": list(policy.trusted_fetch_hosts),
                "file_url_timeout_seconds": policy.file_url_timeout_seconds,
                # Hard requirements applied to every file_url, regardless
                # of allowlist:
                #   - https only (http blocked)
                #   - hostname in allowlist (above)
                #   - resolved IP must be public-routable
                #     (loopback / RFC1918 / link-local / etc. blocked)
                #   - redirects disabled
                # See SECURITY.md and THREAT_MODEL.md in the source repo
                # for the full threat model.
                "scheme_allowed": ["https"],
                "follow_redirects": False,
            },
            "file_ops": {
                # Unified r/rw path model. Each entry tells the LLM both
                # WHERE it can operate and WHAT it can do there:
                #   access "r"  -> read / list / search only
                #   access "rw" -> also edit / move / copy / delete /
                #                  chmod / chown
                # Empty list means all file_ops are effectively disabled
                # (path_not_allowed for any input).
                "paths": [
                    {"path": e.path, "access": e.access}
                    for e in policy.file_ops_paths
                ],
                # Back-compat / convenience: the flat list of every path
                # the agent will read under (both r and rw entries).
                # Existing clients that only knew about
                # `allowed_read_paths` keep getting a sensible value.
                "allowed_read_paths": [
                    e.path for e in policy.file_ops_paths
                ],
                # Just the writable subtree, so the LLM can tell at a
                # glance where mutations (edit + destructive ops) are
                # permitted without re-deriving it from `paths`.
                "writable_paths": [
                    e.path
                    for e in policy.file_ops_paths
                    if e.access == "rw"
                ],
                "max_read_bytes": policy.file_ops_max_read_bytes,
                "max_list_entries": policy.file_ops_max_list_entries,
                "max_search_results": policy.file_ops_max_search_results,
            },
        }

    return handle_capabilities


def make_help_handler(policy: Policy):
    async def handle_help(payload: dict[str, Any]) -> dict[str, Any]:
        """Short human-readable help."""
        return {
            "agent": "sentinelx-cloud-core",
            "summary": (
                "SentinelX gives you safe, structured control of this Linux server. "
                "Use 'capabilities' to see what's allowed; 'state' for current host status; "
                "'exec' for inspection commands; 'service' / 'restart' for service control."
            ),
            "host_label": policy.hostname_label,
            "allowed_commands_count": len(policy.allowed_commands),
            "services_count": len(policy.services),
            "playbooks_count": len(policy.playbooks),
        }

    return handle_help


async def handle_state(payload: dict[str, Any]) -> dict[str, Any]:
    """Real-time host status."""
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "platform": platform.platform(),
        "now_utc": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": _read_uptime(),
        "loadavg": _read_loadavg(),
    }


def _read_uptime() -> float | None:
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError):
        return None


def _read_loadavg() -> tuple[float, float, float] | None:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            return (float(parts[0]), float(parts[1]), float(parts[2]))
    except (OSError, ValueError, IndexError):
        return None

"""On-host audit log: append each executed op (with payload) to a local JSONL file.

This is the host-side counterpart to the hub's metadata ring buffer. Unlike the
hub — which deliberately stores only metadata (op, host, time, status) and never
the payload — this log keeps the full payload of each operation, on the host
itself. It is the only place the actual command/script/content is retained, it
never leaves the host except in response to a `read_audit` op, and it is the host
owner's own record.

Format: JSON Lines (one JSON object per line), append-only, at AUDIT_PATH.
Retention: capped at MAX_LINES; when exceeded, the file is trimmed to the most
recent MAX_LINES entries. Per-host, so this is far more history than the hub's
shared buffer holds for any one user.

Design constraints:
- Writing must NEVER break the operation being audited. Every failure here is
  swallowed (best-effort) — a broken log is not worth failing a real op over.
- No redaction: entries are stored as-is. The payload may contain secrets the
  user themselves passed; that is their record on their own machine.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default location, resolved cross-platform. An explicit SENTINELX_AUDIT_PATH
# always wins (installers set it per mode). Otherwise: on Linux, /var/lib is the
# canonical home for variable application state and is owned by the agent user;
# on macOS there is no /var/lib, so fall back to the user's Library/Logs, which
# is writable for user-mode installs. System-mode (LaunchDaemon) installs point
# SENTINELX_AUDIT_PATH at a path their service user owns.
def _default_audit_path() -> Path:
    override = os.environ.get("SENTINELX_AUDIT_PATH")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "SentinelX" / "audit.jsonl"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "sentinelx" / "audit.jsonl"
    return Path("/var/lib/sentinelx/audit.jsonl")


AUDIT_PATH = _default_audit_path()

# Retention: keep the most recent N entries. Matches the hub ring buffer size
# for conceptual consistency, but because this is per-host it represents far
# more real history than 5000 shared entries ever would.
MAX_LINES = 5000

# Only trim once we've drifted a bit past the cap, so we're not rewriting the
# whole file on every single append once it's full. Amortizes the trim cost.
TRIM_TRIGGER = MAX_LINES + 500

# Ops we never record, to avoid noise / recursion. read_audit reads this very
# log; auditing the read would grow the log every time someone views it.
SKIP_OPS = frozenset({"read_audit", "ping"})


def record(op: str, payload: dict[str, Any], ok: bool,
           error: str | None = None, duration_ms: int | None = None) -> None:
    """Append one entry to the local audit log. Best-effort; never raises."""
    if op in SKIP_OPS:
        return
    try:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "op": op,
            "payload": payload,
            "ok": ok,
            "error": error,
            "duration_ms": duration_ms,
        }
        line = json.dumps(entry, ensure_ascii=False, default=str)

        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

        _maybe_trim()
    except Exception as exc:  # never let auditing break the op
        logger.warning("local_audit_write_failed: %s", exc)


def _maybe_trim() -> None:
    """If the log has grown past TRIM_TRIGGER lines, rewrite it keeping the
    most recent MAX_LINES. Atomic replace so a crash mid-trim can't corrupt or
    truncate the live file."""
    try:
        # Cheap line count without loading the whole file into memory.
        with AUDIT_PATH.open("rb") as f:
            count = sum(1 for _ in f)
        if count <= TRIM_TRIGGER:
            return

        with AUDIT_PATH.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        keep = lines[-MAX_LINES:]

        # Write to a temp file in the same dir, then atomically replace.
        fd, tmp = tempfile.mkstemp(dir=str(AUDIT_PATH.parent), prefix=".audit-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.writelines(keep)
            os.replace(tmp, AUDIT_PATH)
        except Exception:
            # Clean up the temp file if the replace didn't happen.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as exc:
        logger.warning("local_audit_trim_failed: %s", exc)


def read_recent(limit: int = 200) -> list[dict[str, Any]]:
    """Return the most recent `limit` entries, newest first. Best-effort:
    returns whatever parses; a malformed line is skipped, not fatal."""
    limit = max(1, min(int(limit), MAX_LINES))
    try:
        if not AUDIT_PATH.exists():
            return []
        with AUDIT_PATH.open("r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as exc:
        logger.warning("local_audit_read_failed: %s", exc)
        return []

    # Take the tail, parse, return newest-first.
    tail = lines[-limit:]
    out: list[dict[str, Any]] = []
    for raw in reversed(tail):
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            continue
    return out

"""Local audit for SentinelX E2E encrypted fields.

These logs are host-local only. They are deliberately not part of any
SentinelX response and are never sent to the Hub.

The audit files are append-only from the agent's point of view. Retention and
rotation are intentionally NOT performed by the agent: deleting old records
would make the audit trail untrustworthy. The service installation prepares
root-owned, append-only log files; an administrator/root-level rotation policy
may replace them deliberately.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

WIRE_AUDIT_PATH = Path(os.environ.get(
    "SENTINELX_CRYPTO_WIRE_AUDIT_PATH",
    "/var/log/sentinelx/crypto-wire-audit.jsonl",
))
PLAINTEXT_AUDIT_PATH = Path(os.environ.get(
    "SENTINELX_CRYPTO_PLAINTEXT_AUDIT_PATH",
    "/var/log/sentinelx/crypto-plaintext-audit.jsonl",
))


def _append(path: Path, entry: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        # Audit failure must never break the E2E channel.
        pass


def record_wire(direction: str, value: str) -> None:
    _append(WIRE_AUDIT_PATH, {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "direction": direction,
        "value": value,
    })


def record_plain(direction: str, value: str) -> None:
    _append(PLAINTEXT_AUDIT_PATH, {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "direction": direction,
        "value": value,
    })

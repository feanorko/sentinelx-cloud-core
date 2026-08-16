"""Local audit for SentinelX E2E encrypted fields.

These logs are host-local only. They are deliberately not part of any
SentinelX response and are never sent to the Hub.
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
MAX_LINES = 5000
TRIM_TRIGGER = MAX_LINES + 500


def _append(path: Path, entry: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        _trim(path)
    except Exception:
        # Audit failure must never break the E2E channel.
        pass


def _trim(path: Path) -> None:
    try:
        with path.open("rb") as f:
            if sum(1 for _ in f) <= TRIM_TRIGGER:
                return
        with path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        tmp = path.with_name("." + path.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            f.writelines(lines[-MAX_LINES:])
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
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

"""Identity: load /etc/sentinelx/identity.json (host_id + enrollment token)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Identity:
    """Loaded from identity.json — written by sentinelx-installer."""

    host_id: str
    token: str
    hub: str


class IdentityError(Exception):
    """Identity file is missing or malformed."""


def load_identity(path: Path) -> Identity:
    if not path.exists():
        raise IdentityError(
            f"identity file not found at {path} — run sentinelx-enroll to enroll this host"
        )
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise IdentityError(f"could not read {path}: {exc}") from exc

    for required in ("host_id", "token", "hub"):
        if required not in data:
            raise IdentityError(f"identity file missing field: {required}")

    return Identity(host_id=data["host_id"], token=data["token"], hub=data["hub"])

"""Entrypoint: `python -m sentinelx_core` or `sentinelx-core`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from sentinelx_core.client import HubClient
from sentinelx_core.identity import load_identity


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelx-core")
    parser.add_argument("--hub", help="Hub URL (overrides identity.json)")
    parser.add_argument(
        "--identity",
        default="/etc/sentinelx/identity.json",
        type=Path,
        help="Path to identity.json (default: /etc/sentinelx/identity.json)",
    )
    parser.add_argument("--config", default="/etc/sentinelx/config.yaml", type=Path)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )

    identity = load_identity(args.identity)
    hub_url = args.hub or identity.hub

    client = HubClient(
        hub_url=hub_url,
        identity=identity,
        config_path=args.config,
    )

    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()

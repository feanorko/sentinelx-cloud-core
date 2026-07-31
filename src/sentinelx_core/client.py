"""Hub WebSocket client.

Owns the connection lifecycle: handshake, reconnection with exponential backoff,
ping/pong heartbeat, dispatching incoming requests to the executor.
"""

from __future__ import annotations

import asyncio
import json
import logging
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import websockets
from websockets.exceptions import ConnectionClosed
from sentinelx_protocol import (
    HEARTBEAT_INTERVAL_SECONDS,
    PROTOCOL_VERSION,
    HelloMessage,
    HostInfo,
    PongMessage,
    parse_message,
)

from sentinelx_core import AGENT_VERSION
from sentinelx_core.executor import Executor
from sentinelx_core.identity import Identity

logger = logging.getLogger(__name__)


# Reconnection backoff (seconds): inmediate, 1, 5, 30, 60, 120, 300...
BACKOFF_SCHEDULE = [0, 1, 5, 30, 60, 120, 300]


def _detect_os() -> str:
    """Best-effort human-readable OS name from /etc/os-release.

    Returns something like "Ubuntu 24.04.1 LTS" (the PRETTY_NAME) when the
    file is present, else falls back to "linux". Never raises — a missing
    or malformed file, a minimal container, or a non-standard distro all
    degrade gracefully to the generic label. The hub stores whatever we
    send, so an older agent (plain "linux") and a newer one (pretty name)
    coexist fine.
    """
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return "linux"
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value:
                return value
    return "linux"


class HubClient:
    def __init__(
        self,
        hub_url: str,
        identity: Identity,
        config_path: Path,
    ) -> None:
        # Normalize: hub URL might be https://, we need wss://
        if hub_url.startswith("http://"):
            self._ws_url = "ws://" + hub_url[7:]
        elif hub_url.startswith("https://"):
            self._ws_url = "wss://" + hub_url[8:]
        else:
            self._ws_url = hub_url

        self._identity = identity
        self._executor = Executor(config_path=config_path)
        self._stop = asyncio.Event()

    async def run(self) -> None:
        """Main loop: connect, handle messages, reconnect on failure."""
        attempt = 0
        while not self._stop.is_set():
            wait = BACKOFF_SCHEDULE[min(attempt, len(BACKOFF_SCHEDULE) - 1)]
            if wait > 0:
                logger.info("reconnecting in %ss (attempt %d)", wait, attempt)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=wait)
                    return  # stop signalled during wait
                except asyncio.TimeoutError:
                    pass

            try:
                await self._connect_and_serve()
                attempt = 0  # reset on clean disconnect
            except FatalProtocolError as exc:
                logger.error("fatal protocol error, not reconnecting: %s", exc)
                return
            except ConnectionClosed as exc:
                # 1012 = "service restart": the hub told us it is coming
                # right back (e.g. a deploy). That is not a network failure,
                # so don't grow the backoff — reset it and reconnect promptly.
                # Otherwise a hub restart could leave an agent that already
                # had a high attempt count waiting up to 300s to return.
                if exc.code == 1012:
                    logger.info("hub restarting (1012); reconnecting promptly")
                    attempt = 0
                else:
                    logger.warning("connection closed (%s): %s", exc.code, exc)
                    attempt += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("connection failed: %s", exc)
                attempt += 1

    async def _connect_and_serve(self) -> None:
        url = f"{self._ws_url}/agent/connect?token={self._identity.token}"
        logger.info("connecting to %s", self._ws_url)

        async with websockets.connect(url, ping_interval=None) as ws:
            # 1. Send hello
            hello = HelloMessage(
                protocol_version=PROTOCOL_VERSION,
                agent_version=AGENT_VERSION,
                host=HostInfo(
                    id=self._identity.host_id,
                    hostname=socket.gethostname(),
                    os=_detect_os(),
                    kernel=platform.release(),
                    arch=platform.machine(),
                ),
                capabilities=self._executor.capability_names(),
            )
            await ws.send(hello.model_dump_json())

            # 2. Wait for welcome (or fatal error)
            raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
            welcome = parse_message(json.loads(raw))
            if welcome.type == "error":  # type: ignore[union-attr]
                raise FatalProtocolError(
                    f"hub rejected: {welcome.code}: {welcome.message}"  # type: ignore[union-attr]
                )
            if welcome.type != "welcome":  # type: ignore[union-attr]
                raise RuntimeError(f"expected welcome, got {welcome.type}")  # type: ignore[union-attr]

            logger.info("connected; session=%s", welcome.session_id)  # type: ignore[union-attr]

            # 3. Concurrent loops: read messages, send heartbeat
            read_task = asyncio.create_task(self._read_loop(ws))
            heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))
            try:
                done, pending = await asyncio.wait(
                    [read_task, heartbeat_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                # surface the first exception
                for task in done:
                    if exc := task.exception():
                        raise exc
            finally:
                for task in (read_task, heartbeat_task):
                    if not task.done():
                        task.cancel()

    async def _read_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        async for raw in ws:
            try:
                data = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode())
                msg = parse_message(data)
            except Exception as exc:  # noqa: BLE001
                logger.warning("failed to parse incoming message: %s", exc)
                continue

            if msg.type == "request":  # type: ignore[union-attr]
                # Handle in background so a slow op doesn't block the read loop
                asyncio.create_task(self._handle_request(ws, msg))
            elif msg.type == "ping":  # type: ignore[union-attr]
                await ws.send(
                    PongMessage(timestamp=datetime.now(timezone.utc)).model_dump_json()
                )
            elif msg.type == "error":  # type: ignore[union-attr]
                raise FatalProtocolError(
                    f"{msg.code}: {msg.message}"  # type: ignore[union-attr]
                )
            elif msg.type == "pong":  # type: ignore[union-attr]
                pass  # heartbeat ack
            else:
                logger.warning("unexpected message type: %s", msg.type)  # type: ignore[union-attr]

    async def _handle_request(
        self,
        ws: websockets.WebSocketClientProtocol,
        request: Any,  # RequestMessage
    ) -> None:
        try:
            response = await self._executor.dispatch(request)
        except Exception as exc:  # noqa: BLE001
            logger.exception("executor crashed on %s", request.op)
            response = {
                "type": "response",
                "id": request.id,
                "ok": False,
                "error": {"code": "internal_error", "message": str(exc)},
            }
        await ws.send(json.dumps(response, default=str))

    async def _heartbeat_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        from sentinelx_protocol import PingMessage

        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            ping = PingMessage(timestamp=datetime.now(timezone.utc))
            await ws.send(ping.model_dump_json())


class FatalProtocolError(Exception):
    """Hub sent a fatal error. Don't reconnect."""

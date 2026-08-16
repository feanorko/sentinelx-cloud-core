"""Hub WebSocket client with transparent SentinelX field encryption."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import websockets
from websockets.exceptions import ConnectionClosed
from sentinelx_protocol import (
    HEARTBEAT_INTERVAL_SECONDS,
    MAX_BINARY_FRAME_BYTES,
    PROTOCOL_VERSION,
    ConfigSummary,
    EventMessage,
    HelloMessage,
    HostInfo,
    PongMessage,
    decode_binary_frame,
    encode_binary_frame,
    is_binary_transfer_frame,
    parse_message,
)

from sentinelx_core import AGENT_VERSION
from sentinelx_core.crypto import decrypt_command, encrypt_text, load_public_key
from sentinelx_core.executor import Executor
from sentinelx_core.identity import Identity

logger = logging.getLogger(__name__)

BACKOFF_SCHEDULE = [0, 1, 5, 30, 60, 120, 300]


def _read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _run(args: list[str]) -> str | None:
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=3)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _detect_machine_type() -> str | None:
    osrelease = (_read_text("/proc/sys/kernel/osrelease") or "").lower()
    version = (_read_text("/proc/version") or "").lower()
    if "microsoft" in osrelease or "wsl" in osrelease or "microsoft" in version:
        return "wsl"
    if os.path.exists("/.dockerenv"):
        return "container"
    cgroup = (_read_text("/proc/1/cgroup") or "").lower()
    if any(x in cgroup for x in ("docker", "lxc", "kubepods", "containerd")):
        return "container"
    for p in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"):
        v = (_read_text(p) or "").lower()
        if any(x in v for x in ("kvm", "vmware", "virtualbox", "qemu", "xen", "hyper-v", "amazon", "google", "digitalocean", "vultr", "openstack", "bochs")):
            return "vm"
    if "hypervisor" in (_read_text("/proc/cpuinfo") or "").lower():
        return "vm"
    return "physical"


def _gather_linux(info: dict[str, Any]) -> None:
    try:
        for line in (_read_text("/proc/cpuinfo") or "").splitlines():
            if line.lower().startswith("model name"):
                info["cpu_model"] = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass
    try:
        for line in (_read_text("/proc/meminfo") or "").splitlines():
            if line.startswith("MemTotal:"):
                info["mem_total_bytes"] = int(line.split()[1]) * 1024
                break
    except Exception:
        pass
    try:
        for line in (_read_text("/etc/os-release") or "").splitlines():
            if line.startswith("PRETTY_NAME="):
                info["distro"] = line.split("=", 1)[1].strip().strip('"')
                break
    except Exception:
        pass
    try:
        info["machine_type"] = _detect_machine_type()
    except Exception:
        pass


def _gather_darwin(info: dict[str, Any]) -> None:
    try:
        info["cpu_model"] = _run(["sysctl", "-n", "machdep.cpu.brand_string"]) or None
    except Exception:
        pass
    try:
        mem = _run(["sysctl", "-n", "hw.memsize"])
        if mem:
            info["mem_total_bytes"] = int(mem)
    except Exception:
        pass
    try:
        name = _run(["sw_vers", "-productName"]) or "macOS"
        ver = _run(["sw_vers", "-productVersion"]) or ""
        info["distro"] = (name + " " + ver).strip()
    except Exception:
        pass
    try:
        vmm = _run(["sysctl", "-n", "kern.hv_vmm_present"])
        model = (_run(["sysctl", "-n", "hw.model"]) or "").lower()
        info["machine_type"] = "vm" if vmm == "1" or any(x in model for x in ("vmware", "parallels", "virtualbox", "qemu")) else "physical"
    except Exception:
        pass


def _gather_windows(info: dict[str, Any]) -> None:
    try:
        info["cpu_model"] = os.environ.get("PROCESSOR_IDENTIFIER") or platform.processor() or None
    except Exception:
        pass
    try:
        import ctypes
        class _MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        stat = _MEMORYSTATUSEX(); stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            info["mem_total_bytes"] = int(stat.ullTotalPhys)
    except Exception:
        pass
    try:
        info["distro"] = _detect_os()
    except Exception:
        pass
    info["machine_type"] = "physical"


def _gather_machine_info() -> dict[str, Any]:
    info: dict[str, Any] = {"cpu_model": None, "cpu_cores": None, "mem_total_bytes": None, "disk_total_bytes": None, "machine_type": None, "distro": None}
    try: info["cpu_cores"] = os.cpu_count()
    except Exception: pass
    try: info["disk_total_bytes"] = shutil.disk_usage("/").total
    except Exception: pass
    try:
        if sys.platform == "win32": _gather_windows(info)
        elif sys.platform == "darwin": _gather_darwin(info)
        else: _gather_linux(info)
    except Exception: pass
    return info


def _detect_os() -> str:
    if sys.platform == "win32":
        rel = platform.release(); build = platform.version().split(".")[-1] if platform.version() else ""
        return f"Windows {rel} (build {build})" if build else f"Windows {rel}"
    if sys.platform == "darwin":
        name = _run(["sw_vers", "-productName"]) or "macOS"; ver = _run(["sw_vers", "-productVersion"]) or ""
        return (name + " " + ver).strip()
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError): return "linux"
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value: return value
    return "linux"


def _encrypt_response_fields(response: dict[str, Any], response_public) -> dict[str, Any]:
    """Encrypt textual command output while retaining the standard response schema."""
    result = response.get("result")
    if isinstance(result, dict):
        for key in ("stdout", "stderr", "output", "message"):
            value = result.get(key)
            if isinstance(value, str) and value:
                result[key] = encrypt_text(value, response_public)
    error = response.get("error")
    if isinstance(error, dict):
        value = error.get("message")
        if isinstance(value, str) and value:
            error["message"] = encrypt_text(value, response_public)
    return response


class HubClient:
    def __init__(self, hub_url: str, identity: Identity, config_path: Path, command_private_key: Path, response_public_key: Path) -> None:
        if hub_url.startswith("http://"): self._ws_url = "ws://" + hub_url[7:]
        elif hub_url.startswith("https://"): self._ws_url = "wss://" + hub_url[8:]
        else: self._ws_url = hub_url
        self._identity = identity
        self._executor = Executor(config_path=config_path)
        self._stop = asyncio.Event()
        self._command_private_key = command_private_key
        self._response_public = load_public_key(response_public_key)

    async def run(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            wait = BACKOFF_SCHEDULE[min(attempt, len(BACKOFF_SCHEDULE) - 1)]
            if wait > 0:
                logger.info("reconnecting in %ss (attempt %d)", wait, attempt)
                try: await asyncio.wait_for(self._stop.wait(), timeout=wait); return
                except asyncio.TimeoutError: pass
            try:
                await self._connect_and_serve(); attempt = 0
            except FatalProtocolError as exc:
                logger.error("fatal protocol error, not reconnecting: %s", exc); return
            except ConnectionClosed as exc:
                if exc.code == 1012: attempt = 0
                else: logger.warning("connection closed (%s): %s", exc.code, exc); attempt += 1
            except Exception as exc:
                logger.warning("connection failed: %s", exc); attempt += 1

    async def _connect_and_serve(self) -> None:
        url = f"{self._ws_url}/agent/connect?token={self._identity.token}"
        logger.info("connecting to %s", self._ws_url)
        async with websockets.connect(url, ping_interval=None, max_size=MAX_BINARY_FRAME_BYTES) as ws:
            hello = HelloMessage(protocol_version=PROTOCOL_VERSION, agent_version=AGENT_VERSION, agent_name="sentinelx-core", host=HostInfo(id=self._identity.host_id, hostname=socket.gethostname(), os=_detect_os(), kernel=platform.release(), arch=platform.machine(), config_summary=ConfigSummary(**self._executor.config_summary()), **_gather_machine_info()), capabilities=self._executor.capability_names())
            await ws.send(hello.model_dump_json())
            raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
            welcome = parse_message(json.loads(raw))
            if welcome.type == "error": raise FatalProtocolError(f"hub rejected: {welcome.code}: {welcome.message}")
            if welcome.type != "welcome": raise RuntimeError(f"expected welcome, got {welcome.type}")
            logger.info("connected; session=%s", welcome.session_id)
            read_task = asyncio.create_task(self._read_loop(ws)); heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))
            try:
                done, pending = await asyncio.wait([read_task, heartbeat_task], return_when=asyncio.FIRST_COMPLETED)
                for task in pending: task.cancel()
                for task in done:
                    if exc := task.exception(): raise exc
            finally:
                for task in (read_task, heartbeat_task):
                    if not task.done(): task.cancel()

    async def _read_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        async for raw in ws:
            if is_binary_transfer_frame(raw):
                asyncio.create_task(self._handle_binary_frame(ws, raw)); continue
            try:
                data = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode())
                msg = parse_message(data)
            except Exception as exc:
                logger.warning("failed to parse incoming message: %s", exc); continue
            if msg.type == "request":
                asyncio.create_task(self._handle_request(ws, msg))
            elif msg.type == "ping":
                await ws.send(PongMessage(timestamp=datetime.now(timezone.utc)).model_dump_json())
            elif msg.type == "error":
                raise FatalProtocolError(f"{msg.code}: {msg.message}")
            elif msg.type == "pong": pass
            else: logger.warning("unexpected message type: %s", msg.type)

    async def _handle_request(self, ws: websockets.WebSocketClientProtocol, request: Any) -> None:
        try:
            # The Hub message remains a normal SentinelX request. Only the textual
            # command field is encrypted; all routing/op/id metadata remains intact.
            if request.op == "exec" and isinstance(request.payload, dict):
                payload = dict(request.payload)
                command = payload.get("command")
                if isinstance(command, str) and (command.startswith("sx1:") or command.startswith("echo sx1:")):
                    from sentinelx_core.crypto import decrypt_command
                    encrypted = command[len("echo "):] if command.startswith("echo sx1:") else command
                    payload["command"] = decrypt_command(encrypted, self._command_private_key)
                    request = request.model_copy(update={"payload": payload})
            response = await self._executor.dispatch(request)
        except Exception as exc:
            logger.exception("executor crashed on %s", request.op)
            response = {"type": "response", "id": request.id, "ok": False, "error": {"code": "internal_error", "message": str(exc)}}
        response = _encrypt_response_fields(response, self._response_public)
        result = response.get("result") if isinstance(response, dict) else None
        if response.get("ok") and isinstance(result, dict) and "__binary_payload__" in result:
            payload = result.pop("__binary_payload__")
            try:
                frame = encode_binary_frame(bytes.fromhex(result["transfer_id"]), int(result["chunk_index"]), payload)
                await ws.send(frame)
            except Exception:
                await ws.send(json.dumps({"type": "response", "id": request.id, "ok": False, "error": {"code": "binary_emit_error", "message": "failed to emit binary transfer chunk"}})); return
        await ws.send(json.dumps(response, default=str))

    async def _handle_binary_frame(self, ws: websockets.WebSocketClientProtocol, raw: bytes) -> None:
        try: frame = decode_binary_frame(bytes(raw))
        except Exception as exc: logger.warning("bad binary transfer frame: %s", exc); return
        upload_id = frame.transfer_id.hex(); data = {"transfer_id": upload_id, "chunk_index": frame.chunk_index}
        try:
            written = await self._executor.ingest_transfer_chunk(upload_id, frame.chunk_index, frame.payload); data.update(ok=True, bytes=written)
        except Exception as exc:
            code = getattr(exc, "code", "ingest_error"); data.update(ok=False, error=f"{code}: {exc}")
        try: await ws.send(EventMessage(kind="transfer_chunk_ack", data=data, timestamp=datetime.now(timezone.utc)).model_dump_json())
        except Exception: pass

    async def _heartbeat_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        from sentinelx_protocol import PingMessage
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            await ws.send(PingMessage(timestamp=datetime.now(timezone.utc)).model_dump_json())


class FatalProtocolError(Exception):
    """Hub sent a fatal error. Don't reconnect."""

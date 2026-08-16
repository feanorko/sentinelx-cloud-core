"""Pydantic models for SentinelX protocol messages.

These are the wire format. Both core and hub import from here to ensure
they're speaking the same language.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

OpType = Literal[
    "ping", "capabilities", "help", "state", "exec", "script_run", "edit",
    "edit_upload_init", "edit_upload_file", "edit_upload_complete", "restart",
    "service", "upload_init", "upload_chunk", "upload_complete", "upload_file",
    "read", "list", "search", "project_snapshot", "read_audit", "move", "copy",
    "delete", "chmod", "chown", "file_export_init", "file_export_chunk",
    "file_export_complete",
]

class ConfigSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_command_count: int | None = None
    file_ops_path_count: int | None = None
    file_ops_rw_count: int | None = None
    service_count: int | None = None
    playbook_count: int | None = None
    trusted_fetch_host_count: int | None = None
    exec_timeout_default: int | None = None
    exec_timeout_max: int | None = None

class HostInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(..., description="Unique host identifier (generated at install)")
    hostname: str
    os: str = "linux"
    kernel: str | None = None
    arch: str | None = None
    cpu_model: str | None = None
    cpu_cores: int | None = None
    mem_total_bytes: int | None = None
    disk_total_bytes: int | None = None
    machine_type: str | None = None
    distro: str | None = None
    config_summary: ConfigSummary | None = None

class HelloMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["hello"] = "hello"
    protocol_version: str
    agent_version: str
    agent_name: str | None = None
    host: HostInfo
    capabilities: list[str] = Field(default_factory=list)

class WelcomeMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["welcome"] = "welcome"
    session_id: str
    server_time: datetime
    heartbeat_interval_seconds: int = 30

class RequestMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["request"] = "request"
    id: str
    op: OpType
    payload: dict[str, Any] = Field(default_factory=dict)
    deadline: datetime | None = None

class ResponseError(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    message: str
    details: dict[str, Any] | None = None

class ResponseMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["response"] = "response"
    id: str
    ok: bool
    result: dict[str, Any] | None = None
    error: ResponseError | None = None

class PingMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["ping"] = "ping"
    timestamp: datetime

class PongMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["pong"] = "pong"
    timestamp: datetime

class EventMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["event"] = "event"
    kind: str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime

class ErrorMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["error"] = "error"
    code: str
    message: str
    fatal: bool = True

AnyMessage = HelloMessage | WelcomeMessage | RequestMessage | ResponseMessage | PingMessage | PongMessage | EventMessage | ErrorMessage
_MESSAGE_TYPES: dict[str, type[BaseModel]] = {
    "hello": HelloMessage, "welcome": WelcomeMessage, "request": RequestMessage,
    "response": ResponseMessage, "ping": PingMessage, "pong": PongMessage,
    "event": EventMessage, "error": ErrorMessage,
}

class UnknownMessageTypeError(ValueError):
    pass

def parse_message(data: dict[str, Any]) -> AnyMessage:
    msg_type = data.get("type")
    if not msg_type or msg_type not in _MESSAGE_TYPES:
        raise UnknownMessageTypeError(f"Unknown message type: {msg_type!r}")
    return _MESSAGE_TYPES[msg_type].model_validate(data)  # type: ignore[return-value]

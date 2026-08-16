"""Binary WebSocket frame framing for cross-host file transfer."""

from __future__ import annotations

import struct
from typing import NamedTuple

TRANSFER_ID_BYTES = 16
CHUNK_INDEX_BYTES = 4
BINARY_HEADER_BYTES = TRANSFER_ID_BYTES + CHUNK_INDEX_BYTES
TRANSFER_CHUNK_BYTES = 1_048_576
MAX_BINARY_FRAME_BYTES = 2_097_152
_CHUNK_INDEX_STRUCT = struct.Struct(">I")

class BinaryFrame(NamedTuple):
    transfer_id: bytes
    chunk_index: int
    payload: bytes

class BinaryFrameError(ValueError):
    pass

def encode_binary_frame(transfer_id: bytes, chunk_index: int, payload: bytes) -> bytes:
    if len(transfer_id) != TRANSFER_ID_BYTES:
        raise BinaryFrameError(f"transfer_id must be {TRANSFER_ID_BYTES} bytes, got {len(transfer_id)}")
    if not 0 <= chunk_index <= 0xFFFFFFFF:
        raise BinaryFrameError(f"chunk_index out of uint32 range: {chunk_index}")
    return bytes(transfer_id) + _CHUNK_INDEX_STRUCT.pack(chunk_index) + bytes(payload)

def decode_binary_frame(frame: bytes) -> BinaryFrame:
    if len(frame) < BINARY_HEADER_BYTES:
        raise BinaryFrameError(f"frame too short: {len(frame)} < {BINARY_HEADER_BYTES} header bytes")
    transfer_id = bytes(frame[:TRANSFER_ID_BYTES])
    (chunk_index,) = _CHUNK_INDEX_STRUCT.unpack(frame[TRANSFER_ID_BYTES:BINARY_HEADER_BYTES])
    return BinaryFrame(transfer_id=transfer_id, chunk_index=chunk_index, payload=bytes(frame[BINARY_HEADER_BYTES:]))

def is_binary_transfer_frame(data: object) -> bool:
    return isinstance(data, (bytes, bytearray)) and len(data) >= BINARY_HEADER_BYTES

"""upload handlers: receive files from the hub via WebSocket payloads.

Big difference from the legacy core: there is no `multipart/form-data` here.
File bytes arrive in the WebSocket payload as either:

  - `content_base64` (str): the file inlined as base64
  - `file_url` (str): an http(s) URL the agent fetches itself

Single upload  -> `upload_file`
Chunked upload -> `upload_init` + `upload_chunk` (N times) + `upload_complete`

Why chunked at all? WebSocket frames have a ceiling (typically 1 MiB to a few
MiB depending on infra), so anything bigger has to be split into chunks. The
hub does the splitting client-side; the agent reassembles.

Uploads always land under the configured upload base directory. Path traversal
attempts are rejected up front via `safe_path_under()`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import shutil
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.executor_engine import safe_path_under

# 10 GiB hard ceiling, mirrors legacy SENTINEL_MAX_UPLOAD_BYTES default
MAX_UPLOAD_BYTES = 10 * 1024 * 1024 * 1024
CHUNK_READ_SIZE = 1024 * 1024  # 1 MiB


def _meta_file(upload_dir: Path) -> Path:
    return upload_dir / "meta.json"


def _parts_dir(upload_dir: Path) -> Path:
    d = upload_dir / "parts"
    d.mkdir(parents=True, exist_ok=True)
    return d


async def _fetch_url(url: str, dest: Path) -> tuple[int, str]:
    """Download a URL into `dest`. Returns (size, sha256_hex)."""
    if not url.startswith(("http://", "https://")):
        raise HandlerError("invalid_payload", "file_url must be http(s)")

    def _do_fetch() -> tuple[int, str]:
        hasher = hashlib.sha256()
        size = 0
        try:
            with urllib.request.urlopen(url, timeout=60) as r, dest.open("wb") as f:
                while True:
                    block = r.read(CHUNK_READ_SIZE)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_UPLOAD_BYTES:
                        raise HandlerError(
                            "file_too_large",
                            f"file exceeds {MAX_UPLOAD_BYTES} bytes",
                        )
                    hasher.update(block)
                    f.write(block)
        except urllib.error.URLError as exc:
            raise HandlerError("fetch_failed", f"could not fetch URL: {exc}") from exc
        return size, hasher.hexdigest()

    return await asyncio.to_thread(_do_fetch)


def _decode_base64_to(content_b64: str, dest: Path) -> tuple[int, str]:
    try:
        raw = base64.b64decode(content_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise HandlerError("invalid_payload", f"bad base64: {exc}") from exc
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HandlerError("file_too_large", f"size {len(raw)} > limit {MAX_UPLOAD_BYTES}")
    dest.write_bytes(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


def make_upload_file_handler(upload_base: Path):
    """Single-call upload (small/medium files). Bytes inline or via URL."""

    async def handle_upload_file(payload: dict[str, Any]) -> dict[str, Any]:
        target_path = payload.get("target_path")
        overwrite = bool(payload.get("overwrite", False))
        filename = payload.get("filename")
        content_b64 = payload.get("content_base64")
        file_url = payload.get("file_url")

        if not target_path:
            raise HandlerError("invalid_payload", "missing 'target_path'")
        if (content_b64 is None) == (file_url is None):
            raise HandlerError(
                "invalid_payload",
                "provide exactly one of 'content_base64' or 'file_url'",
            )

        upload_base.mkdir(parents=True, exist_ok=True)
        try:
            dest = safe_path_under(upload_base, str(target_path))
        except ValueError as exc:
            raise HandlerError("path_traversal", str(exc)) from exc

        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and not overwrite:
            raise HandlerError("conflict", f"file exists: {dest}")

        tmp_root = upload_base / ".sentinelx_uploads"
        tmp_root.mkdir(parents=True, exist_ok=True)
        tmp = tmp_root / f"{uuid.uuid4().hex}.upload"

        try:
            if content_b64 is not None:
                size, sha256 = _decode_base64_to(content_b64, tmp)
            else:
                size, sha256 = await _fetch_url(file_url, tmp)
            tmp.replace(dest)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

        return {
            "ok": True,
            "mode": "single",
            "target_path": str(dest),
            "size": size,
            "sha256": sha256,
            "filename": filename,
        }

    return handle_upload_file


def make_upload_init_handler(upload_base: Path):
    async def handle_upload_init(payload: dict[str, Any]) -> dict[str, Any]:
        target_path = payload.get("target_path")
        overwrite = bool(payload.get("overwrite", False))
        total_size = int(payload.get("total_size", 0) or 0)
        filename = payload.get("filename")

        if not target_path:
            raise HandlerError("invalid_payload", "missing 'target_path'")
        if total_size and total_size > MAX_UPLOAD_BYTES:
            raise HandlerError(
                "file_too_large",
                f"declared total_size {total_size} exceeds limit {MAX_UPLOAD_BYTES}",
            )

        upload_base.mkdir(parents=True, exist_ok=True)
        try:
            dest = safe_path_under(upload_base, str(target_path))
        except ValueError as exc:
            raise HandlerError("path_traversal", str(exc)) from exc

        if dest.exists() and not overwrite:
            raise HandlerError("conflict", f"file exists: {dest}")

        upload_id = uuid.uuid4().hex
        tmp_root = upload_base / ".sentinelx_uploads"
        upload_dir = tmp_root / upload_id
        _parts_dir(upload_dir)

        meta = {
            "upload_id": upload_id,
            "target_path": str(dest),
            "overwrite": overwrite,
            "total_size": total_size,
            "filename": filename,
        }
        _meta_file(upload_dir).write_text(json.dumps(meta))

        return {
            "ok": True,
            "mode": "chunked",
            "upload_id": upload_id,
            "target_path": str(dest),
            "total_size": total_size,
        }

    return handle_upload_init


def make_upload_chunk_handler(upload_base: Path):
    async def handle_upload_chunk(payload: dict[str, Any]) -> dict[str, Any]:
        upload_id = payload.get("upload_id")
        index = payload.get("index")
        content_b64 = payload.get("content_base64")

        if not upload_id:
            raise HandlerError("invalid_payload", "missing 'upload_id'")
        if index is None:
            raise HandlerError("invalid_payload", "missing 'index'")
        if content_b64 is None:
            raise HandlerError("invalid_payload", "missing 'content_base64'")

        try:
            idx = int(index)
        except (TypeError, ValueError) as exc:
            raise HandlerError("invalid_payload", "index must be int") from exc
        if idx < 0:
            raise HandlerError("invalid_payload", "index must be >= 0")

        tmp_root = upload_base / ".sentinelx_uploads"
        upload_dir = tmp_root / upload_id
        if not _meta_file(upload_dir).exists():
            raise HandlerError("not_found", f"upload_id not found: {upload_id}")

        try:
            data = base64.b64decode(content_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HandlerError("invalid_payload", f"bad base64: {exc}") from exc

        part_path = _parts_dir(upload_dir) / f"{idx:08d}.part"
        part_path.write_bytes(data)

        return {
            "ok": True,
            "upload_id": upload_id,
            "index": idx,
            "chunk_size": len(data),
        }

    return handle_upload_chunk


def make_upload_complete_handler(upload_base: Path):
    async def handle_upload_complete(payload: dict[str, Any]) -> dict[str, Any]:
        upload_id = payload.get("upload_id")
        sha256_expected = payload.get("sha256")

        if not upload_id:
            raise HandlerError("invalid_payload", "missing 'upload_id'")

        tmp_root = upload_base / ".sentinelx_uploads"
        upload_dir = tmp_root / upload_id
        meta_file = _meta_file(upload_dir)
        if not meta_file.exists():
            raise HandlerError("not_found", f"upload_id not found: {upload_id}")

        meta = json.loads(meta_file.read_text())
        dest = Path(meta["target_path"]).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        parts = sorted((upload_dir / "parts").glob("*.part"))
        if not parts:
            raise HandlerError("invalid_state", "no chunks uploaded")

        # Reassemble while hashing
        tmp = upload_dir / "assembled.bin"
        hasher = hashlib.sha256()
        total = 0

        def _assemble() -> None:
            nonlocal total
            with tmp.open("wb") as out:
                for part in parts:
                    with part.open("rb") as pf:
                        while True:
                            block = pf.read(CHUNK_READ_SIZE)
                            if not block:
                                break
                            total += len(block)
                            if total > MAX_UPLOAD_BYTES:
                                raise HandlerError(
                                    "file_too_large",
                                    f"reassembly exceeded limit {MAX_UPLOAD_BYTES}",
                                )
                            hasher.update(block)
                            out.write(block)

        await asyncio.to_thread(_assemble)
        sha256 = hasher.hexdigest()

        # Validations
        expected_size = int(meta.get("total_size", 0) or 0)
        if expected_size and total != expected_size:
            raise HandlerError(
                "size_mismatch",
                f"expected {expected_size}, got {total}",
            )
        if sha256_expected and sha256_expected != sha256:
            raise HandlerError("checksum_mismatch", "sha256 does not match")
        if dest.exists() and not meta.get("overwrite", False):
            raise HandlerError("conflict", f"file exists: {dest}")

        tmp.replace(dest)
        shutil.rmtree(upload_dir, ignore_errors=True)

        return {
            "ok": True,
            "mode": "chunked",
            "upload_id": upload_id,
            "target_path": str(dest),
            "size": total,
            "sha256": sha256,
            "filename": meta.get("filename"),
        }

    return handle_upload_complete

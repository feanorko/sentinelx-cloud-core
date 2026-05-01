"""edit handlers: structured file editing via the `pensa-safe-edit` binary.

Ported from legacy SentinelX 0.3.5. Three ops:

  - edit                         -> single-call edit (small/medium changes)
  - edit_upload_init             -> begin a multi-step edit (large content)
  - edit_upload_file             -> upload a role file (new/old) to that step
  - edit_upload_complete         -> run the edit using uploaded files

Why this complexity? `pensa-safe-edit` accepts content via `--old-file` and
`--new-file`. For large content, transmitting it inline would be unwieldy.
The chunked path lets the caller stage files up front, then run the edit.

The agent does NOT validate `path` against any allowlist — that's the user's
responsibility via the underlying filesystem permissions and sudo policy.
What the agent DOES guarantee:

  - Only the configured `pensa-safe-edit` binary is called.
  - Mode/argument validation happens before exec.
  - Workdirs are created in the upload base, never elsewhere.
  - Each request gets a fresh workdir and is cleaned up after.

Modes:
  - replace        literal old -> new_text (count, multiline, dotall)
  - regex          pattern -> new_text (count, multiline, dotall)
  - replace-block  start_marker..end_marker -> new_text
  - append         append new_text to file
  - prepend        prepend new_text to file
  - write          overwrite file with new_text
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.policy import Policy

VALID_MODES = ("replace", "regex", "replace-block", "append", "prepend", "write")
VALID_PRESETS = ("nginx", "json", "python", "sh", "yaml", "systemd")

# Default location of pensa-safe-edit. Override via policy if installed elsewhere.
DEFAULT_SAFE_EDIT_BIN = "/usr/local/bin/pensa-safe-edit"


def _validate_mode_payload(mode: str, payload: dict[str, Any]) -> None:
    """Mirror the legacy EditRequest validators."""
    if mode not in VALID_MODES:
        raise HandlerError(
            "invalid_payload",
            f"mode must be one of: {', '.join(VALID_MODES)}",
        )

    validator = payload.get("validator")
    validator_preset = payload.get("validator_preset")
    if validator and validator_preset:
        raise HandlerError(
            "invalid_payload",
            "cannot use 'validator' and 'validator_preset' together",
        )
    if validator_preset and validator_preset not in VALID_PRESETS:
        raise HandlerError(
            "invalid_payload",
            f"validator_preset must be one of: {', '.join(VALID_PRESETS)}",
        )

    count = int(payload.get("count", 0) or 0)
    if count < 0:
        raise HandlerError("invalid_payload", "count cannot be negative")

    if mode == "replace":
        if payload.get("old") is None:
            raise HandlerError("invalid_payload", "mode=replace requires 'old'")
        if payload.get("new_text") is None:
            raise HandlerError("invalid_payload", "mode=replace requires 'new_text'")

    elif mode == "regex":
        if not payload.get("pattern"):
            raise HandlerError("invalid_payload", "mode=regex requires 'pattern'")
        if payload.get("new_text") is None:
            raise HandlerError("invalid_payload", "mode=regex requires 'new_text'")

    elif mode == "replace-block":
        if not payload.get("start_marker") or not payload.get("end_marker"):
            raise HandlerError(
                "invalid_payload",
                "mode=replace-block requires 'start_marker' and 'end_marker'",
            )
        if payload.get("new_text") is None:
            raise HandlerError(
                "invalid_payload",
                "mode=replace-block requires 'new_text'",
            )

    elif mode in ("append", "prepend", "write"):
        if payload.get("new_text") is None:
            raise HandlerError(
                "invalid_payload",
                f"mode={mode} requires 'new_text'",
            )


def _build_argv(
    *,
    binary: str,
    workdir: Path,
    path: str,
    sudo: bool,
    mode: str,
    old: str | None = None,
    new_text: str | None = None,
    pattern: str | None = None,
    start_marker: str | None = None,
    end_marker: str | None = None,
    count: int = 0,
    multiline: bool = False,
    dotall: bool = False,
    interpret_escapes: bool = False,
    backup_dir: str | None = None,
    validator: str | None = None,
    validator_preset: str | None = None,
    diff: bool = False,
    dry_run: bool = False,
    allow_no_change: bool = False,
    create: bool = False,
    old_file_path: Path | None = None,
    new_file_path: Path | None = None,
) -> list[str]:
    """Build the argv list for pensa-safe-edit. Faithful port of legacy."""
    argv: list[str] = []
    if sudo:
        argv.append("sudo")
    argv.extend([binary, path, "--mode", mode])

    # Old content: prefer file path, fall back to writing inline content
    if old_file_path is not None:
        argv.extend(["--old-file", str(old_file_path)])
    elif old is not None:
        p = workdir / "old.txt"
        p.write_text(old, encoding="utf-8")
        argv.extend(["--old-file", str(p)])

    # New content: same pattern
    if new_file_path is not None:
        argv.extend(["--new-file", str(new_file_path)])
    elif new_text is not None:
        p = workdir / "new.txt"
        p.write_text(new_text, encoding="utf-8")
        argv.extend(["--new-file", str(p)])

    if pattern:
        argv.extend(["--pattern", pattern])
    if start_marker:
        argv.extend(["--start-marker", start_marker])
    if end_marker:
        argv.extend(["--end-marker", end_marker])
    if count:
        argv.extend(["--count", str(count)])
    if multiline:
        argv.append("--multiline")
    if dotall:
        argv.append("--dotall")
    if interpret_escapes:
        argv.append("--interpret-escapes")
    if backup_dir:
        argv.extend(["--backup-dir", backup_dir])
    if validator:
        argv.extend(["--validator", validator])
    if validator_preset:
        argv.extend(["--validator-preset", validator_preset])
    if diff:
        argv.append("--diff")
    if dry_run:
        argv.append("--dry-run")
    if allow_no_change:
        argv.append("--allow-no-change")
    if create:
        argv.append("--create")

    return argv


async def _run_argv(argv: list[str], timeout: int = 60) -> dict[str, Any]:
    """Run the assembled argv directly (no shell). Returns legacy-shape dict."""
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {
            "output": "⏱️ Timeout",
            "duration": round(time.time() - start, 2),
            "returncode": -1,
        }
    except FileNotFoundError as exc:
        raise HandlerError(
            "binary_missing",
            f"required binary not found: {exc.filename}",
        ) from exc

    duration = round(time.time() - start, 2)
    stdout = (stdout_b.decode(errors="replace") or "").strip()
    stderr = (stderr_b.decode(errors="replace") or "").strip()
    output = (stdout + "\n" + stderr).strip() or "⚠️ Sin salida"
    return {"output": output, "duration": duration, "returncode": proc.returncode}


def make_edit_handler(policy: Policy, upload_base: Path):
    """Single-call edit, content passed inline as 'old' and 'new_text'."""
    binary = DEFAULT_SAFE_EDIT_BIN  # could come from policy in the future

    async def handle_edit(payload: dict[str, Any]) -> dict[str, Any]:
        path = payload.get("path")
        mode = payload.get("mode")
        sudo = bool(payload.get("sudo", False))

        if not path or not str(path).strip():
            raise HandlerError("invalid_payload", "missing 'path'")
        if not mode:
            raise HandlerError("invalid_payload", "missing 'mode'")

        _validate_mode_payload(mode, payload)

        upload_base.mkdir(parents=True, exist_ok=True)
        tmp_root = upload_base / ".sentinelx_uploads"
        tmp_root.mkdir(parents=True, exist_ok=True)

        workdir = tmp_root / f"edit_job_{uuid.uuid4().hex}"
        workdir.mkdir(parents=True, exist_ok=True)

        try:
            argv = _build_argv(
                binary=binary,
                workdir=workdir,
                path=path,
                sudo=sudo,
                mode=mode,
                old=payload.get("old"),
                new_text=payload.get("new_text"),
                pattern=payload.get("pattern"),
                start_marker=payload.get("start_marker"),
                end_marker=payload.get("end_marker"),
                count=int(payload.get("count", 0) or 0),
                multiline=bool(payload.get("multiline", False)),
                dotall=bool(payload.get("dotall", False)),
                interpret_escapes=bool(payload.get("interpret_escapes", False)),
                backup_dir=payload.get("backup_dir"),
                validator=payload.get("validator"),
                validator_preset=payload.get("validator_preset"),
                diff=bool(payload.get("diff", False)),
                dry_run=bool(payload.get("dry_run", False)),
                allow_no_change=bool(payload.get("allow_no_change", False)),
                create=bool(payload.get("create", False)),
            )

            result = await _run_argv(argv)
            return {
                "ok": result["returncode"] == 0,
                "path": path,
                "mode": mode,
                "sudo": sudo,
                "command": argv,
                **result,
            }
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    return handle_edit


# --- Chunked edit upload --------------------------------------------------------

def _edit_upload_dir(upload_base: Path, upload_id: str) -> Path:
    tmp_root = upload_base / ".sentinelx_uploads"
    tmp_root.mkdir(parents=True, exist_ok=True)
    upload_dir = tmp_root / f"edit_{upload_id}"
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


def _safe_filename(filename: str) -> str:
    """Refuse path traversal: only basename allowed."""
    safe = Path(filename).name
    if not safe or safe.startswith("."):
        raise HandlerError("invalid_payload", f"invalid filename: {filename}")
    return safe


def make_edit_upload_init_handler(upload_base: Path):
    async def handle_edit_upload_init(payload: dict[str, Any]) -> dict[str, Any]:
        """Allocate a workdir, return the upload_id to use in subsequent calls."""
        upload_id = uuid.uuid4().hex
        upload_dir = _edit_upload_dir(upload_base, upload_id)
        return {
            "upload_id": upload_id,
            "upload_dir": str(upload_dir),
        }

    return handle_edit_upload_init


def make_edit_upload_file_handler(upload_base: Path):
    async def handle_edit_upload_file(payload: dict[str, Any]) -> dict[str, Any]:
        """Receive a role file ('old' or 'new') for an in-progress edit upload.

        Content can come either as 'content' (utf-8 string) or 'content_base64'.
        Filename is sanitized to its basename only.
        """
        upload_id = payload.get("upload_id")
        role = payload.get("role")
        filename = payload.get("filename")
        content = payload.get("content")
        content_b64 = payload.get("content_base64")

        if not upload_id:
            raise HandlerError("invalid_payload", "missing 'upload_id'")
        if role not in ("old", "new"):
            raise HandlerError("invalid_payload", "role must be 'old' or 'new'")
        if not filename:
            filename = f"{role}.txt"

        safe_name = _safe_filename(filename)
        upload_dir = _edit_upload_dir(upload_base, upload_id)
        dest = upload_dir / safe_name

        if content is not None and content_b64 is not None:
            raise HandlerError(
                "invalid_payload",
                "provide exactly one of 'content' or 'content_base64'",
            )
        if content is not None:
            dest.write_text(str(content), encoding="utf-8")
        elif content_b64 is not None:
            import base64
            try:
                dest.write_bytes(base64.b64decode(content_b64))
            except Exception as exc:  # noqa: BLE001
                raise HandlerError("invalid_payload", f"bad base64: {exc}") from exc
        else:
            raise HandlerError(
                "invalid_payload",
                "missing 'content' or 'content_base64'",
            )

        return {
            "upload_id": upload_id,
            "role": role,
            "filename": safe_name,
            "size_bytes": dest.stat().st_size,
            "path": str(dest),
        }

    return handle_edit_upload_file


def make_edit_upload_complete_handler(policy: Policy, upload_base: Path):
    """Run pensa-safe-edit using files staged via edit_upload_file."""
    binary = DEFAULT_SAFE_EDIT_BIN

    async def handle_edit_upload_complete(payload: dict[str, Any]) -> dict[str, Any]:
        upload_id = payload.get("upload_id")
        path = payload.get("path")
        mode = payload.get("mode")
        sudo = bool(payload.get("sudo", False))

        if not upload_id:
            raise HandlerError("invalid_payload", "missing 'upload_id'")
        if not path or not str(path).strip():
            raise HandlerError("invalid_payload", "missing 'path'")
        if not mode:
            raise HandlerError("invalid_payload", "missing 'mode'")

        # Mode validation, but slightly looser than single-edit because the
        # 'old' / 'new' content lives in files, not in the payload.
        if mode not in VALID_MODES:
            raise HandlerError(
                "invalid_payload",
                f"mode must be one of: {', '.join(VALID_MODES)}",
            )
        if payload.get("validator") and payload.get("validator_preset"):
            raise HandlerError(
                "invalid_payload",
                "cannot use 'validator' and 'validator_preset' together",
            )
        if mode == "regex" and not payload.get("pattern"):
            raise HandlerError("invalid_payload", "mode=regex requires 'pattern'")
        if mode == "replace-block" and (
            not payload.get("start_marker") or not payload.get("end_marker")
        ):
            raise HandlerError(
                "invalid_payload",
                "mode=replace-block requires 'start_marker' and 'end_marker'",
            )

        upload_dir = _edit_upload_dir(upload_base, upload_id)
        old_file = upload_dir / "old.txt"
        new_file = upload_dir / "new.txt"

        argv = _build_argv(
            binary=binary,
            workdir=upload_dir,
            path=path,
            sudo=sudo,
            mode=mode,
            pattern=payload.get("pattern"),
            start_marker=payload.get("start_marker"),
            end_marker=payload.get("end_marker"),
            count=int(payload.get("count", 0) or 0),
            multiline=bool(payload.get("multiline", False)),
            dotall=bool(payload.get("dotall", False)),
            interpret_escapes=bool(payload.get("interpret_escapes", False)),
            backup_dir=payload.get("backup_dir"),
            validator=payload.get("validator"),
            validator_preset=payload.get("validator_preset"),
            diff=bool(payload.get("diff", False)),
            dry_run=bool(payload.get("dry_run", False)),
            allow_no_change=bool(payload.get("allow_no_change", False)),
            create=bool(payload.get("create", False)),
            old_file_path=old_file if old_file.exists() else None,
            new_file_path=new_file if new_file.exists() else None,
        )

        try:
            result = await _run_argv(argv)
            return {
                "ok": result["returncode"] == 0,
                "path": path,
                "mode": mode,
                "sudo": sudo,
                "upload_id": upload_id,
                "command": argv,
                **result,
            }
        finally:
            shutil.rmtree(upload_dir, ignore_errors=True)

    return handle_edit_upload_complete

"""fsmutate handlers: the destructive filesystem ops.

Five ops, every one gated by the unified file_ops r/rw model — the
resolved path (and, for move/copy, BOTH source and destination) must
fall under a file_ops entry whose access is "rw":

  - move    -> rename/move a file or directory
  - copy    -> copy a file or directory
  - delete  -> delete a file or (with explicit recursive) a directory
  - chmod   -> change mode bits
  - chown   -> change owner/group

Why a separate module from fileops.py? fileops is STRICTLY read-only
(read/list/search). Mixing destructive ops into it would blur the one
property that makes fileops easy to reason about. fsmutate is the
explicit, auditable home for mutation.

Security model
==============

  1. PATH ENFORCE (rw). Every path argument is resolved via
     policy.resolve_path(p, need_write=True). For move/copy that means
     BOTH endpoints — you cannot move a file out of an rw subtree into
     a place you don't control, nor copy from outside in by tricking
     the destination check. Canonicalization resolves symlinks BEFORE
     the prefix check, so `../` traversal and symlink-escape are
     defeated (same load-bearing check as read/edit). This is the
     A1/A2 defense: a compromised hub or LLM cannot reach outside the
     operator's declared writable surface.

  2. MANDATORY BACKUP BEFORE DELETE. delete always makes a backup
     first. A single file -> copy via make_backup (the same helper the
     editor uses, so backups look identical). A directory -> a
     timestamped .tar.gz next to it. If the backup can't be made, the
     delete is REFUSED (backup_failed) — we never destroy without a
     recovery path.

  3. EXPLICIT RECURSION. Deleting a directory requires
     recursive=true in the payload. Without it, a directory delete is
     refused (is_directory). This makes "rm -rf"-shaped mistakes
     impossible to trigger implicitly.

  4. NO SILENT PRIVILEGE FAILURES. chown typically needs root. When
     the agent isn't privileged enough, chown reports
     permission_denied with the errno detail rather than pretending
     it worked — consistent with the editor's copy_metadata refusing
     to swallow chown EPERM.

  5. BEST-EFFORT AUDIT LOG. Every successful mutation appends one
     JSON line to /var/log/sentinelx/mutations.log. This is
     best-effort: if the log can't be written (perms, disk), the op
     STILL succeeds — an audit-log failure must not make a destructive
     op fail half-way. The agent-side log is a partial mitigation
     (THREAT_MODEL §5.5): the authoritative audit trail is still the
     hub's, but a local record helps post-incident on a compromised
     hub.

All error codes are English and structured (HandlerError), matching
fileops.py style: invalid_payload / path_not_allowed / not_found /
is_directory / not_a_directory / exists / permission_denied /
backup_failed / move_failed / copy_failed / delete_failed /
chmod_failed / chown_failed.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelx_core.executor import HandlerError
from sentinelx_core.policy import Policy
from sentinelx_core.vendored.pensa_safe_edit import make_backup

MUTATION_LOG = Path("/var/log/sentinelx/mutations.log")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require_str(payload: dict[str, Any], key: str) -> str:
    val = payload.get(key)
    if not isinstance(val, str) or not val.strip():
        raise HandlerError(
            "invalid_payload", f"missing or non-string {key!r}"
        )
    return val


def _resolve_rw(policy: Policy, path: str, *, label: str = "path") -> Path:
    """Resolve `path` requiring rw access, or raise path_not_allowed.

    This is the fsmutate equivalent of fileops._resolve_or_reject, but
    with need_write=True: destructive ops only operate inside subtrees
    the operator explicitly declared access: rw.
    """
    if not policy.file_ops_paths:
        raise HandlerError(
            "path_not_allowed",
            "file_ops has no paths configured. Destructive ops require "
            "an entry with access: rw.",
            details={label: path, "writable_paths": []},
        )
    resolved = policy.resolve_path(path, need_write=True)
    if resolved is None:
        rw_paths = [
            e.path for e in policy.file_ops_paths if e.access == "rw"
        ]
        raise HandlerError(
            "path_not_allowed",
            f"{label} {path!r} (or its target after resolving "
            "symlinks) is not under any file_ops entry with access: rw.",
            details={label: path, "writable_paths": rw_paths},
        )
    return resolved


def _audit(op: str, detail: dict[str, Any]) -> None:
    """Append one JSON line to the mutation log. Best-effort: never
    raises. An audit-log failure must not fail the operation."""
    try:
        MUTATION_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "op": op,
            **detail,
        }
        with MUTATION_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        # Intentionally swallowed: see module docstring point 5.
        pass


def _dir_backup_targz(src: Path) -> Path:
    """Make a timestamped .tar.gz of a directory next to it."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    archive = src.parent / f"{src.name}.bak.{ts}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(src, arcname=src.name)
    return archive


# ---------------------------------------------------------------------------
# move
# ---------------------------------------------------------------------------


def make_move_handler(policy: Policy):
    async def handle_move(payload: dict[str, Any]) -> dict[str, Any]:
        """Move/rename a file or directory.

        Payload: src (str, required), dst (str, required),
                 overwrite (bool, default False)
        BOTH src and dst must resolve under an rw entry.
        """
        src_str = _require_str(payload, "src")
        dst_str = _require_str(payload, "dst")
        overwrite = bool(payload.get("overwrite", False))

        src = _resolve_rw(policy, src_str, label="src")
        dst = _resolve_rw(policy, dst_str, label="dst")

        if not src.exists():
            raise HandlerError(
                "not_found", f"src does not exist: {src_str!r}"
            )
        if dst.exists() and not overwrite:
            raise HandlerError(
                "exists",
                f"dst already exists: {dst_str!r} (pass overwrite=true "
                "to replace it)",
            )

        try:
            if dst.exists() and overwrite:
                if dst.is_dir() and not dst.is_symlink():
                    shutil.rmtree(dst)
                else:
                    dst.unlink()
            shutil.move(str(src), str(dst))
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot move: {exc.strerror or exc}. The agent's OS "
                "user lacks Unix write permission on the target or a "
                "parent directory. The path is rw-allowed in file_ops, "
                "so this is a filesystem-permission issue, not an "
                "allowlist one, and fsmutate ops never use sudo. Ask "
                "the operator to grant the agent's user write access "
                "there (chmod/chown or an ACL on the file and its "
                "parent directory), or run the agent as a user that "
                "can write. To change a file's contents instead, "
                "sentinel_edit supports sudo=true.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "move_failed", f"move failed: {exc}"
            ) from exc

        _audit("move", {"src": str(src), "dst": str(dst)})
        return {
            "ok": True,
            "op": "move",
            "src": str(src),
            "dst": str(dst),
        }

    return handle_move


# ---------------------------------------------------------------------------
# copy
# ---------------------------------------------------------------------------


def make_copy_handler(policy: Policy):
    async def handle_copy(payload: dict[str, Any]) -> dict[str, Any]:
        """Copy a file or directory.

        Payload: src (str, required), dst (str, required),
                 overwrite (bool, default False)
        BOTH src and dst must resolve under an rw entry — copy is a
        write at the destination, so the destination must be writable.
        """
        src_str = _require_str(payload, "src")
        dst_str = _require_str(payload, "dst")
        overwrite = bool(payload.get("overwrite", False))

        src = _resolve_rw(policy, src_str, label="src")
        dst = _resolve_rw(policy, dst_str, label="dst")

        if not src.exists():
            raise HandlerError(
                "not_found", f"src does not exist: {src_str!r}"
            )
        if dst.exists() and not overwrite:
            raise HandlerError(
                "exists",
                f"dst already exists: {dst_str!r} (pass overwrite=true "
                "to replace it)",
            )

        try:
            if src.is_dir() and not src.is_symlink():
                if dst.exists() and overwrite:
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
                kind = "dir"
            else:
                if dst.exists() and overwrite and dst.is_dir():
                    shutil.rmtree(dst)
                shutil.copy2(src, dst)
                kind = "file"
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot copy: {exc.strerror or exc}. The agent's OS "
                "user lacks Unix write permission on the target or a "
                "parent directory. The path is rw-allowed in file_ops, "
                "so this is a filesystem-permission issue, not an "
                "allowlist one, and fsmutate ops never use sudo. Ask "
                "the operator to grant the agent's user write access "
                "there (chmod/chown or an ACL on the file and its "
                "parent directory), or run the agent as a user that "
                "can write. To change a file's contents instead, "
                "sentinel_edit supports sudo=true.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "copy_failed", f"copy failed: {exc}"
            ) from exc

        _audit("copy", {"src": str(src), "dst": str(dst), "kind": kind})
        return {
            "ok": True,
            "op": "copy",
            "src": str(src),
            "dst": str(dst),
            "kind": kind,
        }

    return handle_copy


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def make_delete_handler(policy: Policy):
    async def handle_delete(payload: dict[str, Any]) -> dict[str, Any]:
        """Delete a file or (with explicit recursive) a directory.

        Payload: path (str, required), recursive (bool, default False)

        ALWAYS backs up first:
          - file      -> sibling .bak.<ts> copy (make_backup)
          - directory -> sibling .bak.<ts>.tar.gz
        If the backup can't be made the delete is refused — we never
        destroy without a recovery path. A directory delete without
        recursive=true is refused (is_directory).
        """
        path_str = _require_str(payload, "path")
        recursive = bool(payload.get("recursive", False))

        target = _resolve_rw(policy, path_str, label="path")

        if not target.exists() and not target.is_symlink():
            raise HandlerError(
                "not_found", f"path does not exist: {path_str!r}"
            )

        is_dir = target.is_dir() and not target.is_symlink()
        if is_dir and not recursive:
            raise HandlerError(
                "is_directory",
                f"{path_str!r} is a directory; pass recursive=true to "
                "delete it (and its contents) — this is deliberate so a "
                "directory is never removed implicitly.",
            )

        # Mandatory backup BEFORE destruction.
        try:
            if is_dir:
                backup = _dir_backup_targz(target)
            else:
                backup = make_backup(target, None)
        except Exception as exc:
            raise HandlerError(
                "backup_failed",
                f"refusing to delete: could not back up {path_str!r} "
                f"first ({exc})",
            ) from exc

        try:
            if is_dir:
                shutil.rmtree(target)
            else:
                target.unlink()
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot delete: {exc.strerror or exc}. The agent's OS "
                "user lacks Unix write permission on the target or a "
                "parent directory. The path is rw-allowed in file_ops, "
                "so this is a filesystem-permission issue, not an "
                "allowlist one, and fsmutate ops never use sudo. Ask "
                "the operator to grant the agent's user write access "
                "there (chmod/chown or an ACL on the file and its "
                "parent directory), or run the agent as a user that "
                "can write. To change a file's contents instead, "
                "sentinel_edit supports sudo=true.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "delete_failed", f"delete failed: {exc}"
            ) from exc

        _audit(
            "delete",
            {
                "path": str(target),
                "kind": "dir" if is_dir else "file",
                "backup": str(backup),
            },
        )
        return {
            "ok": True,
            "op": "delete",
            "path": str(target),
            "kind": "dir" if is_dir else "file",
            "backup": str(backup),
        }

    return handle_delete


# ---------------------------------------------------------------------------
# chmod
# ---------------------------------------------------------------------------


def make_chmod_handler(policy: Policy):
    async def handle_chmod(payload: dict[str, Any]) -> dict[str, Any]:
        """Change mode bits.

        Payload: path (str, required),
                 mode (str octal like "644" or "0755", required)
        """
        path_str = _require_str(payload, "path")
        mode_str = _require_str(payload, "mode")

        try:
            mode = int(mode_str, 8)
        except ValueError as exc:
            raise HandlerError(
                "invalid_payload",
                f"mode must be octal (e.g. '644', '0755'): "
                f"{mode_str!r}",
            ) from exc

        target = _resolve_rw(policy, path_str, label="path")
        if not target.exists():
            raise HandlerError(
                "not_found", f"path does not exist: {path_str!r}"
            )

        try:
            target.chmod(mode)
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                f"cannot chmod: {exc.strerror or exc}. The agent's OS "
                "user lacks Unix write permission on the target or a "
                "parent directory. The path is rw-allowed in file_ops, "
                "so this is a filesystem-permission issue, not an "
                "allowlist one, and fsmutate ops never use sudo. Ask "
                "the operator to grant the agent's user write access "
                "there (chmod/chown or an ACL on the file and its "
                "parent directory), or run the agent as a user that "
                "can write. To change a file's contents instead, "
                "sentinel_edit supports sudo=true.",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "chmod_failed", f"chmod failed: {exc}"
            ) from exc

        _audit("chmod", {"path": str(target), "mode": oct(mode)})
        return {
            "ok": True,
            "op": "chmod",
            "path": str(target),
            "mode": oct(mode),
        }

    return handle_chmod


# ---------------------------------------------------------------------------
# chown
# ---------------------------------------------------------------------------


def make_chown_handler(policy: Policy):
    async def handle_chown(payload: dict[str, Any]) -> dict[str, Any]:
        """Change owner and/or group.

        Payload: path (str, required),
                 owner (str username, optional),
                 group (str group name, optional)
        At least one of owner/group is required. chown typically needs
        root; when the agent isn't privileged the op fails LOUD with
        permission_denied (never a silent no-op).
        """
        path_str = _require_str(payload, "path")
        owner = payload.get("owner")
        group = payload.get("group")
        if not owner and not group:
            raise HandlerError(
                "invalid_payload",
                "at least one of 'owner' or 'group' is required",
            )

        target = _resolve_rw(policy, path_str, label="path")
        if not target.exists():
            raise HandlerError(
                "not_found", f"path does not exist: {path_str!r}"
            )

        uid = -1
        gid = -1
        if owner:
            try:
                uid = pwd.getpwnam(str(owner)).pw_uid
            except KeyError as exc:
                raise HandlerError(
                    "invalid_payload",
                    f"unknown user: {owner!r}",
                ) from exc
        if group:
            try:
                gid = grp.getgrnam(str(group)).gr_gid
            except KeyError as exc:
                raise HandlerError(
                    "invalid_payload",
                    f"unknown group: {group!r}",
                ) from exc

        try:
            os.chown(target, uid, gid)
        except PermissionError as exc:
            raise HandlerError(
                "permission_denied",
                "cannot chown (this usually requires root; the agent "
                f"is not privileged enough): {exc.strerror or exc}",
            ) from exc
        except OSError as exc:
            raise HandlerError(
                "chown_failed", f"chown failed: {exc}"
            ) from exc

        _audit(
            "chown",
            {
                "path": str(target),
                "owner": owner or None,
                "group": group or None,
            },
        )
        return {
            "ok": True,
            "op": "chown",
            "path": str(target),
            "owner": owner or None,
            "group": group or None,
        }

    return handle_chown

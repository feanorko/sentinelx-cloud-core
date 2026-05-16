"""Tests for the fsmutate handlers (move/copy/delete/chmod/chown).

Coverage priorities:
  - happy path for each op
  - the rw gate: a path outside an rw entry is refused; BOTH endpoints
    of move/copy are gated (destination too)
  - delete always backs up first; a directory needs recursive=true and
    is archived to .tar.gz
  - hostile traversal / symlink-escape is defeated (A1/A2)
  - chown with no privilege fails LOUD (permission_denied), never a
    silent no-op
  - the audit log is best-effort (a broken log dir never fails the op)

Everything runs in tmp_path. The rw policy points at a tmp subtree.
"""

from __future__ import annotations

import os
import tarfile
from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers.fsmutate import (
    make_chmod_handler,
    make_chown_handler,
    make_copy_handler,
    make_delete_handler,
    make_move_handler,
)
from sentinelx_core.policy import Policy


@pytest.fixture
def rw_root(tmp_path: Path) -> Path:
    d = tmp_path / "rw"
    d.mkdir()
    return d


@pytest.fixture
def policy(rw_root: Path) -> Policy:
    """A policy with the tmp rw subtree declared access: rw, plus a
    separate read-only subtree to prove the gate distinguishes them."""
    ro = rw_root.parent / "ro"
    ro.mkdir()
    return Policy.from_dict(
        {
            "file_ops": {
                "paths": [
                    {"path": str(rw_root), "access": "rw"},
                    {"path": str(ro), "access": "r"},
                ]
            }
        }
    )


# --- move --------------------------------------------------------------------


async def test_move_happy(policy: Policy, rw_root: Path) -> None:
    src = rw_root / "a.txt"
    src.write_text("hello")
    dst = rw_root / "b.txt"
    h = make_move_handler(policy)
    res = await h({"src": str(src), "dst": str(dst)})
    assert res["ok"] is True
    assert not src.exists()
    assert dst.read_text() == "hello"


async def test_move_destination_outside_rw_is_refused(
    policy: Policy, rw_root: Path, tmp_path: Path
) -> None:
    """The destination is gated exactly like the source — otherwise
    move would be an exfiltration primitive."""
    src = rw_root / "a.txt"
    src.write_text("x")
    outside = tmp_path / "elsewhere" / "a.txt"
    outside.parent.mkdir()
    h = make_move_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"src": str(src), "dst": str(outside)})
    assert exc.value.code == "path_not_allowed"
    assert src.exists()  # nothing moved


async def test_move_source_in_readonly_is_refused(
    policy: Policy, rw_root: Path
) -> None:
    ro = rw_root.parent / "ro"
    src = ro / "a.txt"
    src.write_text("x")
    h = make_move_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"src": str(src), "dst": str(rw_root / "a.txt")})
    assert exc.value.code == "path_not_allowed"


# --- copy --------------------------------------------------------------------


async def test_copy_file_happy(policy: Policy, rw_root: Path) -> None:
    src = rw_root / "a.txt"
    src.write_text("data")
    dst = rw_root / "copy.txt"
    h = make_copy_handler(policy)
    res = await h({"src": str(src), "dst": str(dst)})
    assert res["ok"] is True
    assert src.read_text() == "data"  # source preserved
    assert dst.read_text() == "data"


async def test_copy_directory_happy(
    policy: Policy, rw_root: Path
) -> None:
    srcdir = rw_root / "tree"
    (srcdir / "sub").mkdir(parents=True)
    (srcdir / "sub" / "f.txt").write_text("nested")
    dst = rw_root / "tree_copy"
    h = make_copy_handler(policy)
    res = await h({"src": str(srcdir), "dst": str(dst)})
    assert res["ok"] is True
    assert (dst / "sub" / "f.txt").read_text() == "nested"


async def test_copy_existing_destination_needs_overwrite(
    policy: Policy, rw_root: Path
) -> None:
    src = rw_root / "a.txt"
    src.write_text("new")
    dst = rw_root / "b.txt"
    dst.write_text("old")
    h = make_copy_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"src": str(src), "dst": str(dst)})
    assert exc.value.code == "exists"
    assert dst.read_text() == "old"  # untouched
    # with overwrite it proceeds
    res = await h(
        {"src": str(src), "dst": str(dst), "overwrite": True}
    )
    assert res["ok"] is True
    assert dst.read_text() == "new"


# --- delete ------------------------------------------------------------------


async def test_delete_file_makes_backup_first(
    policy: Policy, rw_root: Path
) -> None:
    f = rw_root / "doomed.txt"
    f.write_text("precious")
    h = make_delete_handler(policy)
    res = await h({"path": str(f)})
    assert res["ok"] is True
    assert not f.exists()
    backup = Path(res["backup"])
    assert backup.exists()
    assert backup.read_text() == "precious"  # recoverable


async def test_delete_directory_requires_recursive(
    policy: Policy, rw_root: Path
) -> None:
    d = rw_root / "adir"
    d.mkdir()
    (d / "f").write_text("x")
    h = make_delete_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"path": str(d)})
    assert exc.value.code == "is_directory"
    assert d.exists()  # not deleted without explicit recursive


async def test_delete_directory_recursive_makes_targz(
    policy: Policy, rw_root: Path
) -> None:
    d = rw_root / "adir"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "f").write_text("content")
    h = make_delete_handler(policy)
    res = await h({"path": str(d), "recursive": True})
    assert res["ok"] is True
    assert not d.exists()
    backup = Path(res["backup"])
    assert backup.exists()
    assert backup.name.endswith(".tar.gz")
    # the archive actually contains the tree
    with tarfile.open(backup, "r:gz") as tar:
        names = tar.getnames()
    assert any("sub/f" in n for n in names)


async def test_delete_outside_rw_is_refused(
    policy: Policy, tmp_path: Path
) -> None:
    outside = tmp_path / "notallowed.txt"
    outside.write_text("safe")
    h = make_delete_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"path": str(outside)})
    assert exc.value.code == "path_not_allowed"
    assert outside.exists()


async def test_delete_traversal_escape_is_defeated(
    policy: Policy, rw_root: Path, tmp_path: Path
) -> None:
    """A `..` path that resolves outside the rw subtree must be
    refused — canonicalization happens before the gate."""
    secret = tmp_path / "secret.txt"
    secret.write_text("dont touch")
    h = make_delete_handler(policy)
    traversal = str(rw_root / ".." / "secret.txt")
    with pytest.raises(HandlerError) as exc:
        await h({"path": traversal})
    assert exc.value.code == "path_not_allowed"
    assert secret.exists()


# --- chmod -------------------------------------------------------------------


async def test_chmod_happy(policy: Policy, rw_root: Path) -> None:
    f = rw_root / "s.sh"
    f.write_text("#!/bin/sh\n")
    h = make_chmod_handler(policy)
    res = await h({"path": str(f), "mode": "750"})
    assert res["ok"] is True
    assert (f.stat().st_mode & 0o777) == 0o750


async def test_chmod_rejects_bad_mode(
    policy: Policy, rw_root: Path
) -> None:
    f = rw_root / "f"
    f.write_text("x")
    h = make_chmod_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"path": str(f), "mode": "not-octal"})
    assert exc.value.code == "invalid_payload"


async def test_chmod_outside_rw_is_refused(
    policy: Policy, tmp_path: Path
) -> None:
    f = tmp_path / "f"
    f.write_text("x")
    h = make_chmod_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"path": str(f), "mode": "600"})
    assert exc.value.code == "path_not_allowed"


# --- chown -------------------------------------------------------------------


async def test_chown_no_privilege_fails_loud(
    policy: Policy, rw_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """chown to another owner EPERMs for a non-root agent. It must
    surface permission_denied — never pretend success."""
    f = rw_root / "f"
    f.write_text("x")

    def boom(*_a, **_k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chown", boom)
    h = make_chown_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"path": str(f), "owner": "root"})
    assert exc.value.code == "permission_denied"


async def test_chown_requires_owner_or_group(
    policy: Policy, rw_root: Path
) -> None:
    f = rw_root / "f"
    f.write_text("x")
    h = make_chown_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h({"path": str(f)})
    assert exc.value.code == "invalid_payload"


async def test_chown_unknown_user_is_invalid_payload(
    policy: Policy, rw_root: Path
) -> None:
    f = rw_root / "f"
    f.write_text("x")
    h = make_chown_handler(policy)
    with pytest.raises(HandlerError) as exc:
        await h(
            {"path": str(f), "owner": "nosuchuser_xyzzy_12345"}
        )
    assert exc.value.code == "invalid_payload"


# --- audit log is best-effort -----------------------------------------------


async def test_audit_failure_does_not_break_op(
    policy: Policy, rw_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the mutation log can't be written, the op still succeeds —
    auditing must never be the reason a legitimate op fails."""
    import sentinelx_core.handlers.fsmutate as fsm

    def boom(*_a, **_k):
        raise OSError("disk full")

    # Break the log path's mkdir so _audit's try/except is exercised.
    monkeypatch.setattr(
        fsm.MUTATION_LOG.__class__, "mkdir",
        lambda *a, **k: (_ for _ in ()).throw(OSError("nope")),
    )
    f = rw_root / "a.txt"
    f.write_text("x")
    h = make_move_handler(policy)
    res = await h({"src": str(f), "dst": str(rw_root / "b.txt")})
    assert res["ok"] is True  # op succeeded despite audit failure

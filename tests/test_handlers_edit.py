"""Tests for edit handlers — both single-call and chunked.

These tests use a fake `pensa-safe-edit` binary (a small bash script we drop
into the workdir's PATH) so they can run anywhere, not just on pensa-orion.
The fake script prints its arguments and writes a marker file so we can verify
the handler called it correctly.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.handlers.edit import _build_argv
from sentinelx_core.policy import FileOpsPath, Policy


@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    # edit is now path-enforced under the unified r/rw model: the
    # target must fall under a file_ops entry with access "rw". The
    # existing happy-path tests target /tmp/..., so declare /tmp as rw
    # here. Tests that specifically exercise the path-enforce (r path
    # rejected, outside-allowlist rejected, traversal) build their own
    # policy explicitly.
    p = Policy(file_ops_paths=(FileOpsPath(path="/tmp", access="rw"),))
    object.__setattr__(p, "upload_base", tmp_path)
    return p


@pytest.fixture
def fake_safe_edit(tmp_path: Path):
    """Drop a fake pensa-safe-edit binary that just exits 0 and echoes args."""
    fake_bin = tmp_path / "pensa-safe-edit"
    fake_bin.write_text(
        "#!/bin/bash\n"
        'echo "FAKE-SAFE-EDIT $@"\n'
        "exit 0\n"
    )
    fake_bin.chmod(0o755)
    return fake_bin


# --- argv-building tests (pure, no exec) -------------------------------------

def test_build_argv_replace_mode(tmp_path: Path) -> None:
    workdir = tmp_path / "wd"
    workdir.mkdir()
    argv = _build_argv(
        binary="/usr/local/bin/pensa-safe-edit",
        workdir=workdir,
        path="/etc/example.conf",
        sudo=True,
        mode="replace",
        old="foo",
        new_text="bar",
        diff=True,
    )
    assert argv[0] == "sudo"
    assert argv[1] == "/usr/local/bin/pensa-safe-edit"
    assert argv[2] == "/etc/example.conf"
    assert "--mode" in argv and "replace" in argv
    assert "--diff" in argv
    # old/new should have been written to files
    assert "--old-file" in argv
    assert "--new-file" in argv
    # And the files should exist with the right content
    old_file = argv[argv.index("--old-file") + 1]
    new_file = argv[argv.index("--new-file") + 1]
    assert Path(old_file).read_text() == "foo"
    assert Path(new_file).read_text() == "bar"


def test_build_argv_regex_with_flags(tmp_path: Path) -> None:
    workdir = tmp_path / "wd"
    workdir.mkdir()
    argv = _build_argv(
        binary="/bin/pensa-safe-edit",
        workdir=workdir,
        path="/tmp/x",
        sudo=False,
        mode="regex",
        pattern=r"foo\d+",
        new_text="bar",
        count=2,
        multiline=True,
        dotall=True,
        validator_preset="json",
    )
    assert argv[0] != "sudo"
    assert "--pattern" in argv
    assert r"foo\d+" in argv
    assert "--count" in argv
    assert "2" in argv
    assert "--multiline" in argv
    assert "--dotall" in argv
    assert "--validator-preset" in argv
    assert "json" in argv


def test_build_argv_replace_block(tmp_path: Path) -> None:
    workdir = tmp_path / "wd"
    workdir.mkdir()
    argv = _build_argv(
        binary="/bin/pensa-safe-edit",
        workdir=workdir,
        path="/tmp/x",
        sudo=False,
        mode="replace-block",
        start_marker="# BEGIN",
        end_marker="# END",
        new_text="REPLACED",
    )
    assert "--start-marker" in argv
    assert "--end-marker" in argv


# --- handler validation tests (no exec) --------------------------------------

async def test_edit_missing_path(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError):
        await handlers["edit"]({"mode": "replace", "old": "x", "new_text": "y"})


async def test_edit_missing_mode(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError):
        await handlers["edit"]({"path": "/tmp/x"})


async def test_edit_invalid_mode(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["edit"]({"path": "/tmp/x", "mode": "nonexistent"})
    assert "mode must be" in str(exc.value)


async def test_edit_replace_requires_old_and_new(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    # Missing 'old'
    with pytest.raises(HandlerError):
        await handlers["edit"]({
            "path": "/tmp/x", "mode": "replace", "new_text": "y",
        })
    # Missing 'new_text'
    with pytest.raises(HandlerError):
        await handlers["edit"]({
            "path": "/tmp/x", "mode": "replace", "old": "x",
        })


async def test_edit_validator_and_preset_conflict(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["edit"]({
            "path": "/tmp/x",
            "mode": "write",
            "new_text": "y",
            "validator": "true",
            "validator_preset": "json",
        })
    assert "together" in str(exc.value)


async def test_edit_negative_count(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError):
        await handlers["edit"]({
            "path": "/tmp/x",
            "mode": "replace",
            "old": "x",
            "new_text": "y",
            "count": -1,
        })


async def test_edit_replace_block_requires_markers(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError):
        await handlers["edit"]({
            "path": "/tmp/x",
            "mode": "replace-block",
            "new_text": "y",
            # missing start_marker / end_marker
        })


# --- end-to-end with fake binary ---------------------------------------------

async def test_edit_runs_fake_binary(policy: Policy, fake_safe_edit: Path) -> None:
    """Patch the binary resolver and verify the handler builds + runs argv correctly.

    NOTE: we patch `_resolve_safe_edit_bin` (the actual resolution
    function the handler calls at construction time), NOT the legacy
    `DEFAULT_SAFE_EDIT_BIN` constant. That constant is dead — kept only
    for backward-compat with old references — and the resolver stopped
    consulting it when binary resolution moved to the bundled→legacy→PATH
    lookup. Patching the dead constant left the handler resolving the
    real bundled binary, which is why these three tests failed on main
    independently of the r/rw work. This is an incidental test fix.
    """
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=policy)
        result = await handlers["edit"]({
            "path": "/tmp/example",
            "mode": "write",
            "new_text": "hello world",
        })
    assert result["ok"] is True
    assert result["returncode"] == 0
    assert "FAKE-SAFE-EDIT" in result["output"]
    assert "/tmp/example" in result["output"]


async def test_edit_returns_error_when_binary_missing(policy: Policy) -> None:
    """If pensa-safe-edit isn't installed, handler should raise binary_missing.

    Same incidental fix as above: patch the resolver, not the dead
    DEFAULT_SAFE_EDIT_BIN constant.
    """
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value="/no/such/binary/here",
    ):
        handlers = build_registry(policy=policy)
        with pytest.raises(HandlerError) as exc:
            await handlers["edit"]({
                "path": "/tmp/x",
                "mode": "write",
                "new_text": "y",
            })
    assert exc.value.code == "binary_missing"


# --- chunked edit upload -----------------------------------------------------

async def test_edit_upload_init_returns_id(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    result = await handlers["edit_upload_init"]({})
    assert "upload_id" in result
    assert "upload_dir" in result
    assert Path(result["upload_dir"]).is_dir()


async def test_edit_upload_file_writes_role(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    init = await handlers["edit_upload_init"]({})
    upload_id = init["upload_id"]

    await handlers["edit_upload_file"]({
        "upload_id": upload_id,
        "role": "old",
        "content": "OLD CONTENT",
    })
    await handlers["edit_upload_file"]({
        "upload_id": upload_id,
        "role": "new",
        "content": "NEW CONTENT",
    })

    upload_dir = Path(init["upload_dir"])
    assert (upload_dir / "old.txt").read_text() == "OLD CONTENT"
    assert (upload_dir / "new.txt").read_text() == "NEW CONTENT"


async def test_edit_upload_file_invalid_role(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    init = await handlers["edit_upload_init"]({})
    with pytest.raises(HandlerError):
        await handlers["edit_upload_file"]({
            "upload_id": init["upload_id"],
            "role": "middle",  # invalid
            "content": "x",
        })


async def test_edit_upload_complete_runs_with_files(
    policy: Policy, fake_safe_edit: Path
) -> None:
    # Incidental fix: patch the resolver, not the dead constant (see
    # test_edit_runs_fake_binary for the full explanation).
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=policy)
        init = await handlers["edit_upload_init"]({})
        await handlers["edit_upload_file"]({
            "upload_id": init["upload_id"],
            "role": "old",
            "content": "before",
        })
        await handlers["edit_upload_file"]({
            "upload_id": init["upload_id"],
            "role": "new",
            "content": "after",
        })
        result = await handlers["edit_upload_complete"]({
            "upload_id": init["upload_id"],
            "path": "/tmp/test",
            "mode": "replace",
        })
    assert result["ok"] is True
    assert "--old-file" in result["command"]
    assert "--new-file" in result["command"]


# --- path-enforce under the unified r/rw model -------------------------------
#
# edit is a mutating op: the target MUST resolve under a file_ops entry
# whose access is "rw". These tests build their own policies (the shared
# `policy` fixture declares /tmp as rw for the happy-path tests above).


def _policy_with(tmp_path: Path, entries) -> Policy:
    p = Policy(file_ops_paths=tuple(entries))
    object.__setattr__(p, "upload_base", tmp_path)
    return p


async def test_edit_rejected_when_path_outside_allowlist(
    tmp_path: Path, fake_safe_edit: Path
) -> None:
    """A path under no file_ops entry at all is rejected with
    path_not_allowed — before the binary is ever invoked."""
    pol = _policy_with(tmp_path, [FileOpsPath(path="/srv/app", access="rw")])
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=pol)
        with pytest.raises(HandlerError) as exc:
            await handlers["edit"]({
                "path": "/etc/passwd",
                "mode": "write",
                "new_text": "x",
            })
    assert exc.value.code == "path_not_allowed"
    assert "writable_paths" in exc.value.details


async def test_edit_rejected_when_path_is_read_only(
    tmp_path: Path, fake_safe_edit: Path
) -> None:
    """A path under an access:r entry is rejected for edit (read-only
    means no mutation), even though read/list/search would resolve."""
    ro = tmp_path / "ro"
    ro.mkdir()
    pol = _policy_with(tmp_path, [FileOpsPath(path=str(ro), access="r")])
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=pol)
        with pytest.raises(HandlerError) as exc:
            await handlers["edit"]({
                "path": str(ro / "f.txt"),
                "mode": "write",
                "new_text": "x",
            })
    assert exc.value.code == "path_not_allowed"


async def test_edit_allowed_under_rw_entry(
    tmp_path: Path, fake_safe_edit: Path
) -> None:
    """The happy path: a target under an access:rw entry reaches the
    binary and succeeds."""
    rw = tmp_path / "rw"
    rw.mkdir()
    pol = _policy_with(tmp_path, [FileOpsPath(path=str(rw), access="rw")])
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=pol)
        result = await handlers["edit"]({
            "path": str(rw / "f.txt"),
            "mode": "write",
            "new_text": "hello",
        })
    assert result["ok"] is True
    assert "FAKE-SAFE-EDIT" in result["output"]


async def test_edit_traversal_escape_is_rejected(
    tmp_path: Path, fake_safe_edit: Path
) -> None:
    """`../` cannot climb out of the rw entry — canonicalization in
    resolve_path defeats it before the binary is touched. This is the
    A1/A2 defense: a hostile caller can't escape the writable subtree."""
    rw = tmp_path / "rw"
    rw.mkdir()
    (tmp_path / "secret").mkdir()
    pol = _policy_with(tmp_path, [FileOpsPath(path=str(rw), access="rw")])
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=pol)
        with pytest.raises(HandlerError) as exc:
            await handlers["edit"]({
                "path": str(rw / ".." / "secret" / "loot"),
                "mode": "write",
                "new_text": "x",
            })
    assert exc.value.code == "path_not_allowed"


async def test_edit_upload_complete_is_also_path_enforced(
    tmp_path: Path, fake_safe_edit: Path
) -> None:
    """The chunked-upload completion path must enforce rw too — it
    must not be a bypass of the single-edit path-enforce."""
    pol = _policy_with(tmp_path, [FileOpsPath(path="/srv/app", access="rw")])
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=pol)
        init = await handlers["edit_upload_init"]({})
        await handlers["edit_upload_file"]({
            "upload_id": init["upload_id"],
            "role": "new",
            "content": "after",
        })
        with pytest.raises(HandlerError) as exc:
            await handlers["edit_upload_complete"]({
                "upload_id": init["upload_id"],
                "path": "/etc/shadow",
                "mode": "write",
            })
    assert exc.value.code == "path_not_allowed"



async def test_edit_sudo_bypasses_rw_gate_outside_allowlist(
    tmp_path: Path, fake_safe_edit: Path
) -> None:
    """sudo=True edits are NOT gated by the rw model — they cross the
    operator's sudoers boundary instead. This is what makes the
    add_allowed_read_path playbook work: it edits the root-owned
    /etc/sentinelx/config.yaml (under no rw entry) with sudo=true.
    Without this carve-out, self-service policy administration is
    broken by the path-enforce hardening."""
    # An rw entry exists but the target is deliberately OUTSIDE it,
    # mimicking editing /etc/sentinelx/config.yaml when only a project
    # dir is rw.
    rw = tmp_path / "rw"
    rw.mkdir()
    outside = tmp_path / "etc_like"
    outside.mkdir()
    pol = _policy_with(tmp_path, [FileOpsPath(path=str(rw), access="rw")])
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=pol)
        result = await handlers["edit"]({
            "path": str(outside / "config.yaml"),
            "mode": "write",
            "new_text": "x",
            "sudo": True,
        })
    assert result["ok"] is True
    assert "FAKE-SAFE-EDIT" in result["output"]


async def test_edit_nonsudo_still_rejected_outside_allowlist(
    tmp_path: Path, fake_safe_edit: Path
) -> None:
    """The load-bearing check MUST survive the sudo carve-out: a
    NON-sudo edit outside any rw entry still rejects with
    path_not_allowed. A2 (compromised LLM) cannot grant itself write
    on an unprivileged path just because the sudo path now exists."""
    rw = tmp_path / "rw"
    rw.mkdir()
    outside = tmp_path / "etc_like"
    outside.mkdir()
    pol = _policy_with(tmp_path, [FileOpsPath(path=str(rw), access="rw")])
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=pol)
        with pytest.raises(HandlerError) as exc:
            await handlers["edit"]({
                "path": str(outside / "config.yaml"),
                "mode": "write",
                "new_text": "x",
                # no sudo → still gated
            })
    assert exc.value.code == "path_not_allowed"
    assert "writable_paths" in exc.value.details


async def test_edit_sudo_still_canonicalizes_path(
    tmp_path: Path, fake_safe_edit: Path
) -> None:
    """The sudo carve-out lifts the rw VERDICT but NOT the
    canonicalization: `../` in a sudo edit path is still collapsed
    before the binary is invoked, so sudo is not a traversal bypass.
    We assert the argv handed to the fake binary contains the
    canonical (resolved) path, not the raw `..`-containing string."""
    rw = tmp_path / "rw"
    rw.mkdir()
    target_dir = tmp_path / "real"
    target_dir.mkdir()
    pol = _policy_with(tmp_path, [FileOpsPath(path=str(rw), access="rw")])
    raw = str(rw / ".." / "real" / "f.txt")
    canonical = str((target_dir / "f.txt").resolve())
    with patch(
        "sentinelx_core.handlers.edit._resolve_safe_edit_bin",
        return_value=str(fake_safe_edit),
    ):
        handlers = build_registry(policy=pol)
        result = await handlers["edit"]({
            "path": raw,
            "mode": "write",
            "new_text": "x",
            "sudo": True,
        })
    assert result["ok"] is True
    # The fake binary echoes its argv; the canonical path must appear
    # and the raw `..` form must NOT.
    assert canonical in result["output"]
    assert "/.." not in result["output"]
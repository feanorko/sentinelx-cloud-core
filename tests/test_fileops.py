"""Regression tests for fileops path-enforce under the unified r/rw model.

Context: when file_ops_allowed_read_paths was renamed to file_ops_paths,
fileops._resolve_or_reject still referenced the old attribute and broke
silently — there was no test_fileops.py to catch it (basic.py had tests
that did catch the equivalent break). This file adds the minimum
regression coverage for the path-resolution contract of read/list/search
so that break can't recur unnoticed. It is intentionally NOT a full
read/list/search behaviour suite — only the security-relevant path gate
that the r/rw refactor touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import FileOpsPath, Policy


def _policy(tmp_path: Path, entries) -> Policy:
    p = Policy(file_ops_paths=tuple(entries))
    object.__setattr__(p, "upload_base", tmp_path)
    return p


async def test_read_rejects_when_no_paths_configured(tmp_path: Path) -> None:
    """Empty allowlist => path_not_allowed (not AttributeError). This is
    the exact regression: the renamed attribute used to blow up here."""
    pol = _policy(tmp_path, [])
    handlers = build_registry(policy=pol)
    with pytest.raises(HandlerError) as exc:
        await handlers["read"]({"path": str(tmp_path / "x")})
    assert exc.value.code == "path_not_allowed"


async def test_read_rejects_path_outside_allowlist(tmp_path: Path) -> None:
    inside = tmp_path / "allowed"
    inside.mkdir()
    pol = _policy(tmp_path, [FileOpsPath(path=str(inside), access="r")])
    handlers = build_registry(policy=pol)
    with pytest.raises(HandlerError) as exc:
        await handlers["read"]({"path": "/etc/passwd"})
    assert exc.value.code == "path_not_allowed"


async def test_read_resolves_under_r_entry(tmp_path: Path) -> None:
    """A real file under an access:r entry is readable (read does not
    require rw — need_write=False)."""
    d = tmp_path / "allowed"
    d.mkdir()
    f = d / "hello.txt"
    f.write_text("content here")
    pol = _policy(tmp_path, [FileOpsPath(path=str(d), access="r")])
    handlers = build_registry(policy=pol)
    result = await handlers["read"]({"path": str(f)})
    assert "content here" in result["content"]


async def test_read_resolves_under_rw_entry(tmp_path: Path) -> None:
    """Reading an rw path is fine too — access level only gates
    mutation, never reads."""
    d = tmp_path / "rw"
    d.mkdir()
    f = d / "f.txt"
    f.write_text("data")
    pol = _policy(tmp_path, [FileOpsPath(path=str(d), access="rw")])
    handlers = build_registry(policy=pol)
    result = await handlers["read"]({"path": str(f)})
    assert "data" in result["content"]


async def test_read_traversal_escape_rejected(tmp_path: Path) -> None:
    d = tmp_path / "allowed"
    d.mkdir()
    (tmp_path / "secret").mkdir()
    secret = tmp_path / "secret" / "loot.txt"
    secret.write_text("TOPSECRET")
    pol = _policy(tmp_path, [FileOpsPath(path=str(d), access="r")])
    handlers = build_registry(policy=pol)
    with pytest.raises(HandlerError) as exc:
        await handlers["read"]({
            "path": str(d / ".." / "secret" / "loot.txt"),
        })
    assert exc.value.code == "path_not_allowed"


async def test_list_and_search_share_the_same_gate(tmp_path: Path) -> None:
    """list and search go through the same _resolve_or_reject — a quick
    smoke that neither regressed to AttributeError on empty allowlist."""
    pol = _policy(tmp_path, [])
    handlers = build_registry(policy=pol)
    for op in ("list", "search"):
        payload = {"path": str(tmp_path)}
        if op == "search":
            payload["pattern"] = "x"
        with pytest.raises(HandlerError) as exc:
            await handlers[op](payload)
        assert exc.value.code == "path_not_allowed"

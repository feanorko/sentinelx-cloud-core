"""Tests for upload handlers."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy


@pytest.fixture
def policy(tmp_path: Path) -> Policy:
    p = Policy()
    object.__setattr__(p, "upload_base", tmp_path)
    return p


async def test_upload_file_inline_base64(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    payload = b"hello world\n" * 10
    b64 = base64.b64encode(payload).decode()

    result = await handlers["upload_file"]({
        "target_path": "test/hello.txt",
        "content_base64": b64,
        "filename": "hello.txt",
    })
    assert result["ok"] is True
    assert result["mode"] == "single"
    assert result["size"] == len(payload)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert Path(result["target_path"]).read_bytes() == payload


async def test_upload_file_rejects_path_traversal(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_file"]({
            "target_path": "../../../etc/passwd",
            "content_base64": base64.b64encode(b"hi").decode(),
        })
    assert exc.value.code == "path_traversal"


async def test_upload_file_conflict_when_exists(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    payload = b"first"
    b64 = base64.b64encode(payload).decode()

    # First write succeeds
    result1 = await handlers["upload_file"]({
        "target_path": "x.txt",
        "content_base64": b64,
    })
    assert result1["ok"] is True

    # Second without overwrite fails
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_file"]({
            "target_path": "x.txt",
            "content_base64": b64,
        })
    assert exc.value.code == "conflict"


async def test_upload_file_overwrite_works(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    b64a = base64.b64encode(b"first").decode()
    b64b = base64.b64encode(b"second").decode()

    await handlers["upload_file"]({"target_path": "x.txt", "content_base64": b64a})
    r = await handlers["upload_file"]({
        "target_path": "x.txt", "content_base64": b64b, "overwrite": True,
    })
    assert r["ok"] is True
    assert Path(r["target_path"]).read_bytes() == b"second"


async def test_upload_file_requires_one_source(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    # Neither source
    with pytest.raises(HandlerError):
        await handlers["upload_file"]({"target_path": "x.txt"})
    # Both sources
    with pytest.raises(HandlerError):
        await handlers["upload_file"]({
            "target_path": "x.txt",
            "content_base64": base64.b64encode(b"a").decode(),
            "file_url": "http://example.com",
        })


async def test_chunked_upload_full_cycle(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    payload = b"A" * 200_000  # 200 KB, split into 2 chunks of 100 KB
    chunk1 = payload[:100_000]
    chunk2 = payload[100_000:]

    init = await handlers["upload_init"]({
        "target_path": "big/file.bin",
        "total_size": len(payload),
        "filename": "file.bin",
    })
    assert init["ok"] is True
    upload_id = init["upload_id"]

    # Upload chunks
    await handlers["upload_chunk"]({
        "upload_id": upload_id,
        "index": 0,
        "content_base64": base64.b64encode(chunk1).decode(),
    })
    await handlers["upload_chunk"]({
        "upload_id": upload_id,
        "index": 1,
        "content_base64": base64.b64encode(chunk2).decode(),
    })

    # Complete with sha256 verification
    expected_sha = hashlib.sha256(payload).hexdigest()
    result = await handlers["upload_complete"]({
        "upload_id": upload_id,
        "sha256": expected_sha,
    })
    assert result["ok"] is True
    assert result["size"] == len(payload)
    assert result["sha256"] == expected_sha
    assert Path(result["target_path"]).read_bytes() == payload


async def test_chunked_upload_size_mismatch(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    init = await handlers["upload_init"]({
        "target_path": "x.bin",
        "total_size": 100,  # we'll only upload 5 bytes
    })
    upload_id = init["upload_id"]

    await handlers["upload_chunk"]({
        "upload_id": upload_id,
        "index": 0,
        "content_base64": base64.b64encode(b"hello").decode(),
    })

    with pytest.raises(HandlerError) as exc:
        await handlers["upload_complete"]({"upload_id": upload_id})
    assert exc.value.code == "size_mismatch"


async def test_chunked_upload_checksum_mismatch(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    init = await handlers["upload_init"]({"target_path": "x.bin"})
    upload_id = init["upload_id"]

    await handlers["upload_chunk"]({
        "upload_id": upload_id,
        "index": 0,
        "content_base64": base64.b64encode(b"hello").decode(),
    })

    with pytest.raises(HandlerError) as exc:
        await handlers["upload_complete"]({
            "upload_id": upload_id,
            "sha256": "0" * 64,  # definitely wrong
        })
    assert exc.value.code == "checksum_mismatch"


async def test_upload_complete_unknown_id(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_complete"]({"upload_id": "does-not-exist"})
    assert exc.value.code == "not_found"


async def test_upload_chunk_unknown_id(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["upload_chunk"]({
            "upload_id": "does-not-exist",
            "index": 0,
            "content_base64": base64.b64encode(b"x").decode(),
        })
    assert exc.value.code == "not_found"

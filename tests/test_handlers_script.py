"""Tests for script_run handler."""

from __future__ import annotations

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


async def test_script_run_python_simple(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    result = await handlers["script_run"]({
        "interpreter": "python3",
        "content": "print('hello'); print(2 + 2)",
    })
    assert result["ok"] is True
    assert result["returncode"] == 0
    assert "hello" in result["output"]
    assert "4" in result["output"]
    assert result["interpreter"] == "python3"


async def test_script_run_bash_simple(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    result = await handlers["script_run"]({
        "interpreter": "bash",
        "content": "echo hello; echo done",
    })
    assert result["ok"] is True
    assert "hello" in result["output"]
    assert "done" in result["output"]


async def test_script_run_with_args(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    result = await handlers["script_run"]({
        "interpreter": "python3",
        "content": "import sys; print(' '.join(sys.argv[1:]))",
        "args": ["alpha", "beta", "gamma"],
    })
    assert "alpha beta gamma" in result["output"]


async def test_script_run_with_env(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    result = await handlers["script_run"]({
        "interpreter": "bash",
        "content": "echo $MY_VAR",
        "env": {"MY_VAR": "from-env"},
    })
    assert "from-env" in result["output"]


async def test_script_run_failing_script_returns_nonzero(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    result = await handlers["script_run"]({
        "interpreter": "python3",
        "content": "import sys; sys.exit(7)",
    })
    assert result["ok"] is False
    assert result["returncode"] == 7


async def test_script_run_timeout(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    result = await handlers["script_run"]({
        "interpreter": "bash",
        "content": "sleep 10",
        "timeout": 1,
    })
    assert result["ok"] is False
    assert result["returncode"] == -1
    assert "Timeout" in result["output"]


async def test_script_run_invalid_interpreter(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["script_run"]({
            "interpreter": "perl",
            "content": "print 'hi'",
        })
    assert exc.value.code == "invalid_payload"


async def test_script_run_empty_content(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError) as exc:
        await handlers["script_run"]({
            "interpreter": "bash",
            "content": "",
        })
    assert exc.value.code == "invalid_payload"


async def test_script_run_timeout_out_of_range(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    with pytest.raises(HandlerError):
        await handlers["script_run"]({
            "interpreter": "bash",
            "content": "echo hi",
            "timeout": 9999,  # > 300 max
        })


async def test_script_run_cleanup_false_returns_paths(policy: Policy) -> None:
    handlers = build_registry(policy=policy)
    result = await handlers["script_run"]({
        "interpreter": "bash",
        "content": "echo hi",
        "cleanup": False,
    })
    assert "script_path" in result
    assert "workdir" in result
    # Confirm it actually exists on disk
    assert Path(result["script_path"]).exists()

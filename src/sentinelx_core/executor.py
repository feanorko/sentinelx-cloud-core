"""Executor: receives a RequestMessage, runs the right handler, returns a response dict.

This is the integration seam with the legacy core code. Each handler in
`handlers/` is a thin wrapper that calls into the proven execution logic.

Right now the handlers are stubs. The plan is to copy the implementations from
the legacy `agent.py` (at /home/carlos/projects/sentinelx/agent.py) one by one
as the new core gets validated end-to-end.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Awaitable, Callable

from sentinelx_protocol import RequestMessage

logger = logging.getLogger(__name__)

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class Executor:
    def __init__(self, config_path: Path) -> None:
        self._config_path = config_path
        # Lazy-loaded
        self._handlers: dict[str, Handler] | None = None

    def capability_names(self) -> list[str]:
        """Names of supported ops, used in the `hello` capabilities list."""
        return list(self._get_handlers().keys())

    def _get_handlers(self) -> dict[str, Handler]:
        if self._handlers is None:
            from sentinelx_core.handlers import build_registry

            self._handlers = build_registry(config_path=self._config_path)
        return self._handlers

    async def dispatch(self, request: RequestMessage) -> dict[str, Any]:
        """Run the handler for `request.op` and build a response dict ready to send."""
        handlers = self._get_handlers()
        handler = handlers.get(request.op)

        if handler is None:
            return {
                "type": "response",
                "id": request.id,
                "ok": False,
                "error": {
                    "code": "unsupported_op",
                    "message": f"agent does not support op: {request.op}",
                },
            }

        try:
            result = await handler(request.payload)
            return {
                "type": "response",
                "id": request.id,
                "ok": True,
                "result": result,
            }
        except HandlerError as exc:
            return {
                "type": "response",
                "id": request.id,
                "ok": False,
                "error": {
                    "code": exc.code,
                    "message": str(exc),
                    "details": exc.details,
                },
            }


class HandlerError(Exception):
    """A handler explicitly rejected a request (e.g. policy violation)."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}

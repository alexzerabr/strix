"""The bearer gate: no token configured means the server refuses to start, and a
request without the exact token is rejected before it reaches a tool."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from strix.interface.mcp_server.auth import (
    BearerAuthMiddleware,
    MissingTokenError,
    require_token,
)


def test_require_token_refuses_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_MCP_TOKEN", raising=False)
    with pytest.raises(MissingTokenError):
        require_token()


def test_require_token_refuses_a_blank_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MCP_TOKEN", "   ")
    with pytest.raises(MissingTokenError):
        require_token()


class _Downstream:
    def __init__(self) -> None:
        self.reached = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.reached = True


def _drive(app: BearerAuthMiddleware, headers: list[tuple[bytes, bytes]]) -> int:
    scope: dict[str, Any] = {"type": "http", "headers": headers}
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request"}

    async def send(message: Any) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    starts = [m for m in sent if m["type"] == "http.response.start"]
    return starts[0]["status"] if starts else 0


def test_correct_token_reaches_the_app() -> None:
    downstream = _Downstream()
    app = BearerAuthMiddleware(downstream, token="secret-abc")
    status = _drive(app, [(b"authorization", b"Bearer secret-abc")])
    assert downstream.reached is True
    assert status == 0  # downstream handled it, middleware sent nothing


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"authorization", b"Bearer wrong")],
        [(b"authorization", b"secret-abc")],  # missing the Bearer scheme
        [(b"authorization", b"Bearer secret-abc-extra")],
    ],
)
def test_a_bad_or_missing_token_is_rejected_401(headers: list[tuple[bytes, bytes]]) -> None:
    downstream = _Downstream()
    app = BearerAuthMiddleware(downstream, token="secret-abc")
    status = _drive(app, headers)
    assert status == 401
    assert downstream.reached is False


def test_non_http_scope_passes_through() -> None:
    downstream = _Downstream()
    app = BearerAuthMiddleware(downstream, token="secret-abc")
    scope: dict[str, Any] = {"type": "lifespan"}

    async def receive() -> dict[str, Any]:
        return {}

    async def send(_message: Any) -> None:
        pass

    asyncio.run(app(scope, receive, send))
    assert downstream.reached is True

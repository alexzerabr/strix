"""Bearer-token gate for the MCP server, as ASGI middleware.

A LAN is not zero-trust: any host on the network can reach the port, so a token
is what separates "on the network" from "allowed to spend the scan quota". The
token is read once from ``STRIX_MCP_TOKEN`` and compared with
``secrets.compare_digest`` so the check does not leak length through timing.
"""

from __future__ import annotations

import os
import secrets
from typing import TYPE_CHECKING

from starlette.responses import JSONResponse


if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


class MissingTokenError(RuntimeError):
    """``STRIX_MCP_TOKEN`` is unset, so the server must not start unauthenticated."""


def require_token() -> str:
    """The configured bearer token, or raise so the server refuses to start open."""
    token = os.environ.get("STRIX_MCP_TOKEN") or ""
    if not token.strip():
        raise MissingTokenError(
            "STRIX_MCP_TOKEN is not set. Refusing to start an unauthenticated MCP server on the "
            "network. Set it to a long random secret and give the same value to the agents."
        )
    return token


class BearerAuthMiddleware:
    """Reject any request without ``Authorization: Bearer <STRIX_MCP_TOKEN>``."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        self._token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        if self._authorized(scope):
            await self._app(scope, receive, send)
            return
        response = JSONResponse({"error": "unauthorized"}, status_code=401)
        await response(scope, receive, send)

    def _authorized(self, scope: Scope) -> bool:
        for name, value in scope.get("headers") or []:
            if name == b"authorization":
                header = value.decode("latin-1", "replace")
                # Require the scheme: a raw token with no "Bearer " prefix must
                # not authenticate, so removeprefix is not enough on its own.
                if not header.startswith("Bearer "):
                    return False
                presented = header[len("Bearer ") :].strip()
                return secrets.compare_digest(presented, self._token)
        return False

"""
Pure ASGI request-body limit middleware.

Declared over-limit requests are rejected before the application parses them.
For chunked or otherwise unbounded bodies, received bytes are counted and the
request is aborted as soon as the applicable limit is exceeded. The download
path never reads an incoming body, so the limit does not affect responses.
"""

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from backend.app.config import settings

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class BodyTooLarge(Exception):
    """Raised internally when a streamed request body exceeds its limit."""


def _header_value(scope: Scope, name: bytes) -> bytes | None:
    for header_name, header_value in scope.get("headers", []):
        if header_name.lower() == name:
            return header_value
    return None


def _limit_for_scope(scope: Scope) -> int:
    content_type = (_header_value(scope, b"content-type") or b"").decode(
        "latin-1"
    ).lower()
    if content_type.split(";", 1)[0].strip() == "multipart/form-data":
        return settings.MAX_FILE_SIZE_BYTES + settings.MAX_MULTIPART_OVERHEAD_BYTES
    return settings.MAX_JSON_BODY_BYTES


async def _send_json(
    send: Send,
    status_code: int,
    detail: str,
    *,
    close_connection: bool = False,
) -> None:
    body = json.dumps({"detail": detail}).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if close_connection:
        headers.append((b"connection", b"close"))
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": headers,
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class RequestBodyLimitMiddleware:
    """Enforce request body limits before the application reads the body."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = _limit_for_scope(scope)
        raw_content_length = _header_value(scope, b"content-length")
        if raw_content_length is not None:
            try:
                content_length = int(raw_content_length.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                await _send_json(
                    send,
                    status_code=400,
                    detail="Invalid Content-Length header",
                    close_connection=True,
                )
                return
            if content_length < 0:
                await _send_json(
                    send,
                    status_code=400,
                    detail="Invalid Content-Length header",
                    close_connection=True,
                )
                return
            if content_length > limit:
                await _send_json(
                    send,
                    status_code=413,
                    detail="Request body too large",
                    close_connection=True,
                )
                return

        received_bytes = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > limit:
                    raise BodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except BodyTooLarge:
            if not response_started:
                await _send_json(
                    send,
                    status_code=413,
                    detail="Request body too large",
                    close_connection=True,
                )

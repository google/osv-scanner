from __future__ import annotations

import ssl
import typing

import httpx
import trio
from hypercorn.typing import (
    ASGIReceiveCallable,
    ASGISendCallable,
    HTTPResponseBodyEvent,
    HTTPResponseStartEvent,
    HTTPScope,
    Scope,
)


async def _read_body(receive: ASGIReceiveCallable) -> bytes:
    body = bytearray()
    body_consumed = False
    while not body_consumed:
        event = await receive()
        if event["type"] == "http.request":
            body.extend(event["body"])
            body_consumed = not event["more_body"]
        else:
            raise ValueError(event["type"])
    return bytes(body)


class ProxyApp:
    def __init__(self, upstream_ca_certs: str | None = None):
        self.ssl_context = None
        if upstream_ca_certs:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.ssl_context.load_verify_locations(cafile=upstream_ca_certs)

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        assert scope["type"] == "http"
        if scope["method"] in ["GET", "POST"]:
            await self.absolute_uri(scope, receive, send)
        elif scope["method"] == "CONNECT":
            await self.connect(scope, send)
        else:
            raise ValueError(scope["method"])

    async def absolute_uri(
        self,
        scope: HTTPScope,
        receive: ASGIReceiveCallable,
        send: ASGISendCallable,
    ) -> None:
        async with httpx.AsyncClient(verify=self.ssl_context or True) as client:
            client_response = await client.request(
                method=scope["method"],
                url=scope["path"],
                headers=list(scope["headers"]),
                content=await _read_body(receive),
            )

        headers = []
        for header in (
            "Date",
            "Cache-Control",
            "Server",
            "Content-Type",
            "Location",
        ):
            v = client_response.headers.get(header)
            if v:
                headers.append((header.encode(), v.encode()))
        headers.append((b"Content-Length", str(len(client_response.content)).encode()))

        await send(
            HTTPResponseStartEvent(
                type="http.response.start",
                status=client_response.status_code,
                headers=headers,
            )
        )
        await send(
            HTTPResponseBodyEvent(
                type="http.response.body",
                body=client_response.content,
                more_body=False,
            )
        )

    async def connect(self, scope: HTTPScope, send: ASGISendCallable) -> None:
        async def start_forward(
            reader: trio.SocketStream, writer: trio.SocketStream
        ) -> None:
            while True:
                try:
                    data = await reader.receive_some(4096)
                except trio.ClosedResourceError:
                    break
                if not data:
                    break
                await writer.send_all(data)
            await writer.aclose()

        host, port = scope["path"].split(":")
        async with await trio.open_tcp_stream(host, int(port)) as upstream:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"", "more_body": True})

            client = typing.cast(trio.SocketStream, scope["extensions"]["_transport"])

            async with trio.open_nursery(strict_exception_groups=True) as nursery:
                nursery.start_soon(start_forward, client, upstream)
                nursery.start_soon(start_forward, upstream, client)

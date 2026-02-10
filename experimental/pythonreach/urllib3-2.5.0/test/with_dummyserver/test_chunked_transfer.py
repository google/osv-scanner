from __future__ import annotations

import io
import socket
import typing

import pytest

from dummyserver.testcase import (
    ConnectionMarker,
    SocketDummyServerTestCase,
    consume_socket,
)
from urllib3 import HTTPConnectionPool
from urllib3.util import SKIP_HEADER
from urllib3.util.retry import Retry


class TestChunkedTransfer(SocketDummyServerTestCase):
    def start_chunked_handler(self) -> None:
        self.buffer = b""

        def socket_handler(listener: socket.socket) -> None:
            sock = listener.accept()[0]

            while not self.buffer.endswith(b"\r\n0\r\n\r\n"):
                self.buffer += sock.recv(65536)

            sock.send(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-type: text/plain\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n"
            )
            sock.close()

        self._start_server(socket_handler)

    @pytest.mark.parametrize(
        "chunks",
        [
            ["foo", "bar", "", "bazzzzzzzzzzzzzzzzzzzzzz"],
            [b"foo", b"bar", b"", b"bazzzzzzzzzzzzzzzzzzzzzz"],
        ],
    )
    def test_chunks(self, chunks: list[bytes | str]) -> None:
        self.start_chunked_handler()
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen("GET", "/", body=chunks, headers=dict(DNT="1"), chunked=True)  # type: ignore[arg-type]

            assert b"Transfer-Encoding" in self.buffer
            body = self.buffer.split(b"\r\n\r\n", 1)[1]
            lines = body.split(b"\r\n")
            # Empty chunks should have been skipped, as this could not be distinguished
            # from terminating the transmission
            for i, chunk in enumerate(
                [c.decode() if isinstance(c, bytes) else c for c in chunks if c]
            ):
                assert lines[i * 2] == hex(len(chunk))[2:].encode("utf-8")
                assert lines[i * 2 + 1] == chunk.encode("utf-8")

    def _test_body(
        self,
        data: (
            bytes
            | str
            | io.BytesIO
            | io.StringIO
            | typing.Iterable[bytes]
            | typing.Iterable[str]
            | None
        ),
        expected_data: bytes | None = None,
    ) -> None:
        self.start_chunked_handler()
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen("GET", "/", body=data, chunked=True)  # type: ignore[arg-type]
            header, body = self.buffer.split(b"\r\n\r\n", 1)

            assert b"Transfer-Encoding: chunked" in header.split(b"\r\n")
            if data:
                if expected_data is not None:
                    bdata = expected_data
                else:
                    assert isinstance(data, (bytes, str))
                    bdata = data if isinstance(data, bytes) else data.encode("utf-8")
                assert b"\r\n" + bdata + b"\r\n" in body
                assert body.endswith(b"\r\n0\r\n\r\n")

                len_str = body.split(b"\r\n", 1)[0]
                stated_len = int(len_str, 16)
                assert stated_len == len(bdata)
            else:
                assert body == b"0\r\n\r\n"

    def test_bytestring_body(self) -> None:
        self._test_body(b"thisshouldbeonechunk\r\nasdf")

    def test_unicode_body(self) -> None:
        self._test_body(
            "thisshouldbeonechunk\r\näöüß\xFF",
            expected_data=b"thisshouldbeonechunk\r\n\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f\xc3\xbf",
        )

    @pytest.mark.parametrize(
        "bytes_data",
        [
            b"thisshouldbeonechunk\r\n\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f\xc3\xbf",  # utf-8
            b"thisshouldbeonechunk\r\n\xe4\xf6\xfc\xdf\xff",  # latin-1
        ],
    )
    def test_bytes_body_fileio(self, bytes_data: bytes) -> None:
        self._test_body(io.BytesIO(bytes_data), expected_data=bytes_data)

    def test_unicode_body_fileio(self) -> None:
        self._test_body(
            io.StringIO("thisshouldbeonechunk\r\näöüß\xFF"),
            expected_data=b"thisshouldbeonechunk\r\n\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f\xc3\xbf",
        )

    @pytest.mark.parametrize(
        "bytes_data",
        [
            b"thisshouldbeonechunk\r\n\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f\xc3\xbf",  # utf-8
            b"thisshouldbeonechunk\r\n\xe4\xf6\xfc\xdf\xff",  # latin-1
        ],
    )
    def test_bytes_body_iterable(self, bytes_data: bytes) -> None:
        def send_body() -> typing.Iterable[bytes]:
            yield bytes_data

        self._test_body(send_body(), expected_data=bytes_data)

    def test_unicode_body_iterable(self) -> None:
        def send_body() -> typing.Iterable[str]:
            yield "thisshouldbeonechunk\r\näöüß\xFF"

        self._test_body(
            send_body(),
            expected_data=b"thisshouldbeonechunk\r\n\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f\xc3\xbf",
        )

    def test_empty_body(self) -> None:
        self._test_body(None)

    def test_empty_string_body(self) -> None:
        self._test_body("")

    def test_empty_iterable_body(self) -> None:
        self._test_body(None)

    def _get_header_lines(self, prefix: bytes) -> list[bytes]:
        header_block = self.buffer.split(b"\r\n\r\n", 1)[0].lower()
        header_lines = header_block.split(b"\r\n")[1:]
        return [x for x in header_lines if x.startswith(prefix)]

    def test_removes_duplicate_host_header(self) -> None:
        self.start_chunked_handler()
        chunks = [b"foo", b"bar", b"", b"bazzzzzzzzzzzzzzzzzzzzzz"]
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen(
                "GET", "/", body=chunks, headers={"Host": "test.org"}, chunked=True
            )

            host_headers = self._get_header_lines(b"host")
            assert len(host_headers) == 1

    def test_provides_default_host_header(self) -> None:
        self.start_chunked_handler()
        chunks = [b"foo", b"bar", b"", b"bazzzzzzzzzzzzzzzzzzzzzz"]
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen("GET", "/", body=chunks, chunked=True)

            host_headers = self._get_header_lines(b"host")
            assert len(host_headers) == 1

    def test_provides_default_user_agent_header(self) -> None:
        self.start_chunked_handler()
        chunks = [b"foo", b"bar", b"", b"bazzzzzzzzzzzzzzzzzzzzzz"]
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen("GET", "/", body=chunks, chunked=True)

            ua_headers = self._get_header_lines(b"user-agent")
            assert len(ua_headers) == 1

    def test_preserve_user_agent_header(self) -> None:
        self.start_chunked_handler()
        chunks = [b"foo", b"bar", b"", b"bazzzzzzzzzzzzzzzzzzzzzz"]
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen(
                "GET",
                "/",
                body=chunks,
                headers={"user-Agent": "test-agent"},
                chunked=True,
            )

            ua_headers = self._get_header_lines(b"user-agent")
            # Validate that there is only one User-Agent header.
            assert len(ua_headers) == 1
            # Validate that the existing User-Agent header is the one that was
            # provided.
            assert ua_headers[0] == b"user-agent: test-agent"

    def test_remove_user_agent_header(self) -> None:
        self.start_chunked_handler()
        chunks = [b"foo", b"bar", b"", b"bazzzzzzzzzzzzzzzzzzzzzz"]
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen(
                "GET",
                "/",
                body=chunks,
                headers={"User-Agent": SKIP_HEADER},
                chunked=True,
            )

            ua_headers = self._get_header_lines(b"user-agent")
            assert len(ua_headers) == 0

    def test_provides_default_transfer_encoding_header(self) -> None:
        self.start_chunked_handler()
        chunks = [b"foo", b"bar", b"", b"bazzzzzzzzzzzzzzzzzzzzzz"]
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen("GET", "/", body=chunks, chunked=True)

            te_headers = self._get_header_lines(b"transfer-encoding")
            assert len(te_headers) == 1

    def test_preserve_transfer_encoding_header(self) -> None:
        self.start_chunked_handler()
        chunks = [b"foo", b"bar", b"", b"bazzzzzzzzzzzzzzzzzzzzzz"]
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            pool.urlopen(
                "GET",
                "/",
                body=chunks,
                headers={"transfer-Encoding": "test-transfer-encoding"},
                chunked=True,
            )

            te_headers = self._get_header_lines(b"transfer-encoding")
            # Validate that there is only one Transfer-Encoding header.
            assert len(te_headers) == 1
            # Validate that the existing Transfer-Encoding header is the one that
            # was provided.
            assert te_headers[0] == b"transfer-encoding: test-transfer-encoding"

    def test_preserve_chunked_on_retry_after(self) -> None:
        self.chunked_requests = 0
        self.socks: list[socket.socket] = []

        def socket_handler(listener: socket.socket) -> None:
            for _ in range(2):
                sock = listener.accept()[0]
                self.socks.append(sock)
                request = consume_socket(sock)
                if b"Transfer-Encoding: chunked" in request.split(b"\r\n"):
                    self.chunked_requests += 1

                sock.send(
                    b"HTTP/1.1 429 Too Many Requests\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Retry-After: 1\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                )

        self._start_server(socket_handler)
        with HTTPConnectionPool(self.host, self.port) as pool:
            retries = Retry(total=1)
            pool.urlopen("GET", "/", chunked=True, retries=retries)
            for sock in self.socks:
                sock.close()
        assert self.chunked_requests == 2

    def test_preserve_chunked_on_redirect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.chunked_requests = 0

        def socket_handler(listener: socket.socket) -> None:
            for i in range(2):
                sock = listener.accept()[0]
                request = ConnectionMarker.consume_request(sock)
                if b"Transfer-Encoding: chunked" in request.split(b"\r\n"):
                    self.chunked_requests += 1

                if i == 0:
                    sock.sendall(
                        b"HTTP/1.1 301 Moved Permanently\r\n"
                        b"Location: /redirect\r\n\r\n"
                    )
                else:
                    sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                sock.close()

        self._start_server(socket_handler)
        with ConnectionMarker.mark(monkeypatch):
            with HTTPConnectionPool(self.host, self.port) as pool:
                retries = Retry(redirect=1)
                pool.urlopen(
                    "GET", "/", chunked=True, preload_content=False, retries=retries
                )
        assert self.chunked_requests == 2

    def test_preserve_chunked_on_broken_connection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.chunked_requests = 0

        def socket_handler(listener: socket.socket) -> None:
            for i in range(2):
                sock = listener.accept()[0]
                request = ConnectionMarker.consume_request(sock)
                if b"Transfer-Encoding: chunked" in request.split(b"\r\n"):
                    self.chunked_requests += 1

                if i == 0:
                    # Bad HTTP version will trigger a connection close
                    sock.sendall(b"HTTP/0.5 200 OK\r\n\r\n")
                else:
                    sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                sock.close()

        self._start_server(socket_handler)
        with ConnectionMarker.mark(monkeypatch):
            with HTTPConnectionPool(self.host, self.port) as pool:
                retries = Retry(read=1)
                pool.urlopen(
                    "GET", "/", chunked=True, preload_content=False, retries=retries
                )
            assert self.chunked_requests == 2

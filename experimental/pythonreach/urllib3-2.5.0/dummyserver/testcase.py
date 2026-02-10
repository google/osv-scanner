from __future__ import annotations

import contextlib
import socket
import ssl
import threading
import typing
from test import LONG_TIMEOUT

import pytest

from dummyserver.app import hypercorn_app
from dummyserver.asgi_proxy import ProxyApp
from dummyserver.hypercornserver import run_hypercorn_in_thread
from dummyserver.socketserver import DEFAULT_CERTS, HAS_IPV6, SocketServerThread
from urllib3.connection import HTTPConnection
from urllib3.util.ssltransport import SSLTransport


def consume_socket(
    sock: SSLTransport | socket.socket,
    chunks: int = 65536,
    quit_event: threading.Event | None = None,
) -> bytearray:
    consumed = bytearray()
    sock.settimeout(LONG_TIMEOUT)
    while True:
        if quit_event and quit_event.is_set():
            break
        try:
            b = sock.recv(chunks)
        except (TimeoutError, socket.timeout):
            continue
        assert isinstance(b, bytes)
        consumed += b
        if b.endswith(b"\r\n\r\n"):
            break
    return consumed


class SocketDummyServerTestCase:
    """
    A simple socket-based server is created for this class that is good for
    exactly one request.
    """

    scheme = "http"
    host = "localhost"

    server_thread: typing.ClassVar[SocketServerThread]
    port: typing.ClassVar[int]

    tmpdir: typing.ClassVar[str]
    ca_path: typing.ClassVar[str]
    cert_combined_path: typing.ClassVar[str]
    cert_path: typing.ClassVar[str]
    key_path: typing.ClassVar[str]
    password_key_path: typing.ClassVar[str]

    server_context: typing.ClassVar[ssl.SSLContext]
    client_context: typing.ClassVar[ssl.SSLContext]

    proxy_server: typing.ClassVar[SocketDummyServerTestCase]

    @classmethod
    def _start_server(
        cls,
        socket_handler: typing.Callable[[socket.socket], None],
        quit_event: threading.Event | None = None,
    ) -> None:
        ready_event = threading.Event()
        cls.server_thread = SocketServerThread(
            socket_handler=socket_handler,
            ready_event=ready_event,
            host=cls.host,
            quit_event=quit_event,
        )
        cls.server_thread.start()
        ready_event.wait(5)
        if not ready_event.is_set():
            raise Exception("most likely failed to start server")
        cls.port = cls.server_thread.port

    @classmethod
    def start_response_handler(
        cls,
        response: bytes,
        num: int = 1,
        block_send: threading.Event | None = None,
    ) -> threading.Event:
        ready_event = threading.Event()
        quit_event = threading.Event()

        def socket_handler(listener: socket.socket) -> None:
            for _ in range(num):
                ready_event.set()

                listener.settimeout(LONG_TIMEOUT)
                while True:
                    if quit_event.is_set():
                        return
                    try:
                        sock = listener.accept()[0]
                        break
                    except (TimeoutError, socket.timeout):
                        continue
                consume_socket(sock, quit_event=quit_event)
                if quit_event.is_set():
                    sock.close()
                    return
                if block_send:
                    while not block_send.wait(LONG_TIMEOUT):
                        if quit_event.is_set():
                            sock.close()
                            return
                    block_send.clear()
                sock.send(response)
                sock.close()

        cls._start_server(socket_handler, quit_event=quit_event)
        return ready_event

    @classmethod
    def start_basic_handler(
        cls, num: int = 1, block_send: threading.Event | None = None
    ) -> threading.Event:
        return cls.start_response_handler(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            num,
            block_send,
        )

    @staticmethod
    def quit_server_thread(server_thread: SocketServerThread) -> None:
        if server_thread.quit_event:
            server_thread.quit_event.set()
        # in principle the maximum time that the thread can take to notice
        # the quit_event is LONG_TIMEOUT and the thread should terminate
        # shortly after that, we give 5 seconds leeway just in case
        server_thread.join(LONG_TIMEOUT * 2 + 5.0)
        if server_thread.is_alive():
            raise Exception("server_thread did not exit")

    @classmethod
    def teardown_class(cls) -> None:
        if hasattr(cls, "server_thread"):
            cls.quit_server_thread(cls.server_thread)

    def teardown_method(self) -> None:
        if hasattr(self, "server_thread"):
            self.quit_server_thread(self.server_thread)

    def assert_header_received(
        self,
        received_headers: typing.Iterable[bytes],
        header_name: str,
        expected_value: str | None = None,
    ) -> None:
        header_name_bytes = header_name.encode("ascii")
        if expected_value is None:
            expected_value_bytes = None
        else:
            expected_value_bytes = expected_value.encode("ascii")
        header_titles = []
        for header in received_headers:
            key, value = header.split(b": ")
            header_titles.append(key)
            if key == header_name_bytes and expected_value_bytes is not None:
                assert value == expected_value_bytes
        assert header_name_bytes in header_titles


class IPV4SocketDummyServerTestCase(SocketDummyServerTestCase):
    @classmethod
    def _start_server(
        cls,
        socket_handler: typing.Callable[[socket.socket], None],
        quit_event: threading.Event | None = None,
    ) -> None:
        ready_event = threading.Event()
        cls.server_thread = SocketServerThread(
            socket_handler=socket_handler,
            ready_event=ready_event,
            host=cls.host,
            quit_event=quit_event,
        )
        cls.server_thread.USE_IPV6 = False
        cls.server_thread.start()
        ready_event.wait(5)
        if not ready_event.is_set():
            raise Exception("most likely failed to start server")
        cls.port = cls.server_thread.port


class HypercornDummyServerTestCase:
    host = "localhost"
    host_alt = "127.0.0.1"
    port: typing.ClassVar[int]
    base_url: typing.ClassVar[str]
    base_url_alt: typing.ClassVar[str]
    certs: typing.ClassVar[dict[str, typing.Any]] = {}

    _stack: typing.ClassVar[contextlib.ExitStack]

    @classmethod
    def setup_class(cls) -> None:
        with contextlib.ExitStack() as stack:
            cls.port = stack.enter_context(
                run_hypercorn_in_thread(cls.host, cls.certs, hypercorn_app)
            )
            cls._stack = stack.pop_all()

    @classmethod
    def teardown_class(cls) -> None:
        cls._stack.close()


class HTTPSHypercornDummyServerTestCase(HypercornDummyServerTestCase):
    scheme = "https"
    host = "localhost"
    certs = DEFAULT_CERTS
    certs_dir = ""
    bad_ca_path = ""


class HypercornDummyProxyTestCase:
    http_host: typing.ClassVar[str] = "localhost"
    http_host_alt: typing.ClassVar[str] = "127.0.0.1"
    http_port: typing.ClassVar[int]
    http_url: typing.ClassVar[str]
    http_url_alt: typing.ClassVar[str]

    https_host: typing.ClassVar[str] = "localhost"
    https_host_alt: typing.ClassVar[str] = "127.0.0.1"
    https_certs: typing.ClassVar[dict[str, typing.Any]] = DEFAULT_CERTS
    https_port: typing.ClassVar[int]
    https_url: typing.ClassVar[str]
    https_url_alt: typing.ClassVar[str]
    https_url_fqdn: typing.ClassVar[str]

    proxy_host: typing.ClassVar[str] = "localhost"
    proxy_host_alt: typing.ClassVar[str] = "127.0.0.1"
    proxy_port: typing.ClassVar[int]
    proxy_url: typing.ClassVar[str]
    https_proxy_port: typing.ClassVar[int]
    https_proxy_url: typing.ClassVar[str]

    certs_dir: typing.ClassVar[str] = ""
    bad_ca_path: typing.ClassVar[str] = ""

    server_thread: typing.ClassVar[threading.Thread]
    _stack: typing.ClassVar[contextlib.ExitStack]

    @classmethod
    def setup_class(cls) -> None:
        with contextlib.ExitStack() as stack:
            cls.http_port = stack.enter_context(
                run_hypercorn_in_thread(cls.http_host, None, hypercorn_app)
            )
            cls.https_port = stack.enter_context(
                run_hypercorn_in_thread(cls.https_host, cls.https_certs, hypercorn_app)
            )
            cls.proxy_port = stack.enter_context(
                run_hypercorn_in_thread(cls.proxy_host, None, ProxyApp())
            )
            upstream_ca_certs = cls.https_certs.get("ca_certs")
            cls.https_proxy_port = stack.enter_context(
                run_hypercorn_in_thread(
                    cls.proxy_host, cls.https_certs, ProxyApp(upstream_ca_certs)
                )
            )
            cls._stack = stack.pop_all()

    @classmethod
    def teardown_class(cls) -> None:
        cls._stack.close()


@pytest.mark.skipif(not HAS_IPV6, reason="IPv6 not available")
class IPv6HypercornDummyServerTestCase(HypercornDummyServerTestCase):
    host = "::1"


@pytest.mark.skipif(not HAS_IPV6, reason="IPv6 not available")
class IPv6HypercornDummyProxyTestCase(HypercornDummyProxyTestCase):
    http_host = "localhost"
    http_host_alt = "127.0.0.1"

    https_host = "localhost"
    https_host_alt = "127.0.0.1"
    https_certs = DEFAULT_CERTS

    proxy_host = "::1"
    proxy_host_alt = "127.0.0.1"


class ConnectionMarker:
    """
    Marks an HTTP(S)Connection's socket after a request was made.

    Helps a test server understand when a client finished a request,
    without implementing a complete HTTP server.
    """

    MARK_FORMAT = b"$#MARK%04x*!"

    @classmethod
    @contextlib.contextmanager
    def mark(cls, monkeypatch: pytest.MonkeyPatch) -> typing.Generator[None]:
        """
        Mark connections under in that context.
        """

        orig_request = HTTPConnection.request

        def call_and_mark(
            target: typing.Callable[..., None]
        ) -> typing.Callable[..., None]:
            def part(
                self: HTTPConnection, *args: typing.Any, **kwargs: typing.Any
            ) -> None:
                target(self, *args, **kwargs)
                self.sock.sendall(cls._get_socket_mark(self.sock, False))

            return part

        with monkeypatch.context() as m:
            m.setattr(HTTPConnection, "request", call_and_mark(orig_request))
            yield

    @classmethod
    def consume_request(cls, sock: socket.socket, chunks: int = 65536) -> bytearray:
        """
        Consume a socket until after the HTTP request is sent.
        """
        consumed = bytearray()
        mark = cls._get_socket_mark(sock, True)
        while True:
            b = sock.recv(chunks)
            if not b:
                break
            consumed += b
            if consumed.endswith(mark):
                break
        return consumed

    @classmethod
    def _get_socket_mark(cls, sock: socket.socket, server: bool) -> bytes:
        if server:
            port = sock.getpeername()[1]
        else:
            port = sock.getsockname()[1]
        return cls.MARK_FORMAT % (port,)

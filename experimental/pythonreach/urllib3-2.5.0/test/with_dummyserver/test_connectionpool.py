from __future__ import annotations

import io
import logging
import platform
import socket
import time
import typing
import warnings
from test import LONG_TIMEOUT, SHORT_TIMEOUT
from threading import Event
from unittest import mock
from urllib.parse import urlencode

import pytest

from dummyserver.socketserver import NoIPv6Warning
from dummyserver.testcase import HypercornDummyServerTestCase, SocketDummyServerTestCase
from urllib3 import HTTPConnectionPool, encode_multipart_formdata
from urllib3._collections import HTTPHeaderDict
from urllib3.connection import _get_default_user_agent
from urllib3.exceptions import (
    ConnectTimeoutError,
    DecodeError,
    EmptyPoolError,
    MaxRetryError,
    NameResolutionError,
    NewConnectionError,
    ReadTimeoutError,
    UnrewindableBodyError,
)
from urllib3.fields import _TYPE_FIELD_VALUE_TUPLE
from urllib3.util import SKIP_HEADER, SKIPPABLE_HEADERS
from urllib3.util.retry import RequestHistory, Retry
from urllib3.util.timeout import _TYPE_TIMEOUT, Timeout

from .. import INVALID_SOURCE_ADDRESSES, TARPIT_HOST, VALID_SOURCE_ADDRESSES
from ..port_helpers import find_unused_port


def wait_for_socket(ready_event: Event) -> None:
    ready_event.wait()
    ready_event.clear()


class TestConnectionPoolTimeouts(SocketDummyServerTestCase):
    def test_timeout_float(self) -> None:
        block_event = Event()
        ready_event = self.start_basic_handler(block_send=block_event, num=2)

        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            wait_for_socket(ready_event)
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/", timeout=SHORT_TIMEOUT)
            block_event.set()  # Release block

            # Shouldn't raise this time
            wait_for_socket(ready_event)
            block_event.set()  # Pre-release block
            pool.request("GET", "/", timeout=LONG_TIMEOUT)

    def test_conn_closed(self) -> None:
        block_event = Event()
        self.start_basic_handler(block_send=block_event, num=1)

        with HTTPConnectionPool(
            self.host, self.port, timeout=SHORT_TIMEOUT, retries=False
        ) as pool:
            conn = pool._get_conn()
            pool._put_conn(conn)
            try:
                with pytest.raises(ReadTimeoutError):
                    pool.urlopen("GET", "/")
                if not conn.is_closed:
                    with pytest.raises(socket.error):
                        conn.sock.recv(1024)  # type: ignore[attr-defined]
            finally:
                pool._put_conn(conn)

            block_event.set()

    def test_timeout(self) -> None:
        # Requests should time out when expected
        block_event = Event()
        ready_event = self.start_basic_handler(block_send=block_event, num=3)

        # Pool-global timeout
        short_timeout = Timeout(read=SHORT_TIMEOUT)
        with HTTPConnectionPool(
            self.host, self.port, timeout=short_timeout, retries=False
        ) as pool:
            wait_for_socket(ready_event)
            block_event.clear()
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/")
            block_event.set()  # Release request

        # Request-specific timeouts should raise errors
        with HTTPConnectionPool(
            self.host, self.port, timeout=short_timeout, retries=False
        ) as pool:
            wait_for_socket(ready_event)
            now = time.perf_counter()
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/", timeout=LONG_TIMEOUT)
            delta = time.perf_counter() - now

            message = "timeout was pool-level SHORT_TIMEOUT rather than request-level LONG_TIMEOUT"
            if platform.system() == "Windows":
                # Adjust tolerance for floating-point comparison on Windows to
                # avoid flakiness in CI #3413
                assert delta >= (LONG_TIMEOUT - 1e-3), message
            else:
                assert delta >= (LONG_TIMEOUT - 1e-5), message
            block_event.set()  # Release request

            # Timeout passed directly to request should raise a request timeout
            wait_for_socket(ready_event)
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/", timeout=SHORT_TIMEOUT)
            block_event.set()  # Release request

    def test_connect_timeout(self) -> None:
        url = "/"
        host, port = TARPIT_HOST, 80
        timeout = Timeout(connect=SHORT_TIMEOUT)

        # Pool-global timeout
        with HTTPConnectionPool(host, port, timeout=timeout) as pool:
            conn = pool._get_conn()
            with pytest.raises(ConnectTimeoutError):
                pool._make_request(conn, "GET", url)

            # Retries
            retries = Retry(connect=0)
            with pytest.raises(MaxRetryError):
                pool.request("GET", url, retries=retries)

        # Request-specific connection timeouts
        big_timeout = Timeout(read=LONG_TIMEOUT, connect=LONG_TIMEOUT)
        with HTTPConnectionPool(host, port, timeout=big_timeout, retries=False) as pool:
            conn = pool._get_conn()
            with pytest.raises(ConnectTimeoutError):
                pool._make_request(conn, "GET", url, timeout=timeout)

            pool._put_conn(conn)
            with pytest.raises(ConnectTimeoutError):
                pool.request("GET", url, timeout=timeout)

    def test_total_applies_connect(self) -> None:
        host, port = TARPIT_HOST, 80

        timeout = Timeout(total=None, connect=SHORT_TIMEOUT)
        with HTTPConnectionPool(host, port, timeout=timeout) as pool:
            conn = pool._get_conn()
            try:
                with pytest.raises(ConnectTimeoutError):
                    pool._make_request(conn, "GET", "/")
            finally:
                conn.close()

        timeout = Timeout(connect=3, read=5, total=SHORT_TIMEOUT)
        with HTTPConnectionPool(host, port, timeout=timeout) as pool:
            conn = pool._get_conn()
            try:
                with pytest.raises(ConnectTimeoutError):
                    pool._make_request(conn, "GET", "/")
            finally:
                conn.close()

    def test_total_timeout(self) -> None:
        block_event = Event()
        ready_event = self.start_basic_handler(block_send=block_event, num=2)

        wait_for_socket(ready_event)
        # This will get the socket to raise an EAGAIN on the read
        timeout = Timeout(connect=3, read=SHORT_TIMEOUT)
        with HTTPConnectionPool(
            self.host, self.port, timeout=timeout, retries=False
        ) as pool:
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/")

            block_event.set()
            wait_for_socket(ready_event)
            block_event.clear()

        # The connect should succeed and this should hit the read timeout
        timeout = Timeout(connect=3, read=5, total=SHORT_TIMEOUT)
        with HTTPConnectionPool(
            self.host, self.port, timeout=timeout, retries=False
        ) as pool:
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/")

    def test_create_connection_timeout(self) -> None:
        self.start_basic_handler(block_send=Event(), num=0)  # needed for self.port

        timeout = Timeout(connect=SHORT_TIMEOUT, total=LONG_TIMEOUT)
        with HTTPConnectionPool(
            TARPIT_HOST, self.port, timeout=timeout, retries=False
        ) as pool:
            conn = pool._new_conn()
            with pytest.raises(ConnectTimeoutError):
                conn.connect()


class TestConnectionPool(HypercornDummyServerTestCase):
    def test_http2_test_error(self, http_version: str) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            if http_version == "h2":
                with pytest.raises(
                    ValueError, match="HTTP/2 support currently only applies to HTTPS.*"
                ):
                    r = pool.request("GET", "/")
            else:
                r = pool.request("GET", "/")
                assert r.status == 200

    def test_get(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("GET", "/specific_method", fields={"method": "GET"})
            assert r.status == 200, r.data

    def test_debug_log(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.DEBUG, logger="urllib3.connectionpool")
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.urlopen("GET", "/")
            assert r.status == 200
        logs = [record.getMessage() for record in caplog.records]
        assert logs == [
            f"Starting new HTTP connection (1): {self.host}:{self.port}",
            f'http://{self.host}:{self.port} "GET / HTTP/1.1" 200 0',
        ]

    def test_post_url(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("POST", "/specific_method", fields={"method": "POST"})
            assert r.status == 200, r.data

    def test_urlopen_put(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.urlopen("PUT", "/specific_method?method=PUT")
            assert r.status == 200, r.data

    def test_wrong_specific_method(self) -> None:
        # To make sure the dummy server is actually returning failed responses
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("GET", "/specific_method", fields={"method": "POST"})
            assert r.status == 400, r.data

        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("POST", "/specific_method", fields={"method": "GET"})
            assert r.status == 400, r.data

    def test_upload(self) -> None:
        data = "I'm in ur multipart form-data, hazing a cheezburgr"
        fields: dict[str, _TYPE_FIELD_VALUE_TUPLE] = {
            "upload_param": "filefield",
            "upload_filename": "lolcat.txt",
            "filefield": ("lolcat.txt", data),
        }
        fields["upload_size"] = len(data)  # type: ignore[assignment]

        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("POST", "/upload", fields=fields)
            assert r.status == 200, r.data

    def test_one_name_multiple_values(self) -> None:
        fields = [("foo", "a"), ("foo", "b")]

        with HTTPConnectionPool(self.host, self.port) as pool:
            # urlencode
            r = pool.request("GET", "/echo", fields=fields)
            assert r.data == b"foo=a&foo=b"

            # multipart
            r = pool.request("POST", "/echo", fields=fields)
            assert r.data.count(b'name="foo"') == 2

    def test_request_method_body(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            body = b"hi"
            r = pool.request("POST", "/echo", body=body)
            assert r.data == body

            fields = [("hi", "hello")]
            with pytest.raises(TypeError):
                pool.request("POST", "/echo", body=body, fields=fields)

    def test_unicode_upload(self) -> None:
        fieldname = "myfile"
        filename = "\xe2\x99\xa5.txt"
        data = "\xe2\x99\xa5".encode()
        size = len(data)

        fields: dict[str, _TYPE_FIELD_VALUE_TUPLE] = {
            "upload_param": fieldname,
            "upload_filename": filename,
            fieldname: (filename, data),
        }
        fields["upload_size"] = size  # type: ignore[assignment]
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("POST", "/upload", fields=fields)
            assert r.status == 200, r.data

    def test_nagle(self) -> None:
        """Test that connections have TCP_NODELAY turned on"""
        # This test needs to be here in order to be run. socket.create_connection actually tries
        # to connect to the host provided so we need a dummyserver to be running.
        with HTTPConnectionPool(self.host, self.port) as pool:
            conn = pool._get_conn()
            try:
                pool._make_request(conn, "GET", "/")
                tcp_nodelay_setting = conn.sock.getsockopt(  # type: ignore[attr-defined]
                    socket.IPPROTO_TCP, socket.TCP_NODELAY
                )
                assert tcp_nodelay_setting
            finally:
                conn.close()

    @pytest.mark.parametrize(
        "socket_options",
        [
            [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)],
            ((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),),
        ],
    )
    def test_socket_options(self, socket_options: tuple[int, int, int]) -> None:
        """Test that connections accept socket options."""
        # This test needs to be here in order to be run. socket.create_connection actually tries to
        # connect to the host provided so we need a dummyserver to be running.
        with HTTPConnectionPool(
            self.host,
            self.port,
            socket_options=socket_options,
        ) as pool:
            # Get the socket of a new connection.
            s = pool._new_conn()._new_conn()  # type: ignore[attr-defined]
            try:
                using_keepalive = (
                    s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) > 0
                )
                assert using_keepalive
            finally:
                s.close()

    @pytest.mark.parametrize("socket_options", [None, []])
    def test_disable_default_socket_options(
        self, socket_options: list[int] | None
    ) -> None:
        """Test that passing None or empty list disables all socket options."""
        # This test needs to be here in order to be run. socket.create_connection actually tries
        # to connect to the host provided so we need a dummyserver to be running.
        with HTTPConnectionPool(
            self.host, self.port, socket_options=socket_options
        ) as pool:
            s = pool._new_conn()._new_conn()  # type: ignore[attr-defined]
            try:
                using_nagle = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 0
                assert using_nagle
            finally:
                s.close()

    def test_defaults_are_applied(self) -> None:
        """Test that modifying the default socket options works."""
        # This test needs to be here in order to be run. socket.create_connection actually tries
        # to connect to the host provided so we need a dummyserver to be running.
        with HTTPConnectionPool(self.host, self.port) as pool:
            # Get the HTTPConnection instance
            conn = pool._new_conn()
            try:
                # Update the default socket options
                assert conn.socket_options is not None
                conn.socket_options += [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]
                s = conn._new_conn()  # type: ignore[attr-defined]
                nagle_disabled = (
                    s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) > 0
                )
                using_keepalive = (
                    s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) > 0
                )
                assert nagle_disabled
                assert using_keepalive
            finally:
                conn.close()
                s.close()

    def test_connection_error_retries(self) -> None:
        """ECONNREFUSED error should raise a connection error, with retries"""
        port = find_unused_port()
        with HTTPConnectionPool(self.host, port) as pool:
            with pytest.raises(MaxRetryError) as e:
                pool.request("GET", "/", retries=Retry(connect=3))
            assert type(e.value.reason) is NewConnectionError

    def test_timeout_success(self) -> None:
        timeout = Timeout(connect=3, read=5, total=None)
        with HTTPConnectionPool(self.host, self.port, timeout=timeout) as pool:
            pool.request("GET", "/")
            # This should not raise a "Timeout already started" error
            pool.request("GET", "/")

        with HTTPConnectionPool(self.host, self.port, timeout=timeout) as pool:
            # This should also not raise a "Timeout already started" error
            pool.request("GET", "/")

        timeout = Timeout(total=None)
        with HTTPConnectionPool(self.host, self.port, timeout=timeout) as pool:
            pool.request("GET", "/")

    socket_timeout_reuse_testdata = pytest.mark.parametrize(
        ["timeout", "expect_settimeout_calls"],
        [
            (1, (1, 1)),
            (None, (None, None)),
            (Timeout(read=4), (None, 4)),
            (Timeout(read=4, connect=5), (5, 4)),
            (Timeout(connect=6), (6, None)),
        ],
    )

    @socket_timeout_reuse_testdata
    def test_socket_timeout_updated_on_reuse_constructor(
        self,
        timeout: _TYPE_TIMEOUT,
        expect_settimeout_calls: typing.Sequence[float | None],
    ) -> None:
        with HTTPConnectionPool(self.host, self.port, timeout=timeout) as pool:
            # Make a request to create a new connection.
            pool.urlopen("GET", "/")

            # Grab the connection and mock the inner socket.
            assert pool.pool is not None
            conn = pool.pool.get_nowait()
            conn_sock = mock.Mock(wraps=conn.sock)
            conn.sock = conn_sock
            pool._put_conn(conn)

            # Assert that sock.settimeout() is called with the new connect timeout, then the read timeout.
            pool.urlopen("GET", "/", timeout=timeout)
            conn_sock.settimeout.assert_has_calls(
                [mock.call(x) for x in expect_settimeout_calls]
            )

    @socket_timeout_reuse_testdata
    def test_socket_timeout_updated_on_reuse_parameter(
        self,
        timeout: _TYPE_TIMEOUT,
        expect_settimeout_calls: typing.Sequence[float | None],
    ) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            # Make a request to create a new connection.
            pool.urlopen("GET", "/", timeout=LONG_TIMEOUT)

            # Grab the connection and mock the inner socket.
            assert pool.pool is not None
            conn = pool.pool.get_nowait()
            conn_sock = mock.Mock(wraps=conn.sock)
            conn.sock = conn_sock
            pool._put_conn(conn)

            # Assert that sock.settimeout() is called with the new connect timeout, then the read timeout.
            pool.urlopen("GET", "/", timeout=timeout)
            conn_sock.settimeout.assert_has_calls(
                [mock.call(x) for x in expect_settimeout_calls]
            )

    def test_tunnel(self) -> None:
        timeout = Timeout(total=None)
        with HTTPConnectionPool(self.host, self.port, timeout=timeout) as pool:
            conn = pool._get_conn()
            try:
                conn.set_tunnel(self.host, self.port)
                with mock.patch.object(
                    conn, "_tunnel", create=True, return_value=None
                ) as conn_tunnel:
                    pool._make_request(conn, "GET", "/")
                conn_tunnel.assert_called_once_with()
            finally:
                conn.close()

        # test that it's not called when tunnel is not set
        timeout = Timeout(total=None)
        with HTTPConnectionPool(self.host, self.port, timeout=timeout) as pool:
            conn = pool._get_conn()
            try:
                with mock.patch.object(
                    conn, "_tunnel", create=True, return_value=None
                ) as conn_tunnel:
                    pool._make_request(conn, "GET", "/")
                assert not conn_tunnel.called
            finally:
                conn.close()

    def test_redirect_relative_url_no_deprecation(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            with warnings.catch_warnings():
                warnings.simplefilter("error", DeprecationWarning)
                pool.request("GET", "/redirect", fields={"target": "/"})

    def test_redirect(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("GET", "/redirect", fields={"target": "/"}, redirect=False)
            assert r.status == 303

            r = pool.request("GET", "/redirect", fields={"target": "/"})
            assert r.status == 200
            assert r.data == b"Dummy server!"

    def test_303_redirect_makes_request_lose_body(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            response = pool.request(
                "POST",
                "/redirect",
                fields={"target": "/headers_and_params", "status": "303 See Other"},
            )
        data = response.json()
        assert data["params"] == {}
        assert "Content-Type" not in HTTPHeaderDict(data["headers"])

    def test_bad_connect(self) -> None:
        with HTTPConnectionPool("badhost.invalid", self.port) as pool:
            with pytest.raises(MaxRetryError) as e:
                pool.request("GET", "/", retries=5)
            assert type(e.value.reason) is NameResolutionError

    def test_keepalive(self) -> None:
        with HTTPConnectionPool(self.host, self.port, block=True, maxsize=1) as pool:
            r = pool.request("GET", "/keepalive?close=0")
            r = pool.request("GET", "/keepalive?close=0")

            assert r.status == 200
            assert pool.num_connections == 1
            assert pool.num_requests == 2

    def test_keepalive_close(self) -> None:
        with HTTPConnectionPool(
            self.host, self.port, block=True, maxsize=1, timeout=2
        ) as pool:
            r = pool.request(
                "GET", "/keepalive?close=1", retries=0, headers={"Connection": "close"}
            )

            assert pool.num_connections == 1

            # The dummyserver will have responded with Connection:close,
            # and httplib will properly cleanup the socket.

            # We grab the HTTPConnection object straight from the Queue,
            # because _get_conn() is where the check & reset occurs
            assert pool.pool is not None
            conn = pool.pool.get()
            assert conn.sock is None
            pool._put_conn(conn)

            # Now with keep-alive
            r = pool.request(
                "GET",
                "/keepalive?close=0",
                retries=0,
                headers={"Connection": "keep-alive"},
            )

            # The dummyserver responded with Connection:keep-alive, the connection
            # persists.
            conn = pool.pool.get()
            assert conn.sock is not None
            pool._put_conn(conn)

            # Another request asking the server to close the connection. This one
            # should get cleaned up for the next request.
            r = pool.request(
                "GET", "/keepalive?close=1", retries=0, headers={"Connection": "close"}
            )

            assert r.status == 200

            conn = pool.pool.get()
            assert conn.sock is None
            pool._put_conn(conn)

            # Next request
            r = pool.request("GET", "/keepalive?close=0")

    def test_post_with_urlencode(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            data = {"banana": "hammock", "lol": "cat"}
            r = pool.request("POST", "/echo", fields=data, encode_multipart=False)
            assert r.data.decode("utf-8") == urlencode(data)

    def test_post_with_multipart(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            data = {"banana": "hammock", "lol": "cat"}
            r = pool.request("POST", "/echo", fields=data, encode_multipart=True)
            body = r.data.split(b"\r\n")

            encoded_data = encode_multipart_formdata(data)[0]
            expected_body = encoded_data.split(b"\r\n")

            # TODO: Get rid of extra parsing stuff when you can specify
            # a custom boundary to encode_multipart_formdata
            """
            We need to loop the return lines because a timestamp is attached
            from within encode_multipart_formdata. When the server echos back
            the data, it has the timestamp from when the data was encoded, which
            is not equivalent to when we run encode_multipart_formdata on
            the data again.
            """
            for i, line in enumerate(body):
                if line.startswith(b"--"):
                    continue

                assert body[i] == expected_body[i]

    def test_post_with_multipart__iter__(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            data = {"hello": "world"}
            r = pool.request(
                "POST",
                "/echo",
                fields=data,
                preload_content=False,
                multipart_boundary="boundary",
                encode_multipart=True,
            )

            chunks = [chunk for chunk in r]
            assert chunks == [
                b"--boundary\r\n",
                b'Content-Disposition: form-data; name="hello"\r\n',
                b"\r\n",
                b"world\r\n",
                b"--boundary--\r\n",
            ]

    def test_check_gzip(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request(
                "GET", "/encodingrequest", headers={"accept-encoding": "gzip"}
            )
            assert r.headers.get("content-encoding") == "gzip"
            assert r.data == b"hello, world!"

    def test_check_deflate(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request(
                "GET", "/encodingrequest", headers={"accept-encoding": "deflate"}
            )
            assert r.headers.get("content-encoding") == "deflate"
            assert r.data == b"hello, world!"

    def test_bad_decode(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            with pytest.raises(DecodeError):
                pool.request(
                    "GET",
                    "/encodingrequest",
                    headers={"accept-encoding": "garbage-deflate"},
                )

            with pytest.raises(DecodeError):
                pool.request(
                    "GET",
                    "/encodingrequest",
                    headers={"accept-encoding": "garbage-gzip"},
                )

    def test_connection_count(self) -> None:
        with HTTPConnectionPool(self.host, self.port, maxsize=1) as pool:
            pool.request("GET", "/")
            pool.request("GET", "/")
            pool.request("GET", "/")

            assert pool.num_connections == 1
            assert pool.num_requests == 3

    def test_connection_count_bigpool(self) -> None:
        with HTTPConnectionPool(self.host, self.port, maxsize=16) as http_pool:
            http_pool.request("GET", "/")
            http_pool.request("GET", "/")
            http_pool.request("GET", "/")

            assert http_pool.num_connections == 1
            assert http_pool.num_requests == 3

    def test_partial_response(self) -> None:
        with HTTPConnectionPool(self.host, self.port, maxsize=1) as pool:
            req_data = {"lol": "cat"}
            resp_data = urlencode(req_data).encode("utf-8")

            r = pool.request("GET", "/echo", fields=req_data, preload_content=False)

            assert r.read(5) == resp_data[:5]
            assert r.read() == resp_data[5:]

    def test_lazy_load_twice(self) -> None:
        # This test is sad and confusing. Need to figure out what's
        # going on with partial reads and socket reuse.

        with HTTPConnectionPool(
            self.host, self.port, block=True, maxsize=1, timeout=2
        ) as pool:
            payload_size = 1024 * 2
            first_chunk = 512

            boundary = "foo"

            req_data = {"count": "a" * payload_size}
            resp_data = encode_multipart_formdata(req_data, boundary=boundary)[0]

            req2_data = {"count": "b" * payload_size}
            resp2_data = encode_multipart_formdata(req2_data, boundary=boundary)[0]

            r1 = pool.request(
                "POST",
                "/echo",
                fields=req_data,
                multipart_boundary=boundary,
                preload_content=False,
            )

            assert r1.read(first_chunk) == resp_data[:first_chunk]

            try:
                r2 = pool.request(
                    "POST",
                    "/echo",
                    fields=req2_data,
                    multipart_boundary=boundary,
                    preload_content=False,
                    pool_timeout=0.001,
                )

                # This branch should generally bail here, but maybe someday it will
                # work? Perhaps by some sort of magic. Consider it a TODO.

                assert r2.read(first_chunk) == resp2_data[:first_chunk]

                assert r1.read() == resp_data[first_chunk:]
                assert r2.read() == resp2_data[first_chunk:]
                assert pool.num_requests == 2

            except EmptyPoolError:
                assert r1.read() == resp_data[first_chunk:]
                assert pool.num_requests == 1

            assert pool.num_connections == 1

    def test_for_double_release(self) -> None:
        MAXSIZE = 5

        # Check default state
        with HTTPConnectionPool(self.host, self.port, maxsize=MAXSIZE) as pool:
            assert pool.num_connections == 0
            assert pool.pool is not None
            assert pool.pool.qsize() == MAXSIZE

            # Make an empty slot for testing
            pool.pool.get()
            assert pool.pool.qsize() == MAXSIZE - 1

            # Check state after simple request
            pool.urlopen("GET", "/")
            assert pool.pool.qsize() == MAXSIZE - 1

            # Check state without release
            pool.urlopen("GET", "/", preload_content=False)
            assert pool.pool.qsize() == MAXSIZE - 2

            pool.urlopen("GET", "/")
            assert pool.pool.qsize() == MAXSIZE - 2

            # Check state after read
            pool.urlopen("GET", "/").data
            assert pool.pool.qsize() == MAXSIZE - 2

            pool.urlopen("GET", "/")
            assert pool.pool.qsize() == MAXSIZE - 2

    def test_release_conn_parameter(self) -> None:
        MAXSIZE = 5
        with HTTPConnectionPool(self.host, self.port, maxsize=MAXSIZE) as pool:
            assert pool.pool is not None
            assert pool.pool.qsize() == MAXSIZE

            # Make request without releasing connection
            pool.request("GET", "/", release_conn=False, preload_content=False)
            assert pool.pool.qsize() == MAXSIZE - 1

    def test_dns_error(self) -> None:
        with HTTPConnectionPool(
            "thishostdoesnotexist.invalid", self.port, timeout=0.001
        ) as pool:
            with pytest.raises(MaxRetryError):
                pool.request("GET", "/test", retries=2)

    @pytest.mark.parametrize("char", [" ", "\r", "\n", "\x00"])
    def test_invalid_method_not_allowed(self, char: str) -> None:
        with pytest.raises(ValueError):
            with HTTPConnectionPool(self.host, self.port) as pool:
                pool.request("GET" + char, "/")

    def test_percent_encode_invalid_target_chars(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("GET", "/echo_params?q=\r&k=\n \n")
            assert r.data == b"[('k', '\\n \\n'), ('q', '\\r')]"

    def test_source_address(self) -> None:
        for addr, is_ipv6 in VALID_SOURCE_ADDRESSES:
            if is_ipv6:
                # TODO enable if HAS_IPV6_AND_DNS when this is fixed:
                # https://github.com/pgjones/hypercorn/issues/160
                warnings.warn("No IPv6 support: skipping.", NoIPv6Warning)
                continue
            with HTTPConnectionPool(
                self.host, self.port, source_address=addr, retries=False
            ) as pool:
                r = pool.request("GET", "/source_address")
                assert r.data == addr[0].encode()

    @pytest.mark.parametrize(
        "invalid_source_address, is_ipv6", INVALID_SOURCE_ADDRESSES
    )
    def test_source_address_error(
        self, invalid_source_address: tuple[str, int], is_ipv6: bool
    ) -> None:
        with HTTPConnectionPool(
            self.host, self.port, source_address=invalid_source_address, retries=False
        ) as pool:
            if is_ipv6:
                # with pytest.raises(NameResolutionError):
                with pytest.raises(NewConnectionError):
                    pool.request("GET", f"/source_address?{invalid_source_address}")
            else:
                with pytest.raises(NewConnectionError):
                    pool.request("GET", f"/source_address?{invalid_source_address}")

    def test_stream_keepalive(self) -> None:
        x = 2

        with HTTPConnectionPool(self.host, self.port) as pool:
            for _ in range(x):
                response = pool.request(
                    "GET",
                    "/chunked",
                    headers={"Connection": "keep-alive"},
                    preload_content=False,
                    retries=False,
                )
                for chunk in response.stream():
                    assert chunk == b"123"

            assert pool.num_connections == 1
            assert pool.num_requests == x

    def test_read_chunked_short_circuit(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            response = pool.request("GET", "/chunked", preload_content=False)
            response.read()
            with pytest.raises(StopIteration):
                next(response.read_chunked())

    def test_read_chunked_on_closed_response(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            response = pool.request("GET", "/chunked", preload_content=False)
            response.close()
            with pytest.raises(StopIteration):
                next(response.read_chunked())

    def test_chunked_gzip(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            response = pool.request(
                "GET", "/chunked_gzip", preload_content=False, decode_content=True
            )

            assert b"123" * 4 == response.read()

    def test_cleanup_on_connection_error(self) -> None:
        """
        Test that connections are recycled to the pool on
        connection errors where no http response is received.
        """
        poolsize = 3
        with HTTPConnectionPool(
            self.host, self.port, maxsize=poolsize, block=True
        ) as http:
            assert http.pool is not None
            assert http.pool.qsize() == poolsize

            # force a connection error by supplying a non-existent
            # url. We won't get a response for this  and so the
            # conn won't be implicitly returned to the pool.
            with pytest.raises(MaxRetryError):
                http.request(
                    "GET",
                    "/redirect",
                    fields={"target": "/"},
                    release_conn=False,
                    retries=0,
                )

            r = http.request(
                "GET",
                "/redirect",
                fields={"target": "/"},
                release_conn=False,
                retries=1,
            )
            r.release_conn()

            # the pool should still contain poolsize elements
            assert http.pool.qsize() == http.pool.maxsize

    def test_shutdown_on_connection_released_to_pool(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            resp = pool.urlopen("GET", "/", preload_content=False)
            resp.drain_conn()
            resp.release_conn()

        with pytest.raises(
            RuntimeError,
            match="Cannot shutdown as connection has already been released to the pool",
        ):
            resp.shutdown()

    def test_mixed_case_hostname(self) -> None:
        with HTTPConnectionPool("LoCaLhOsT", self.port) as pool:
            response = pool.request("GET", f"http://LoCaLhOsT:{self.port}/")
            assert response.status == 200

    def test_preserves_path_dot_segments(self) -> None:
        """ConnectionPool preserves dot segments in the URI"""
        with HTTPConnectionPool(self.host, self.port) as pool:
            response = pool.request("GET", "/echo_uri/seg0/../seg2")
            assert response.data == b"/echo_uri/seg0/../seg2?"

    def test_default_user_agent_header(self) -> None:
        """ConnectionPool has a default user agent"""
        default_ua = _get_default_user_agent()
        custom_ua = "I'm not a web scraper, what are you talking about?"
        custom_ua2 = "Yet Another User Agent"
        with HTTPConnectionPool(self.host, self.port) as pool:
            # Use default user agent if no user agent was specified.
            r = pool.request("GET", "/headers")
            request_headers = r.json()
            assert request_headers.get("User-Agent") == _get_default_user_agent()

            # Prefer the request user agent over the default.
            headers = {"UsEr-AGENt": custom_ua}
            r = pool.request("GET", "/headers", headers=headers)
            request_headers = r.json()
            assert request_headers.get("User-Agent") == custom_ua

            # Do not modify pool headers when using the default user agent.
            pool_headers = {"foo": "bar"}
            pool.headers = pool_headers
            r = pool.request("GET", "/headers")
            request_headers = r.json()
            assert request_headers.get("User-Agent") == default_ua
            assert "User-Agent" not in pool_headers

            pool.headers.update({"User-Agent": custom_ua2})
            r = pool.request("GET", "/headers")
            request_headers = r.json()
            assert request_headers.get("User-Agent") == custom_ua2

    @pytest.mark.parametrize(
        "headers",
        [
            None,
            {},
            {"User-Agent": "key"},
            {"user-agent": "key"},
            {b"uSeR-AgEnT": b"key"},
            {b"user-agent": "key"},
        ],
    )
    @pytest.mark.parametrize("chunked", [True, False])
    def test_user_agent_header_not_sent_twice(
        self, headers: dict[str, str] | None, chunked: bool
    ) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("GET", "/headers", headers=headers, chunked=chunked)
            request_headers = r.json()

            if not headers:
                assert request_headers["User-Agent"].startswith("python-urllib3/")
                assert "key" not in request_headers["User-Agent"]
            else:
                assert request_headers["User-Agent"] == "key"

    def test_no_user_agent_header(self) -> None:
        """ConnectionPool can suppress sending a user agent header"""
        custom_ua = "I'm not a web scraper, what are you talking about?"
        with HTTPConnectionPool(self.host, self.port) as pool:
            # Suppress user agent in the request headers.
            no_ua_headers = {"User-Agent": SKIP_HEADER}
            r = pool.request("GET", "/headers", headers=no_ua_headers)
            request_headers = r.json()
            assert "User-Agent" not in request_headers
            assert no_ua_headers["User-Agent"] == SKIP_HEADER

            # Suppress user agent in the pool headers.
            pool.headers = no_ua_headers
            r = pool.request("GET", "/headers")
            request_headers = r.json()
            assert "User-Agent" not in request_headers
            assert no_ua_headers["User-Agent"] == SKIP_HEADER

            # Request headers override pool headers.
            pool_headers = {"User-Agent": custom_ua}
            pool.headers = pool_headers
            r = pool.request("GET", "/headers", headers=no_ua_headers)
            request_headers = r.json()
            assert "User-Agent" not in request_headers
            assert no_ua_headers["User-Agent"] == SKIP_HEADER
            assert pool_headers.get("User-Agent") == custom_ua

    @pytest.mark.parametrize("header", ["Content-Length", "content-length"])
    @pytest.mark.parametrize("chunked", [True, False])
    def test_skip_header_non_supported(self, header: str, chunked: bool) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            with pytest.raises(
                ValueError,
                match="urllib3.util.SKIP_HEADER only supports 'Accept-Encoding', 'Host', 'User-Agent'",
            ) as e:
                pool.request(
                    "GET", "/headers", headers={header: SKIP_HEADER}, chunked=chunked
                )
            # Ensure that the error message stays up to date with 'SKIP_HEADER_SUPPORTED_HEADERS'
            assert all(
                ("'" + header.title() + "'") in str(e.value)
                for header in SKIPPABLE_HEADERS
            )

    @pytest.mark.parametrize("chunked", [True, False])
    @pytest.mark.parametrize("pool_request", [True, False])
    @pytest.mark.parametrize("header_type", [dict, HTTPHeaderDict])
    def test_headers_not_modified_by_request(
        self,
        chunked: bool,
        pool_request: bool,
        header_type: type[dict[str, str] | HTTPHeaderDict],
    ) -> None:
        # Test that the .request*() methods of ConnectionPool and HTTPConnection
        # don't modify the given 'headers' structure, instead they should
        # make their own internal copies at request time.
        headers = header_type()
        headers["key"] = "val"

        with HTTPConnectionPool(self.host, self.port) as pool:
            pool.headers = headers
            if pool_request:
                pool.request("GET", "/headers", chunked=chunked)
            else:
                conn = pool._get_conn()
                conn.request("GET", "/headers", chunked=chunked)
                conn.getresponse().close()
                conn.close()

            assert pool.headers == {"key": "val"}
            assert type(pool.headers) is header_type

        with HTTPConnectionPool(self.host, self.port) as pool:
            if pool_request:
                pool.request("GET", "/headers", headers=headers, chunked=chunked)
            else:
                conn = pool._get_conn()
                conn.request("GET", "/headers", headers=headers, chunked=chunked)
                conn.getresponse().close()
                conn.close()

            assert headers == {"key": "val"}

    def test_request_chunked_is_deprecated(
        self,
    ) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            conn = pool._get_conn()

            with pytest.warns(DeprecationWarning) as w:
                conn.request_chunked("GET", "/headers")  # type: ignore[attr-defined]
            assert len(w) == 1 and str(w[0].message) == (
                "HTTPConnection.request_chunked() is deprecated and will be removed in urllib3 v2.1.0. "
                "Instead use HTTPConnection.request(..., chunked=True)."
            )

            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.json()["Transfer-Encoding"] == "chunked"
            conn.close()

    def test_bytes_header(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            headers = {"User-Agent": "test header"}
            r = pool.request("GET", "/headers", headers=headers)
            request_headers = r.json()
            assert "User-Agent" in request_headers
            assert request_headers["User-Agent"] == "test header"

    @pytest.mark.parametrize(
        "user_agent", ["Schönefeld/1.18.0", "Schönefeld/1.18.0".encode("iso-8859-1")]
    )
    def test_user_agent_non_ascii_user_agent(self, user_agent: str) -> None:
        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            r = pool.urlopen(
                "GET",
                "/headers",
                headers={"User-Agent": user_agent},
            )
            request_headers = r.json()
            assert "User-Agent" in request_headers
            assert request_headers["User-Agent"] == "Schönefeld/1.18.0"


class TestRetry(HypercornDummyServerTestCase):
    def test_max_retry(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            with pytest.raises(MaxRetryError):
                pool.request("GET", "/redirect", fields={"target": "/"}, retries=0)

    def test_disabled_retry(self) -> None:
        """Disabled retries should disable redirect handling."""
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("GET", "/redirect", fields={"target": "/"}, retries=False)
            assert r.status == 303

            r = pool.request(
                "GET",
                "/redirect",
                fields={"target": "/"},
                retries=Retry(redirect=False),
            )
            assert r.status == 303

        with HTTPConnectionPool(
            "thishostdoesnotexist.invalid", self.port, timeout=0.001
        ) as pool:
            with pytest.raises(NameResolutionError):
                pool.request("GET", "/test", retries=False)

    def test_read_retries(self) -> None:
        """Should retry for status codes in the forcelist"""
        with HTTPConnectionPool(self.host, self.port) as pool:
            retry = Retry(read=1, status_forcelist=[418])
            resp = pool.request(
                "GET",
                "/successful_retry",
                headers={"test-name": "test_read_retries"},
                retries=retry,
            )
            assert resp.status == 200

    def test_read_total_retries(self) -> None:
        """HTTP response w/ status code in the forcelist should be retried"""
        with HTTPConnectionPool(self.host, self.port) as pool:
            headers = {"test-name": "test_read_total_retries"}
            retry = Retry(total=1, status_forcelist=[418])
            resp = pool.request(
                "GET", "/successful_retry", headers=headers, retries=retry
            )
            assert resp.status == 200

    def test_retries_wrong_forcelist(self) -> None:
        """HTTP response w/ status code not in forcelist shouldn't be retried"""
        with HTTPConnectionPool(self.host, self.port) as pool:
            retry = Retry(total=1, status_forcelist=[202])
            resp = pool.request(
                "GET",
                "/successful_retry",
                headers={"test-name": "test_wrong_forcelist"},
                retries=retry,
            )
            assert resp.status == 418

    def test_default_method_forcelist_retried(self) -> None:
        """urllib3 should retry methods in the default method forcelist"""
        with HTTPConnectionPool(self.host, self.port) as pool:
            retry = Retry(total=1, status_forcelist=[418])
            resp = pool.request(
                "OPTIONS",
                "/successful_retry",
                headers={"test-name": "test_default_forcelist"},
                retries=retry,
            )
            assert resp.status == 200

    def test_retries_wrong_method_list(self) -> None:
        """Method not in our allowed list should not be retried, even if code matches"""
        with HTTPConnectionPool(self.host, self.port) as pool:
            headers = {"test-name": "test_wrong_allowed_method"}
            retry = Retry(total=1, status_forcelist=[418], allowed_methods=["POST"])
            resp = pool.request(
                "GET", "/successful_retry", headers=headers, retries=retry
            )
            assert resp.status == 418

    def test_read_retries_unsuccessful(
        self,
    ) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            headers = {"test-name": "test_read_retries_unsuccessful"}
            resp = pool.request("GET", "/successful_retry", headers=headers, retries=1)
            assert resp.status == 418

    def test_retry_reuse_safe(self) -> None:
        """It should be possible to reuse a Retry object across requests"""
        with HTTPConnectionPool(self.host, self.port) as pool:
            headers = {"test-name": "test_retry_safe"}
            retry = Retry(total=1, status_forcelist=[418])
            resp = pool.request(
                "GET", "/successful_retry", headers=headers, retries=retry
            )
            assert resp.status == 200

        with HTTPConnectionPool(self.host, self.port) as pool:
            resp = pool.request(
                "GET", "/successful_retry", headers=headers, retries=retry
            )
            assert resp.status == 200

    def test_retry_return_in_response(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            headers = {"test-name": "test_retry_return_in_response"}
            retry = Retry(total=2, status_forcelist=[418])
            resp = pool.request(
                "GET", "/successful_retry", headers=headers, retries=retry
            )
            assert resp.status == 200
            assert resp.retries is not None
            assert resp.retries.total == 1
            assert resp.retries.history == (
                RequestHistory("GET", "/successful_retry", None, 418, None),
            )

    def test_retry_redirect_history(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            resp = pool.request("GET", "/redirect", fields={"target": "/"})
            assert resp.status == 200
            assert resp.retries is not None
            assert resp.retries.history == (
                RequestHistory("GET", "/redirect?target=%2F", None, 303, "/"),
            )

    def test_multi_redirect_history(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request(
                "GET",
                "/multi_redirect",
                fields={"redirect_codes": "303,302,200"},
                redirect=False,
            )
            assert r.status == 303
            assert r.retries is not None
            assert r.retries.history == tuple()

        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request(
                "GET",
                "/multi_redirect",
                retries=10,
                fields={"redirect_codes": "303,302,301,307,302,200"},
            )
            assert r.status == 200
            assert r.data == b"Done redirecting"

            expected = [
                (303, "/multi_redirect?redirect_codes=302,301,307,302,200"),
                (302, "/multi_redirect?redirect_codes=301,307,302,200"),
                (301, "/multi_redirect?redirect_codes=307,302,200"),
                (307, "/multi_redirect?redirect_codes=302,200"),
                (302, "/multi_redirect?redirect_codes=200"),
            ]
            assert r.retries is not None
            actual = [
                (history.status, history.redirect_location)
                for history in r.retries.history
            ]
            assert actual == expected


class TestRetryAfter(HypercornDummyServerTestCase):
    def test_retry_after(self) -> None:
        # Request twice in a second to get a 429 response.
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request(
                "GET",
                "/retry_after",
                fields={"status": "429 Too Many Requests"},
                retries=False,
            )
            r = pool.request(
                "GET",
                "/retry_after",
                fields={"status": "429 Too Many Requests"},
                retries=False,
            )
            assert r.status == 429

            r = pool.request(
                "GET",
                "/retry_after",
                fields={"status": "429 Too Many Requests"},
                retries=True,
            )
            assert r.status == 200

            # Request twice in a second to get a 503 response.
            r = pool.request(
                "GET",
                "/retry_after",
                fields={"status": "503 Service Unavailable"},
                retries=False,
            )
            r = pool.request(
                "GET",
                "/retry_after",
                fields={"status": "503 Service Unavailable"},
                retries=False,
            )
            assert r.status == 503

            r = pool.request(
                "GET",
                "/retry_after",
                fields={"status": "503 Service Unavailable"},
                retries=True,
            )
            assert r.status == 200

            # Ignore Retry-After header on status which is not defined in
            # Retry.RETRY_AFTER_STATUS_CODES.
            r = pool.request(
                "GET",
                "/retry_after",
                fields={"status": "418 I'm a teapot"},
                retries=True,
            )
            assert r.status == 418

    def test_redirect_after(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("GET", "/redirect_after", retries=False)
            assert r.status == 303

            # Real timestamps are needed for this test
            t = time.time()
            r = pool.request("GET", "/redirect_after")
            assert r.status == 200
            delta = time.time() - t
            assert delta >= 1

            t = time.time()
            timestamp = t + 2
            r = pool.request("GET", "/redirect_after?date=" + str(timestamp))
            assert r.status == 200
            delta = time.time() - t
            assert delta >= 1

            # Retry-After is past
            t = time.time()
            timestamp = t - 1
            r = pool.request("GET", "/redirect_after?date=" + str(timestamp))
            delta = time.time() - t
            assert r.status == 200
            assert delta < 1


class TestFileBodiesOnRetryOrRedirect(HypercornDummyServerTestCase):
    def test_retries_put_filehandle(self) -> None:
        """HTTP PUT retry with a file-like object should not timeout"""
        with HTTPConnectionPool(self.host, self.port, timeout=LONG_TIMEOUT) as pool:
            retry = Retry(total=3, status_forcelist=[418])
            # httplib reads in 8k chunks; use a larger content length
            content_length = 65535
            data = b"A" * content_length
            uploaded_file = io.BytesIO(data)
            headers = {
                "test-name": "test_retries_put_filehandle",
                "Content-Length": str(content_length),
            }
            resp = pool.urlopen(
                "PUT",
                "/successful_retry",
                headers=headers,
                retries=retry,
                body=uploaded_file,
                assert_same_host=False,
                redirect=False,
            )
            assert resp.status == 200

    def test_redirect_put_file(self) -> None:
        """PUT with file object should work with a redirection response"""
        with HTTPConnectionPool(self.host, self.port, timeout=LONG_TIMEOUT) as pool:
            retry = Retry(total=3, status_forcelist=[418])
            # httplib reads in 8k chunks; use a larger content length
            content_length = 65535
            data = b"A" * content_length
            uploaded_file = io.BytesIO(data)
            headers = {
                "test-name": "test_redirect_put_file",
                "Content-Length": str(content_length),
            }
            url = "/redirect?target=/echo&status=307"
            resp = pool.urlopen(
                "PUT",
                url,
                headers=headers,
                retries=retry,
                body=uploaded_file,
                assert_same_host=False,
                redirect=True,
            )
            assert resp.status == 200
            assert resp.data == data

    def test_redirect_with_failed_tell(self) -> None:
        """Abort request if failed to get a position from tell()"""

        class BadTellObject(io.BytesIO):
            def tell(self) -> typing.NoReturn:
                raise OSError

        body = BadTellObject(b"the data")
        url = "/redirect?target=/successful_retry"
        # httplib uses fileno if Content-Length isn't supplied,
        # which is unsupported by BytesIO.
        headers = {"Content-Length": "8"}
        with HTTPConnectionPool(self.host, self.port, timeout=LONG_TIMEOUT) as pool:
            with pytest.raises(
                UnrewindableBodyError, match="Unable to record file position for"
            ):
                pool.urlopen("PUT", url, headers=headers, body=body)


class TestRetryPoolSize(HypercornDummyServerTestCase):
    def test_pool_size_retry(self) -> None:
        retries = Retry(total=1, raise_on_status=False, status_forcelist=[404])
        with HTTPConnectionPool(
            self.host, self.port, maxsize=10, retries=retries, block=True
        ) as pool:
            pool.urlopen("GET", "/not_found", preload_content=False)
            assert pool.num_connections == 1


class TestRedirectPoolSize(HypercornDummyServerTestCase):
    def test_pool_size_redirect(self) -> None:
        retries = Retry(
            total=1, raise_on_status=False, status_forcelist=[404], redirect=True
        )
        with HTTPConnectionPool(
            self.host, self.port, maxsize=10, retries=retries, block=True
        ) as pool:
            pool.urlopen("GET", "/redirect", preload_content=False)
            assert pool.num_connections == 1

from __future__ import annotations

import http.client as httplib
import ssl
import typing
from http.client import HTTPException
from queue import Empty
from socket import error as SocketError
from ssl import SSLError as BaseSSLError
from test import SHORT_TIMEOUT
from unittest.mock import Mock, patch

import pytest

from dummyserver.socketserver import DEFAULT_CA
from urllib3 import Retry
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import (
    HTTPConnectionPool,
    HTTPSConnectionPool,
    _url_from_pool,
    connection_from_url,
)
from urllib3.exceptions import (
    ClosedPoolError,
    EmptyPoolError,
    FullPoolError,
    HostChangedError,
    LocationValueError,
    MaxRetryError,
    ProtocolError,
    ReadTimeoutError,
    SSLError,
    TimeoutError,
)
from urllib3.response import HTTPResponse
from urllib3.util.ssl_match_hostname import CertificateError
from urllib3.util.timeout import _DEFAULT_TIMEOUT, Timeout

from .test_response import MockChunkedEncodingResponse, MockSock


class HTTPUnixConnection(HTTPConnection):
    def __init__(self, host: str, timeout: int = 60, **kwargs: typing.Any) -> None:
        super().__init__("localhost")
        self.unix_socket = host
        self.timeout = timeout
        self.sock = None


class HTTPUnixConnectionPool(HTTPConnectionPool):
    scheme = "http+unix"
    ConnectionCls = HTTPUnixConnection


class TestConnectionPool:
    """
    Tests in this suite should exercise the ConnectionPool functionality
    without actually making any network requests or connections.
    """

    @pytest.mark.parametrize(
        "a, b",
        [
            ("http://google.com/", "/"),
            ("http://google.com/", "http://google.com/"),
            ("http://google.com/", "http://google.com"),
            ("http://google.com/", "http://google.com/abra/cadabra"),
            ("http://google.com:42/", "http://google.com:42/abracadabra"),
            # Test comparison using default ports
            ("http://google.com:80/", "http://google.com/abracadabra"),
            ("http://google.com/", "http://google.com:80/abracadabra"),
            ("https://google.com:443/", "https://google.com/abracadabra"),
            ("https://google.com/", "https://google.com:443/abracadabra"),
            (
                "http://[2607:f8b0:4005:805::200e%25eth0]/",
                "http://[2607:f8b0:4005:805::200e%eth0]/",
            ),
            (
                "https://[2607:f8b0:4005:805::200e%25eth0]:443/",
                "https://[2607:f8b0:4005:805::200e%eth0]:443/",
            ),
            ("http://[::1]/", "http://[::1]"),
            (
                "http://[2001:558:fc00:200:f816:3eff:fef9:b954%lo]/",
                "http://[2001:558:fc00:200:f816:3eff:fef9:b954%25lo]",
            ),
        ],
    )
    def test_same_host(self, a: str, b: str) -> None:
        with connection_from_url(a) as c:
            assert c.is_same_host(b)

    @pytest.mark.parametrize(
        "a, b",
        [
            ("https://google.com/", "http://google.com/"),
            ("http://google.com/", "https://google.com/"),
            ("http://yahoo.com/", "http://google.com/"),
            ("http://google.com:42", "https://google.com/abracadabra"),
            ("http://google.com", "https://google.net/"),
            # Test comparison with default ports
            ("http://google.com:42", "http://google.com"),
            ("https://google.com:42", "https://google.com"),
            ("http://google.com:443", "http://google.com"),
            ("https://google.com:80", "https://google.com"),
            ("http://google.com:443", "https://google.com"),
            ("https://google.com:80", "http://google.com"),
            ("https://google.com:443", "http://google.com"),
            ("http://google.com:80", "https://google.com"),
            # Zone identifiers are unique connection end points and should
            # never be equivalent.
            ("http://[dead::beef]", "https://[dead::beef%en5]/"),
        ],
    )
    def test_not_same_host(self, a: str, b: str) -> None:
        with connection_from_url(a) as c:
            assert not c.is_same_host(b)

        with connection_from_url(b) as c:
            assert not c.is_same_host(a)

    @pytest.mark.parametrize(
        "a, b",
        [
            ("google.com", "/"),
            ("google.com", "http://google.com/"),
            ("google.com", "http://google.com"),
            ("google.com", "http://google.com/abra/cadabra"),
            # Test comparison using default ports
            ("google.com", "http://google.com:80/abracadabra"),
        ],
    )
    def test_same_host_no_port_http(self, a: str, b: str) -> None:
        # This test was introduced in #801 to deal with the fact that urllib3
        # never initializes ConnectionPool objects with port=None.
        with HTTPConnectionPool(a) as c:
            assert c.is_same_host(b)

    @pytest.mark.parametrize(
        "a, b",
        [
            ("google.com", "/"),
            ("google.com", "https://google.com/"),
            ("google.com", "https://google.com"),
            ("google.com", "https://google.com/abra/cadabra"),
            # Test comparison using default ports
            ("google.com", "https://google.com:443/abracadabra"),
        ],
    )
    def test_same_host_no_port_https(self, a: str, b: str) -> None:
        # This test was introduced in #801 to deal with the fact that urllib3
        # never initializes ConnectionPool objects with port=None.
        with HTTPSConnectionPool(a) as c:
            assert c.is_same_host(b)

    @pytest.mark.parametrize(
        "a, b",
        [
            ("google.com", "https://google.com/"),
            ("yahoo.com", "http://google.com/"),
            ("google.com", "https://google.net/"),
            ("google.com", "http://google.com./"),
        ],
    )
    def test_not_same_host_no_port_http(self, a: str, b: str) -> None:
        with HTTPConnectionPool(a) as c:
            assert not c.is_same_host(b)

        with HTTPConnectionPool(b) as c:
            assert not c.is_same_host(a)

    @pytest.mark.parametrize(
        "a, b",
        [
            ("google.com", "http://google.com/"),
            ("yahoo.com", "https://google.com/"),
            ("google.com", "https://google.net/"),
            ("google.com", "https://google.com./"),
        ],
    )
    def test_not_same_host_no_port_https(self, a: str, b: str) -> None:
        with HTTPSConnectionPool(a) as c:
            assert not c.is_same_host(b)

        with HTTPSConnectionPool(b) as c:
            assert not c.is_same_host(a)

    @pytest.mark.parametrize(
        "a, b",
        [
            ("%2Fvar%2Frun%2Fdocker.sock", "http+unix://%2Fvar%2Frun%2Fdocker.sock"),
            ("%2Fvar%2Frun%2Fdocker.sock", "http+unix://%2Fvar%2Frun%2Fdocker.sock/"),
            (
                "%2Fvar%2Frun%2Fdocker.sock",
                "http+unix://%2Fvar%2Frun%2Fdocker.sock/abracadabra",
            ),
            ("%2Ftmp%2FTEST.sock", "http+unix://%2Ftmp%2FTEST.sock"),
            ("%2Ftmp%2FTEST.sock", "http+unix://%2Ftmp%2FTEST.sock/"),
            ("%2Ftmp%2FTEST.sock", "http+unix://%2Ftmp%2FTEST.sock/abracadabra"),
        ],
    )
    def test_same_host_custom_protocol(self, a: str, b: str) -> None:
        with HTTPUnixConnectionPool(a) as c:
            assert c.is_same_host(b)

    @pytest.mark.parametrize(
        "a, b",
        [
            ("%2Ftmp%2Ftest.sock", "http+unix://%2Ftmp%2FTEST.sock"),
            ("%2Ftmp%2Ftest.sock", "http+unix://%2Ftmp%2FTEST.sock/"),
            ("%2Ftmp%2Ftest.sock", "http+unix://%2Ftmp%2FTEST.sock/abracadabra"),
            ("%2Fvar%2Frun%2Fdocker.sock", "http+unix://%2Ftmp%2FTEST.sock"),
        ],
    )
    def test_not_same_host_custom_protocol(self, a: str, b: str) -> None:
        with HTTPUnixConnectionPool(a) as c:
            assert not c.is_same_host(b)

    def test_max_connections(self) -> None:
        with HTTPConnectionPool(host="localhost", maxsize=1, block=True) as pool:
            pool._get_conn(timeout=SHORT_TIMEOUT)

            with pytest.raises(EmptyPoolError):
                pool._get_conn(timeout=SHORT_TIMEOUT)

            with pytest.raises(EmptyPoolError):
                pool.request("GET", "/", pool_timeout=SHORT_TIMEOUT)

            assert pool.num_connections == 1

    def test_put_conn_when_pool_is_full_nonblocking(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """
        If maxsize = n and we _put_conn n + 1 conns, the n + 1th conn will
        get closed and will not get added to the pool.
        """
        with HTTPConnectionPool(host="localhost", maxsize=1, block=False) as pool:
            conn1 = pool._get_conn()
            # pool.pool is empty because we popped the one None that pool.pool was initialized with
            # but this pool._get_conn call will not raise EmptyPoolError because block is False
            conn2 = pool._get_conn()

            with patch.object(conn1, "close") as conn1_close:
                with patch.object(conn2, "close") as conn2_close:
                    pool._put_conn(conn1)
                    pool._put_conn(conn2)

            assert conn1_close.called is False
            assert conn2_close.called is True

            assert conn1 == pool._get_conn()
            assert conn2 != pool._get_conn()

            assert pool.num_connections == 3
            assert "Connection pool is full, discarding connection" in caplog.text
            assert "Connection pool size: 1" in caplog.text

    def test_put_conn_when_pool_is_full_blocking(self) -> None:
        """
        If maxsize = n and we _put_conn n + 1 conns, the n + 1th conn will
        cause a FullPoolError.
        """
        with HTTPConnectionPool(host="localhost", maxsize=1, block=True) as pool:
            conn1 = pool._get_conn()
            conn2 = pool._new_conn()

            with patch.object(conn1, "close") as conn1_close:
                with patch.object(conn2, "close") as conn2_close:
                    pool._put_conn(conn1)
                    with pytest.raises(FullPoolError):
                        pool._put_conn(conn2)

            assert conn1_close.called is False
            assert conn2_close.called is True

            assert conn1 == pool._get_conn()

    def test_put_conn_closed_pool(self) -> None:
        with HTTPConnectionPool(host="localhost", maxsize=1, block=True) as pool:
            conn1 = pool._get_conn()
            with patch.object(conn1, "close") as conn1_close:
                pool.close()

                assert pool.pool is None

                # Accessing pool.pool will raise AttributeError, which will get
                # caught and will close conn1
                pool._put_conn(conn1)

            assert conn1_close.called is True

    def test_exception_str(self) -> None:
        assert (
            str(EmptyPoolError(HTTPConnectionPool(host="localhost"), "Test."))
            == "HTTPConnectionPool(host='localhost', port=None): Test."
        )

    def test_retry_exception_str(self) -> None:
        assert (
            str(MaxRetryError(HTTPConnectionPool(host="localhost"), "Test.", None))
            == "HTTPConnectionPool(host='localhost', port=None): "
            "Max retries exceeded with url: Test. (Caused by None)"
        )

        err = SocketError("Test")

        # using err.__class__ here, as socket.error is an alias for OSError
        # since Py3.3 and gets printed as this
        assert (
            str(MaxRetryError(HTTPConnectionPool(host="localhost"), "Test.", err))
            == "HTTPConnectionPool(host='localhost', port=None): "
            "Max retries exceeded with url: Test. "
            "(Caused by %r)" % err
        )

    def test_pool_size(self) -> None:
        POOL_SIZE = 1
        with HTTPConnectionPool(
            host="localhost", maxsize=POOL_SIZE, block=True
        ) as pool:

            def _test(
                exception: type[BaseException],
                expect: type[BaseException],
                reason: type[BaseException] | None = None,
            ) -> None:
                with patch.object(pool, "_make_request", side_effect=exception()):
                    with pytest.raises(expect) as excinfo:
                        pool.request("GET", "/")
                if reason is not None:
                    assert isinstance(excinfo.value.reason, reason)  # type: ignore[attr-defined]
                assert pool.pool is not None
                assert pool.pool.qsize() == POOL_SIZE

            # Make sure that all of the exceptions return the connection
            # to the pool
            _test(BaseSSLError, MaxRetryError, SSLError)
            _test(CertificateError, MaxRetryError, SSLError)

            # The pool should never be empty, and with these two exceptions
            # being raised, a retry will be triggered, but that retry will
            # fail, eventually raising MaxRetryError, not EmptyPoolError
            # See: https://github.com/urllib3/urllib3/issues/76
            with patch.object(pool, "_make_request", side_effect=HTTPException()):
                with pytest.raises(MaxRetryError):
                    pool.request("GET", "/", retries=1, pool_timeout=SHORT_TIMEOUT)
            assert pool.pool is not None
            assert pool.pool.qsize() == POOL_SIZE

    def test_empty_does_not_put_conn(self) -> None:
        """Do not put None back in the pool if the pool was empty"""

        with HTTPConnectionPool(host="localhost", maxsize=1, block=True) as pool:
            with patch.object(
                pool, "_get_conn", side_effect=EmptyPoolError(pool, "Pool is empty")
            ):
                with patch.object(
                    pool,
                    "_put_conn",
                    side_effect=AssertionError("Unexpected _put_conn"),
                ):
                    with pytest.raises(EmptyPoolError):
                        pool.request("GET", "/")

    def test_assert_same_host(self) -> None:
        with connection_from_url("http://google.com:80") as c:
            with pytest.raises(HostChangedError):
                c.request("GET", "http://yahoo.com:80", assert_same_host=True)

    def test_pool_close(self) -> None:
        pool = connection_from_url("http://google.com:80")

        # Populate with some connections
        conn1 = pool._get_conn()
        conn2 = pool._get_conn()
        conn3 = pool._get_conn()
        pool._put_conn(conn1)
        pool._put_conn(conn2)

        old_pool_queue = pool.pool

        pool.close()
        assert pool.pool is None

        with pytest.raises(ClosedPoolError):
            pool._get_conn()

        pool._put_conn(conn3)

        with pytest.raises(ClosedPoolError):
            pool._get_conn()

        with pytest.raises(Empty):
            assert old_pool_queue is not None
            old_pool_queue.get(block=False)

    def test_pool_close_twice(self) -> None:
        pool = connection_from_url("http://google.com:80")

        # Populate with some connections
        conn1 = pool._get_conn()
        conn2 = pool._get_conn()
        pool._put_conn(conn1)
        pool._put_conn(conn2)

        pool.close()
        assert pool.pool is None

        try:
            pool.close()
        except AttributeError:
            pytest.fail("Pool of the ConnectionPool is None and has no attribute get.")

    def test_pool_timeouts(self) -> None:
        with HTTPConnectionPool(host="localhost") as pool:
            conn = pool._new_conn()
            assert conn.__class__ == HTTPConnection
            assert pool.timeout.__class__ == Timeout
            assert pool.timeout._read == _DEFAULT_TIMEOUT
            assert pool.timeout._connect == _DEFAULT_TIMEOUT
            assert pool.timeout.total is None

            pool = HTTPConnectionPool(host="localhost", timeout=SHORT_TIMEOUT)
            assert pool.timeout._read == SHORT_TIMEOUT
            assert pool.timeout._connect == SHORT_TIMEOUT
            assert pool.timeout.total is None

    def test_no_host(self) -> None:
        with pytest.raises(LocationValueError):
            HTTPConnectionPool(None)  # type: ignore[arg-type]

    def test_contextmanager(self) -> None:
        with connection_from_url("http://google.com:80") as pool:
            # Populate with some connections
            conn1 = pool._get_conn()
            conn2 = pool._get_conn()
            conn3 = pool._get_conn()
            pool._put_conn(conn1)
            pool._put_conn(conn2)

            old_pool_queue = pool.pool

        assert pool.pool is None
        with pytest.raises(ClosedPoolError):
            pool._get_conn()

        pool._put_conn(conn3)
        with pytest.raises(ClosedPoolError):
            pool._get_conn()
        with pytest.raises(Empty):
            assert old_pool_queue is not None
            old_pool_queue.get(block=False)

    def test_url_from_pool(self) -> None:
        with connection_from_url("http://google.com:80") as pool:
            path = "path?query=foo"
            assert f"http://google.com:80/{path}" == _url_from_pool(pool, path)

    def test_ca_certs_default_cert_required(self) -> None:
        with connection_from_url("https://google.com:80", ca_certs=DEFAULT_CA) as pool:
            conn = pool._get_conn()
            assert conn.cert_reqs == ssl.CERT_REQUIRED  # type: ignore[attr-defined]

    def test_cleanup_on_extreme_connection_error(self) -> None:
        """
        This test validates that we clean up properly even on exceptions that
        we'd not otherwise catch, i.e. those that inherit from BaseException
        like KeyboardInterrupt or gevent.Timeout. See #805 for more details.
        """

        class RealBad(BaseException):
            pass

        def kaboom(*args: typing.Any, **kwargs: typing.Any) -> None:
            raise RealBad()

        with connection_from_url("http://localhost:80") as c:
            with patch.object(c, "_make_request", kaboom):
                assert c.pool is not None
                initial_pool_size = c.pool.qsize()

                try:
                    # We need to release_conn this way or we'd put it away
                    # regardless.
                    c.urlopen("GET", "/", release_conn=False)
                except RealBad:
                    pass

            new_pool_size = c.pool.qsize()
            assert initial_pool_size == new_pool_size

    def test_release_conn_param_is_respected_after_http_error_retry(self) -> None:
        """For successful ```urlopen(release_conn=False)```,
        the connection isn't released, even after a retry.

        This is a regression test for issue #651 [1], where the connection
        would be released if the initial request failed, even if a retry
        succeeded.

        [1] <https://github.com/urllib3/urllib3/issues/651>
        """

        class _raise_once_make_request_function:
            """Callable that can mimic `_make_request()`.

            Raises the given exception on its first call, but returns a
            successful response on subsequent calls.
            """

            def __init__(
                self, ex: type[BaseException], pool: HTTPConnectionPool
            ) -> None:
                super().__init__()
                self._ex: type[BaseException] | None = ex
                self._pool = pool

            def __call__(
                self,
                conn: HTTPConnection,
                method: str,
                url: str,
                *args: typing.Any,
                retries: Retry,
                **kwargs: typing.Any,
            ) -> HTTPResponse:
                if self._ex:
                    ex, self._ex = self._ex, None
                    raise ex()
                httplib_response = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
                httplib_response.fp = MockChunkedEncodingResponse([b"f", b"o", b"o"])  # type: ignore[assignment]
                httplib_response.headers = httplib_response.msg = httplib.HTTPMessage()

                response_conn: HTTPConnection | None = kwargs.get("response_conn")

                response = HTTPResponse(
                    body=httplib_response,
                    headers=httplib_response.headers,  # type: ignore[arg-type]
                    status=httplib_response.status,
                    version=httplib_response.version,
                    reason=httplib_response.reason,
                    original_response=httplib_response,
                    retries=retries,
                    request_method=method,
                    request_url=url,
                    preload_content=False,
                    connection=response_conn,
                    pool=self._pool,
                )
                return response

        def _test(exception: type[BaseException]) -> None:
            with HTTPConnectionPool(host="localhost", maxsize=1, block=True) as pool:
                # Verify that the request succeeds after two attempts, and that the
                # connection is left on the response object, instead of being
                # released back into the pool.
                with patch.object(
                    pool,
                    "_make_request",
                    _raise_once_make_request_function(exception, pool),
                ):
                    response = pool.urlopen(
                        "GET",
                        "/",
                        retries=1,
                        release_conn=False,
                        preload_content=False,
                        chunked=True,
                    )
                assert pool.pool is not None
                assert pool.pool.qsize() == 0
                assert pool.num_connections == 2
                assert response.connection is not None

                response.release_conn()
                assert pool.pool.qsize() == 1
                assert response.connection is None

        # Run the test case for all the retriable exceptions.
        _test(TimeoutError)
        _test(HTTPException)
        _test(SocketError)
        _test(ProtocolError)

    def test_read_timeout_0_does_not_raise_bad_status_line_error(self) -> None:
        with HTTPConnectionPool(host="localhost", maxsize=1) as pool:
            conn = Mock(spec=HTTPConnection)
            # Needed to tell the pool that the connection is alive.
            conn.is_closed = False
            with patch.object(Timeout, "read_timeout", 0):
                timeout = Timeout(1, 1, 1)
                with pytest.raises(ReadTimeoutError):
                    pool._make_request(conn, "", "", timeout=timeout)

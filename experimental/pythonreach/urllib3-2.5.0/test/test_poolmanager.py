from __future__ import annotations

import gc
import socket
from test import resolvesLocalhostFQDN
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from urllib3 import connection_from_url
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import LocationValueError
from urllib3.poolmanager import (
    _DEFAULT_BLOCKSIZE,
    PoolKey,
    PoolManager,
    key_fn_by_scheme,
)
from urllib3.util import retry, timeout
from urllib3.util.url import Url


class TestPoolManager:
    @resolvesLocalhostFQDN()
    def test_same_url(self) -> None:
        # Convince ourselves that normally we don't get the same object
        conn1 = connection_from_url("http://localhost:8081/foo")
        conn2 = connection_from_url("http://localhost:8081/bar")

        assert conn1 != conn2

        # Now try again using the PoolManager
        p = PoolManager(1)

        conn1 = p.connection_from_url("http://localhost:8081/foo")
        conn2 = p.connection_from_url("http://localhost:8081/bar")

        assert conn1 == conn2

        # Ensure that FQDNs are handled separately from relative domains
        p = PoolManager(2)

        conn1 = p.connection_from_url("http://localhost.:8081/foo")
        conn2 = p.connection_from_url("http://localhost:8081/bar")

        assert conn1 != conn2

    def test_many_urls(self) -> None:
        urls = [
            "http://localhost:8081/foo",
            "http://www.google.com/mail",
            "http://localhost:8081/bar",
            "https://www.google.com/",
            "https://www.google.com/mail",
            "http://yahoo.com",
            "http://bing.com",
            "http://yahoo.com/",
        ]

        connections = set()

        p = PoolManager(10)

        for url in urls:
            conn = p.connection_from_url(url)
            connections.add(conn)

        assert len(connections) == 5

    def test_manager_clear(self) -> None:
        p = PoolManager(5)

        p.connection_from_url("http://google.com")
        assert len(p.pools) == 1

        p.clear()
        assert len(p.pools) == 0

    @pytest.mark.parametrize("url", ["http://@", None])
    def test_nohost(self, url: str | None) -> None:
        p = PoolManager(5)
        with pytest.raises(LocationValueError):
            p.connection_from_url(url=url)  # type: ignore[arg-type]

    def test_contextmanager(self) -> None:
        with PoolManager(1) as p:
            p.connection_from_url("http://google.com")
            assert len(p.pools) == 1

        assert len(p.pools) == 0

    def test_http_pool_key_fields(self) -> None:
        """Assert the HTTPPoolKey fields are honored when selecting a pool."""
        connection_pool_kw = {
            "timeout": timeout.Timeout(3.14),
            "retries": retry.Retry(total=6, connect=2),
            "block": True,
            "source_address": "127.0.0.1",
            "blocksize": _DEFAULT_BLOCKSIZE + 1,
        }
        p = PoolManager()
        conn_pools = [
            p.connection_from_url("http://example.com/"),
            p.connection_from_url("http://example.com:8000/"),
            p.connection_from_url("http://other.example.com/"),
        ]

        for key, value in connection_pool_kw.items():
            p.connection_pool_kw[key] = value
            conn_pools.append(p.connection_from_url("http://example.com/"))

        assert all(
            x is not y
            for i, x in enumerate(conn_pools)
            for j, y in enumerate(conn_pools)
            if i != j
        )
        assert all(isinstance(key, PoolKey) for key in p.pools.keys())

    def test_https_pool_key_fields(self) -> None:
        """Assert the HTTPSPoolKey fields are honored when selecting a pool."""
        connection_pool_kw = {
            "timeout": timeout.Timeout(3.14),
            "retries": retry.Retry(total=6, connect=2),
            "block": True,
            "source_address": "127.0.0.1",
            "key_file": "/root/totally_legit.key",
            "cert_file": "/root/totally_legit.crt",
            "cert_reqs": "CERT_REQUIRED",
            "ca_certs": "/root/path_to_pem",
            "ssl_version": "SSLv23_METHOD",
            "blocksize": _DEFAULT_BLOCKSIZE + 1,
        }
        p = PoolManager()
        conn_pools = [
            p.connection_from_url("https://example.com/"),
            p.connection_from_url("https://example.com:4333/"),
            p.connection_from_url("https://other.example.com/"),
        ]
        # Asking for a connection pool with the same key should give us an
        # existing pool.
        dup_pools = []

        for key, value in connection_pool_kw.items():
            p.connection_pool_kw[key] = value
            conn_pools.append(p.connection_from_url("https://example.com/"))
            dup_pools.append(p.connection_from_url("https://example.com/"))

        assert all(
            x is not y
            for i, x in enumerate(conn_pools)
            for j, y in enumerate(conn_pools)
            if i != j
        )
        assert all(pool in conn_pools for pool in dup_pools)
        assert all(isinstance(key, PoolKey) for key in p.pools.keys())

    def test_default_pool_key_funcs_copy(self) -> None:
        """Assert each PoolManager gets a copy of ``pool_keys_by_scheme``."""
        p = PoolManager()
        assert p.key_fn_by_scheme == p.key_fn_by_scheme
        assert p.key_fn_by_scheme is not key_fn_by_scheme

    def test_pools_keyed_with_from_host(self) -> None:
        """Assert pools are still keyed correctly with connection_from_host."""
        ssl_kw = {
            "key_file": "/root/totally_legit.key",
            "cert_file": "/root/totally_legit.crt",
            "cert_reqs": "CERT_REQUIRED",
            "ca_certs": "/root/path_to_pem",
            "ssl_version": "SSLv23_METHOD",
        }
        p = PoolManager(5, **ssl_kw)  # type: ignore[arg-type]
        conns = [p.connection_from_host("example.com", 443, scheme="https")]

        for k in ssl_kw:
            p.connection_pool_kw[k] = "newval"
            conns.append(p.connection_from_host("example.com", 443, scheme="https"))

        assert all(
            x is not y
            for i, x in enumerate(conns)
            for j, y in enumerate(conns)
            if i != j
        )

    def test_https_connection_from_url_case_insensitive(self) -> None:
        """Assert scheme case is ignored when pooling HTTPS connections."""
        p = PoolManager()
        pool = p.connection_from_url("https://example.com/")
        other_pool = p.connection_from_url("HTTPS://EXAMPLE.COM/")

        assert 1 == len(p.pools)
        assert pool is other_pool
        assert all(isinstance(key, PoolKey) for key in p.pools.keys())

    def test_https_connection_from_host_case_insensitive(self) -> None:
        """Assert scheme case is ignored when getting the https key class."""
        p = PoolManager()
        pool = p.connection_from_host("example.com", scheme="https")
        other_pool = p.connection_from_host("EXAMPLE.COM", scheme="HTTPS")

        assert 1 == len(p.pools)
        assert pool is other_pool
        assert all(isinstance(key, PoolKey) for key in p.pools.keys())

    def test_https_connection_from_context_case_insensitive(self) -> None:
        """Assert scheme case is ignored when getting the https key class."""
        p = PoolManager()
        context = {"scheme": "https", "host": "example.com", "port": "443"}
        other_context = {"scheme": "HTTPS", "host": "EXAMPLE.COM", "port": "443"}
        pool = p.connection_from_context(context)
        other_pool = p.connection_from_context(other_context)

        assert 1 == len(p.pools)
        assert pool is other_pool
        assert all(isinstance(key, PoolKey) for key in p.pools.keys())

    def test_http_connection_from_url_case_insensitive(self) -> None:
        """Assert scheme case is ignored when pooling HTTP connections."""
        p = PoolManager()
        pool = p.connection_from_url("http://example.com/")
        other_pool = p.connection_from_url("HTTP://EXAMPLE.COM/")

        assert 1 == len(p.pools)
        assert pool is other_pool
        assert all(isinstance(key, PoolKey) for key in p.pools.keys())

    def test_http_connection_from_host_case_insensitive(self) -> None:
        """Assert scheme case is ignored when getting the https key class."""
        p = PoolManager()
        pool = p.connection_from_host("example.com", scheme="http")
        other_pool = p.connection_from_host("EXAMPLE.COM", scheme="HTTP")

        assert 1 == len(p.pools)
        assert pool is other_pool
        assert all(isinstance(key, PoolKey) for key in p.pools.keys())

    def test_assert_hostname_and_fingerprint_flag(self) -> None:
        """Assert that pool manager can accept hostname and fingerprint flags."""
        fingerprint = "92:81:FE:85:F7:0C:26:60:EC:D6:B3:BF:93:CF:F9:71:CC:07:7D:0A"
        p = PoolManager(assert_hostname=True, assert_fingerprint=fingerprint)
        pool = p.connection_from_url("https://example.com/")
        assert 1 == len(p.pools)
        assert isinstance(pool, HTTPSConnectionPool)
        assert pool.assert_hostname
        assert fingerprint == pool.assert_fingerprint

    def test_http_connection_from_context_case_insensitive(self) -> None:
        """Assert scheme case is ignored when getting the https key class."""
        p = PoolManager()
        context = {"scheme": "http", "host": "example.com", "port": "8080"}
        other_context = {"scheme": "HTTP", "host": "EXAMPLE.COM", "port": "8080"}
        pool = p.connection_from_context(context)
        other_pool = p.connection_from_context(other_context)

        assert 1 == len(p.pools)
        assert pool is other_pool
        assert all(isinstance(key, PoolKey) for key in p.pools.keys())

    @patch("urllib3.poolmanager.PoolManager.connection_from_host")
    def test_deprecated_no_scheme(self, connection_from_host: mock.MagicMock) -> None:
        # Don't actually make a network connection, just verify the DeprecationWarning
        connection_from_host.side_effect = ConnectionError("Not attempting connection")
        p = PoolManager()

        with pytest.warns(DeprecationWarning) as records:
            with pytest.raises(ConnectionError):
                p.request(method="GET", url="evil.com://good.com")

        msg = (
            "URLs without a scheme (ie 'https://') are deprecated and will raise an error "
            "in a future version of urllib3. To avoid this DeprecationWarning ensure all URLs "
            "start with 'https://' or 'http://'. Read more in this issue: "
            "https://github.com/urllib3/urllib3/issues/2920"
        )

        assert len(records) == 1
        assert isinstance(records[0].message, DeprecationWarning)
        assert records[0].message.args[0] == msg

    @patch("urllib3.poolmanager.PoolManager.connection_from_pool_key")
    def test_connection_from_context_strict_param(
        self, connection_from_pool_key: mock.MagicMock
    ) -> None:
        p = PoolManager()
        context = {
            "scheme": "http",
            "host": "example.com",
            "port": 8080,
            "strict": True,
        }
        with pytest.warns(DeprecationWarning) as records:
            p.connection_from_context(context)

        msg = (
            "The 'strict' parameter is no longer needed on Python 3+. "
            "This will raise an error in urllib3 v2.1.0."
        )
        record = records[0]
        assert isinstance(record.message, Warning)
        assert record.message.args[0] == msg

        _, kwargs = connection_from_pool_key.call_args
        assert kwargs["request_context"] == {
            "scheme": "http",
            "host": "example.com",
            "port": 8080,
        }

    def test_custom_pool_key(self) -> None:
        """Assert it is possible to define a custom key function."""
        p = PoolManager(10)

        p.key_fn_by_scheme["http"] = lambda x: tuple(x["key"])  # type: ignore[assignment]
        pool1 = p.connection_from_url(
            "http://example.com", pool_kwargs={"key": "value"}
        )
        pool2 = p.connection_from_url(
            "http://example.com", pool_kwargs={"key": "other"}
        )
        pool3 = p.connection_from_url(
            "http://example.com", pool_kwargs={"key": "value", "x": "y"}
        )

        assert 2 == len(p.pools)
        assert pool1 is pool3
        assert pool1 is not pool2

    def test_override_pool_kwargs_url(self) -> None:
        """Assert overriding pool kwargs works with connection_from_url."""
        p = PoolManager()
        pool_kwargs = {"retries": 100, "block": True}

        default_pool = p.connection_from_url("http://example.com/")
        override_pool = p.connection_from_url(
            "http://example.com/", pool_kwargs=pool_kwargs
        )

        assert retry.Retry.DEFAULT == default_pool.retries
        assert not default_pool.block

        assert 100 == override_pool.retries
        assert override_pool.block

    def test_override_pool_kwargs_host(self) -> None:
        """Assert overriding pool kwargs works with connection_from_host"""
        p = PoolManager()
        pool_kwargs = {"retries": 100, "block": True}

        default_pool = p.connection_from_host("example.com", scheme="http")
        override_pool = p.connection_from_host(
            "example.com", scheme="http", pool_kwargs=pool_kwargs
        )

        assert retry.Retry.DEFAULT == default_pool.retries
        assert not default_pool.block

        assert 100 == override_pool.retries
        assert override_pool.block

    def test_pool_kwargs_socket_options(self) -> None:
        """Assert passing socket options works with connection_from_host"""
        p = PoolManager(socket_options=[])
        override_opts = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
        ]
        pool_kwargs = {"socket_options": override_opts}

        default_pool = p.connection_from_host("example.com", scheme="http")
        override_pool = p.connection_from_host(
            "example.com", scheme="http", pool_kwargs=pool_kwargs
        )

        assert default_pool.conn_kw["socket_options"] == []
        assert override_pool.conn_kw["socket_options"] == override_opts

    def test_merge_pool_kwargs(self) -> None:
        """Assert _merge_pool_kwargs works in the happy case"""
        retries = retry.Retry(total=100)
        p = PoolManager(retries=retries)
        merged = p._merge_pool_kwargs({"new_key": "value"})
        assert {"retries": retries, "new_key": "value"} == merged

    def test_merge_pool_kwargs_none(self) -> None:
        """Assert false-y values to _merge_pool_kwargs result in defaults"""
        p = PoolManager(retries=100)
        merged = p._merge_pool_kwargs({})
        assert p.connection_pool_kw == merged
        merged = p._merge_pool_kwargs(None)
        assert p.connection_pool_kw == merged

    def test_merge_pool_kwargs_remove_key(self) -> None:
        """Assert keys can be removed with _merge_pool_kwargs"""
        p = PoolManager(retries=100)
        merged = p._merge_pool_kwargs({"retries": None})
        assert "retries" not in merged

    def test_merge_pool_kwargs_invalid_key(self) -> None:
        """Assert removing invalid keys with _merge_pool_kwargs doesn't break"""
        p = PoolManager(retries=100)
        merged = p._merge_pool_kwargs({"invalid_key": None})
        assert p.connection_pool_kw == merged

    def test_pool_manager_no_url_absolute_form(self) -> None:
        """Valides we won't send a request with absolute form without a proxy"""
        p = PoolManager()
        assert p._proxy_requires_url_absolute_form(Url("http://example.com")) is False
        assert p._proxy_requires_url_absolute_form(Url("https://example.com")) is False

    @pytest.mark.parametrize(
        "input_blocksize,expected_blocksize",
        [
            (_DEFAULT_BLOCKSIZE, _DEFAULT_BLOCKSIZE),
            (None, _DEFAULT_BLOCKSIZE),
            (8192, 8192),
        ],
    )
    def test_poolmanager_blocksize(
        self, input_blocksize: int, expected_blocksize: int
    ) -> None:
        """Assert PoolManager sets blocksize properly"""
        p = PoolManager()

        pool_blocksize = p.connection_from_url(
            "http://example.com", {"blocksize": input_blocksize}
        )
        assert pool_blocksize.conn_kw["blocksize"] == expected_blocksize
        assert pool_blocksize._get_conn().blocksize == expected_blocksize

    @pytest.mark.parametrize(
        "url",
        [
            "[a::b%zone]",
            "[a::b%25zone]",
            "http://[a::b%zone]",
            "http://[a::b%25zone]",
        ],
    )
    @patch("urllib3.util.connection.create_connection")
    def test_e2e_connect_to_ipv6_scoped(
        self, create_connection: MagicMock, url: str
    ) -> None:
        """Checks that IPv6 scoped addresses are properly handled end-to-end.

        This is not strictly speaking a pool manager unit test - this test
        lives here in absence of a better code location for e2e/integration
        tests.
        """
        p = PoolManager()
        conn_pool = p.connection_from_url(url)
        conn = conn_pool._get_conn()
        conn.connect()

        assert create_connection.call_args[0][0] == ("a::b%zone", 80)

    @patch("urllib3.connection.ssl_wrap_socket")
    @patch("urllib3.util.connection.create_connection")
    def test_e2e_connect_to_ipv6_scoped_tls(
        self, create_connection: MagicMock, ssl_wrap_socket: MagicMock
    ) -> None:
        p = PoolManager()
        conn_pool = p.connection_from_url(
            "https://[a::b%zone]", pool_kwargs={"assert_hostname": False}
        )
        conn = conn_pool._get_conn()
        conn.connect()

        assert ssl_wrap_socket.call_args[1]["server_hostname"] == "a::b"

    def test_thread_safty(self) -> None:
        pool_manager = PoolManager(num_pools=2)

        # thread 1 gets a pool for host x
        pool_1 = pool_manager.connection_from_url("http://host_x:80/")

        # thread 2 gets a pool for host y
        pool_2 = pool_manager.connection_from_url("http://host_y:80/")

        # thread 3 gets a pool for host z
        pool_3 = pool_manager.connection_from_url("http://host_z:80")

        # None of the pools should be closed, since all of them are referenced.
        assert pool_1.pool is not None
        assert pool_2.pool is not None
        assert pool_3.pool is not None

        conn_queue = pool_1.pool
        assert conn_queue.qsize() > 0

        # thread 1 stops.
        del pool_1
        gc.collect()

        # Connection should be closed, because reference to pool_1 is gone.
        assert conn_queue.qsize() == 0

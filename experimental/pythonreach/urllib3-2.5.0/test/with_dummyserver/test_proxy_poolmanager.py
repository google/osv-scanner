from __future__ import annotations

import binascii
import contextlib
import hashlib
import ipaddress
import os.path
import pathlib
import shutil
import socket
import ssl
import tempfile
from test import LONG_TIMEOUT, SHORT_TIMEOUT, resolvesLocalhostFQDN, withPyOpenSSL
from test.conftest import ServerConfig

import pytest
import trustme

import urllib3.exceptions
from dummyserver.socketserver import DEFAULT_CA, HAS_IPV6, get_unreachable_address
from dummyserver.testcase import (
    HypercornDummyProxyTestCase,
    IPv6HypercornDummyProxyTestCase,
)
from urllib3 import HTTPResponse
from urllib3._collections import HTTPHeaderDict
from urllib3.connection import VerifiedHTTPSConnection
from urllib3.connectionpool import connection_from_url
from urllib3.exceptions import (
    ConnectTimeoutError,
    InsecureRequestWarning,
    MaxRetryError,
    ProxyError,
    ProxySchemeUnknown,
    ProxySchemeUnsupported,
    ReadTimeoutError,
    SSLError,
)
from urllib3.poolmanager import ProxyManager, proxy_from_url
from urllib3.util.ssl_ import create_urllib3_context
from urllib3.util.timeout import Timeout

from .. import TARPIT_HOST, requires_network


def assert_is_verified(pm: ProxyManager, *, proxy: bool, target: bool) -> None:
    pool = list(pm.pools._container.values())[-1]  # retrieve last pool entry
    connection = (
        pool.pool.queue[-1] if pool.pool is not None else None
    )  # retrieve last connection entry

    assert connection is not None
    assert connection.proxy_is_verified is proxy
    assert connection.is_verified is target


class TestHTTPProxyManager(HypercornDummyProxyTestCase):
    @classmethod
    def setup_class(cls) -> None:
        super().setup_class()
        cls.http_url = f"http://{cls.http_host}:{int(cls.http_port)}"
        cls.http_url_alt = f"http://{cls.http_host_alt}:{int(cls.http_port)}"
        cls.https_url = f"https://{cls.https_host}:{int(cls.https_port)}"
        cls.https_url_alt = f"https://{cls.https_host_alt}:{int(cls.https_port)}"
        cls.https_url_fqdn = f"https://{cls.https_host}.:{int(cls.https_port)}"
        cls.proxy_url = f"http://{cls.proxy_host}:{int(cls.proxy_port)}"
        cls.https_proxy_url = f"https://{cls.proxy_host}:{int(cls.https_proxy_port)}"

        # Generate another CA to test verification failure
        cls.certs_dir = tempfile.mkdtemp()
        bad_ca = trustme.CA()

        cls.bad_ca_path = os.path.join(cls.certs_dir, "ca_bad.pem")
        bad_ca.cert_pem.write_to_path(cls.bad_ca_path)

    @classmethod
    def teardown_class(cls) -> None:
        super().teardown_class()
        shutil.rmtree(cls.certs_dir)

    def test_basic_proxy(self) -> None:
        with proxy_from_url(self.proxy_url, ca_certs=DEFAULT_CA) as http:
            r = http.request("GET", f"{self.http_url}/")
            assert r.status == 200

            r = http.request("GET", f"{self.https_url}/")
            assert r.status == 200

    def test_https_proxy(self) -> None:
        with proxy_from_url(self.https_proxy_url, ca_certs=DEFAULT_CA) as https:
            r = https.request("GET", f"{self.https_url}/")
            assert r.status == 200

            r = https.request("GET", f"{self.http_url}/")
            assert r.status == 200

    def test_is_verified_http_proxy_to_http_target(self) -> None:
        with proxy_from_url(self.proxy_url, ca_certs=DEFAULT_CA) as http:
            r = http.request("GET", f"{self.http_url}/")
            assert r.status == 200
            assert_is_verified(http, proxy=False, target=False)

    def test_is_verified_http_proxy_to_https_target(self) -> None:
        with proxy_from_url(self.proxy_url, ca_certs=DEFAULT_CA) as http:
            r = http.request("GET", f"{self.https_url}/")
            assert r.status == 200
            assert_is_verified(http, proxy=False, target=True)

    def test_is_verified_https_proxy_to_http_target(self) -> None:
        with proxy_from_url(self.https_proxy_url, ca_certs=DEFAULT_CA) as https:
            r = https.request("GET", f"{self.http_url}/")
            assert r.status == 200
            assert_is_verified(https, proxy=True, target=False)

    def test_is_verified_https_proxy_to_https_target(self) -> None:
        with proxy_from_url(self.https_proxy_url, ca_certs=DEFAULT_CA) as https:
            r = https.request("GET", f"{self.https_url}/")
            assert r.status == 200
            assert_is_verified(https, proxy=True, target=True)

    def test_http_and_https_kwarg_ca_cert_data_proxy(self) -> None:
        with open(DEFAULT_CA) as pem_file:
            pem_file_data = pem_file.read()
        with proxy_from_url(self.https_proxy_url, ca_cert_data=pem_file_data) as https:
            r = https.request("GET", f"{self.https_url}/")
            assert r.status == 200

            r = https.request("GET", f"{self.http_url}/")
            assert r.status == 200

    def test_https_proxy_with_proxy_ssl_context(self) -> None:
        proxy_ssl_context = create_urllib3_context()
        proxy_ssl_context.load_verify_locations(DEFAULT_CA)
        with proxy_from_url(
            self.https_proxy_url,
            proxy_ssl_context=proxy_ssl_context,
            ca_certs=DEFAULT_CA,
        ) as https:
            r = https.request("GET", f"{self.https_url}/")
            assert r.status == 200

            r = https.request("GET", f"{self.http_url}/")
            assert r.status == 200

    @withPyOpenSSL
    def test_https_proxy_pyopenssl_not_supported(self) -> None:
        with proxy_from_url(self.https_proxy_url, ca_certs=DEFAULT_CA) as https:
            r = https.request("GET", f"{self.http_url}/")
            assert r.status == 200

            with pytest.raises(
                ProxySchemeUnsupported, match="isn't available on non-native SSLContext"
            ):
                https.request("GET", f"{self.https_url}/")

    def test_https_proxy_forwarding_for_https(self) -> None:
        with proxy_from_url(
            self.https_proxy_url,
            ca_certs=DEFAULT_CA,
            use_forwarding_for_https=True,
        ) as https:
            r = https.request("GET", f"{self.http_url}/")
            assert r.status == 200

            r = https.request("GET", f"{self.https_url}/")
            assert r.status == 200

    def test_nagle_proxy(self) -> None:
        """Test that proxy connections do not have TCP_NODELAY turned on"""
        with ProxyManager(self.proxy_url) as http:
            hc2 = http.connection_from_host(self.http_host, self.http_port)
            conn = hc2._get_conn()
            try:
                hc2._make_request(conn, "GET", f"{self.http_url}/")
                tcp_nodelay_setting = conn.sock.getsockopt(  # type: ignore[attr-defined]
                    socket.IPPROTO_TCP, socket.TCP_NODELAY
                )
                assert tcp_nodelay_setting == 0, (
                    "Expected TCP_NODELAY for proxies to be set "
                    "to zero, instead was %s" % tcp_nodelay_setting
                )
            finally:
                conn.close()

    @pytest.mark.parametrize("proxy_scheme", ["http", "https"])
    @pytest.mark.parametrize("target_scheme", ["http", "https"])
    def test_proxy_conn_fail_from_dns(
        self, proxy_scheme: str, target_scheme: str
    ) -> None:
        host, port = get_unreachable_address()
        with proxy_from_url(
            f"{proxy_scheme}://{host}:{port}/", retries=1, timeout=LONG_TIMEOUT
        ) as http:
            if target_scheme == "https":
                target_url = self.https_url
            else:
                target_url = self.http_url

            with pytest.raises(MaxRetryError) as e:
                http.request("GET", f"{target_url}/")
            assert isinstance(e.value.reason, ProxyError)
            assert isinstance(
                e.value.reason.original_error, urllib3.exceptions.NameResolutionError
            )

    def test_oldapi(self) -> None:
        with ProxyManager(
            connection_from_url(self.proxy_url), ca_certs=DEFAULT_CA  # type: ignore[arg-type]
        ) as http:
            r = http.request("GET", f"{self.http_url}/")
            assert r.status == 200

            r = http.request("GET", f"{self.https_url}/")
            assert r.status == 200

    @resolvesLocalhostFQDN()
    def test_proxy_https_fqdn(self) -> None:
        with proxy_from_url(self.proxy_url, ca_certs=DEFAULT_CA) as http:
            r = http.request("GET", f"{self.https_url_fqdn}/")
            assert r.status == 200

    def test_proxy_verified(self) -> None:
        with proxy_from_url(
            self.proxy_url, cert_reqs="REQUIRED", ca_certs=self.bad_ca_path
        ) as http:
            with http._new_pool(
                "https", self.https_host, self.https_port
            ) as https_pool:
                with pytest.raises(MaxRetryError) as e:
                    https_pool.request("GET", "/", retries=0)
            assert isinstance(e.value.reason, SSLError)
            assert (
                "certificate verify failed" in str(e.value.reason)
                # PyPy is more specific
                or "self signed certificate in certificate chain" in str(e.value.reason)
            ), f"Expected 'certificate verify failed', instead got: {e.value.reason!r}"

            http = proxy_from_url(
                self.proxy_url, cert_reqs="REQUIRED", ca_certs=DEFAULT_CA
            )
            with http._new_pool(
                "https", self.https_host, self.https_port
            ) as https_pool2:
                with contextlib.closing(https_pool._new_conn()) as conn:
                    assert conn.__class__ == VerifiedHTTPSConnection
                    https_pool2.request(
                        "GET", "/"
                    )  # Should succeed without exceptions.

            http = proxy_from_url(
                self.proxy_url, cert_reqs="REQUIRED", ca_certs=DEFAULT_CA
            )
            with http._new_pool(
                "https", "127.0.0.1", self.https_port
            ) as https_fail_pool:
                with pytest.raises(
                    MaxRetryError, match="doesn't match|IP address mismatch"
                ) as e:
                    https_fail_pool.request("GET", "/", retries=0)
                assert isinstance(e.value.reason, SSLError)

    def test_redirect(self) -> None:
        with proxy_from_url(self.proxy_url) as http:
            r = http.request(
                "GET",
                f"{self.http_url}/redirect",
                fields={"target": f"{self.http_url}/"},
                redirect=False,
            )

            assert r.status == 303

            r = http.request(
                "GET",
                f"{self.http_url}/redirect",
                fields={"target": f"{self.http_url}/"},
            )

            assert r.status == 200
            assert r.data == b"Dummy server!"

    def test_cross_host_redirect(self) -> None:
        with proxy_from_url(self.proxy_url) as http:
            cross_host_location = f"{self.http_url_alt}/echo?a=b"
            with pytest.raises(MaxRetryError):
                http.request(
                    "GET",
                    f"{self.http_url}/redirect",
                    fields={"target": cross_host_location},
                    retries=0,
                )

            r = http.request(
                "GET",
                f"{self.http_url}/redirect",
                fields={"target": f"{self.http_url_alt}/echo?a=b"},
                retries=1,
            )
            assert isinstance(r, HTTPResponse)
            assert r._pool is not None
            assert r._pool.host != self.http_host_alt

    def test_cross_protocol_redirect(self) -> None:
        with proxy_from_url(self.proxy_url, ca_certs=DEFAULT_CA) as http:
            cross_protocol_location = f"{self.https_url}/echo?a=b"
            with pytest.raises(MaxRetryError):
                http.request(
                    "GET",
                    f"{self.http_url}/redirect",
                    fields={"target": cross_protocol_location},
                    retries=0,
                )

            r = http.request(
                "GET",
                f"{self.http_url}/redirect",
                fields={"target": f"{self.https_url}/echo?a=b"},
                retries=1,
            )
            assert isinstance(r, HTTPResponse)
            assert r._pool is not None
            assert r._pool.host == self.https_host

    def test_headers(self) -> None:
        with proxy_from_url(
            self.proxy_url,
            headers={"Foo": "bar"},
            proxy_headers={"Hickory": "dickory"},
            ca_certs=DEFAULT_CA,
        ) as http:
            r = http.request_encode_url("GET", f"{self.http_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"
            assert returned_headers.get("Hickory") == "dickory"
            assert returned_headers.get("Host") == f"{self.http_host}:{self.http_port}"

            r = http.request_encode_url("GET", f"{self.http_url_alt}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"
            assert returned_headers.get("Hickory") == "dickory"
            assert (
                returned_headers.get("Host") == f"{self.http_host_alt}:{self.http_port}"
            )

            r = http.request_encode_url("GET", f"{self.https_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"
            assert returned_headers.get("Hickory") is None
            assert (
                returned_headers.get("Host") == f"{self.https_host}:{self.https_port}"
            )

            r = http.request_encode_body("POST", f"{self.http_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"
            assert returned_headers.get("Hickory") == "dickory"
            assert returned_headers.get("Host") == f"{self.http_host}:{self.http_port}"

            r = http.request_encode_url(
                "GET", f"{self.http_url}/headers", headers={"Baz": "quux"}
            )
            returned_headers = r.json()
            assert returned_headers.get("Foo") is None
            assert returned_headers.get("Baz") == "quux"
            assert returned_headers.get("Hickory") == "dickory"
            assert returned_headers.get("Host") == f"{self.http_host}:{self.http_port}"

            r = http.request_encode_url(
                "GET", f"{self.https_url}/headers", headers={"Baz": "quux"}
            )
            returned_headers = r.json()
            assert returned_headers.get("Foo") is None
            assert returned_headers.get("Baz") == "quux"
            assert returned_headers.get("Hickory") is None
            assert (
                returned_headers.get("Host") == f"{self.https_host}:{self.https_port}"
            )

            r = http.request_encode_body(
                "GET", f"{self.http_url}/headers", headers={"Baz": "quux"}
            )
            returned_headers = r.json()
            assert returned_headers.get("Foo") is None
            assert returned_headers.get("Baz") == "quux"
            assert returned_headers.get("Hickory") == "dickory"
            assert returned_headers.get("Host") == f"{self.http_host}:{self.http_port}"

            r = http.request_encode_body(
                "GET", f"{self.https_url}/headers", headers={"Baz": "quux"}
            )
            returned_headers = r.json()
            assert returned_headers.get("Foo") is None
            assert returned_headers.get("Baz") == "quux"
            assert returned_headers.get("Hickory") is None
            assert (
                returned_headers.get("Host") == f"{self.https_host}:{self.https_port}"
            )

    def test_https_headers(self) -> None:
        with proxy_from_url(
            self.https_proxy_url,
            headers={"Foo": "bar"},
            proxy_headers={"Hickory": "dickory"},
            ca_certs=DEFAULT_CA,
        ) as http:
            r = http.request_encode_url("GET", f"{self.http_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"
            assert returned_headers.get("Hickory") == "dickory"
            assert returned_headers.get("Host") == f"{self.http_host}:{self.http_port}"

            r = http.request_encode_url("GET", f"{self.http_url_alt}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"
            assert returned_headers.get("Hickory") == "dickory"
            assert (
                returned_headers.get("Host") == f"{self.http_host_alt}:{self.http_port}"
            )

            r = http.request_encode_body(
                "GET", f"{self.https_url}/headers", headers={"Baz": "quux"}
            )
            returned_headers = r.json()
            assert returned_headers.get("Foo") is None
            assert returned_headers.get("Baz") == "quux"
            assert returned_headers.get("Hickory") is None
            assert (
                returned_headers.get("Host") == f"{self.https_host}:{self.https_port}"
            )

    def test_https_headers_forwarding_for_https(self) -> None:
        with proxy_from_url(
            self.https_proxy_url,
            headers={"Foo": "bar"},
            proxy_headers={"Hickory": "dickory"},
            ca_certs=DEFAULT_CA,
            use_forwarding_for_https=True,
        ) as http:
            r = http.request_encode_url("GET", f"{self.https_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"
            assert returned_headers.get("Hickory") == "dickory"
            assert (
                returned_headers.get("Host") == f"{self.https_host}:{self.https_port}"
            )

    def test_headerdict(self) -> None:
        default_headers = HTTPHeaderDict(a="b")
        proxy_headers = HTTPHeaderDict()
        proxy_headers.add("foo", "bar")

        with proxy_from_url(
            self.proxy_url, headers=default_headers, proxy_headers=proxy_headers
        ) as http:
            request_headers = HTTPHeaderDict(baz="quux")
            r = http.request("GET", f"{self.http_url}/headers", headers=request_headers)
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"
            assert returned_headers.get("Baz") == "quux"

    def test_proxy_pooling(self) -> None:
        with proxy_from_url(self.proxy_url, cert_reqs="NONE") as http:
            for x in range(2):
                http.urlopen("GET", self.http_url)
            assert len(http.pools) == 1

            for x in range(2):
                http.urlopen("GET", self.http_url_alt)
            assert len(http.pools) == 1

            for x in range(2):
                with pytest.warns(InsecureRequestWarning):
                    http.urlopen("GET", self.https_url)
            assert len(http.pools) == 2

            for x in range(2):
                with pytest.warns(InsecureRequestWarning):
                    http.urlopen("GET", self.https_url_alt)
            assert len(http.pools) == 3

    def test_proxy_pooling_ext(self) -> None:
        with proxy_from_url(self.proxy_url) as http:
            hc1 = http.connection_from_url(self.http_url)
            hc2 = http.connection_from_host(self.http_host, self.http_port)
            hc3 = http.connection_from_url(self.http_url_alt)
            hc4 = http.connection_from_host(self.http_host_alt, self.http_port)
            assert hc1 == hc2
            assert hc2 == hc3
            assert hc3 == hc4

            sc1 = http.connection_from_url(self.https_url)
            sc2 = http.connection_from_host(
                self.https_host, self.https_port, scheme="https"
            )
            sc3 = http.connection_from_url(self.https_url_alt)
            sc4 = http.connection_from_host(
                self.https_host_alt, self.https_port, scheme="https"
            )
            assert sc1 == sc2
            assert sc2 != sc3
            assert sc3 == sc4

    @requires_network()
    @pytest.mark.parametrize(
        ["proxy_scheme", "target_scheme", "use_forwarding_for_https"],
        [
            ("http", "http", False),
            ("https", "http", False),
            # 'use_forwarding_for_https' is only valid for HTTPS+HTTPS.
            ("https", "https", True),
        ],
    )
    def test_forwarding_proxy_request_timeout(
        self, proxy_scheme: str, target_scheme: str, use_forwarding_for_https: bool
    ) -> None:
        proxy_url = self.https_proxy_url if proxy_scheme == "https" else self.proxy_url
        target_url = f"{target_scheme}://{TARPIT_HOST}"

        with proxy_from_url(
            proxy_url,
            ca_certs=DEFAULT_CA,
            use_forwarding_for_https=use_forwarding_for_https,
        ) as proxy:
            with pytest.raises(MaxRetryError) as e:
                timeout = Timeout(connect=LONG_TIMEOUT, read=SHORT_TIMEOUT)
                proxy.request("GET", target_url, timeout=timeout)

            # We sent the request to the proxy but didn't get any response
            # so we're not sure if that's being caused by the proxy or the
            # target so we put the blame on the target.
            assert isinstance(e.value.reason, ReadTimeoutError)

    @requires_network()
    @pytest.mark.parametrize(
        ["proxy_scheme", "target_scheme"], [("http", "https"), ("https", "https")]
    )
    def test_tunneling_proxy_request_timeout(
        self, proxy_scheme: str, target_scheme: str
    ) -> None:
        proxy_url = self.https_proxy_url if proxy_scheme == "https" else self.proxy_url
        target_url = f"{target_scheme}://{TARPIT_HOST}"

        with proxy_from_url(
            proxy_url,
            ca_certs=DEFAULT_CA,
        ) as proxy:
            with pytest.raises(MaxRetryError) as e:
                timeout = Timeout(connect=LONG_TIMEOUT, read=SHORT_TIMEOUT)
                proxy.request("GET", target_url, timeout=timeout)

            assert isinstance(e.value.reason, ReadTimeoutError)

    @requires_network()
    @pytest.mark.parametrize(
        ["proxy_scheme", "target_scheme", "use_forwarding_for_https"],
        [
            ("http", "http", False),
            ("https", "http", False),
            # 'use_forwarding_for_https' is only valid for HTTPS+HTTPS.
            ("https", "https", True),
        ],
    )
    def test_forwarding_proxy_connect_timeout(
        self, proxy_scheme: str, target_scheme: str, use_forwarding_for_https: bool
    ) -> None:
        proxy_url = f"{proxy_scheme}://{TARPIT_HOST}"
        target_url = self.https_url if target_scheme == "https" else self.http_url

        with proxy_from_url(
            proxy_url,
            ca_certs=DEFAULT_CA,
            timeout=SHORT_TIMEOUT,
            use_forwarding_for_https=use_forwarding_for_https,
        ) as proxy:
            with pytest.raises(MaxRetryError) as e:
                proxy.request("GET", target_url)

            assert isinstance(e.value.reason, ProxyError)
            assert isinstance(e.value.reason.original_error, ConnectTimeoutError)

    @requires_network()
    @pytest.mark.parametrize(
        ["proxy_scheme", "target_scheme"], [("http", "https"), ("https", "https")]
    )
    def test_tunneling_proxy_connect_timeout(
        self, proxy_scheme: str, target_scheme: str
    ) -> None:
        proxy_url = f"{proxy_scheme}://{TARPIT_HOST}"
        target_url = self.https_url if target_scheme == "https" else self.http_url

        with proxy_from_url(
            proxy_url, ca_certs=DEFAULT_CA, timeout=SHORT_TIMEOUT
        ) as proxy:
            with pytest.raises(MaxRetryError) as e:
                proxy.request("GET", target_url)

            assert isinstance(e.value.reason, ProxyError)
            assert isinstance(e.value.reason.original_error, ConnectTimeoutError)

    @requires_network()
    @pytest.mark.parametrize(
        ["target_scheme", "use_forwarding_for_https"],
        [
            ("http", False),
            ("https", False),
            ("https", True),
        ],
    )
    def test_https_proxy_tls_error(
        self, target_scheme: str, use_forwarding_for_https: str
    ) -> None:
        target_url = self.https_url if target_scheme == "https" else self.http_url
        proxy_ctx = ssl.create_default_context()
        with proxy_from_url(
            self.https_proxy_url,
            proxy_ssl_context=proxy_ctx,
            use_forwarding_for_https=use_forwarding_for_https,
        ) as proxy:
            with pytest.raises(MaxRetryError) as e:
                proxy.request("GET", target_url)
            assert isinstance(e.value.reason, ProxyError)
            assert isinstance(e.value.reason.original_error, SSLError)

    @requires_network()
    @pytest.mark.parametrize(
        ["proxy_scheme", "use_forwarding_for_https"],
        [
            ("http", False),
            ("https", False),
            ("https", True),
        ],
    )
    def test_proxy_https_target_tls_error(
        self, proxy_scheme: str, use_forwarding_for_https: str
    ) -> None:
        if proxy_scheme == "https" and use_forwarding_for_https:
            pytest.skip("Test is expected to fail due to urllib3/urllib3#2577")

        proxy_url = self.https_proxy_url if proxy_scheme == "https" else self.proxy_url
        proxy_ctx = ssl.create_default_context()
        proxy_ctx.load_verify_locations(DEFAULT_CA)
        ctx = ssl.create_default_context()

        with proxy_from_url(
            proxy_url,
            proxy_ssl_context=proxy_ctx,
            ssl_context=ctx,
            use_forwarding_for_https=use_forwarding_for_https,
        ) as proxy:
            with pytest.raises(MaxRetryError) as e:
                proxy.request("GET", self.https_url)
            assert isinstance(e.value.reason, SSLError)

    def test_scheme_host_case_insensitive(self) -> None:
        """Assert that upper-case schemes and hosts are normalized."""
        with proxy_from_url(self.proxy_url.upper(), ca_certs=DEFAULT_CA) as http:
            r = http.request("GET", f"{self.http_url.upper()}/")
            assert r.status == 200

            r = http.request("GET", f"{self.https_url.upper()}/")
            assert r.status == 200

    @pytest.mark.parametrize(
        "url, error_msg",
        [
            (
                "127.0.0.1",
                "Proxy URL had no scheme, should start with http:// or https://",
            ),
            (
                "localhost:8080",
                "Proxy URL had no scheme, should start with http:// or https://",
            ),
            (
                "ftp://google.com",
                "Proxy URL had unsupported scheme ftp, should use http:// or https://",
            ),
        ],
    )
    def test_invalid_schema(self, url: str, error_msg: str) -> None:
        with pytest.raises(ProxySchemeUnknown, match=error_msg):
            proxy_from_url(url)


@pytest.mark.skipif(not HAS_IPV6, reason="Only runs on IPv6 systems")
class TestIPv6HTTPProxyManager(IPv6HypercornDummyProxyTestCase):
    @classmethod
    def setup_class(cls) -> None:
        super().setup_class()
        cls.http_url = f"http://{cls.http_host}:{int(cls.http_port)}"
        cls.http_url_alt = f"http://{cls.http_host_alt}:{int(cls.http_port)}"
        cls.https_url = f"https://{cls.https_host}:{int(cls.https_port)}"
        cls.https_url_alt = f"https://{cls.https_host_alt}:{int(cls.https_port)}"
        cls.proxy_url = f"http://[{cls.proxy_host}]:{int(cls.proxy_port)}"

    def test_basic_ipv6_proxy(self) -> None:
        with proxy_from_url(self.proxy_url, ca_certs=DEFAULT_CA) as http:
            r = http.request("GET", f"{self.http_url}/")
            assert r.status == 200

            r = http.request("GET", f"{self.https_url}/")
            assert r.status == 200


class TestHTTPSProxyVerification:
    @staticmethod
    def _get_proxy_fingerprint_md5(ca_path: str) -> str:
        proxy_pem_path = pathlib.Path(ca_path).parent / "proxy.pem"
        proxy_der = ssl.PEM_cert_to_DER_cert(proxy_pem_path.read_text())
        proxy_hashed = hashlib.md5(proxy_der).digest()
        fingerprint = binascii.hexlify(proxy_hashed).decode("ascii")
        return fingerprint

    @staticmethod
    def _get_certificate_formatted_proxy_host(host: str) -> str:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return host

        if addr.version != 6:
            return host

        # Transform ipv6 like '::1' to 0:0:0:0:0:0:0:1 via '0000:0000:0000:0000:0000:0000:0000:0001'
        return addr.exploded.replace("0000", "0").replace("000", "")

    def test_https_proxy_assert_fingerprint_md5(
        self, no_san_proxy_with_server: tuple[ServerConfig, ServerConfig]
    ) -> None:
        proxy, server = no_san_proxy_with_server
        proxy_url = f"https://{proxy.host}:{proxy.port}"
        destination_url = f"https://{server.host}:{server.port}"

        proxy_ctx = urllib3.util.ssl_.create_urllib3_context(verify_flags=0)
        proxy_fingerprint = self._get_proxy_fingerprint_md5(proxy.ca_certs)
        with proxy_from_url(
            proxy_url,
            ca_certs=proxy.ca_certs,
            proxy_ssl_context=proxy_ctx,
            proxy_assert_fingerprint=proxy_fingerprint,
        ) as https:
            https.request("GET", destination_url)

    def test_https_proxy_assert_fingerprint_md5_non_matching(
        self, no_san_proxy_with_server: tuple[ServerConfig, ServerConfig]
    ) -> None:
        proxy, server = no_san_proxy_with_server
        proxy_url = f"https://{proxy.host}:{proxy.port}"
        destination_url = f"https://{server.host}:{server.port}"

        proxy_ctx = urllib3.util.ssl_.create_urllib3_context(verify_flags=0)
        proxy_fingerprint = self._get_proxy_fingerprint_md5(proxy.ca_certs)
        new_char = "b" if proxy_fingerprint[5] == "a" else "a"
        proxy_fingerprint = proxy_fingerprint[:5] + new_char + proxy_fingerprint[6:]

        with proxy_from_url(
            proxy_url,
            ca_certs=proxy.ca_certs,
            proxy_ssl_context=proxy_ctx,
            proxy_assert_fingerprint=proxy_fingerprint,
        ) as https:
            with pytest.raises(MaxRetryError) as e:
                https.request("GET", destination_url)

            assert "Fingerprints did not match" in str(e)

    def test_https_proxy_assert_hostname(
        self, san_proxy_with_server: tuple[ServerConfig, ServerConfig]
    ) -> None:
        proxy, server = san_proxy_with_server
        destination_url = f"https://{server.host}:{server.port}"

        with proxy_from_url(
            proxy.base_url, ca_certs=proxy.ca_certs, proxy_assert_hostname=proxy.host
        ) as https:
            https.request("GET", destination_url)

    def test_https_proxy_assert_hostname_non_matching(
        self, san_proxy_with_server: tuple[ServerConfig, ServerConfig]
    ) -> None:
        proxy, server = san_proxy_with_server
        destination_url = f"https://{server.host}:{server.port}"

        proxy_hostname = "example.com"
        with proxy_from_url(
            proxy.base_url,
            ca_certs=proxy.ca_certs,
            proxy_assert_hostname=proxy_hostname,
        ) as https:
            with pytest.raises(MaxRetryError) as e:
                https.request("GET", destination_url)

            proxy_host = self._get_certificate_formatted_proxy_host(proxy.host)
            msg = f"hostname \\'{proxy_hostname}\\' doesn\\'t match \\'{proxy_host}\\'"
            assert msg in str(e)

    def test_https_proxy_hostname_verification(
        self, no_localhost_san_server: ServerConfig
    ) -> None:
        bad_server = no_localhost_san_server
        bad_proxy_url = f"https://{bad_server.host}:{bad_server.port}"

        # An exception will be raised before we contact the destination domain.
        test_url = "testing.com"
        with proxy_from_url(bad_proxy_url, ca_certs=bad_server.ca_certs) as https:
            with pytest.raises(MaxRetryError) as e:
                https.request("GET", "http://%s/" % test_url)
            assert isinstance(e.value.reason, ProxyError)

            ssl_error = e.value.reason.original_error
            assert isinstance(ssl_error, SSLError)
            assert "hostname 'localhost' doesn't match" in str(
                ssl_error
            ) or "Hostname mismatch" in str(ssl_error)

            with pytest.raises(MaxRetryError) as e:
                https.request("GET", "https://%s/" % test_url)
            assert isinstance(e.value.reason, ProxyError)

            ssl_error = e.value.reason.original_error
            assert isinstance(ssl_error, SSLError)
            assert "hostname 'localhost' doesn't match" in str(
                ssl_error
            ) or "Hostname mismatch" in str(ssl_error)

    def test_https_proxy_ipv4_san(
        self, ipv4_san_proxy_with_server: tuple[ServerConfig, ServerConfig]
    ) -> None:
        proxy, server = ipv4_san_proxy_with_server
        proxy_url = f"https://{proxy.host}:{proxy.port}"
        destination_url = f"https://{server.host}:{server.port}"
        with proxy_from_url(proxy_url, ca_certs=proxy.ca_certs) as https:
            r = https.request("GET", destination_url)
            assert r.status == 200

    def test_https_proxy_ipv6_san(
        self, ipv6_san_proxy_with_server: tuple[ServerConfig, ServerConfig]
    ) -> None:
        proxy, server = ipv6_san_proxy_with_server
        proxy_url = f"https://[{proxy.host}]:{proxy.port}"
        destination_url = f"https://{server.host}:{server.port}"
        with proxy_from_url(proxy_url, ca_certs=proxy.ca_certs) as https:
            r = https.request("GET", destination_url)
            assert r.status == 200

    @pytest.mark.parametrize("target_scheme", ["http", "https"])
    def test_https_proxy_no_san(
        self,
        no_san_proxy_with_server: tuple[ServerConfig, ServerConfig],
        target_scheme: str,
    ) -> None:
        proxy, server = no_san_proxy_with_server
        proxy_url = f"https://{proxy.host}:{proxy.port}"
        destination_url = f"{target_scheme}://{server.host}:{server.port}"

        with proxy_from_url(proxy_url, ca_certs=proxy.ca_certs) as https:
            with pytest.raises(MaxRetryError) as e:
                https.request("GET", destination_url)
            assert isinstance(e.value.reason, ProxyError)

            ssl_error = e.value.reason.original_error
            assert isinstance(ssl_error, SSLError)
            assert (
                "no appropriate subjectAltName fields were found" in str(ssl_error)
                or "Hostname mismatch, certificate is not valid for 'localhost'"
                in str(ssl_error)
                or "Empty Subject Alternative Name extension" in str(ssl_error)
            )

    def test_https_proxy_no_san_hostname_checks_common_name(
        self, no_san_proxy_with_server: tuple[ServerConfig, ServerConfig]
    ) -> None:
        proxy, server = no_san_proxy_with_server
        proxy_url = f"https://{proxy.host}:{proxy.port}"
        destination_url = f"https://{server.host}:{server.port}"

        proxy_ctx = urllib3.util.ssl_.create_urllib3_context(verify_flags=0)
        try:
            proxy_ctx.hostname_checks_common_name = True
        # PyPy doesn't like us setting 'hostname_checks_common_name'
        # but also has it enabled by default so we need to handle that.
        except AttributeError:
            pass
        if getattr(proxy_ctx, "hostname_checks_common_name", False) is not True:
            pytest.skip("Test requires 'SSLContext.hostname_checks_common_name=True'")

        with proxy_from_url(
            proxy_url, ca_certs=proxy.ca_certs, proxy_ssl_context=proxy_ctx
        ) as https:
            https.request("GET", destination_url)

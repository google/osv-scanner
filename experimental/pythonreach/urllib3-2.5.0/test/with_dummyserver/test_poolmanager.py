from __future__ import annotations

import gzip
import typing
from test import LONG_TIMEOUT
from unittest import mock

import pytest

from dummyserver.socketserver import HAS_IPV6
from dummyserver.testcase import (
    HypercornDummyServerTestCase,
    IPv6HypercornDummyServerTestCase,
)
from urllib3 import HTTPHeaderDict, HTTPResponse, request
from urllib3.connectionpool import port_by_scheme
from urllib3.exceptions import MaxRetryError, URLSchemeUnknown
from urllib3.poolmanager import PoolManager
from urllib3.util.retry import Retry


class TestPoolManager(HypercornDummyServerTestCase):
    @classmethod
    def setup_class(cls) -> None:
        super().setup_class()
        cls.base_url = f"http://{cls.host}:{cls.port}"
        cls.base_url_alt = f"http://{cls.host_alt}:{cls.port}"

    def test_redirect(self) -> None:
        with PoolManager() as http:
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url}/"},
                redirect=False,
            )

            assert r.status == 303

            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url}/"},
            )

            assert r.status == 200
            assert r.data == b"Dummy server!"

    def test_redirect_twice(self) -> None:
        with PoolManager() as http:
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url}/redirect"},
                redirect=False,
            )

            assert r.status == 303

            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url}/redirect?target={self.base_url}/"},
            )

            assert r.status == 200
            assert r.data == b"Dummy server!"

    def test_redirect_to_relative_url(self) -> None:
        with PoolManager() as http:
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": "/redirect"},
                redirect=False,
            )

            assert r.status == 303

            r = http.request(
                "GET", f"{self.base_url}/redirect", fields={"target": "/redirect"}
            )

            assert r.status == 200
            assert r.data == b"Dummy server!"

    @pytest.mark.parametrize(
        "retries",
        (0, Retry(total=0), Retry(redirect=0), Retry(total=0, redirect=0)),
    )
    def test_redirects_disabled_for_pool_manager_with_0(
        self, retries: typing.Literal[0] | Retry
    ) -> None:
        """
        Check handling redirects when retries is set to 0 on the pool
        manager.
        """
        with PoolManager(retries=retries) as http:
            with pytest.raises(MaxRetryError):
                http.request("GET", f"{self.base_url}/redirect")

            # Setting redirect=True should not change the behavior.
            with pytest.raises(MaxRetryError):
                http.request("GET", f"{self.base_url}/redirect", redirect=True)

            # Setting redirect=False should not make it follow the redirect,
            # but MaxRetryError should not be raised.
            response = http.request("GET", f"{self.base_url}/redirect", redirect=False)
            assert response.status == 303

    @pytest.mark.parametrize(
        "retries",
        (
            False,
            Retry(total=False),
            Retry(redirect=False),
            Retry(total=False, redirect=False),
        ),
    )
    def test_redirects_disabled_for_pool_manager_with_false(
        self, retries: typing.Literal[False] | Retry
    ) -> None:
        """
        Check that setting retries set to False on the pool manager disables
        raising MaxRetryError and redirect=True does not change the
        behavior.
        """
        with PoolManager(retries=retries) as http:
            response = http.request("GET", f"{self.base_url}/redirect")
            assert response.status == 303

            response = http.request("GET", f"{self.base_url}/redirect", redirect=True)
            assert response.status == 303

            response = http.request("GET", f"{self.base_url}/redirect", redirect=False)
            assert response.status == 303

    def test_redirects_disabled_for_individual_request(self) -> None:
        """
        Check handling redirects when they are meant to be disabled
        on the request level.
        """
        with PoolManager() as http:
            # Check when redirect is not passed.
            with pytest.raises(MaxRetryError):
                http.request("GET", f"{self.base_url}/redirect", retries=0)
            response = http.request("GET", f"{self.base_url}/redirect", retries=False)
            assert response.status == 303

            # Check when redirect=True.
            with pytest.raises(MaxRetryError):
                http.request(
                    "GET", f"{self.base_url}/redirect", retries=0, redirect=True
                )
            response = http.request(
                "GET", f"{self.base_url}/redirect", retries=False, redirect=True
            )
            assert response.status == 303

            # Check when redirect=False.
            response = http.request(
                "GET", f"{self.base_url}/redirect", retries=0, redirect=False
            )
            assert response.status == 303
            response = http.request(
                "GET", f"{self.base_url}/redirect", retries=False, redirect=False
            )
            assert response.status == 303

    def test_cross_host_redirect(self) -> None:
        with PoolManager() as http:
            cross_host_location = f"{self.base_url_alt}/echo?a=b"
            with pytest.raises(MaxRetryError):
                http.request(
                    "GET",
                    f"{self.base_url}/redirect",
                    fields={"target": cross_host_location},
                    timeout=LONG_TIMEOUT,
                    retries=0,
                )

            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url_alt}/echo?a=b"},
                timeout=LONG_TIMEOUT,
                retries=1,
            )

            assert isinstance(r, HTTPResponse)
            assert r._pool is not None
            assert r._pool.host == self.host_alt

    def test_too_many_redirects(self) -> None:
        with PoolManager() as http:
            with pytest.raises(MaxRetryError):
                http.request(
                    "GET",
                    f"{self.base_url}/redirect",
                    fields={
                        "target": f"{self.base_url}/redirect?target={self.base_url}/"
                    },
                    retries=1,
                    preload_content=False,
                )

            with pytest.raises(MaxRetryError):
                http.request(
                    "GET",
                    f"{self.base_url}/redirect",
                    fields={
                        "target": f"{self.base_url}/redirect?target={self.base_url}/"
                    },
                    retries=Retry(total=None, redirect=1),
                    preload_content=False,
                )

            # Even with preload_content=False and raise on redirects, we reused the same
            # connection
            assert len(http.pools) == 1
            pool = http.connection_from_host(self.host, self.port)
            assert pool.num_connections == 1

        # Check when retries are configured for the pool manager.
        with PoolManager(retries=1) as http:
            with pytest.raises(MaxRetryError):
                http.request(
                    "GET",
                    f"{self.base_url}/redirect",
                    fields={"target": f"/redirect?target={self.base_url}/"},
                )

            # Here we allow more retries for the request.
            response = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"/redirect?target={self.base_url}/"},
                retries=2,
            )
            assert response.status == 200

    def test_redirect_cross_host_remove_headers(self) -> None:
        with PoolManager() as http:
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url_alt}/headers"},
                headers={
                    "Authorization": "foo",
                    "Proxy-Authorization": "bar",
                    "Cookie": "foo=bar",
                },
            )

            assert r.status == 200

            data = r.json()

            assert "Authorization" not in data
            assert "Proxy-Authorization" not in data
            assert "Cookie" not in data

            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url_alt}/headers"},
                headers={
                    "authorization": "foo",
                    "proxy-authorization": "baz",
                    "cookie": "foo=bar",
                },
            )

            assert r.status == 200

            data = r.json()

            assert "authorization" not in data
            assert "Authorization" not in data
            assert "proxy-authorization" not in data
            assert "Proxy-Authorization" not in data
            assert "cookie" not in data
            assert "Cookie" not in data

    def test_redirect_cross_host_no_remove_headers(self) -> None:
        with PoolManager() as http:
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url_alt}/headers"},
                headers={
                    "Authorization": "foo",
                    "Proxy-Authorization": "bar",
                    "Cookie": "foo=bar",
                },
                retries=Retry(remove_headers_on_redirect=[]),
            )

            assert r.status == 200

            data = r.json()

            assert data["Authorization"] == "foo"
            assert data["Proxy-Authorization"] == "bar"
            assert data["Cookie"] == "foo=bar"

    def test_redirect_cross_host_set_removed_headers(self) -> None:
        with PoolManager() as http:
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url_alt}/headers"},
                headers={
                    "X-API-Secret": "foo",
                    "Authorization": "bar",
                    "Proxy-Authorization": "baz",
                    "Cookie": "foo=bar",
                },
                retries=Retry(remove_headers_on_redirect=["X-API-Secret"]),
            )

            assert r.status == 200

            data = r.json()

            assert "X-API-Secret" not in data
            assert data["Authorization"] == "bar"
            assert data["Proxy-Authorization"] == "baz"
            assert data["Cookie"] == "foo=bar"

            headers = {
                "x-api-secret": "foo",
                "authorization": "bar",
                "proxy-authorization": "baz",
                "cookie": "foo=bar",
            }
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url_alt}/headers"},
                headers=headers,
                retries=Retry(remove_headers_on_redirect=["X-API-Secret"]),
            )

            assert r.status == 200

            data = r.json()

            assert "x-api-secret" not in data
            assert "X-API-Secret" not in data
            assert data["Authorization"] == "bar"
            assert data["Proxy-Authorization"] == "baz"
            assert data["Cookie"] == "foo=bar"

            # Ensure the header argument itself is not modified in-place.
            assert headers == {
                "x-api-secret": "foo",
                "authorization": "bar",
                "proxy-authorization": "baz",
                "cookie": "foo=bar",
            }

    def test_redirect_without_preload_releases_connection(self) -> None:
        with PoolManager(block=True, maxsize=2) as http:
            r = http.request("GET", f"{self.base_url}/redirect", preload_content=False)
            assert isinstance(r, HTTPResponse)
            assert r._pool is not None
            assert r._pool.num_requests == 2
            assert r._pool.num_connections == 1
            assert len(http.pools) == 1

    def test_303_redirect_makes_request_lose_body(self) -> None:
        with PoolManager() as http:
            response = http.request(
                "POST",
                f"{self.base_url}/redirect",
                fields={
                    "target": f"{self.base_url}/headers_and_params",
                    "status": "303 See Other",
                },
            )
        data = response.json()
        assert data["params"] == {}
        assert "Content-Type" not in HTTPHeaderDict(data["headers"])

    def test_unknown_scheme(self) -> None:
        with PoolManager() as http:
            unknown_scheme = "unknown"
            unknown_scheme_url = f"{unknown_scheme}://host"
            with pytest.raises(URLSchemeUnknown) as e:
                r = http.request("GET", unknown_scheme_url)
            assert e.value.scheme == unknown_scheme
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": unknown_scheme_url},
                redirect=False,
            )
            assert r.status == 303
            assert r.headers.get("Location") == unknown_scheme_url
            with pytest.raises(URLSchemeUnknown) as e:
                r = http.request(
                    "GET",
                    f"{self.base_url}/redirect",
                    fields={"target": unknown_scheme_url},
                )
            assert e.value.scheme == unknown_scheme

    def test_raise_on_redirect(self) -> None:
        with PoolManager() as http:
            r = http.request(
                "GET",
                f"{self.base_url}/redirect",
                fields={"target": f"{self.base_url}/redirect?target={self.base_url}/"},
                retries=Retry(total=None, redirect=1, raise_on_redirect=False),
            )

            assert r.status == 303

    def test_raise_on_status(self) -> None:
        with PoolManager() as http:
            with pytest.raises(MaxRetryError):
                # the default is to raise
                r = http.request(
                    "GET",
                    f"{self.base_url}/status",
                    fields={"status": "500 Internal Server Error"},
                    retries=Retry(total=1, status_forcelist=range(500, 600)),
                )

            with pytest.raises(MaxRetryError):
                # raise explicitly
                r = http.request(
                    "GET",
                    f"{self.base_url}/status",
                    fields={"status": "500 Internal Server Error"},
                    retries=Retry(
                        total=1, status_forcelist=range(500, 600), raise_on_status=True
                    ),
                )

            # don't raise
            r = http.request(
                "GET",
                f"{self.base_url}/status",
                fields={"status": "500 Internal Server Error"},
                retries=Retry(
                    total=1, status_forcelist=range(500, 600), raise_on_status=False
                ),
            )

            assert r.status == 500

    def test_missing_port(self) -> None:
        # Can a URL that lacks an explicit port like ':80' succeed, or
        # will all such URLs fail with an error?

        with PoolManager() as http:
            # By globally adjusting `port_by_scheme` we pretend for a moment
            # that HTTP's default port is not 80, but is the port at which
            # our test server happens to be listening.
            port_by_scheme["http"] = self.port
            try:
                r = http.request("GET", f"http://{self.host}/", retries=0)
            finally:
                port_by_scheme["http"] = 80

            assert r.status == 200
            assert r.data == b"Dummy server!"

    def test_headers(self) -> None:
        with PoolManager(headers={"Foo": "bar"}) as http:
            r = http.request("GET", f"{self.base_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"

            r = http.request("POST", f"{self.base_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"

            r = http.request_encode_url("GET", f"{self.base_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"

            r = http.request_encode_body("POST", f"{self.base_url}/headers")
            returned_headers = r.json()
            assert returned_headers.get("Foo") == "bar"

            r = http.request_encode_url(
                "GET", f"{self.base_url}/headers", headers={"Baz": "quux"}
            )
            returned_headers = r.json()
            assert returned_headers.get("Foo") is None
            assert returned_headers.get("Baz") == "quux"

            r = http.request_encode_body(
                "GET", f"{self.base_url}/headers", headers={"Baz": "quux"}
            )
            returned_headers = r.json()
            assert returned_headers.get("Foo") is None
            assert returned_headers.get("Baz") == "quux"

    def test_headers_http_header_dict(self) -> None:
        # Test uses a list of headers to assert the order
        # that headers are sent in the request too.

        headers = HTTPHeaderDict()
        headers.add("Foo", "bar")
        headers.add("Multi", "1")
        headers.add("Baz", "quux")
        headers.add("Multi", "2")

        with PoolManager(headers=headers) as http:
            r = http.request("GET", f"{self.base_url}/multi_headers")
            returned_headers = r.json()["headers"]
            assert returned_headers[-4:] == [
                ["Foo", "bar"],
                ["Multi", "1"],
                ["Multi", "2"],
                ["Baz", "quux"],
            ]

            r = http.request(
                "GET",
                f"{self.base_url}/multi_headers",
                headers={
                    **headers,
                    "Extra": "extra",
                    "Foo": "new",
                },
            )
            returned_headers = r.json()["headers"]
            assert returned_headers[-4:] == [
                ["Foo", "new"],
                ["Multi", "1, 2"],
                ["Baz", "quux"],
                ["Extra", "extra"],
            ]

    def test_merge_headers_with_pool_manager_headers(self) -> None:
        headers = HTTPHeaderDict()
        headers.add("Cookie", "choc-chip")
        headers.add("Cookie", "oatmeal-raisin")
        orig = headers.copy()
        added_headers = {"Cookie": "tim-tam"}

        with PoolManager(headers=headers) as http:
            r = http.request(
                "GET",
                f"{self.base_url}/multi_headers",
                headers=typing.cast(HTTPHeaderDict, http.headers) | added_headers,
            )
            returned_headers = r.json()["headers"]
            assert returned_headers[-3:] == [
                ["Cookie", "choc-chip"],
                ["Cookie", "oatmeal-raisin"],
                ["Cookie", "tim-tam"],
            ]
            # make sure the pool headers weren't modified
            assert http.headers == orig

    def test_headers_http_multi_header_multipart(self) -> None:
        headers = HTTPHeaderDict()
        headers.add("Multi", "1")
        headers.add("Multi", "2")
        old_headers = headers.copy()

        with PoolManager(headers=headers) as http:
            r = http.request(
                "POST",
                f"{self.base_url}/multi_headers",
                fields={"k": "v"},
                multipart_boundary="b",
                encode_multipart=True,
            )
            returned_headers = r.json()["headers"]
            assert returned_headers[5:] == [
                ["Multi", "1"],
                ["Multi", "2"],
                ["Content-Type", "multipart/form-data; boundary=b"],
            ]
            # Assert that the previous headers weren't modified.
            assert headers == old_headers

            # Set a default value for the Content-Type
            headers["Content-Type"] = "multipart/form-data; boundary=b; field=value"
            r = http.request(
                "POST",
                f"{self.base_url}/multi_headers",
                fields={"k": "v"},
                multipart_boundary="b",
                encode_multipart=True,
            )
            returned_headers = r.json()["headers"]
            assert returned_headers[5:] == [
                ["Multi", "1"],
                ["Multi", "2"],
                # Uses the set value, not the one that would be generated.
                ["Content-Type", "multipart/form-data; boundary=b; field=value"],
            ]

    def test_body(self) -> None:
        with PoolManager() as http:
            r = http.request("POST", f"{self.base_url}/echo", body=b"test")
            assert r.data == b"test"

    def test_http_with_ssl_keywords(self) -> None:
        with PoolManager(ca_certs="REQUIRED") as http:
            r = http.request("GET", f"http://{self.host}:{self.port}/")
            assert r.status == 200

    def test_http_with_server_hostname(self) -> None:
        with PoolManager(server_hostname="example.com") as http:
            r = http.request("GET", f"http://{self.host}:{self.port}/")
            assert r.status == 200

    def test_http_with_ca_cert_dir(self) -> None:
        with PoolManager(ca_certs="REQUIRED", ca_cert_dir="/nosuchdir") as http:
            r = http.request("GET", f"http://{self.host}:{self.port}/")
            assert r.status == 200

    @pytest.mark.parametrize(
        ["target", "expected_target"],
        [
            # annoyingly quart.request.full_path adds a stray `?`
            ("/echo_uri", b"/echo_uri?"),
            ("/echo_uri?q=1#fragment", b"/echo_uri?q=1"),
            ("/echo_uri?#", b"/echo_uri?"),
            ("/echo_uri#!", b"/echo_uri?"),
            ("/echo_uri#!#", b"/echo_uri?"),
            ("/echo_uri??#", b"/echo_uri??"),
            ("/echo_uri?%3f#", b"/echo_uri?%3F"),
            ("/echo_uri?%3F#", b"/echo_uri?%3F"),
            ("/echo_uri?[]", b"/echo_uri?%5B%5D"),
        ],
    )
    def test_encode_http_target(self, target: str, expected_target: bytes) -> None:
        with PoolManager() as http:
            url = f"http://{self.host}:{self.port}{target}"
            r = http.request("GET", url)
            assert r.data == expected_target

    def test_top_level_request(self) -> None:
        r = request("GET", f"{self.base_url}/")
        assert r.status == 200
        assert r.data == b"Dummy server!"

    def test_top_level_request_without_keyword_args(self) -> None:
        body = ""
        with pytest.raises(TypeError):
            request("GET", f"{self.base_url}/", body)  # type: ignore[misc]

    def test_top_level_request_with_body(self) -> None:
        r = request("POST", f"{self.base_url}/echo", body=b"test")
        assert r.status == 200
        assert r.data == b"test"

    def test_top_level_request_with_preload_content(self) -> None:
        r = request("GET", f"{self.base_url}/echo", preload_content=False)
        assert r.status == 200
        assert r.connection is not None
        r.data
        assert r.connection is None

    def test_top_level_request_with_decode_content(self) -> None:
        r = request(
            "GET",
            f"{self.base_url}/encodingrequest",
            headers={"accept-encoding": "gzip"},
            decode_content=False,
        )
        assert r.status == 200
        assert gzip.decompress(r.data) == b"hello, world!"

        r = request(
            "GET",
            f"{self.base_url}/encodingrequest",
            headers={"accept-encoding": "gzip"},
            decode_content=True,
        )
        assert r.status == 200
        assert r.data == b"hello, world!"

    def test_top_level_request_with_redirect(self) -> None:
        r = request(
            "GET",
            f"{self.base_url}/redirect",
            fields={"target": f"{self.base_url}/"},
            redirect=False,
        )

        assert r.status == 303

        r = request(
            "GET",
            f"{self.base_url}/redirect",
            fields={"target": f"{self.base_url}/"},
            redirect=True,
        )

        assert r.status == 200
        assert r.data == b"Dummy server!"

    def test_top_level_request_with_retries(self) -> None:
        r = request("GET", f"{self.base_url}/redirect", retries=False)
        assert r.status == 303

        r = request("GET", f"{self.base_url}/redirect", retries=3)
        assert r.status == 200

    def test_top_level_request_with_timeout(self) -> None:
        with mock.patch("urllib3.poolmanager.RequestMethods.request") as mockRequest:
            mockRequest.return_value = HTTPResponse(status=200)

            r = request("GET", f"{self.base_url}/redirect", timeout=2.5)

            assert r.status == 200

            mockRequest.assert_called_with(
                "GET",
                f"{self.base_url}/redirect",
                body=None,
                fields=None,
                headers=None,
                preload_content=True,
                decode_content=True,
                redirect=True,
                retries=None,
                timeout=2.5,
                json=None,
            )

    @pytest.mark.parametrize(
        "headers",
        [
            None,
            {"content-Type": "application/json"},
            {"content-Type": "text/plain"},
            {"attribute": "value", "CONTENT-TYPE": "application/json"},
            HTTPHeaderDict(cookie="foo, bar"),
        ],
    )
    def test_request_with_json(self, headers: HTTPHeaderDict) -> None:
        old_headers = None if headers is None else headers.copy()
        body = {"attribute": "value"}
        r = request(
            method="POST", url=f"{self.base_url}/echo_json", headers=headers, json=body
        )
        assert r.status == 200
        assert r.json() == body
        content_type = HTTPHeaderDict(old_headers).get(
            "Content-Type", "application/json"
        )
        assert content_type in r.headers["Content-Type"].replace(" ", "").split(",")

        # Ensure the header argument itself is not modified in-place.
        assert headers == old_headers

    def test_top_level_request_with_json_with_httpheaderdict(self) -> None:
        body = {"attribute": "value"}
        header = HTTPHeaderDict(cookie="foo, bar")
        with PoolManager(headers=header) as http:
            r = http.request(method="POST", url=f"{self.base_url}/echo_json", json=body)
            assert r.status == 200
            assert r.json() == body
            assert "application/json" in r.headers["Content-Type"].replace(
                " ", ""
            ).split(",")

    def test_top_level_request_with_body_and_json(self) -> None:
        match = "request got values for both 'body' and 'json' parameters which are mutually exclusive"
        with pytest.raises(TypeError, match=match):
            body = {"attribute": "value"}
            request(method="POST", url=f"{self.base_url}/echo", body="", json=body)

    def test_top_level_request_with_invalid_body(self) -> None:
        class BadBody:
            def __repr__(self) -> str:
                return "<BadBody>"

        with pytest.raises(TypeError) as e:
            request(
                method="POST",
                url=f"{self.base_url}/echo",
                body=BadBody(),  # type: ignore[arg-type]
            )
        assert str(e.value) == (
            "'body' must be a bytes-like object, file-like "
            "object, or iterable. Instead was <BadBody>"
        )


@pytest.mark.skipif(not HAS_IPV6, reason="IPv6 is not supported on this system")
class TestIPv6PoolManager(IPv6HypercornDummyServerTestCase):
    @classmethod
    def setup_class(cls) -> None:
        super().setup_class()
        cls.base_url = f"http://[{cls.host}]:{cls.port}"

    def test_ipv6(self) -> None:
        with PoolManager() as http:
            http.request("GET", self.base_url)

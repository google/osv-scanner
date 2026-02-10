from __future__ import annotations

import datetime
import socket
import typing
from http.client import ResponseNotReady
from unittest import mock

import pytest

from urllib3.connection import (  # type: ignore[attr-defined]
    RECENT_DATE,
    CertificateError,
    HTTPConnection,
    HTTPSConnection,
    _match_hostname,
    _url_from_connection,
    _wrap_proxy_error,
)
from urllib3.exceptions import HTTPError, ProxyError, SSLError
from urllib3.util import ssl_
from urllib3.util.request import SKIP_HEADER
from urllib3.util.ssl_match_hostname import (
    CertificateError as ImplementationCertificateError,
)
from urllib3.util.ssl_match_hostname import _dnsname_match, match_hostname

if typing.TYPE_CHECKING:
    from urllib3.util.ssl_ import _TYPE_PEER_CERT_RET_DICT


class TestConnection:
    """
    Tests in this suite should not make any network requests or connections.
    """

    def test_match_hostname_no_cert(self) -> None:
        cert = None
        asserted_hostname = "foo"
        with pytest.raises(ValueError):
            _match_hostname(cert, asserted_hostname)

    def test_match_hostname_empty_cert(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {}
        asserted_hostname = "foo"
        with pytest.raises(ValueError):
            _match_hostname(cert, asserted_hostname)

    def test_match_hostname_match(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", "foo"),)}
        asserted_hostname = "foo"
        _match_hostname(cert, asserted_hostname)

    def test_match_hostname_mismatch(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", "foo"),)}
        asserted_hostname = "bar"
        try:
            with mock.patch("urllib3.connection.log.warning") as mock_log:
                _match_hostname(cert, asserted_hostname)
        except CertificateError as e:
            assert "hostname 'bar' doesn't match 'foo'" in str(e)
            mock_log.assert_called_once_with(
                "Certificate did not match expected hostname: %s. Certificate: %s",
                "bar",
                {"subjectAltName": (("DNS", "foo"),)},
            )
            assert e._peer_cert == cert  # type: ignore[attr-defined]

    def test_match_hostname_no_dns(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", ""),)}
        asserted_hostname = "bar"
        try:
            with mock.patch("urllib3.connection.log.warning") as mock_log:
                _match_hostname(cert, asserted_hostname)
        except CertificateError as e:
            assert "hostname 'bar' doesn't match ''" in str(e)
            mock_log.assert_called_once_with(
                "Certificate did not match expected hostname: %s. Certificate: %s",
                "bar",
                {"subjectAltName": (("DNS", ""),)},
            )
            assert e._peer_cert == cert  # type: ignore[attr-defined]

    def test_match_hostname_startwith_wildcard(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", "*"),)}
        asserted_hostname = "foo"
        _match_hostname(cert, asserted_hostname)

    def test_match_hostname_dnsname(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("DNS", "xn--p1b6ci4b4b3a*.xn--11b5bs8d"),)
        }
        asserted_hostname = "xn--p1b6ci4b4b3a*.xn--11b5bs8d"
        _match_hostname(cert, asserted_hostname)

    def test_match_hostname_include_wildcard(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("DNS", "foo*"),)}
        asserted_hostname = "foobar"
        _match_hostname(cert, asserted_hostname)

    def test_match_hostname_more_than_one_dnsname_error(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("DNS", "foo*"), ("DNS", "fo*"))
        }
        asserted_hostname = "bar"
        with pytest.raises(CertificateError, match="doesn't match either of"):
            _match_hostname(cert, asserted_hostname)

    def test_dnsname_match_include_more_than_one_wildcard_error(self) -> None:
        with pytest.raises(CertificateError, match="too many wildcards in certificate"):
            _dnsname_match("foo**", "foobar")

    def test_match_hostname_ignore_common_name(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subject": ((("commonName", "foo"),),)}
        asserted_hostname = "foo"
        with pytest.raises(
            ImplementationCertificateError,
            match="no appropriate subjectAltName fields were found",
        ):
            match_hostname(cert, asserted_hostname)

    def test_match_hostname_check_common_name(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {"subject": ((("commonName", "foo"),),)}
        asserted_hostname = "foo"
        match_hostname(cert, asserted_hostname, True)

    def test_match_hostname_ip_address(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("IP Address", "1.1.1.1"),)
        }
        asserted_hostname = "1.1.1.2"
        try:
            with mock.patch("urllib3.connection.log.warning") as mock_log:
                _match_hostname(cert, asserted_hostname)
        except CertificateError as e:
            assert "hostname '1.1.1.2' doesn't match '1.1.1.1'" in str(e)
            mock_log.assert_called_once_with(
                "Certificate did not match expected hostname: %s. Certificate: %s",
                "1.1.1.2",
                {"subjectAltName": (("IP Address", "1.1.1.1"),)},
            )
            assert e._peer_cert == cert  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        ["asserted_hostname", "san_ip"],
        [
            ("1:2::3:4", "1:2:0:0:0:0:3:4"),
            ("1:2:0:0::3:4", "1:2:0:0:0:0:3:4"),
            ("::0.1.0.2", "0:0:0:0:0:0:1:2"),
            ("::1%42", "0:0:0:0:0:0:0:1"),
            ("::2%iface", "0:0:0:0:0:0:0:2"),
        ],
    )
    def test_match_hostname_ip_address_ipv6(
        self, asserted_hostname: str, san_ip: str
    ) -> None:
        """Check that hostname matches follow RFC 9110 rules for IPv6."""
        cert: _TYPE_PEER_CERT_RET_DICT = {"subjectAltName": (("IP Address", san_ip),)}
        match_hostname(cert, asserted_hostname)

    def test_match_hostname_ip_address_ipv6_doesnt_match(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("IP Address", "1:2::2:1"),)
        }
        asserted_hostname = "1:2::2:2"
        try:
            with mock.patch("urllib3.connection.log.warning") as mock_log:
                _match_hostname(cert, asserted_hostname)
        except CertificateError as e:
            assert "hostname '1:2::2:2' doesn't match '1:2::2:1'" in str(e)
            mock_log.assert_called_once_with(
                "Certificate did not match expected hostname: %s. Certificate: %s",
                "1:2::2:2",
                {"subjectAltName": (("IP Address", "1:2::2:1"),)},
            )
            assert e._peer_cert == cert  # type: ignore[attr-defined]

    def test_match_hostname_dns_with_brackets_doesnt_match(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (
                ("DNS", "localhost"),
                ("IP Address", "localhost"),
            )
        }
        asserted_hostname = "[localhost]"
        with pytest.raises(CertificateError) as e:
            _match_hostname(cert, asserted_hostname)
        assert (
            "hostname '[localhost]' doesn't match either of 'localhost', 'localhost'"
            in str(e.value)
        )

    def test_match_hostname_ip_address_ipv6_brackets(self) -> None:
        cert: _TYPE_PEER_CERT_RET_DICT = {
            "subjectAltName": (("IP Address", "1:2::2:1"),)
        }
        asserted_hostname = "[1:2::2:1]"
        # Assert no error is raised
        _match_hostname(cert, asserted_hostname)

    def test_recent_date(self) -> None:
        # This test is to make sure that the RECENT_DATE value
        # doesn't get too far behind what the current date is.
        # When this test fails update urllib3.connection.RECENT_DATE
        # according to the rules defined in that file.
        two_years = datetime.timedelta(days=365 * 2)
        assert RECENT_DATE > (datetime.datetime.today() - two_years).date()

    def test_HTTPSConnection_default_socket_options(self) -> None:
        conn = HTTPSConnection("not.a.real.host", port=443)
        assert conn.socket_options == [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]

    @pytest.mark.parametrize(
        "proxy_scheme, err_part",
        [
            ("http", "Unable to connect to proxy"),
            (
                "https",
                "Unable to connect to proxy. Your proxy appears to only use HTTP and not HTTPS",
            ),
        ],
    )
    def test_wrap_proxy_error(self, proxy_scheme: str, err_part: str) -> None:
        new_err = _wrap_proxy_error(HTTPError("unknown protocol"), proxy_scheme)
        assert isinstance(new_err, ProxyError) is True
        assert err_part in new_err.args[0]

    def test_url_from_pool(self) -> None:
        conn = HTTPConnection("google.com", port=80)

        path = "path?query=foo"
        assert f"http://google.com:80/{path}" == _url_from_connection(conn, path)

    def test_getresponse_requires_reponseoptions(self) -> None:
        conn = HTTPConnection("google.com", port=80)

        # Should error if a request has not been sent
        with pytest.raises(ResponseNotReady):
            conn.getresponse()

    def test_assert_fingerprint_closes_socket(self) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.wrap_socket.return_value.getpeercert.return_value = b"fake cert"
        conn = HTTPSConnection(
            "google.com",
            port=443,
            assert_fingerprint="AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA",
            ssl_context=context,
        )
        with mock.patch.object(conn, "_new_conn"):
            with pytest.raises(SSLError):
                conn.connect()

        context.wrap_socket.return_value.close.assert_called_once_with()

    def test_assert_hostname_closes_socket(self) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.wrap_socket.return_value.getpeercert.return_value = {
            "subjectAltName": (("DNS", "google.com"),)
        }
        conn = HTTPSConnection(
            "google.com", port=443, assert_hostname="example.com", ssl_context=context
        )
        with mock.patch.object(conn, "_new_conn"):
            with pytest.raises(ImplementationCertificateError):
                conn.connect()

        context.wrap_socket.return_value.close.assert_called_once_with()

    @pytest.mark.parametrize(
        "accept_encoding",
        [
            "Accept-Encoding",
            "accept-encoding",
            b"Accept-Encoding",
            b"accept-encoding",
            None,
        ],
    )
    @pytest.mark.parametrize("host", ["Host", "host", b"Host", b"host", None])
    @pytest.mark.parametrize(
        "user_agent", ["User-Agent", "user-agent", b"User-Agent", b"user-agent", None]
    )
    @pytest.mark.parametrize("chunked", [True, False])
    def test_skip_header(
        self,
        accept_encoding: str | None,
        host: str | None,
        user_agent: str | None,
        chunked: bool,
    ) -> None:
        headers = {}
        if accept_encoding is not None:
            headers[accept_encoding] = SKIP_HEADER
        if host is not None:
            headers[host] = SKIP_HEADER
        if user_agent is not None:
            headers[user_agent] = SKIP_HEADER

        # When dropping support for Python 3.9, this can be rewritten to parenthesized
        # context managers
        with mock.patch("urllib3.util.connection.create_connection"):
            with mock.patch(
                "urllib3.connection._HTTPConnection.putheader"
            ) as http_client_putheader:
                conn = HTTPConnection("")
                conn.request("GET", "/headers", headers=headers, chunked=chunked)

        request_headers = {}
        for call in http_client_putheader.call_args_list:
            header, value = call.args
            request_headers[header] = value

        if accept_encoding is None:
            assert "Accept-Encoding" in request_headers
        else:
            assert accept_encoding not in request_headers
        if host is None:
            assert "Host" in request_headers
        else:
            assert host not in request_headers
        if user_agent is None:
            assert "User-Agent" in request_headers
        else:
            assert user_agent not in request_headers

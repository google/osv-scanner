from __future__ import annotations

import ssl
import sys
import typing
from unittest import mock

import pytest

from urllib3.exceptions import ProxySchemeUnsupported, SSLError
from urllib3.util import ssl_


class TestSSL:
    @pytest.mark.parametrize(
        "addr",
        [
            # IPv6
            "::1",
            "::",
            "FE80::8939:7684:D84b:a5A4%251",
            # IPv4
            "127.0.0.1",
            "8.8.8.8",
            b"127.0.0.1",
            # IPv6 w/ Zone IDs
            "FE80::8939:7684:D84b:a5A4%251",
            b"FE80::8939:7684:D84b:a5A4%251",
            "FE80::8939:7684:D84b:a5A4%19",
            b"FE80::8939:7684:D84b:a5A4%19",
        ],
    )
    def test_is_ipaddress_true(self, addr: bytes | str) -> None:
        assert ssl_.is_ipaddress(addr)

    @pytest.mark.parametrize(
        "addr",
        [
            "www.python.org",
            b"www.python.org",
            "v2.sg.media-imdb.com",
            b"v2.sg.media-imdb.com",
        ],
    )
    def test_is_ipaddress_false(self, addr: bytes | str) -> None:
        assert not ssl_.is_ipaddress(addr)

    def test_create_urllib3_context_set_ciphers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ciphers = "ECDH+AESGCM:ECDH+CHACHA20"
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        assert ssl_.create_urllib3_context(ciphers=ciphers) is context

        assert context.set_ciphers.call_count == 1
        assert context.set_ciphers.call_args == mock.call(ciphers)

    def test_create_urllib3_no_context(self) -> None:
        with mock.patch("urllib3.util.ssl_.SSLContext", None):
            with pytest.raises(TypeError):
                ssl_.create_urllib3_context()

    def test_create_urllib3_context_default_verify_flags(self) -> None:
        context = ssl_.create_urllib3_context()
        if sys.version_info >= (3, 13):
            assert context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
            assert context.verify_flags & ssl.VERIFY_X509_STRICT
        else:
            # Needed for Python 3.9 which does not define this
            assert not (
                context.verify_flags
                & getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0x80000)
            )
            assert not (context.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_create_urllib3_context_custom_verify_flags(self) -> None:
        context = ssl_.create_urllib3_context()
        assert not (context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF)
        context = ssl_.create_urllib3_context(verify_flags=ssl.VERIFY_CRL_CHECK_LEAF)
        assert context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF

    def test_wrap_socket_given_context_no_load_default_certs(self) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock, ssl_context=context)

        context.load_default_certs.assert_not_called()

    def test_wrap_socket_given_ca_certs_no_load_default_certs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()
        context.options = 0

        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock, ca_certs="/tmp/fake-file")

        context.load_default_certs.assert_not_called()
        context.load_verify_locations.assert_called_with("/tmp/fake-file", None, None)

    def test_wrap_socket_default_loads_default_certs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()
        context.options = 0

        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock)

        context.load_default_certs.assert_called_with()

    def test_wrap_socket_no_ssltransport(self) -> None:
        with mock.patch("urllib3.util.ssl_.SSLTransport", None):
            with pytest.raises(ProxySchemeUnsupported):
                sock = mock.Mock()
                ssl_.ssl_wrap_socket(sock, tls_in_tls=True)

    @pytest.mark.parametrize(
        ["pha", "expected_pha", "cert_reqs"],
        [
            (None, None, None),
            (None, None, ssl.CERT_NONE),
            (None, None, ssl.CERT_OPTIONAL),
            (None, None, ssl.CERT_REQUIRED),
            (False, True, None),
            (False, True, ssl.CERT_NONE),
            (False, True, ssl.CERT_OPTIONAL),
            (False, True, ssl.CERT_REQUIRED),
            (True, True, None),
            (True, True, ssl.CERT_NONE),
            (True, True, ssl.CERT_OPTIONAL),
            (True, True, ssl.CERT_REQUIRED),
        ],
    )
    def test_create_urllib3_context_pha(
        self,
        monkeypatch: pytest.MonkeyPatch,
        pha: bool | None,
        expected_pha: bool | None,
        cert_reqs: int | None,
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        context.post_handshake_auth = pha
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        assert ssl_.create_urllib3_context(cert_reqs=cert_reqs) is context

        assert context.post_handshake_auth == expected_pha

    def test_create_urllib3_context_default_ciphers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        ssl_.create_urllib3_context()

        context.set_ciphers.assert_not_called()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "ssl_version": ssl.PROTOCOL_TLSv1,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLSv1,
                "ssl_maximum_version": ssl.TLSVersion.TLSv1,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLSv1,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
                "ssl_maximum_version": ssl.TLSVersion.MAXIMUM_SUPPORTED,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_errors(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        with pytest.raises(ValueError) as e:
            ssl_.create_urllib3_context(**kwargs)

        assert str(e.value) == (
            "Can't specify both 'ssl_version' and either 'ssl_minimum_version' or 'ssl_maximum_version'"
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "ssl_version": ssl.PROTOCOL_TLS,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLS_CLIENT,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": None,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_no_warning(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        ssl_.create_urllib3_context(**kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"ssl_version": ssl.PROTOCOL_TLSv1, "ssl_minimum_version": None},
            {"ssl_version": ssl.PROTOCOL_TLSv1, "ssl_maximum_version": None},
            {
                "ssl_version": ssl.PROTOCOL_TLSv1,
                "ssl_minimum_version": None,
                "ssl_maximum_version": None,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_no_error(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        with pytest.warns(
            DeprecationWarning,
            match=r"'ssl_version' option is deprecated and will be removed in "
            r"urllib3 v2\.6\.0\. Instead use 'ssl_minimum_version'",
        ):
            ssl_.create_urllib3_context(**kwargs)

    def test_assert_fingerprint_raises_exception_on_none_cert(self) -> None:
        with pytest.raises(SSLError):
            ssl_.assert_fingerprint(
                cert=None, fingerprint="55:39:BF:70:05:12:43:FA:1F:D1:BF:4E:E8:1B:07:1D"
            )

from __future__ import annotations

import concurrent.futures
import contextlib
import datetime
import os.path
import shutil
import ssl
import tempfile
import time
import typing
import warnings
from pathlib import Path
from test import (
    LONG_TIMEOUT,
    SHORT_TIMEOUT,
    TARPIT_HOST,
    requires_network,
    resolvesLocalhostFQDN,
)
from test.conftest import ServerConfig
from unittest import mock

import pytest
import trustme

import urllib3.http2
import urllib3.http2.probe as http2_probe
import urllib3.util as util
import urllib3.util.ssl_
from dummyserver.socketserver import (
    DEFAULT_CA,
    DEFAULT_CA_KEY,
    DEFAULT_CERTS,
    encrypt_key_pem,
)
from dummyserver.testcase import HTTPSHypercornDummyServerTestCase
from urllib3 import HTTPSConnectionPool
from urllib3.connection import RECENT_DATE, HTTPSConnection, VerifiedHTTPSConnection
from urllib3.exceptions import (
    ConnectTimeoutError,
    InsecureRequestWarning,
    MaxRetryError,
    ProtocolError,
    SSLError,
    SystemTimeWarning,
)
from urllib3.util.ssl_match_hostname import CertificateError
from urllib3.util.timeout import Timeout

TLSv1_CERTS = DEFAULT_CERTS.copy()
TLSv1_CERTS["ssl_version"] = getattr(ssl, "PROTOCOL_TLSv1", None)

TLSv1_1_CERTS = DEFAULT_CERTS.copy()
TLSv1_1_CERTS["ssl_version"] = getattr(ssl, "PROTOCOL_TLSv1_1", None)

TLSv1_2_CERTS = DEFAULT_CERTS.copy()
TLSv1_2_CERTS["ssl_version"] = getattr(ssl, "PROTOCOL_TLSv1_2", None)

TLSv1_3_CERTS = DEFAULT_CERTS.copy()
TLSv1_3_CERTS["ssl_version"] = getattr(ssl, "PROTOCOL_TLS", None)


CLIENT_INTERMEDIATE_PEM = "client_intermediate.pem"
CLIENT_NO_INTERMEDIATE_PEM = "client_no_intermediate.pem"
CLIENT_INTERMEDIATE_KEY = "client_intermediate.key"
PASSWORD_CLIENT_KEYFILE = "client_password.key"
CLIENT_CERT = CLIENT_INTERMEDIATE_PEM


class BaseTestHTTPS(HTTPSHypercornDummyServerTestCase):
    tls_protocol_name: str | None = None

    def tls_protocol_not_default(self) -> bool:
        return self.tls_protocol_name in {"TLSv1", "TLSv1.1"}

    def tls_version(self) -> ssl.TLSVersion:
        if self.tls_protocol_name is None:
            return pytest.skip("Skipping base test class")
        try:
            from ssl import TLSVersion
        except ImportError:
            return pytest.skip("ssl.TLSVersion isn't available")
        return TLSVersion[self.tls_protocol_name.replace(".", "_")]

    def ssl_version(self) -> int:
        if self.tls_protocol_name is None:
            return pytest.skip("Skipping base test class")

        if self.tls_protocol_name == "TLSv1.3" and ssl.HAS_TLSv1_3:
            return ssl.PROTOCOL_TLS_CLIENT
        if self.tls_protocol_name == "TLSv1.2" and ssl.HAS_TLSv1_2:
            return ssl.PROTOCOL_TLSv1_2
        if self.tls_protocol_name == "TLSv1.1" and ssl.HAS_TLSv1_1:
            return ssl.PROTOCOL_TLSv1_1
        if self.tls_protocol_name == "TLSv1" and ssl.HAS_TLSv1:
            return ssl.PROTOCOL_TLSv1
        else:
            return pytest.skip(f"{self.tls_protocol_name} isn't available")

    @classmethod
    def setup_class(cls) -> None:
        super().setup_class()

        cls.certs_dir = tempfile.mkdtemp()
        # Start from existing root CA as we don't want to change the server certificate yet
        with open(DEFAULT_CA, "rb") as crt, open(DEFAULT_CA_KEY, "rb") as key:
            root_ca = trustme.CA.from_pem(crt.read(), key.read())

        # Generate another CA to test verification failure
        bad_ca = trustme.CA()
        cls.bad_ca_path = os.path.join(cls.certs_dir, "ca_bad.pem")
        bad_ca.cert_pem.write_to_path(cls.bad_ca_path)

        # client cert chain
        intermediate_ca = root_ca.create_child_ca()
        cert = intermediate_ca.issue_cert("example.com")
        encrypted_key = encrypt_key_pem(cert.private_key_pem, b"letmein")

        cert.private_key_pem.write_to_path(
            os.path.join(cls.certs_dir, CLIENT_INTERMEDIATE_KEY)
        )
        encrypted_key.write_to_path(
            os.path.join(cls.certs_dir, PASSWORD_CLIENT_KEYFILE)
        )
        # Write the client cert and the intermediate CA
        client_cert = os.path.join(cls.certs_dir, CLIENT_INTERMEDIATE_PEM)
        cert.cert_chain_pems[0].write_to_path(client_cert)
        cert.cert_chain_pems[1].write_to_path(client_cert, append=True)
        # Write only the client cert
        cert.cert_chain_pems[0].write_to_path(
            os.path.join(cls.certs_dir, CLIENT_NO_INTERMEDIATE_PEM)
        )

    @classmethod
    def teardown_class(cls) -> None:
        super().teardown_class()

        shutil.rmtree(cls.certs_dir)

    def test_simple(self, http_version: str) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            r = https_pool.request("GET", "/")
            assert r.status == 200, r.data
            assert r.headers["server"] == f"hypercorn-{http_version}"
            assert r.data == b"Dummy server!"

    def test_default_port(self) -> None:
        conn = HTTPSConnection(self.host, port=None)
        assert conn.port == 443

    @resolvesLocalhostFQDN()
    def test_dotted_fqdn(self) -> None:
        with HTTPSConnectionPool(
            self.host + ".",
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as pool:
            r = pool.request("GET", "/")
            assert r.status == 200, r.data

    def test_client_intermediate(self) -> None:
        """Check that certificate chains work well with client certs

        We generate an intermediate CA from the root CA, and issue a client certificate
        from that intermediate CA. Since the server only knows about the root CA, we
        need to send it the certificate *and* the intermediate CA, so that it can check
        the whole chain.
        """
        with HTTPSConnectionPool(
            self.host,
            self.port,
            key_file=os.path.join(self.certs_dir, CLIENT_INTERMEDIATE_KEY),
            cert_file=os.path.join(self.certs_dir, CLIENT_INTERMEDIATE_PEM),
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            r = https_pool.request("GET", "/certificate")
            subject = r.json()
            assert subject["organizationalUnitName"].startswith("Testing cert")

    def test_client_no_intermediate(self) -> None:
        """Check that missing links in certificate chains indeed break

        The only difference with test_client_intermediate is that we don't send the
        intermediate CA to the server, only the client cert.
        """
        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_file=os.path.join(self.certs_dir, CLIENT_NO_INTERMEDIATE_PEM),
            key_file=os.path.join(self.certs_dir, CLIENT_INTERMEDIATE_KEY),
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with pytest.raises((SSLError, ProtocolError)):
                https_pool.request("GET", "/certificate", retries=False)

    def test_client_key_password(self) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            key_file=os.path.join(self.certs_dir, PASSWORD_CLIENT_KEYFILE),
            cert_file=os.path.join(self.certs_dir, CLIENT_CERT),
            key_password="letmein",
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            r = https_pool.request("GET", "/certificate")
            subject = r.json()
            assert subject["organizationalUnitName"].startswith("Testing cert")

    def test_client_encrypted_key_requires_password(self) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            key_file=os.path.join(self.certs_dir, PASSWORD_CLIENT_KEYFILE),
            cert_file=os.path.join(self.certs_dir, CLIENT_CERT),
            key_password=None,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with pytest.raises(MaxRetryError, match="password is required") as e:
                https_pool.request("GET", "/certificate")

            assert type(e.value.reason) is SSLError

    def test_verified(self) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with contextlib.closing(https_pool._new_conn()) as conn:
                assert conn.__class__ == VerifiedHTTPSConnection

            with warnings.catch_warnings(record=True) as w:
                r = https_pool.request("GET", "/")
                assert r.status == 200

            assert [str(wm) for wm in w] == []

    def test_verified_with_context(self) -> None:
        ctx = util.ssl_.create_urllib3_context(
            cert_reqs=ssl.CERT_REQUIRED, ssl_minimum_version=self.tls_version()
        )
        ctx.load_verify_locations(cafile=DEFAULT_CA)
        with HTTPSConnectionPool(self.host, self.port, ssl_context=ctx) as https_pool:
            with contextlib.closing(https_pool._new_conn()) as conn:
                assert conn.__class__ == VerifiedHTTPSConnection

            with mock.patch("warnings.warn") as warn:
                r = https_pool.request("GET", "/")
                assert r.status == 200
                assert not warn.called, warn.call_args_list

    def test_context_combines_with_ca_certs(self) -> None:
        ctx = util.ssl_.create_urllib3_context(
            cert_reqs=ssl.CERT_REQUIRED, ssl_minimum_version=self.tls_version()
        )
        with HTTPSConnectionPool(
            self.host, self.port, ca_certs=DEFAULT_CA, ssl_context=ctx
        ) as https_pool:
            with contextlib.closing(https_pool._new_conn()) as conn:
                assert conn.__class__ == VerifiedHTTPSConnection

            with mock.patch("warnings.warn") as warn:
                r = https_pool.request("GET", "/")
                assert r.status == 200
                assert not warn.called, warn.call_args_list

    def test_ca_dir_verified(self, tmp_path: Path) -> None:
        # OpenSSL looks up certificates by the hash for their name, see c_rehash
        # TODO infer the bytes using `cryptography.x509.Name.public_bytes`.
        # https://github.com/pyca/cryptography/pull/3236
        shutil.copyfile(DEFAULT_CA, str(tmp_path / "81deb5f7.0"))

        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_cert_dir=str(tmp_path),
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with contextlib.closing(https_pool._new_conn()) as conn:
                assert conn.__class__ == VerifiedHTTPSConnection

            with warnings.catch_warnings(record=True) as w:
                r = https_pool.request("GET", "/")
                assert r.status == 200

            assert [str(wm) for wm in w] == []

    def test_invalid_common_name(self) -> None:
        with HTTPSConnectionPool(
            "127.0.0.1",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with pytest.raises(MaxRetryError) as e:
                https_pool.request("GET", "/", retries=0)
            assert type(e.value.reason) is SSLError
            assert "doesn't match" in str(
                e.value.reason
            ) or "certificate verify failed" in str(e.value.reason)

    def test_verified_with_bad_ca_certs(self) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=self.bad_ca_path,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with pytest.raises(MaxRetryError) as e:
                https_pool.request("GET", "/")
            assert type(e.value.reason) is SSLError
            assert (
                "certificate verify failed" in str(e.value.reason)
                # PyPy is more specific
                or "self signed certificate in certificate chain" in str(e.value.reason)
            ), f"Expected 'certificate verify failed', instead got: {e.value.reason!r}"

    def test_wrap_socket_failure_resource_leak(self) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=self.bad_ca_path,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with contextlib.closing(https_pool._get_conn()) as conn:
                with pytest.raises(ssl.SSLError):
                    conn.connect()

                assert conn.sock is not None  # type: ignore[attr-defined]

    def test_verified_without_ca_certs(self) -> None:
        # default is cert_reqs=None which is ssl.CERT_NONE
        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs="CERT_REQUIRED",
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with pytest.raises(MaxRetryError) as e:
                https_pool.request("GET", "/")
            assert type(e.value.reason) is SSLError
            # there is a different error message depending on whether or
            # not pyopenssl is injected
            assert (
                "No root certificates specified" in str(e.value.reason)
                # PyPy is more specific
                or "self signed certificate in certificate chain" in str(e.value.reason)
                # PyPy sometimes uses all-caps here
                or "certificate verify failed" in str(e.value.reason).lower()
                or "invalid certificate chain" in str(e.value.reason)
            ), (
                "Expected 'No root certificates specified',  "
                "'certificate verify failed', or "
                "'invalid certificate chain', "
                "instead got: %r" % e.value.reason
            )

    def test_no_ssl(self) -> None:
        with HTTPSConnectionPool(self.host, self.port) as pool:
            pool.ConnectionCls = None  # type: ignore[assignment]
            with pytest.raises(ImportError):
                pool._new_conn()
            with pytest.raises(ImportError):
                pool.request("GET", "/", retries=0)

    def test_unverified_ssl(self) -> None:
        """Test that bare HTTPSConnection can connect, make requests"""
        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs=ssl.CERT_NONE,
            ssl_minimum_version=self.tls_version(),
        ) as pool:
            with mock.patch("warnings.warn") as warn:
                r = pool.request("GET", "/")
                assert r.status == 200
                assert warn.called

                # Modern versions of Python, or systems using PyOpenSSL, only emit
                # the unverified warning. Older systems may also emit other
                # warnings, which we want to ignore here.
                calls = warn.call_args_list
                assert InsecureRequestWarning in [x[0][1] for x in calls]

    def test_ssl_unverified_with_ca_certs(self) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs="CERT_NONE",
            ca_certs=self.bad_ca_path,
            ssl_minimum_version=self.tls_version(),
        ) as pool:
            with mock.patch("warnings.warn") as warn:
                r = pool.request("GET", "/")
                assert r.status == 200
                assert warn.called

                # Modern versions of Python, or systems using PyOpenSSL, only emit
                # the unverified warning. Older systems may also emit other
                # warnings, which we want to ignore here.
                calls = warn.call_args_list

                category = calls[0][0][1]
                assert category == InsecureRequestWarning

    def test_assert_hostname_false(self) -> None:
        with HTTPSConnectionPool(
            "localhost",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.assert_hostname = False
            https_pool.request("GET", "/")

    def test_assert_specific_hostname(self) -> None:
        with HTTPSConnectionPool(
            "localhost",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.assert_hostname = "localhost"
            https_pool.request("GET", "/")

    def test_server_hostname(self) -> None:
        with HTTPSConnectionPool(
            "127.0.0.1",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            server_hostname="localhost",
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            conn = https_pool._new_conn()
            conn.request("GET", "/")

            # Assert the wrapping socket is using the passed-through SNI name.
            # pyopenssl doesn't let you pull the server_hostname back off the
            # socket, so only add this assertion if the attribute is there (i.e.
            # the python ssl module).
            if hasattr(conn.sock, "server_hostname"):  # type: ignore[attr-defined]
                assert conn.sock.server_hostname == "localhost"  # type: ignore[attr-defined]
            conn.getresponse().close()
            conn.close()

    def test_assert_fingerprint_md5(self) -> None:
        with HTTPSConnectionPool(
            "localhost",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            assert_fingerprint=("55:39:BF:70:05:12:43:FA:1F:D1:BF:4E:E8:1B:07:1D"),
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.request("GET", "/")

    def test_assert_fingerprint_sha1(self) -> None:
        with HTTPSConnectionPool(
            "localhost",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            assert_fingerprint=(
                "72:8B:55:4C:9A:FC:1E:88:A1:1C:AD:1B:B2:E7:CC:3E:DB:C8:F9:8A"
            ),
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.request("GET", "/")

    def test_assert_fingerprint_sha256(self) -> None:
        with HTTPSConnectionPool(
            "localhost",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            assert_fingerprint=(
                "E3:59:8E:69:FF:C5:9F:C7:88:87:44:58:22:7F:90:8D:D9:BC:12:C4:90:79:D5:"
                "DC:A8:5D:4F:60:40:1E:A6:D2"
            ),
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.request("GET", "/")

    def test_assert_invalid_fingerprint(self) -> None:
        def _test_request(pool: HTTPSConnectionPool) -> SSLError:
            with pytest.raises(MaxRetryError) as cm:
                pool.request("GET", "/", retries=0)
            assert type(cm.value.reason) is SSLError
            return cm.value.reason

        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.assert_fingerprint = (
                "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA"
            )
            e = _test_request(https_pool)
            expected = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            got = "728b554c9afc1e88a11cad1bb2e7cc3edbc8f98a"
            assert (
                str(e)
                == f'Fingerprints did not match. Expected "{expected}", got "{got}"'
            )

            # Uneven length
            https_pool.assert_fingerprint = "AA:A"
            e = _test_request(https_pool)
            assert "Fingerprint of invalid length:" in str(e)

            # Invalid length
            https_pool.assert_fingerprint = "AA"
            e = _test_request(https_pool)
            assert "Fingerprint of invalid length:" in str(e)

    def test_verify_none_and_bad_fingerprint(self) -> None:
        with HTTPSConnectionPool(
            "127.0.0.1",
            self.port,
            cert_reqs="CERT_NONE",
            assert_hostname=False,
            assert_fingerprint=(
                "AA:8B:55:4C:9A:FC:1E:88:A1:1C:AD:1B:B2:E7:CC:3E:DB:C8:F9:8A"
            ),
        ) as https_pool:
            with pytest.raises(MaxRetryError) as cm:
                https_pool.request("GET", "/", retries=0)
            assert type(cm.value.reason) is SSLError

    def test_verify_none_and_good_fingerprint(self) -> None:
        with HTTPSConnectionPool(
            "127.0.0.1",
            self.port,
            cert_reqs="CERT_NONE",
            assert_hostname=False,
            assert_fingerprint=(
                "72:8B:55:4C:9A:FC:1E:88:A1:1C:AD:1B:B2:E7:CC:3E:DB:C8:F9:8A"
            ),
        ) as https_pool:
            https_pool.request("GET", "/")

    def test_good_fingerprint_and_hostname_mismatch(self) -> None:
        with HTTPSConnectionPool(
            "127.0.0.1",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            assert_fingerprint=(
                "72:8B:55:4C:9A:FC:1E:88:A1:1C:AD:1B:B2:E7:CC:3E:DB:C8:F9:8A"
            ),
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.request("GET", "/")

    @requires_network()
    def test_https_timeout(self) -> None:
        timeout = Timeout(total=None, connect=SHORT_TIMEOUT)
        with HTTPSConnectionPool(
            TARPIT_HOST,
            self.port,
            timeout=timeout,
            retries=False,
            cert_reqs="CERT_REQUIRED",
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with pytest.raises(ConnectTimeoutError):
                https_pool.request("GET", "/")

        timeout = Timeout(read=0.01)
        with HTTPSConnectionPool(
            self.host,
            self.port,
            timeout=timeout,
            retries=False,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            assert_fingerprint=(
                "72:8B:55:4C:9A:FC:1E:88:A1:1C:AD:1B:B2:E7:CC:3E:DB:C8:F9:8A"
            ),
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            # TODO This was removed in https://github.com/urllib3/urllib3/pull/703/files
            # We need to put something back or remove this block.
            pass

        timeout = Timeout(total=None)
        with HTTPSConnectionPool(
            self.host,
            self.port,
            timeout=timeout,
            cert_reqs="CERT_NONE",
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with pytest.warns(InsecureRequestWarning):
                https_pool.request("GET", "/")

    def test_tunnel(self, http_version: str) -> None:
        """test the _tunnel behavior"""
        timeout = Timeout(total=None)
        with HTTPSConnectionPool(
            self.host,
            self.port,
            timeout=timeout,
            cert_reqs="CERT_NONE",
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            with contextlib.closing(https_pool._new_conn()) as conn:
                if http_version == "h2":
                    with pytest.raises(NotImplementedError) as e:
                        conn.set_tunnel(self.host, self.port)
                    assert (
                        str(e.value)
                        == "HTTP/2 does not support setting up a tunnel through a proxy"
                    )
                else:
                    conn.set_tunnel(self.host, self.port)
                    with mock.patch.object(
                        conn, "_tunnel", create=True, return_value=None
                    ) as conn_tunnel:
                        with pytest.warns(InsecureRequestWarning):
                            https_pool._make_request(conn, "GET", "/")
                    conn_tunnel.assert_called_once_with()

    @requires_network()
    def test_enhanced_timeout(self) -> None:
        with HTTPSConnectionPool(
            TARPIT_HOST,
            self.port,
            timeout=Timeout(connect=SHORT_TIMEOUT),
            retries=False,
            cert_reqs="CERT_REQUIRED",
        ) as https_pool:
            with contextlib.closing(https_pool._new_conn()) as conn:
                with pytest.raises(ConnectTimeoutError):
                    https_pool.request("GET", "/")
                with pytest.raises(ConnectTimeoutError):
                    https_pool._make_request(conn, "GET", "/")

        with HTTPSConnectionPool(
            TARPIT_HOST,
            self.port,
            timeout=Timeout(connect=LONG_TIMEOUT),
            retries=False,
            cert_reqs="CERT_REQUIRED",
        ) as https_pool:
            with pytest.raises(ConnectTimeoutError):
                https_pool.request("GET", "/", timeout=Timeout(connect=SHORT_TIMEOUT))

        with HTTPSConnectionPool(
            TARPIT_HOST,
            self.port,
            timeout=Timeout(total=None),
            retries=False,
            cert_reqs="CERT_REQUIRED",
        ) as https_pool:
            with contextlib.closing(https_pool._new_conn()) as conn:
                with pytest.raises(ConnectTimeoutError):
                    https_pool.request(
                        "GET", "/", timeout=Timeout(total=None, connect=SHORT_TIMEOUT)
                    )

    def test_enhanced_ssl_connection(self) -> None:
        fingerprint = "72:8B:55:4C:9A:FC:1E:88:A1:1C:AD:1B:B2:E7:CC:3E:DB:C8:F9:8A"

        with HTTPSConnectionPool(
            self.host,
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            assert_fingerprint=fingerprint,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            r = https_pool.request("GET", "/")
            assert r.status == 200

    def test_ssl_correct_system_time(self) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.cert_reqs = "CERT_REQUIRED"
            https_pool.ca_certs = DEFAULT_CA

            w = self._request_without_resource_warnings("GET", "/")
            assert [] == w

    def test_ssl_wrong_system_time(self) -> None:
        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            https_pool.cert_reqs = "CERT_REQUIRED"
            https_pool.ca_certs = DEFAULT_CA
            with mock.patch("urllib3.connection.datetime") as mock_date:
                mock_date.date.today.return_value = datetime.date(1970, 1, 1)

                w = self._request_without_resource_warnings("GET", "/")

                assert len(w) == 1
                warning = w[0]

                assert SystemTimeWarning == warning.category
                assert isinstance(warning.message, Warning)
                assert str(RECENT_DATE) in warning.message.args[0]

    def _request_without_resource_warnings(
        self, method: str, url: str
    ) -> list[warnings.WarningMessage]:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with HTTPSConnectionPool(
                self.host,
                self.port,
                ca_certs=DEFAULT_CA,
                ssl_minimum_version=self.tls_version(),
            ) as https_pool:
                https_pool.request(method, url)

        w = [x for x in w if not isinstance(x.message, ResourceWarning)]

        return w

    def test_set_ssl_version_to_tls_version(self) -> None:
        if self.tls_protocol_name is None:
            pytest.skip("Skipping base test class")

        with HTTPSConnectionPool(
            self.host, self.port, ca_certs=DEFAULT_CA
        ) as https_pool:
            https_pool.ssl_version = ssl_version = self.certs["ssl_version"]
            if ssl_version is getattr(ssl, "PROTOCOL_TLS", object()):
                cmgr: contextlib.AbstractContextManager[object] = (
                    contextlib.nullcontext()
                )
            else:
                cmgr = pytest.warns(
                    DeprecationWarning,
                    match=r"'ssl_version' option is deprecated and will be removed "
                    r"in urllib3 v2\.6\.0\. Instead use 'ssl_minimum_version'",
                )
            with cmgr:
                r = https_pool.request("GET", "/")
            assert r.status == 200, r.data

    def test_set_cert_default_cert_required(self) -> None:
        conn = VerifiedHTTPSConnection(self.host, self.port)
        with pytest.warns(DeprecationWarning) as w:
            conn.set_cert()
        assert conn.cert_reqs == ssl.CERT_REQUIRED
        assert len(w) == 1 and str(w[0].message) == (
            "HTTPSConnection.set_cert() is deprecated and will be removed in urllib3 v2.1.0. "
            "Instead provide the parameters to the HTTPSConnection constructor."
        )

    @pytest.mark.parametrize("verify_mode", [ssl.CERT_NONE, ssl.CERT_REQUIRED])
    def test_set_cert_inherits_cert_reqs_from_ssl_context(
        self, verify_mode: int
    ) -> None:
        ssl_context = urllib3.util.ssl_.create_urllib3_context(cert_reqs=verify_mode)
        assert ssl_context.verify_mode == verify_mode

        conn = HTTPSConnection(self.host, self.port, ssl_context=ssl_context)
        with pytest.warns(DeprecationWarning) as w:
            conn.set_cert()

        assert conn.cert_reqs == verify_mode
        assert (
            conn.ssl_context is not None and conn.ssl_context.verify_mode == verify_mode
        )
        assert len(w) == 1 and str(w[0].message) == (
            "HTTPSConnection.set_cert() is deprecated and will be removed in urllib3 v2.1.0. "
            "Instead provide the parameters to the HTTPSConnection constructor."
        )

    def test_tls_protocol_name_of_socket(self) -> None:
        if self.tls_protocol_name is None:
            pytest.skip("Skipping base test class")

        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
            ssl_maximum_version=self.tls_version(),
        ) as https_pool:
            with contextlib.closing(https_pool._get_conn()) as conn:
                conn.connect()
                if not hasattr(conn.sock, "version"):  # type: ignore[attr-defined]
                    pytest.skip("SSLSocket.version() not available")
                assert conn.sock.version() == self.tls_protocol_name  # type: ignore[attr-defined]

    def test_ssl_version_is_deprecated(self) -> None:
        if self.tls_protocol_name is None:
            pytest.skip("Skipping base test class")
        if self.ssl_version() == ssl.PROTOCOL_TLS_CLIENT:
            pytest.skip(
                "Skipping because ssl_version=ssl.PROTOCOL_TLS_CLIENT is not deprecated"
            )

        with HTTPSConnectionPool(
            self.host, self.port, ca_certs=DEFAULT_CA, ssl_version=self.ssl_version()
        ) as https_pool:
            with contextlib.closing(https_pool._get_conn()) as conn:
                with pytest.warns(DeprecationWarning) as w:
                    conn.connect()

        assert len(w) >= 1
        assert any(x.category == DeprecationWarning for x in w)
        assert any(
            str(x.message)
            == (
                "'ssl_version' option is deprecated and will be removed in "
                "urllib3 v2.6.0. Instead use 'ssl_minimum_version'"
            )
            for x in w
        )

    @pytest.mark.parametrize(
        "ssl_version", [None, ssl.PROTOCOL_TLS, ssl.PROTOCOL_TLS_CLIENT]
    )
    def test_ssl_version_with_protocol_tls_or_client_not_deprecated(
        self, ssl_version: int | None
    ) -> None:
        if self.tls_protocol_name is None:
            pytest.skip("Skipping base test class")
        if self.tls_protocol_not_default():
            pytest.skip(
                f"Skipping because '{self.tls_protocol_name}' isn't set by default"
            )

        with HTTPSConnectionPool(
            self.host, self.port, ca_certs=DEFAULT_CA, ssl_version=ssl_version
        ) as https_pool:
            with contextlib.closing(https_pool._get_conn()) as conn:
                with warnings.catch_warnings(record=True) as w:
                    conn.connect()

        assert [str(wm) for wm in w if wm.category != ResourceWarning] == []

    def test_no_tls_version_deprecation_with_ssl_context(self) -> None:
        if self.tls_protocol_name is None:
            pytest.skip("Skipping base test class")

        ctx = util.ssl_.create_urllib3_context(ssl_minimum_version=self.tls_version())

        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_context=ctx,
        ) as https_pool:
            with contextlib.closing(https_pool._get_conn()) as conn:
                with warnings.catch_warnings(record=True) as w:
                    conn.connect()

        assert [str(wm) for wm in w if wm.category != ResourceWarning] == []

    def test_tls_version_maximum_and_minimum(self) -> None:
        if self.tls_protocol_name is None:
            pytest.skip("Skipping base test class")

        from ssl import TLSVersion

        min_max_versions = [
            (self.tls_version(), self.tls_version()),
            (TLSVersion.MINIMUM_SUPPORTED, self.tls_version()),
            (TLSVersion.MINIMUM_SUPPORTED, TLSVersion.MAXIMUM_SUPPORTED),
        ]

        for minimum_version, maximum_version in min_max_versions:
            with HTTPSConnectionPool(
                self.host,
                self.port,
                ca_certs=DEFAULT_CA,
                ssl_minimum_version=minimum_version,
                ssl_maximum_version=maximum_version,
            ) as https_pool:
                conn = https_pool._get_conn()
                try:
                    conn.connect()
                    if maximum_version == TLSVersion.MAXIMUM_SUPPORTED:
                        # A higher protocol than tls_protocol_name could be negotiated
                        assert conn.sock.version() >= self.tls_protocol_name  # type: ignore[attr-defined]
                    else:
                        assert conn.sock.version() == self.tls_protocol_name  # type: ignore[attr-defined]
                finally:
                    conn.close()

    def test_sslkeylogfile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if not hasattr(util.SSLContext, "keylog_filename"):
            pytest.skip("requires OpenSSL 1.1.1+")

        keylog_file = tmp_path / "keylogfile.txt"
        monkeypatch.setenv("SSLKEYLOGFILE", str(keylog_file))

        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            r = https_pool.request("GET", "/")
            assert r.status == 200, r.data
            assert keylog_file.is_file(), "keylogfile '%s' should exist" % str(
                keylog_file
            )
            assert keylog_file.read_text().startswith(
                "# TLS secrets log file"
            ), "keylogfile '%s' should start with '# TLS secrets log file'" % str(
                keylog_file
            )

    @pytest.mark.parametrize("sslkeylogfile", [None, ""])
    def test_sslkeylogfile_empty(
        self, monkeypatch: pytest.MonkeyPatch, sslkeylogfile: str | None
    ) -> None:
        # Assert that an HTTPS connection doesn't error out when given
        # no SSLKEYLOGFILE or an empty value (ie 'SSLKEYLOGFILE=')
        if sslkeylogfile is not None:
            monkeypatch.setenv("SSLKEYLOGFILE", sslkeylogfile)
        else:
            monkeypatch.delenv("SSLKEYLOGFILE", raising=False)
        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as pool:
            r = pool.request("GET", "/")
            assert r.status == 200, r.data

    def test_alpn_default(self, http_version: str) -> None:
        """Default ALPN protocols are sent by default."""
        with HTTPSConnectionPool(
            self.host,
            self.port,
            ca_certs=DEFAULT_CA,
            ssl_minimum_version=self.tls_version(),
        ) as pool:
            r = pool.request("GET", "/alpn_protocol", retries=0)
            assert r.status == 200
            assert r.data.decode("utf-8") == util.ALPN_PROTOCOLS[0]
            assert (
                r.data.decode("utf-8") == {"h11": "http/1.1", "h2": "h2"}[http_version]
            )

    def test_http2_probe_result_is_cached(self, http_version: str) -> None:
        assert http2_probe._values() == {}

        for i in range(2):  # Do this twice to exercise the cache path
            with HTTPSConnectionPool(
                self.host,
                self.port,
                ca_certs=DEFAULT_CA,
            ) as pool:
                r = pool.request("GET", "/alpn_protocol", retries=0)
                assert r.status == 200

            if http_version == "h2":
                # This means the probe was successful.
                assert http2_probe._values() == {(self.host, self.port): True}
            else:
                # This means the probe wasn't attempted, otherwise would have a value.
                assert http_version == "h11"
                assert http2_probe._values() == {}

    @pytest.mark.xfail(reason="Hypercorn always supports both HTTP/2 and HTTP/1.1")
    def test_http2_probe_result_failed(self, http_version: str) -> None:
        if http_version == "h2":
            pytest.skip("Test must have server in HTTP/1.1 mode")
        assert http2_probe._values() == {}

        urllib3.http2.inject_into_urllib3()
        try:
            with HTTPSConnectionPool(
                self.host,
                self.port,
                ca_certs=DEFAULT_CA,
            ) as pool:
                r = pool.request("GET", "/", retries=0)
                assert r.status == 200

            # The probe was a failure because Hypercorn didn't support HTTP/2.
            assert http2_probe._values() == {(self.host, self.port): False}
        finally:
            urllib3.http2.extract_from_urllib3()

    def test_http2_probe_no_result_in_connect_error(self) -> None:
        assert http2_probe._values() == {}

        urllib3.http2.inject_into_urllib3()
        try:
            with HTTPSConnectionPool(
                TARPIT_HOST,
                self.port,
                ca_certs=DEFAULT_CA,
                timeout=SHORT_TIMEOUT,
            ) as pool:
                with pytest.raises(ConnectTimeoutError):
                    pool.request("GET", "/", retries=False)

            # The probe was inconclusive since an error occurred during connection.
            assert http2_probe._values() == {(TARPIT_HOST, self.port): None}
        finally:
            urllib3.http2.extract_from_urllib3()

    def test_http2_probe_no_result_in_ssl_error(self) -> None:
        urllib3.http2.inject_into_urllib3()
        try:
            with HTTPSConnectionPool(
                self.host,
                self.port,
                ca_certs=None,
                timeout=LONG_TIMEOUT,
            ) as pool:
                with pytest.raises(SSLError):
                    pool.request("GET", "/", retries=False)

            # The probe was inconclusive since an error occurred during connection.
            assert http2_probe._values() == {(self.host, self.port): None}
        finally:
            urllib3.http2.extract_from_urllib3()

    def test_http2_probe_blocked_per_thread(self) -> None:
        state, current_thread, last_action = None, None, time.perf_counter()

        def connect_callback(label: str, thread_id: int, **kwargs: typing.Any) -> None:
            nonlocal state, current_thread, last_action

            if label in ("before connect", "after connect failure"):
                # We don't know if the target supports HTTP/2 as connections fail
                assert kwargs["target_supports_http2"] is None

            # Since we're trying to connect to TARPIT_HOST, all connections will
            # fail, but they should be tried one after the other
            now = time.perf_counter()
            assert now >= last_action
            last_action = now

            if label == "before connect":
                assert state is None
                state = "connect"
                assert current_thread != thread_id
                current_thread = thread_id
            elif label == "after connect failure":
                assert state == "connect"
                assert current_thread == thread_id
                state = None

        assert http2_probe._values() == {}

        connect_timeout = LONG_TIMEOUT
        total_threads = 3
        urllib3.http2.inject_into_urllib3()
        try:

            def try_connect(_: typing.Any) -> tuple[float, float]:
                with HTTPSConnectionPool(
                    TARPIT_HOST,
                    self.port,
                    ca_certs=DEFAULT_CA,
                    timeout=connect_timeout,
                ) as pool:
                    start_time = time.time()
                    conn = pool._get_conn()
                    assert isinstance(conn, HTTPSConnection)
                    conn._connect_callback = connect_callback
                    with pytest.raises(ConnectTimeoutError):
                        conn.connect()
                    end_time = time.time()
                    return start_time, end_time

            threadpool = concurrent.futures.ThreadPoolExecutor(total_threads)
            list(threadpool.map(try_connect, range(total_threads)))

            # The probe was inconclusive since an error occurred during connection.
            assert http2_probe._values() == {(TARPIT_HOST, self.port): None}
        finally:
            urllib3.http2.extract_from_urllib3()

    def test_default_ssl_context_ssl_min_max_versions(self) -> None:
        ctx = urllib3.util.ssl_.create_urllib3_context()
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        # urllib3 sets a default maximum version only when it is
        # injected with PyOpenSSL SSL-support.
        # Otherwise, the default maximum version is set by Python's
        # `ssl.SSLContext`. The value respects OpenSSL configuration and
        # can be different from `ssl.TLSVersion.MAXIMUM_SUPPORTED`.
        # https://github.com/urllib3/urllib3/issues/2477#issuecomment-1151452150
        if util.IS_PYOPENSSL:
            expected_maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        else:
            expected_maximum_version = ssl.SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            ).maximum_version
        assert ctx.maximum_version == expected_maximum_version

    def test_ssl_context_ssl_version_uses_ssl_min_max_versions(self) -> None:
        if self.ssl_version() == ssl.PROTOCOL_TLS_CLIENT:
            pytest.skip(
                "Skipping because ssl_version=ssl.PROTOCOL_TLS_CLIENT is not deprecated"
            )

        with pytest.warns(
            DeprecationWarning,
            match=r"'ssl_version' option is deprecated and will be removed in "
            r"urllib3 v2\.6\.0\. Instead use 'ssl_minimum_version'",
        ):
            ctx = urllib3.util.ssl_.create_urllib3_context(
                ssl_version=self.ssl_version()
            )
        assert ctx.minimum_version == self.tls_version()
        assert ctx.maximum_version == self.tls_version()

    def test_default_ssl_context_verify_flags(self) -> None:
        ctx = urllib3.util.ssl_.create_urllib3_context()
        ssl_ctx = ssl.create_default_context()
        assert ctx.verify_flags == ssl_ctx.verify_flags

    def test_assert_missing_hashfunc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fingerprint = "55:39:BF:70:05:12:43:FA:1F:D1:BF:4E:E8:1B:07:1D"
        with HTTPSConnectionPool(
            "localhost",
            self.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=DEFAULT_CA,
            assert_fingerprint=(fingerprint),
            ssl_minimum_version=self.tls_version(),
        ) as https_pool:
            digest_length = len(fingerprint.replace(":", "").lower())
            monkeypatch.setitem(urllib3.util.ssl_.HASHFUNC_MAP, digest_length, None)
            with pytest.raises(MaxRetryError) as cm:
                https_pool.request("GET", "/", retries=0)
            assert type(cm.value.reason) is SSLError
            assert (
                f"Hash function implementation unavailable for fingerprint length: {digest_length}"
                == str(cm.value.reason)
            )


@pytest.mark.usefixtures("requires_tlsv1")
class TestHTTPS_TLSv1(BaseTestHTTPS):
    tls_protocol_name = "TLSv1"
    certs = TLSv1_CERTS


@pytest.mark.usefixtures("requires_tlsv1_1")
class TestHTTPS_TLSv1_1(BaseTestHTTPS):
    tls_protocol_name = "TLSv1.1"
    certs = TLSv1_1_CERTS


@pytest.mark.usefixtures("requires_tlsv1_2")
class TestHTTPS_TLSv1_2(BaseTestHTTPS):
    tls_protocol_name = "TLSv1.2"
    certs = TLSv1_2_CERTS


@pytest.mark.usefixtures("requires_tlsv1_3")
class TestHTTPS_TLSv1_3(BaseTestHTTPS):
    tls_protocol_name = "TLSv1.3"
    certs = TLSv1_3_CERTS


class TestHTTPS_Hostname:
    def test_can_validate_san(self, san_server: ServerConfig) -> None:
        """Ensure that urllib3 can validate SANs with IP addresses in them."""
        with HTTPSConnectionPool(
            san_server.host,
            san_server.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=san_server.ca_certs,
        ) as https_pool:
            r = https_pool.request("GET", "/")
            assert r.status == 200

    def test_common_name_without_san_fails(self, no_san_server: ServerConfig) -> None:
        with HTTPSConnectionPool(
            no_san_server.host,
            no_san_server.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=no_san_server.ca_certs,
        ) as https_pool:
            with pytest.raises(
                MaxRetryError,
            ) as e:
                https_pool.request("GET", "/")
            assert (
                "mismatch, certificate is not valid" in str(e.value)
                or "no appropriate subjectAltName" in str(e.value)
                or "Empty Subject Alternative Name extension" in str(e.value)
            )

    def test_common_name_without_san_with_different_common_name(
        self, no_san_server_with_different_commmon_name: ServerConfig
    ) -> None:
        ctx = urllib3.util.ssl_.create_urllib3_context(verify_flags=0)
        try:
            ctx.hostname_checks_common_name = True
        except AttributeError:
            pytest.skip("Couldn't set 'SSLContext.hostname_checks_common_name'")

        with HTTPSConnectionPool(
            no_san_server_with_different_commmon_name.host,
            no_san_server_with_different_commmon_name.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=no_san_server_with_different_commmon_name.ca_certs,
            ssl_context=ctx,
        ) as https_pool:
            with pytest.raises(MaxRetryError) as e:
                https_pool.request("GET", "/")
            assert "mismatch, certificate is not valid for 'localhost'" in str(
                e.value
            ) or "hostname 'localhost' doesn't match 'example.com'" in str(e.value)

    @pytest.mark.parametrize("use_assert_hostname", [True, False])
    def test_hostname_checks_common_name_respected(
        self, no_san_server: ServerConfig, use_assert_hostname: bool
    ) -> None:
        ctx = urllib3.util.ssl_.create_urllib3_context(verify_flags=0)
        if not hasattr(ctx, "hostname_checks_common_name"):
            pytest.skip("Test requires 'SSLContext.hostname_checks_common_name'")
        ctx.load_verify_locations(no_san_server.ca_certs)
        try:
            ctx.hostname_checks_common_name = True
        except AttributeError:
            pytest.skip("Couldn't set 'SSLContext.hostname_checks_common_name'")

        err: MaxRetryError | None
        try:
            with HTTPSConnectionPool(
                no_san_server.host,
                no_san_server.port,
                cert_reqs="CERT_REQUIRED",
                ssl_context=ctx,
                assert_hostname=no_san_server.host if use_assert_hostname else None,
            ) as https_pool:
                https_pool.request("GET", "/")
        except MaxRetryError as e:
            err = e
        else:
            err = None

        # commonName is only valid for DNS names, not IP addresses.
        if no_san_server.host == "localhost":
            assert err is None

        # IP addresses should fail for commonName.
        else:
            assert err is not None
            assert type(err.reason) is SSLError
            assert isinstance(
                err.reason.args[0], (ssl.SSLCertVerificationError, CertificateError)
            )

    def test_assert_hostname_invalid_san(
        self, no_localhost_san_server: ServerConfig
    ) -> None:
        """Ensure SAN errors are not raised while assert_hostname is false"""
        with HTTPSConnectionPool(
            no_localhost_san_server.host,
            no_localhost_san_server.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=no_localhost_san_server.ca_certs,
            assert_hostname=False,
        ) as https_pool:
            https_pool.request("GET", "/")

    def test_assert_hostname_invalid_cn(
        self, no_san_server_with_different_commmon_name: ServerConfig
    ) -> None:
        """Ensure CN errors are not raised while assert_hostname is false"""
        ctx = urllib3.util.ssl_.create_urllib3_context(verify_flags=0)
        with HTTPSConnectionPool(
            no_san_server_with_different_commmon_name.host,
            no_san_server_with_different_commmon_name.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=no_san_server_with_different_commmon_name.ca_certs,
            ssl_context=ctx,
            assert_hostname=False,
        ) as https_pool:
            https_pool.request("GET", "/")


class TestHTTPS_IPV4SAN:
    def test_can_validate_ip_san(self, ipv4_san_server: ServerConfig) -> None:
        """Ensure that urllib3 can validate SANs with IP addresses in them."""
        with HTTPSConnectionPool(
            ipv4_san_server.host,
            ipv4_san_server.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=ipv4_san_server.ca_certs,
        ) as https_pool:
            r = https_pool.request("GET", "/")
            assert r.status == 200


class TestHTTPS_IPV6SAN:
    @pytest.mark.parametrize("host", ["::1", "[::1]"])
    def test_can_validate_ipv6_san(
        self, ipv6_san_server: ServerConfig, host: str, http_version: str
    ) -> None:
        """Ensure that urllib3 can validate SANs with IPv6 addresses in them."""
        with HTTPSConnectionPool(
            host,
            ipv6_san_server.port,
            cert_reqs="CERT_REQUIRED",
            ca_certs=ipv6_san_server.ca_certs,
        ) as https_pool:
            r = https_pool.request("GET", "/")
            assert r.status == 200
            assert r.headers["server"] == f"hypercorn-{http_version}"

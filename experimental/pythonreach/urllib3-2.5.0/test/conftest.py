from __future__ import annotations

import contextlib
import socket
import ssl
import typing
from pathlib import Path

import pytest
import trustme

import urllib3.http2
import urllib3.http2.probe as http2_probe
from dummyserver.app import hypercorn_app
from dummyserver.asgi_proxy import ProxyApp
from dummyserver.hypercornserver import run_hypercorn_in_thread
from dummyserver.socketserver import HAS_IPV6
from dummyserver.testcase import HTTPSHypercornDummyServerTestCase
from urllib3.util import ssl_

from .tz_stub import stub_timezone_ctx


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run integration tests only",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    integration_mode = bool(config.getoption("--integration"))
    skip_integration = pytest.mark.skip(
        reason="skipping, need --integration option to run"
    )
    skip_normal = pytest.mark.skip(
        reason="skipping non integration tests in --integration mode"
    )
    for item in items:
        if "integration" in item.keywords and not integration_mode:
            item.add_marker(skip_integration)
        elif integration_mode and "integration" not in item.keywords:
            item.add_marker(skip_normal)


class ServerConfig(typing.NamedTuple):
    scheme: str
    host: str
    port: int
    ca_certs: str

    @property
    def base_url(self) -> str:
        host = self.host
        if ":" in host:
            host = f"[{host}]"
        return f"{self.scheme}://{host}:{self.port}"


def _write_cert_to_dir(
    cert: trustme.LeafCert, tmpdir: Path, file_prefix: str = "server"
) -> dict[str, str]:
    cert_path = str(tmpdir / ("%s.pem" % file_prefix))
    key_path = str(tmpdir / ("%s.key" % file_prefix))
    cert.private_key_pem.write_to_path(key_path)
    cert.cert_chain_pems[0].write_to_path(cert_path)
    certs = {"keyfile": key_path, "certfile": cert_path}
    return certs


@contextlib.contextmanager
def run_server_in_thread(
    scheme: str, host: str, tmpdir: Path, ca: trustme.CA, server_cert: trustme.LeafCert
) -> typing.Generator[ServerConfig]:
    ca_cert_path = str(tmpdir / "ca.pem")
    ca.cert_pem.write_to_path(ca_cert_path)
    server_certs = _write_cert_to_dir(server_cert, tmpdir)

    with run_hypercorn_in_thread(host, server_certs, hypercorn_app) as port:
        yield ServerConfig(scheme, host, port, ca_cert_path)


@contextlib.contextmanager
def run_server_and_proxy_in_thread(
    proxy_scheme: str,
    proxy_host: str,
    tmpdir: Path,
    ca: trustme.CA,
    proxy_cert: trustme.LeafCert,
    server_cert: trustme.LeafCert,
) -> typing.Generator[tuple[ServerConfig, ServerConfig]]:
    ca_cert_path = str(tmpdir / "ca.pem")
    ca.cert_pem.write_to_path(ca_cert_path)

    server_certs = _write_cert_to_dir(server_cert, tmpdir)
    proxy_certs = _write_cert_to_dir(proxy_cert, tmpdir, "proxy")

    with contextlib.ExitStack() as stack:
        port = stack.enter_context(
            run_hypercorn_in_thread("localhost", server_certs, hypercorn_app)
        )
        proxy_port = stack.enter_context(
            run_hypercorn_in_thread(proxy_host, proxy_certs, ProxyApp())
        )

        yield (
            ServerConfig(proxy_scheme, proxy_host, proxy_port, ca_cert_path),
            ServerConfig("https", "localhost", port, ca_cert_path),
        )


@pytest.fixture(params=["localhost", "127.0.0.1", "::1"])
def loopback_host(request: typing.Any) -> typing.Generator[str]:
    host = request.param
    if host == "::1" and not HAS_IPV6:
        pytest.skip("Test requires IPv6 on loopback")
    yield host


@pytest.fixture()
def san_server(
    loopback_host: str, tmp_path_factory: pytest.TempPathFactory
) -> typing.Generator[ServerConfig]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()

    server_cert = ca.issue_cert(loopback_host)

    with run_server_in_thread("https", loopback_host, tmpdir, ca, server_cert) as cfg:
        yield cfg


@pytest.fixture()
def no_san_server(
    loopback_host: str, tmp_path_factory: pytest.TempPathFactory
) -> typing.Generator[ServerConfig]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    server_cert = ca.issue_cert(common_name=loopback_host)

    with run_server_in_thread("https", loopback_host, tmpdir, ca, server_cert) as cfg:
        yield cfg


@pytest.fixture()
def no_san_server_with_different_commmon_name(
    tmp_path_factory: pytest.TempPathFactory,
) -> typing.Generator[ServerConfig]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    server_cert = ca.issue_cert(common_name="example.com")

    with run_server_in_thread("https", "localhost", tmpdir, ca, server_cert) as cfg:
        yield cfg


@pytest.fixture
def san_proxy_with_server(
    loopback_host: str, tmp_path_factory: pytest.TempPathFactory
) -> typing.Generator[tuple[ServerConfig, ServerConfig]]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    proxy_cert = ca.issue_cert(loopback_host)
    server_cert = ca.issue_cert("localhost")

    with run_server_and_proxy_in_thread(
        "https", loopback_host, tmpdir, ca, proxy_cert, server_cert
    ) as cfg:
        yield cfg


@pytest.fixture
def no_san_proxy_with_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> typing.Generator[tuple[ServerConfig, ServerConfig]]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    # only common name, no subject alternative names
    proxy_cert = ca.issue_cert(common_name="localhost")
    server_cert = ca.issue_cert("localhost")

    with run_server_and_proxy_in_thread(
        "https", "localhost", tmpdir, ca, proxy_cert, server_cert
    ) as cfg:
        yield cfg


@pytest.fixture
def no_localhost_san_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> typing.Generator[ServerConfig]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    # non localhost common name
    server_cert = ca.issue_cert("example.com")

    with run_server_in_thread("https", "localhost", tmpdir, ca, server_cert) as cfg:
        yield cfg


@pytest.fixture
def ipv4_san_proxy_with_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> typing.Generator[tuple[ServerConfig, ServerConfig]]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    # IP address in Subject Alternative Name
    proxy_cert = ca.issue_cert("127.0.0.1")

    server_cert = ca.issue_cert("localhost")

    with run_server_and_proxy_in_thread(
        "https", "127.0.0.1", tmpdir, ca, proxy_cert, server_cert
    ) as cfg:
        yield cfg


@pytest.fixture
def ipv6_san_proxy_with_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> typing.Generator[tuple[ServerConfig, ServerConfig]]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    # IP addresses in Subject Alternative Name
    proxy_cert = ca.issue_cert("::1")

    server_cert = ca.issue_cert("localhost")

    with run_server_and_proxy_in_thread(
        "https", "::1", tmpdir, ca, proxy_cert, server_cert
    ) as cfg:
        yield cfg


@pytest.fixture
def ipv4_san_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> typing.Generator[ServerConfig]:
    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    # IP address in Subject Alternative Name
    server_cert = ca.issue_cert("127.0.0.1")

    with run_server_in_thread("https", "127.0.0.1", tmpdir, ca, server_cert) as cfg:
        yield cfg


@pytest.fixture
def ipv6_san_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> typing.Generator[ServerConfig]:
    if not HAS_IPV6:
        pytest.skip("Only runs on IPv6 systems")

    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    # IP address in Subject Alternative Name
    server_cert = ca.issue_cert("::1")

    with run_server_in_thread("https", "::1", tmpdir, ca, server_cert) as cfg:
        yield cfg


@pytest.fixture
def ipv6_no_san_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> typing.Generator[ServerConfig]:
    if not HAS_IPV6:
        pytest.skip("Only runs on IPv6 systems")

    tmpdir = tmp_path_factory.mktemp("certs")
    ca = trustme.CA()
    # IP address in Common Name
    server_cert = ca.issue_cert(common_name="::1")

    with run_server_in_thread("https", "::1", tmpdir, ca, server_cert) as cfg:
        yield cfg


@pytest.fixture
def stub_timezone(request: pytest.FixtureRequest) -> typing.Generator[None]:
    """
    A pytest fixture that runs the test with a stub timezone.
    """
    with stub_timezone_ctx(request.param):
        yield


@pytest.fixture(scope="session")
def supported_tls_versions() -> typing.AbstractSet[str | None]:
    # We have to create an actual TLS connection
    # to test if the TLS version is not disabled by
    # OpenSSL config. Ubuntu 20.04 specifically
    # disables TLSv1 and TLSv1.1.
    tls_versions = set()

    _server = HTTPSHypercornDummyServerTestCase
    _server.setup_class()
    for _ssl_version_name, min_max_version in (
        ("PROTOCOL_TLSv1", ssl.TLSVersion.TLSv1),
        ("PROTOCOL_TLSv1_1", ssl.TLSVersion.TLSv1_1),
        ("PROTOCOL_TLSv1_2", ssl.TLSVersion.TLSv1_2),
        ("PROTOCOL_TLS", None),
    ):
        _ssl_version = getattr(ssl, _ssl_version_name, 0)
        if _ssl_version == 0:
            continue
        _sock = socket.create_connection((_server.host, _server.port))
        try:
            _sock = ssl_.ssl_wrap_socket(
                _sock,
                ssl_context=ssl_.create_urllib3_context(
                    cert_reqs=ssl.CERT_NONE,
                    ssl_minimum_version=min_max_version,
                    ssl_maximum_version=min_max_version,
                ),
            )
        except ssl.SSLError:
            pass
        else:
            tls_versions.add(_sock.version())
        _sock.close()
    _server.teardown_class()
    return tls_versions


@pytest.fixture(scope="function")
def requires_tlsv1(supported_tls_versions: typing.AbstractSet[str]) -> None:
    """Test requires TLSv1 available"""
    if not hasattr(ssl, "PROTOCOL_TLSv1") or "TLSv1" not in supported_tls_versions:
        pytest.skip("Test requires TLSv1")


@pytest.fixture(scope="function")
def requires_tlsv1_1(supported_tls_versions: typing.AbstractSet[str]) -> None:
    """Test requires TLSv1.1 available"""
    if not hasattr(ssl, "PROTOCOL_TLSv1_1") or "TLSv1.1" not in supported_tls_versions:
        pytest.skip("Test requires TLSv1.1")


@pytest.fixture(scope="function")
def requires_tlsv1_2(supported_tls_versions: typing.AbstractSet[str]) -> None:
    """Test requires TLSv1.2 available"""
    if not hasattr(ssl, "PROTOCOL_TLSv1_2") or "TLSv1.2" not in supported_tls_versions:
        pytest.skip("Test requires TLSv1.2")


@pytest.fixture(scope="function")
def requires_tlsv1_3(supported_tls_versions: typing.AbstractSet[str]) -> None:
    """Test requires TLSv1.3 available"""
    if (
        not getattr(ssl, "HAS_TLSv1_3", False)
        or "TLSv1.3" not in supported_tls_versions
    ):
        pytest.skip("Test requires TLSv1.3")


class ErroringHTTPConnection:
    def __init__(self, *args: typing.Any, **kwargs: typing.Any):
        raise ValueError(
            "HTTP/2 support currently only applies to HTTPS, don't use http_version for HTTP tests"
        )


@pytest.fixture(params=["h11", "h2"])
def http_version(request: pytest.FixtureRequest) -> typing.Generator[str]:
    orig_HTTPConnection: typing.Any = None

    if request.param == "h2":
        urllib3.http2.inject_into_urllib3()

        from urllib3 import connection as urllib3_connection
        from urllib3.connectionpool import HTTPConnectionPool

        orig_HTTPConnection = urllib3_connection.HTTPConnection
        urllib3_connection.HTTPConnection = ErroringHTTPConnection  # type: ignore[misc,assignment]
        HTTPConnectionPool.ConnectionCls = ErroringHTTPConnection  # type: ignore[assignment]
    try:
        yield request.param
    finally:
        if request.param == "h2":
            urllib3_connection.HTTPConnection = orig_HTTPConnection  # type: ignore[misc]
            HTTPConnectionPool.ConnectionCls = orig_HTTPConnection

            urllib3.http2.extract_from_urllib3()


@pytest.fixture(autouse=True, scope="function")
def reset_http2_probe_cache() -> typing.Generator[None]:
    # Always reset the HTTP/2 probe cache per test case.
    try:
        yield
    finally:
        http2_probe._reset()

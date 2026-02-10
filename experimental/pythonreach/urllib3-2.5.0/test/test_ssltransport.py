from __future__ import annotations

import platform
import select
import socket
import ssl
import threading
import typing
from unittest import mock

import pytest

from dummyserver.socketserver import DEFAULT_CA, DEFAULT_CERTS
from dummyserver.testcase import SocketDummyServerTestCase, consume_socket
from urllib3.util import ssl_
from urllib3.util.ssltransport import SSLTransport

# consume_socket can iterate forever, we add timeouts to prevent halting.
PER_TEST_TIMEOUT = 60


def server_client_ssl_contexts() -> tuple[ssl.SSLContext, ssl.SSLContext]:
    if hasattr(ssl, "PROTOCOL_TLS_SERVER"):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(DEFAULT_CERTS["certfile"], DEFAULT_CERTS["keyfile"])

    if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    client_context.load_verify_locations(DEFAULT_CA)
    return server_context, client_context


@typing.overload
def sample_request(binary: typing.Literal[True] = ...) -> bytes: ...


@typing.overload
def sample_request(binary: typing.Literal[False]) -> str: ...


def sample_request(binary: bool = True) -> bytes | str:
    request = (
        b"GET http://www.testing.com/ HTTP/1.1\r\n"
        b"Host: www.testing.com\r\n"
        b"User-Agent: awesome-test\r\n"
        b"\r\n"
    )
    return request if binary else request.decode("utf-8")


def validate_request(
    provided_request: bytearray, binary: typing.Literal[False, True] = True
) -> None:
    assert provided_request is not None
    expected_request = sample_request(binary)
    assert provided_request == expected_request


@typing.overload
def sample_response(binary: typing.Literal[True] = ...) -> bytes: ...


@typing.overload
def sample_response(binary: typing.Literal[False]) -> str: ...


@typing.overload
def sample_response(binary: bool = ...) -> bytes | str: ...


def sample_response(binary: bool = True) -> bytes | str:
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    return response if binary else response.decode("utf-8")


def validate_response(
    provided_response: bytes | bytearray | str, binary: bool = True
) -> None:
    assert provided_response is not None
    expected_response = sample_response(binary)
    assert provided_response == expected_response


def validate_peercert(ssl_socket: SSLTransport) -> None:
    binary_cert = ssl_socket.getpeercert(binary_form=True)
    assert type(binary_cert) is bytes
    assert len(binary_cert) > 0

    cert = ssl_socket.getpeercert()
    assert type(cert) is dict
    assert "serialNumber" in cert
    assert cert["serialNumber"] != ""


class SingleTLSLayerTestCase(SocketDummyServerTestCase):
    """
    Uses the SocketDummyServer to validate a single TLS layer can be
    established through the SSLTransport.
    """

    @classmethod
    def setup_class(cls) -> None:
        cls.server_context, cls.client_context = server_client_ssl_contexts()

    def start_dummy_server(
        self,
        handler: typing.Callable[[socket.socket], None] | None = None,
        validate: bool = True,
    ) -> None:
        quit_event = threading.Event()

        def socket_handler(listener: socket.socket) -> None:
            sock = listener.accept()[0]
            try:
                with self.server_context.wrap_socket(sock, server_side=True) as ssock:
                    request = consume_socket(
                        ssock,
                        quit_event=quit_event,
                    )
                    if not validate:
                        return
                    validate_request(request)
                    ssock.send(sample_response())
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                return

        chosen_handler = handler if handler else socket_handler
        self._start_server(chosen_handler, quit_event=quit_event)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_start_closed_socket(self) -> None:
        """Errors generated from an unconnected socket should bubble up."""
        sock = socket.socket(socket.AF_INET)
        context = ssl.create_default_context()
        sock.close()
        with pytest.raises(OSError):
            SSLTransport(sock, context)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_close_after_handshake(self) -> None:
        """Socket errors should be bubbled up"""
        self.start_dummy_server(validate=False)

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(
            sock, self.client_context, server_hostname="localhost"
        ) as ssock:
            ssock.close()
            with pytest.raises(OSError):
                ssock.send(b"blaaargh")

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_wrap_existing_socket(self) -> None:
        """Validates a single TLS layer can be established."""
        self.start_dummy_server()

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(
            sock, self.client_context, server_hostname="localhost"
        ) as ssock:
            assert ssock.version() is not None
            ssock.send(sample_request())
            response = consume_socket(ssock)
            validate_response(response)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_unbuffered_text_makefile(self) -> None:
        self.start_dummy_server()

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(
            sock, self.client_context, server_hostname="localhost"
        ) as ssock:
            with pytest.raises(ValueError):
                ssock.makefile("r", buffering=0)
            ssock.send(sample_request())
            response = consume_socket(ssock)
            validate_response(response)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_unwrap_existing_socket(self) -> None:
        """
        Validates we can break up the TLS layer
        A full request/response is sent over TLS, and later over plain text.
        """

        def shutdown_handler(listener: socket.socket) -> None:
            with (
                listener.accept()[0] as sock,
                self.server_context.wrap_socket(sock, server_side=True) as ssl_sock,
            ):
                request = consume_socket(ssl_sock)
                validate_request(request)
                ssl_sock.sendall(sample_response())

                with ssl_sock.unwrap() as unwrapped_sock:
                    request = consume_socket(unwrapped_sock)
                    validate_request(request)
                    unwrapped_sock.sendall(sample_response())

        self.start_dummy_server(shutdown_handler)
        with socket.create_connection((self.host, self.port)) as sock:
            ssock = SSLTransport(sock, self.client_context, server_hostname="localhost")

            # request/response over TLS.
            ssock.sendall(sample_request())
            response = consume_socket(ssock)
            validate_response(response)

            # request/response over plaintext after unwrap.
            ssock.unwrap()
            sock.sendall(sample_request())
            response = consume_socket(sock)
            validate_response(response)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_ssl_object_attributes(self) -> None:
        """Ensures common ssl attributes are exposed"""
        self.start_dummy_server()

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(
            sock, self.client_context, server_hostname="localhost"
        ) as ssock:
            cipher = ssock.cipher()
            assert type(cipher) is tuple

            # No chosen protocol.
            assert ssock.selected_alpn_protocol() is None

            shared_ciphers = ssock.shared_ciphers()
            # SSLContext.shared_ciphers() changed behavior completely in a patch version.
            # See: https://github.com/python/cpython/issues/96931
            assert shared_ciphers is None or (
                type(shared_ciphers) is list and len(shared_ciphers) > 0
            )

            assert ssock.compression() is None

            validate_peercert(ssock)

            ssock.send(sample_request())
            response = consume_socket(ssock)
            validate_response(response)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_socket_object_attributes(self) -> None:
        """Ensures common socket attributes are exposed"""
        self.start_dummy_server()

        sock = socket.create_connection((self.host, self.port))
        with SSLTransport(
            sock, self.client_context, server_hostname="localhost"
        ) as ssock:
            assert ssock.fileno() is not None
            test_timeout = 10
            ssock.settimeout(test_timeout)
            assert ssock.gettimeout() == test_timeout
            assert ssock.socket.gettimeout() == test_timeout

            ssock.send(sample_request())
            response = consume_socket(ssock)
            validate_response(response)


class SocketProxyDummyServer(SocketDummyServerTestCase):
    """
    Simulates a proxy that performs a simple I/O loop on client/server
    socket.
    """

    def __init__(
        self, destination_server_host: str, destination_server_port: int
    ) -> None:
        self.destination_server_host = destination_server_host
        self.destination_server_port = destination_server_port
        self.server_ctx, _ = server_client_ssl_contexts()

    def start_proxy_handler(self) -> None:
        """
        Socket handler for the proxy. Terminates the first TLS layer and tunnels
        any bytes needed for client <-> server communicatin.
        """

        def proxy_handler(listener: socket.socket) -> None:
            sock = listener.accept()[0]
            with self.server_ctx.wrap_socket(sock, server_side=True) as client_sock:
                upstream_sock = socket.create_connection(
                    (self.destination_server_host, self.destination_server_port)
                )
                self._read_write_loop(client_sock, upstream_sock)
                upstream_sock.close()
                client_sock.close()

        self._start_server(proxy_handler)

    def _read_write_loop(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket,
        chunks: int = 65536,
    ) -> None:
        inputs = [client_sock, server_sock]
        output = [client_sock, server_sock]

        while inputs:
            readable, writable, exception = select.select(inputs, output, inputs)

            if exception:
                # Error occurred with either of the sockets, time to
                # wrap up, parent func will close sockets.
                break

            for s in readable:
                read_socket, write_socket = None, None
                if s == client_sock:
                    read_socket = client_sock
                    write_socket = server_sock
                else:
                    read_socket = server_sock
                    write_socket = client_sock

                # Ensure buffer is not full before writing
                if write_socket in writable:
                    try:
                        b = read_socket.recv(chunks)
                        if len(b) == 0:
                            # One of the sockets has EOFed, we return to close
                            # both.
                            return
                        write_socket.send(b)
                    except ssl.SSLEOFError:
                        # It's possible, depending on shutdown order, that we'll
                        # try to use a socket that was closed between select
                        # calls.
                        return


class TlsInTlsTestCase(SocketDummyServerTestCase):
    """
    Creates a TLS in TLS tunnel by chaining a 'SocketProxyDummyServer' and a
    `SocketDummyServerTestCase`.

    Client will first connect to the proxy, who will then proxy any bytes send
    to the destination server. First TLS layer terminates at the proxy, second
    TLS layer terminates at the destination server.
    """

    @classmethod
    def setup_class(cls) -> None:
        cls.server_context, cls.client_context = server_client_ssl_contexts()

    @classmethod
    def start_proxy_server(cls) -> None:
        # Proxy server will handle the first TLS connection and create a
        # connection to the destination server.
        cls.proxy_server = SocketProxyDummyServer(cls.host, cls.port)
        cls.proxy_server.start_proxy_handler()

    @classmethod
    def teardown_class(cls) -> None:
        if hasattr(cls, "proxy_server"):
            cls.proxy_server.teardown_class()
        super().teardown_class()

    @classmethod
    def start_destination_server(cls) -> None:
        """
        Socket handler for the destination_server. Terminates the second TLS
        layer and send a basic HTTP response.
        """

        def socket_handler(listener: socket.socket) -> None:
            sock = listener.accept()[0]
            try:
                with cls.server_context.wrap_socket(sock, server_side=True) as ssock:
                    request = consume_socket(ssock)
                    validate_request(request)
                    ssock.send(sample_response())
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError, OSError):
                return
            sock.close()

        cls._start_server(socket_handler)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_tls_in_tls_tunnel(self) -> None:
        """
        Basic communication over the TLS in TLS tunnel.
        """
        self.start_destination_server()
        self.start_proxy_server()

        sock = socket.create_connection(
            (self.proxy_server.host, self.proxy_server.port)
        )
        with self.client_context.wrap_socket(
            sock, server_hostname="localhost"
        ) as proxy_sock:
            with SSLTransport(
                proxy_sock, self.client_context, server_hostname="localhost"
            ) as destination_sock:
                assert destination_sock.version() is not None
                destination_sock.send(sample_request())
                response = consume_socket(destination_sock)
                validate_response(response)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_wrong_sni_hint(self) -> None:
        """
        Provides a wrong sni hint to validate an exception is thrown.
        """
        self.start_destination_server()
        self.start_proxy_server()

        sock = socket.create_connection(
            (self.proxy_server.host, self.proxy_server.port)
        )
        with self.client_context.wrap_socket(
            sock, server_hostname="localhost"
        ) as proxy_sock:
            with pytest.raises(ssl.SSLCertVerificationError):
                SSLTransport(
                    proxy_sock, self.client_context, server_hostname="veryverywrong"
                )

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    @pytest.mark.parametrize("buffering", [None, 0])
    def test_tls_in_tls_makefile_raw_rw_binary(self, buffering: int | None) -> None:
        """
        Uses makefile with read, write and binary modes without buffering.
        """
        self.start_destination_server()
        self.start_proxy_server()

        sock = socket.create_connection(
            (self.proxy_server.host, self.proxy_server.port)
        )
        with self.client_context.wrap_socket(
            sock, server_hostname="localhost"
        ) as proxy_sock:
            with SSLTransport(
                proxy_sock, self.client_context, server_hostname="localhost"
            ) as destination_sock:
                file = destination_sock.makefile("rwb", buffering)
                file.write(sample_request())  # type: ignore[arg-type]
                file.flush()

                response = bytearray(65536)
                wrote = file.readinto(response)  # type: ignore[union-attr]
                assert wrote is not None
                # Allocated response is bigger than the actual response, we
                # rtrim remaining x00 bytes.
                str_response = response.decode("utf-8").rstrip("\x00")
                validate_response(str_response, binary=False)
                file.close()

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="Skipping windows due to text makefile support",
    )
    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_tls_in_tls_makefile_rw_text(self) -> None:
        """
        Creates a separate buffer for reading and writing using text mode and
        utf-8 encoding.
        """
        self.start_destination_server()
        self.start_proxy_server()

        sock = socket.create_connection(
            (self.proxy_server.host, self.proxy_server.port)
        )
        with self.client_context.wrap_socket(
            sock, server_hostname="localhost"
        ) as proxy_sock:
            with SSLTransport(
                proxy_sock, self.client_context, server_hostname="localhost"
            ) as destination_sock:
                read = destination_sock.makefile("r", encoding="utf-8")
                write = destination_sock.makefile("w", encoding="utf-8")

                write.write(sample_request(binary=False))  # type: ignore[arg-type, call-overload]
                write.flush()

                response = read.read()
                assert type(response) is str
                if "\r" not in response:
                    # Carriage return will be removed when reading as a file on
                    # some platforms.  We add it before the comparison.
                    assert type(response) is str
                    response = response.replace("\n", "\r\n")
                validate_response(response, binary=False)

    @pytest.mark.timeout(PER_TEST_TIMEOUT)
    def test_tls_in_tls_recv_into_sendall(self) -> None:
        """
        Valides recv_into and sendall also work as expected. Other tests are
        using recv/send.
        """
        self.start_destination_server()
        self.start_proxy_server()

        sock = socket.create_connection(
            (self.proxy_server.host, self.proxy_server.port)
        )
        with self.client_context.wrap_socket(
            sock, server_hostname="localhost"
        ) as proxy_sock:
            with SSLTransport(
                proxy_sock, self.client_context, server_hostname="localhost"
            ) as destination_sock:
                destination_sock.sendall(sample_request())
                response = bytearray(65536)
                destination_sock.recv_into(response)
                str_response = response.decode("utf-8").rstrip("\x00")
                validate_response(str_response, binary=False)


class TestSSLTransportWithMock:
    def test_constructor_params(self) -> None:
        server_hostname = "example-domain.com"
        sock = mock.Mock()
        context = mock.create_autospec(ssl_.SSLContext)
        ssl_transport = SSLTransport(
            sock, context, server_hostname=server_hostname, suppress_ragged_eofs=False
        )
        context.wrap_bio.assert_called_with(
            mock.ANY, mock.ANY, server_hostname=server_hostname
        )
        assert not ssl_transport.suppress_ragged_eofs

    def test_various_flags_errors(self) -> None:
        server_hostname = "example-domain.com"
        sock = mock.Mock()
        context = mock.create_autospec(ssl_.SSLContext)
        ssl_transport = SSLTransport(
            sock, context, server_hostname=server_hostname, suppress_ragged_eofs=False
        )
        with pytest.raises(ValueError):
            ssl_transport.recv(flags=1)

        with pytest.raises(ValueError):
            ssl_transport.recv_into(bytearray(), flags=1)

        with pytest.raises(ValueError):
            ssl_transport.sendall(bytearray(), flags=1)

        with pytest.raises(ValueError):
            ssl_transport.send(None, flags=1)  # type: ignore[arg-type]

    def test_makefile_wrong_mode_error(self) -> None:
        server_hostname = "example-domain.com"
        sock = mock.Mock()
        context = mock.create_autospec(ssl_.SSLContext)
        ssl_transport = SSLTransport(
            sock, context, server_hostname=server_hostname, suppress_ragged_eofs=False
        )
        with pytest.raises(ValueError):
            ssl_transport.makefile(mode="x")

    def test_wrap_ssl_read_error(self) -> None:
        server_hostname = "example-domain.com"
        sock = mock.Mock()
        context = mock.create_autospec(ssl_.SSLContext)
        ssl_transport = SSLTransport(
            sock, context, server_hostname=server_hostname, suppress_ragged_eofs=False
        )
        with mock.patch.object(ssl_transport, "_ssl_io_loop") as _ssl_io_loop:
            _ssl_io_loop.side_effect = ssl.SSLError()
            with pytest.raises(ssl.SSLError):
                ssl_transport._wrap_ssl_read(1)

from __future__ import annotations

import contextlib
import errno
import functools
import socket
import sys
import typing

import anyio.abc
import anyio.to_thread
import hypercorn
import hypercorn.config
import hypercorn.trio
import hypercorn.typing
import trio
from quart_trio import QuartTrio

from urllib3.util.url import parse_url


class Config(hypercorn.Config):
    def create_sockets(self) -> hypercorn.config.Sockets:
        assert len(self.bind) == 1
        secure_sockets, insecure_sockets = [], []
        if self.ssl_enabled:
            secure_sockets = self._create_urllib3_sockets(self.bind[0])
        else:
            insecure_sockets = self._create_urllib3_sockets(self.bind[0])
        return hypercorn.config.Sockets(
            secure_sockets, insecure_sockets, quic_sockets=[]
        )

    def _retry_create_urllib3_sockets(self, bind: str) -> list[socket.socket]:
        # When we request a socket with host localhost and port zero, Hypercorn
        # only binds to IPv4. But we want to bind to IPv6 too, otherwise we
        # waste about 2 second for each test on Windows since urllib3 tries
        # IPv6 first as it does not implement Happy Eyeballs.
        # We want to use the same port for IPv4 and IPv6, so we first get a
        # free port in IPv4 and request the same port in IPv6. But that port
        # could easily be taken with IPv6 already, especially on crowded CI
        # environments, which would fail the run. For this reason we retry
        # _create_urllib3_sockets up to 10 times, which completely eliminates
        # this failure mode.
        for i in range(10):
            try:
                return self._create_urllib3_sockets(bind)
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    print(
                        f"Retrying binding to {bind} after EADDRINUSE", file=sys.stderr
                    )
        raise OSError("failed to bind socket")

    def _create_urllib3_sockets(self, bind: str) -> list[socket.socket]:
        sockets = []

        bind = bind.replace("[", "").replace("]", "")
        host = bind.rsplit(":", 1)[0]
        port = 0  # Get a random port
        family = socket.AF_INET6 if ":" in host else socket.AF_UNSPEC

        for res in socket.getaddrinfo(
            host, port, family, socket.SOCK_STREAM, 0, socket.AI_PASSIVE
        ):
            af, socktype, proto, canonname, sockadddr = res

            sock = socket.socket(af, socket.SOCK_STREAM, proto)

            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            sock.setblocking(False)
            sock.bind((host, port))
            port = sock.getsockname()[1]
            sock.set_inheritable(True)
            sockets.append(sock)

        return sockets


async def _start_server(
    config: Config,
    app: QuartTrio,
    shutdown_event: trio.Event,
    *,
    task_status: anyio.abc.TaskStatus[list[str]] = anyio.TASK_STATUS_IGNORED,
) -> None:
    async with trio.open_nursery() as nursery:
        with trio.fail_after(5):
            config_bind: list[str]
            config_bind = await nursery.start(
                functools.partial(
                    hypercorn.trio.serve,
                    app,
                    config,
                    shutdown_trigger=shutdown_event.wait,
                )
            )
        task_status.started(config_bind)


@contextlib.contextmanager
def run_hypercorn_in_thread(
    host: str, certs: dict[str, typing.Any] | None, app: hypercorn.typing.ASGIFramework
) -> typing.Iterator[int]:
    config = Config()
    if certs:
        config.certfile = certs["certfile"]
        config.keyfile = certs["keyfile"]
        if "cert_reqs" in certs:
            config.verify_mode = certs["cert_reqs"]
        if "ca_certs" in certs:
            config.ca_certs = certs["ca_certs"]
        if "alpn_protocols" in certs:
            config.alpn_protocols = certs["alpn_protocols"]
    config.bind = [f"{host}:0"]

    shutdown_event = trio.Event()

    with anyio.from_thread.start_blocking_portal(backend="trio") as portal:
        future, config_bind = portal.start_task(
            _start_server, config, app, shutdown_event
        )
        try:
            port = parse_url(config_bind[0]).port
            assert port is not None
            yield port
        finally:
            portal.call(shutdown_event.set)
            future.result()


def main() -> int:
    # For debugging dummyserver itself - PYTHONPATH=src python -m dummyserver.hypercornserver
    from .app import hypercorn_app

    config = Config()
    config.bind = ["localhost:0"]
    shutdown_event = trio.Event()
    trio.run(_start_server, config, hypercorn_app, shutdown_event)
    return 0


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import contextlib
import os
import random
import textwrap
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from dummyserver.app import pyodide_testing_app
from dummyserver.hypercornserver import run_hypercorn_in_thread
from dummyserver.socketserver import DEFAULT_CERTS

_coverage_count = 0


def _get_coverage_filename(prefix: str) -> str:
    global _coverage_count
    _coverage_count += 1
    rand_part = "".join([random.choice("1234567890") for x in range(20)])
    return prefix + rand_part + f".{_coverage_count}"


@pytest.fixture(scope="module")
def testserver_http(
    request: pytest.FixtureRequest,
) -> Generator[PyodideServerInfo]:
    pyodide_dist_dir = Path(os.getcwd(), request.config.getoption("--dist-dir"))
    pyodide_testing_app.config["pyodide_dist_dir"] = str(pyodide_dist_dir)
    http_host = "localhost"
    with contextlib.ExitStack() as stack:
        http_port = stack.enter_context(
            run_hypercorn_in_thread(http_host, None, pyodide_testing_app)
        )
        https_port = stack.enter_context(
            run_hypercorn_in_thread(http_host, DEFAULT_CERTS, pyodide_testing_app)
        )

        yield PyodideServerInfo(
            http_host=http_host,
            http_port=http_port,
            https_port=https_port,
            pyodide_dist_dir=pyodide_dist_dir,
        )
        print("Server teardown")


@dataclass
class PyodideServerInfo:
    http_port: int
    https_port: int
    http_host: str
    pyodide_dist_dir: Path


@pytest.fixture()
def selenium_with_jspi_if_possible(
    request: pytest.FixtureRequest, runtime: str, has_jspi: bool
) -> Generator[Any]:
    if runtime.startswith("firefox") or not has_jspi:
        fixture_name = "selenium"
        with_jspi = False
    else:
        fixture_name = "selenium_jspi"
        with_jspi = True
    selenium_obj = request.getfixturevalue(fixture_name)
    selenium_obj.with_jspi = with_jspi
    yield selenium_obj


@pytest.fixture()
def selenium_coverage(
    selenium_with_jspi_if_possible: Any, testserver_http: PyodideServerInfo
) -> Generator[Any]:
    def _install_packages(self: Any) -> None:
        if self.browser == "node":
            # stop Node.js checking our https certificates
            self.run_js('process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;')
        # install urllib3 from our test server, rather than from existing package
        result = self.run_js(
            f'await pyodide.loadPackage("http://{testserver_http.http_host}:{testserver_http.http_port}/dist/urllib3.whl")'
        )
        if not self.with_jspi:
            # force Chrome to execute the current test without JSPI
            # even though it is always enabled in
            # chrome >= 137. We do this by monkeypatching
            # pyodide.ffi.can_run_sync
            self.run_async(
                """
                import pyodide.ffi
                if pyodide.ffi.can_run_sync():
                    pyodide.ffi.can_run_sync = lambda: False
                """
            )

        print("Installed package:", result)
        self.run_js(
            """
            await pyodide.loadPackage("coverage")
            await pyodide.runPythonAsync(`import coverage
_coverage= coverage.Coverage(source_pkgs=['urllib3'])
_coverage.start()
        `
        )"""
        )

    setattr(
        selenium_with_jspi_if_possible,
        "_install_packages",
        _install_packages.__get__(
            selenium_with_jspi_if_possible, selenium_with_jspi_if_possible.__class__
        ),
    )

    selenium_with_jspi_if_possible._install_packages()
    yield selenium_with_jspi_if_possible
    # on teardown, save _coverage output
    coverage_out_binary = bytes(
        selenium_with_jspi_if_possible.run_js(
            """
return await pyodide.runPythonAsync(`
_coverage.stop()
_coverage.save()
_coverage_datafile = open(".coverage","rb")
_coverage_outdata = _coverage_datafile.read()
# avoid polluting main namespace too much
import js as _coverage_js
# convert to js Array (as default conversion is TypedArray which does
# bad things in firefox)
_coverage_js.Array.from_(_coverage_outdata)
`)
    """
        )
    )
    with open(f"{_get_coverage_filename('.coverage.emscripten.')}", "wb") as outfile:
        outfile.write(coverage_out_binary)


class ServerRunnerInfo:
    def __init__(
        self, host: str, port: int, selenium: Any, dist_dir: Path, has_jspi: bool
    ) -> None:
        self.host = host
        self.port = port
        self.selenium = selenium
        self.dist_dir = dist_dir
        self.has_jspi = has_jspi

    def run_webworker(self, code: str) -> Any:
        if isinstance(code, str) and code.startswith("\n"):
            # we have a multiline string, fix indentation
            code = textwrap.dedent(code)

        # add coverage collection to this code
        coverage_init_code = textwrap.dedent(
            """
            import coverage
            _coverage= coverage.Coverage(source_pkgs=['urllib3'])
            _coverage.start()
            """
        )

        # Monkeypatch pyodide to force disable JSPI in newer chrome
        # so those code paths get tested
        if self.has_jspi is False:
            jspi_fix_code = textwrap.dedent(
                """
                import pyodide.ffi
                if pyodide.ffi.can_run_sync():
                    pyodide.ffi.can_run_sync = lambda: False
                """
            )
        else:
            jspi_fix_code = ""

        coverage_end_code = textwrap.dedent(
            """
            _coverage.stop()
            _coverage.save()
            _coverage_datafile = open(".coverage","rb")
            _coverage_outdata = _coverage_datafile.read()
            # avoid polluting main namespace too much
            import js as _coverage_js
            # convert to js Array (as default conversion is TypedArray which does
            # bad things in firefox)
            _coverage_js.Array.from_(_coverage_outdata)
            """
        )

        # the ordering of these code blocks is important - makes sure
        # that the first thing that happens is our wheel is loaded
        code = (
            coverage_init_code
            + "\n"
            + jspi_fix_code
            + "\n"
            + code
            + "\n"
            + coverage_end_code
        )

        if self.selenium.browser == "firefox":
            # running in worker is SLOW on firefox
            self.selenium.set_script_timeout(30)
        if self.selenium.browser == "node":
            worker_path = str(self.dist_dir / "webworker_dev.js")
            self.selenium.run_js(
                f"""const {{
                    Worker, isMainThread, parentPort, workerData,
                }} = require('node:worker_threads');
                globalThis.Worker= Worker;
                process.chdir('{self.dist_dir}');
                """
            )
        else:
            worker_path = f"https://{self.host}:{self.port}/pyodide/webworker_dev.js"
        coverage_out_binary = bytes(
            self.selenium.run_js(
                f"""
            let worker = new Worker('{worker_path}');
            let p = new Promise((res, rej) => {{
                worker.onmessageerror = e => rej(e);
                worker.onerror = e => rej(e);
                worker.onmessage = e => {{
                    if (e.data.results) {{
                       res(e.data.results);
                    }} else {{
                       rej(e.data.error);
                    }}
                }};
                worker.postMessage({{ python: {repr(code)} }});
            }});
            return await p;
            """,
                pyodide_checks=False,
            )
        )
        with open(
            f"{_get_coverage_filename('.coverage.emscripten.worker.')}", "wb"
        ) as outfile:
            outfile.write(coverage_out_binary)


# run pyodide on our test server instead of on the default
# pytest-pyodide one - this makes it so that
# we are at the same origin as web requests to server_host
@pytest.fixture()
def run_from_server(
    selenium_coverage: Any, testserver_http: PyodideServerInfo
) -> Generator[ServerRunnerInfo]:
    if selenium_coverage.browser != "node":
        # on node, we don't need to be on the same origin
        # so we can ignore all this
        addr = f"https://{testserver_http.http_host}:{testserver_http.https_port}/pyodide/test.html"
        selenium_coverage.goto(addr)
        selenium_coverage.javascript_setup()
        selenium_coverage.load_pyodide()
        selenium_coverage.initialize_pyodide()
        selenium_coverage.save_state()
        selenium_coverage.restore_state()
        selenium_coverage._install_packages()
    dist_dir = testserver_http.pyodide_dist_dir
    yield ServerRunnerInfo(
        testserver_http.http_host,
        testserver_http.https_port,
        selenium_coverage,
        dist_dir,
        selenium_coverage.with_jspi,
    )


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Generate tests with WebAssembly JavaScript Promise Integration both
     enabled and disabled depending on browser/node.js support for features.
     Also drops any test that requires a browser or web-workers in Node.js.
    ).
    """
    if "has_jspi" in metafunc.fixturenames:
        can_run_with_jspi = False
        can_run_without_jspi = False
        # node only supports JSPI and doesn't support workers or
        # webbrowser specific tests
        if metafunc.config.getoption("--runtime").startswith("node"):
            if (
                metafunc.definition.get_closest_marker("webworkers") is None
                and metafunc.definition.get_closest_marker("in_webbrowser") is None
            ):
                can_run_with_jspi = True
            if metafunc.definition.get_closest_marker("node_without_jspi"):
                can_run_without_jspi = True
                can_run_with_jspi = False
        # firefox doesn't support JSPI
        elif metafunc.config.getoption("--runtime").startswith("firefox"):
            can_run_without_jspi = True
        else:
            # chrome supports JSPI on or off
            can_run_without_jspi = True
            can_run_with_jspi = True

        # if the function is marked to only run with or without jspi,
        # then disable the alternative option
        if metafunc.definition.get_closest_marker("with_jspi"):
            can_run_without_jspi = False
        elif metafunc.definition.get_closest_marker("without_jspi"):
            can_run_with_jspi = False

        jspi_options = []
        if can_run_without_jspi:
            jspi_options.append(False)
        if can_run_with_jspi:
            jspi_options.append(True)
        metafunc.parametrize("has_jspi", jspi_options)

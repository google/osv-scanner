from __future__ import annotations

import sys
import typing

import pytest

from urllib3.fields import _TYPE_FIELD_VALUE_TUPLE

from ...port_helpers import find_unused_port

if sys.version_info < (3, 11):
    # pyodide only works on 3.11+
    pytest.skip(allow_module_level=True)

# only run these tests if pytest_pyodide is installed
# so we don't break non-emscripten pytest running
pytest_pyodide = pytest.importorskip("pytest_pyodide")

from pytest_pyodide import run_in_pyodide  # type: ignore[import-not-found] # noqa: E402

from .conftest import PyodideServerInfo, ServerRunnerInfo  # noqa: E402

# make our ssl certificates work in chrome
pyodide_config = pytest_pyodide.config.get_global_config()
pyodide_config.set_flags(
    "chrome", ["ignore-certificate-errors"] + pyodide_config.get_flags("chrome")
)


def test_index(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int, has_jspi: bool) -> None:  # type: ignore[no-untyped-def]
        import urllib3.contrib.emscripten.fetch
        from urllib3.connection import HTTPConnection
        from urllib3.response import BaseHTTPResponse

        assert urllib3.contrib.emscripten.fetch.has_jspi() == has_jspi
        conn = HTTPConnection(host, port)
        url = f"http://{host}:{port}/"
        conn.request("GET", url)
        response = conn.getresponse()
        # check methods of response
        assert isinstance(response, BaseHTTPResponse)
        assert response.url == url
        response.url = "http://woo"
        assert response.url == "http://woo"
        assert response.connection == conn
        assert response.retries is None
        data1 = response.data
        decoded1 = data1.decode("utf-8")
        data2 = response.data  # check that getting data twice works
        decoded2 = data2.decode("utf-8")
        assert decoded1 == decoded2 == "Dummy server!"

    pyodide_test(
        selenium_coverage,
        testserver_http.http_host,
        testserver_http.http_port,
        has_jspi,
    )


def test_pool_requests(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int, https_port: int, has_jspi: bool) -> None:  # type: ignore[no-untyped-def]
        # first with PoolManager
        import urllib3
        import urllib3.contrib.emscripten.fetch

        assert urllib3.contrib.emscripten.fetch.has_jspi() == has_jspi

        http = urllib3.PoolManager()
        resp = http.request("GET", f"http://{host}:{port}/")
        assert resp.data.decode("utf-8") == "Dummy server!"

        resp2 = http.request("GET", f"http://{host}:{port}/index")
        assert resp2.data.decode("utf-8") == "Dummy server!"

        # should all have come from one pool
        assert len(http.pools) == 1

        resp3 = http.request("GET", f"https://{host}:{https_port}/")
        assert resp3.data.decode("utf-8") == "Dummy server!"

        # one http pool + one https pool
        assert len(http.pools) == 2

        # now with ConnectionPool
        # because block == True, this will fail if the connection isn't
        # returned to the pool correctly after the first request
        pool = urllib3.HTTPConnectionPool(host, port, maxsize=1, block=True)
        resp3 = pool.urlopen("GET", "/index")
        assert resp3.data.decode("utf-8") == "Dummy server!"

        resp4 = pool.urlopen("GET", "/")
        assert resp4.data.decode("utf-8") == "Dummy server!"

        # now with manual release of connection
        # first - connection should be released once all
        # data is read
        pool2 = urllib3.HTTPConnectionPool(host, port, maxsize=1, block=True)

        resp5 = pool2.urlopen("GET", "/index", preload_content=False)
        assert pool2.pool is not None
        # at this point, the connection should not be in the pool
        assert pool2.pool.qsize() == 0
        assert resp5.data.decode("utf-8") == "Dummy server!"
        # now we've read all the data, connection should be back to the pool
        assert pool2.pool.qsize() == 1
        resp6 = pool2.urlopen("GET", "/index", preload_content=False)
        assert pool2.pool.qsize() == 0
        # force it back to the pool
        resp6.release_conn()
        assert pool2.pool.qsize() == 1
        read_str = resp6.read()
        # for consistency with urllib3, this still returns the correct data even though
        # we are in theory not using the connection any more
        assert read_str.decode("utf-8") == "Dummy server!"

    pyodide_test(
        selenium_coverage,
        testserver_http.http_host,
        testserver_http.http_port,
        testserver_http.https_port,
        has_jspi,
    )


# wrong protocol / protocol error etc. should raise an exception of http.client.HTTPException
def test_wrong_protocol(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import http.client

        import pytest

        from urllib3.connection import HTTPConnection

        conn = HTTPConnection(host, port)
        with pytest.raises(http.client.HTTPException):
            conn.request("GET", f"http://{host}:{port}/")

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.https_port
    )


# wrong protocol / protocol error etc. should raise an exception of http.client.HTTPException
def test_bad_method(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import http.client

        import pytest

        from urllib3.connection import HTTPConnection

        conn = HTTPConnection(host, port)
        with pytest.raises(http.client.HTTPException):
            conn.request("TRACE", f"http://{host}:{port}/")

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.https_port
    )


# no connection - should raise
def test_no_response(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import http.client

        import pytest

        from urllib3.connection import HTTPConnection

        conn = HTTPConnection(host, port)
        with pytest.raises(http.client.HTTPException):
            conn.request("GET", f"http://{host}:{port}/")
            _ = conn.getresponse()

    pyodide_test(selenium_coverage, testserver_http.http_host, find_unused_port())


def test_404(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        from urllib3.connection import HTTPConnection
        from urllib3.response import BaseHTTPResponse

        conn = HTTPConnection(host, port)
        conn.request("GET", f"http://{host}:{port}/status?status=404 NOT FOUND")
        response = conn.getresponse()
        assert isinstance(response, BaseHTTPResponse)
        assert response.status == 404

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


# setting timeout should show a warning to js console
# if we're on the ui thread, because XMLHttpRequest doesn't
# support timeout in async mode if globalThis == Window
@pytest.mark.without_jspi
def test_timeout_warning(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
) -> None:
    @run_in_pyodide()  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import js  # type: ignore[import-not-found]

        import urllib3.contrib.emscripten.fetch
        from urllib3.connection import HTTPConnection

        old_log = js.console.warn
        log_msgs = []

        def capture_log(*args):  # type: ignore[no-untyped-def]
            log_msgs.append(str(args))
            old_log(*args)

        js.console.warn = capture_log

        conn = HTTPConnection(host, port, timeout=1.0)
        conn.request("GET", f"http://{host}:{port}/")
        conn.getresponse()
        js.console.warn = old_log
        # should have shown timeout warning exactly once by now
        assert len([x for x in log_msgs if x.find("Warning: Timeout") != -1]) == 1
        assert urllib3.contrib.emscripten.fetch._SHOWN_TIMEOUT_WARNING

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


@pytest.mark.webworkers
def test_timeout_in_worker_non_streaming(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
    has_jspi: bool,
) -> None:
    worker_code = f"""
        from urllib3.exceptions import TimeoutError
        from urllib3.connection import HTTPConnection
        from pyodide.ffi import JsException
        from http.client import HTTPException
        conn = HTTPConnection("{testserver_http.http_host}", {testserver_http.http_port},timeout=1.0)
        result=-1
        try:
            conn.request("GET","/slow",preload_content = True)
            _response = conn.getresponse()
            result=-3
        except TimeoutError as e:
            result=1 # we've got the correct exception
        except HTTPException as e:
            result=-3
        except BaseException as e:
            result=-2
            raise BaseException(str(result)+":"+str(type(e))+str(e.args) )
        except JsException as e:
            result=-4
        assert result == 1
"""
    run_from_server.run_webworker(worker_code)


@pytest.mark.webworkers
def test_timeout_in_worker_streaming(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
    has_jspi: bool,
) -> None:
    worker_code = f"""
        import urllib3.contrib.emscripten.fetch
        await urllib3.contrib.emscripten.fetch.wait_for_streaming_ready()
        from urllib3.exceptions import TimeoutError
        from urllib3.connection import HTTPConnection
        conn = HTTPConnection("{testserver_http.http_host}", {testserver_http.http_port},timeout=1.0)
        result=-1
        try:
            conn.request("GET","/slow",preload_content=False)
            _response = conn.getresponse()
            result=-3
        except TimeoutError as e:
            result=1 # we've got the correct exception
        except BaseException as e:
            result=-2
        assert result == 1
"""
    run_from_server.run_webworker(worker_code)


def test_index_https(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        from urllib3.connection import HTTPSConnection
        from urllib3.response import BaseHTTPResponse

        conn = HTTPSConnection(host, port)
        conn.request("GET", f"https://{host}:{port}/")
        response = conn.getresponse()
        assert isinstance(response, BaseHTTPResponse)
        data = response.data
        assert data.decode("utf-8") == "Dummy server!"

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.https_port
    )


@pytest.mark.without_jspi
def test_non_streaming_no_fallback_warning(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import js

        import urllib3.contrib.emscripten.fetch
        from urllib3.connection import HTTPSConnection
        from urllib3.response import BaseHTTPResponse

        log_msgs = []
        old_log = js.console.warn

        def capture_log(*args):  # type: ignore[no-untyped-def]
            log_msgs.append(str(args))
            old_log(*args)

        js.console.warn = capture_log
        conn = HTTPSConnection(host, port)
        conn.request("GET", f"https://{host}:{port}/", preload_content=True)
        response = conn.getresponse()
        js.console.warn = old_log
        assert isinstance(response, BaseHTTPResponse)
        data = response.data
        assert data.decode("utf-8") == "Dummy server!"
        # no console warnings because we didn't ask it to stream the response
        # check no log messages
        assert (
            len([x for x in log_msgs if x.find("Can't stream HTTP requests") != -1])
            == 0
        )
        assert not urllib3.contrib.emscripten.fetch._SHOWN_STREAMING_WARNING

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.https_port
    )


@pytest.mark.without_jspi
def test_streaming_fallback_warning(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import js

        import urllib3.contrib.emscripten.fetch
        from urllib3.connection import HTTPSConnection
        from urllib3.response import BaseHTTPResponse

        # monkeypatch is_cross_origin_isolated so that it warns about that
        # even if we're serving it so it is fine
        urllib3.contrib.emscripten.fetch.is_cross_origin_isolated = lambda: False

        log_msgs = []
        old_log = js.console.warn

        def capture_log(*args):  # type: ignore[no-untyped-def]
            log_msgs.append(str(args))
            old_log(*args)

        js.console.warn = capture_log

        conn = HTTPSConnection(host, port)
        conn.request("GET", f"https://{host}:{port}/", preload_content=False)
        response = conn.getresponse()
        js.console.warn = old_log
        assert isinstance(response, BaseHTTPResponse)
        data = response.data
        assert data.decode("utf-8") == "Dummy server!"
        # check that it has warned about falling back to non-streaming fetch exactly once
        assert (
            len([x for x in log_msgs if x.find("Can't stream HTTP requests") != -1])
            == 1
        )
        assert urllib3.contrib.emscripten.fetch._SHOWN_STREAMING_WARNING

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.https_port
    )


def test_specific_method(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
    has_jspi: bool,
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        from urllib3 import HTTPSConnectionPool

        with HTTPSConnectionPool(host, port) as pool:
            path = "/specific_method?method=POST"
            response = pool.request("POST", path)
            assert response.status == 200

            response = pool.request("PUT", path)
            assert response.status == 400

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.https_port
    )


@pytest.mark.webworkers
def test_streaming_download(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
    has_jspi: bool,
) -> None:
    # test streaming download, which must be in a webworker
    # as you can't do it on main thread

    # this should return the 17mb big file, and
    # should not log any warning about falling back
    bigfile_url = (
        f"http://{testserver_http.http_host}:{testserver_http.http_port}/bigfile"
    )
    worker_code = f"""
            import urllib3.contrib.emscripten.fetch
            await urllib3.contrib.emscripten.fetch.wait_for_streaming_ready()
            from urllib3.response import BaseHTTPResponse
            from urllib3.connection import HTTPConnection

            conn = HTTPConnection("{testserver_http.http_host}", {testserver_http.http_port})
            conn.request("GET", "{bigfile_url}",preload_content=False)
            response = conn.getresponse()
            assert isinstance(response, BaseHTTPResponse)
            assert urllib3.contrib.emscripten.fetch._SHOWN_STREAMING_WARNING==False
            assert(urllib3.contrib.emscripten.fetch.has_jspi() == {has_jspi})
            data=response.data.decode('utf-8')
            assert len(data) == 17825792
"""
    run_from_server.run_webworker(worker_code)


@pytest.mark.webworkers
def test_streaming_close(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
    has_jspi: bool,
) -> None:
    # test streaming download, which must be in a webworker
    # as you can't do it on main thread

    # this should return the 17mb big file, and
    # should not log any warning about falling back
    url = f"http://{testserver_http.http_host}:{testserver_http.http_port}/"
    worker_code = f"""
            import urllib3.contrib.emscripten.fetch
            await urllib3.contrib.emscripten.fetch.wait_for_streaming_ready()
            from urllib3.response import BaseHTTPResponse
            from urllib3.connection import HTTPConnection
            from io import RawIOBase

            conn = HTTPConnection("{testserver_http.http_host}", {testserver_http.http_port})
            conn.request("GET", "{url}",preload_content=False)
            response = conn.getresponse()
            # check body is a RawIOBase stream and isn't seekable, writeable
            body_internal = response._response.body
            assert(isinstance(body_internal,RawIOBase))
            assert(body_internal.writable() is False)
            assert(body_internal.seekable() is False)
            assert(body_internal.readable() is True)
            assert(urllib3.contrib.emscripten.fetch.has_jspi() == {has_jspi})

            response.drain_conn()
            x=response.read()
            assert(not x)
            response.close()
            conn.close()
            # try and make destructor be covered
            # by killing everything
            del response
            del body_internal
            del conn
"""
    run_from_server.run_webworker(worker_code)


@pytest.mark.webworkers
def test_streaming_bad_url(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
    has_jspi: bool,
) -> None:
    # this should cause an error
    # because the protocol is bad
    bad_url = f"hsffsdft://{testserver_http.http_host}:{testserver_http.http_port}/"
    # this must be in a webworker
    # as you can't do it on main thread
    worker_code = f"""
            import pytest
            import http.client
            import urllib3.contrib.emscripten.fetch
            await urllib3.contrib.emscripten.fetch.wait_for_streaming_ready()
            from urllib3.response import BaseHTTPResponse
            from urllib3.connection import HTTPConnection

            conn = HTTPConnection("{testserver_http.http_host}", {testserver_http.http_port})
            with pytest.raises(http.client.HTTPException):
                conn.request("GET", "{bad_url}",preload_content=False)
"""
    run_from_server.run_webworker(worker_code)


@pytest.mark.webworkers
def test_streaming_bad_method(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
    has_jspi: bool,
) -> None:
    # this should cause an error
    # because the protocol is bad
    bad_url = f"http://{testserver_http.http_host}:{testserver_http.http_port}/"
    # this must be in a webworker
    # as you can't do it on main thread
    worker_code = f"""
            import pytest
            import http.client

            import urllib3.contrib.emscripten.fetch
            await urllib3.contrib.emscripten.fetch.wait_for_streaming_ready()
            from urllib3.response import BaseHTTPResponse
            from urllib3.connection import HTTPConnection

            conn = HTTPConnection("{testserver_http.http_host}", {testserver_http.http_port})
            with pytest.raises(http.client.HTTPException):
                # TRACE method should throw SecurityError in Javascript
                conn.request("TRACE", "{bad_url}",preload_content=False)
"""
    run_from_server.run_webworker(worker_code)


@pytest.mark.webworkers
@pytest.mark.without_jspi
def test_streaming_notready_warning(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
) -> None:
    # test streaming download but don't wait for
    # worker to be ready - should fallback to non-streaming
    # and log a warning
    file_url = f"http://{testserver_http.http_host}:{testserver_http.http_port}/"
    worker_code = f"""
        import js
        import urllib3.contrib.emscripten.fetch
        from urllib3.response import BaseHTTPResponse
        from urllib3.connection import HTTPConnection

        urllib3.contrib.emscripten.fetch.streaming_ready = lambda :False
        log_msgs=[]
        old_log=js.console.warn
        def capture_log(*args):
            log_msgs.append(str(args))
            old_log(*args)
        js.console.warn=capture_log

        conn = HTTPConnection("{testserver_http.http_host}", {testserver_http.http_port})
        conn.request("GET", "{file_url}",preload_content=False)
        js.console.warn=old_log
        response = conn.getresponse()
        assert isinstance(response, BaseHTTPResponse)
        data=response.data.decode('utf-8')
        #assert len([x for x in log_msgs if x.find("Can't stream HTTP requests")!=-1])==1
        #assert urllib3.contrib.emscripten.fetch._SHOWN_STREAMING_WARNING==True
        """
    run_from_server.run_webworker(worker_code)


def test_post_receive_json(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import json

        from urllib3.connection import HTTPConnection
        from urllib3.response import BaseHTTPResponse

        json_data = {
            "Bears": "like",
            "to": {"eat": "buns", "with": ["marmalade", "and custard"]},
        }
        conn = HTTPConnection(host, port)
        conn.request(
            "POST",
            f"http://{host}:{port}/echo_json",
            body=json.dumps(json_data).encode("utf-8"),
            headers={"Content-type": "application/json"},
        )
        response = conn.getresponse()
        assert isinstance(response, BaseHTTPResponse)
        data = response.json()
        assert data == json_data

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


def test_upload(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        from urllib3 import HTTPConnectionPool

        data = "I'm in ur multipart form-data, hazing a cheezburgr"
        fields: dict[str, _TYPE_FIELD_VALUE_TUPLE] = {
            "upload_param": "filefield",
            "upload_filename": "lolcat.txt",
            "filefield": ("lolcat.txt", data),
        }
        fields["upload_size"] = str(len(data))
        with HTTPConnectionPool(host, port) as pool:
            r = pool.request("POST", "/upload", fields=fields)
            assert r.status == 200

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


@pytest.mark.without_jspi
@pytest.mark.in_webbrowser
def test_streaming_not_ready_in_browser(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    # streaming ready should always be false
    # if we're in the main browser thread
    selenium_coverage.run_async(
        """
        import urllib3.contrib.emscripten.fetch
        result=await urllib3.contrib.emscripten.fetch.wait_for_streaming_ready()
        assert(result is False)
        assert(urllib3.contrib.emscripten.fetch.streaming_ready() is None )
        """
    )


def test_requests_with_micropip(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
) -> None:
    @run_in_pyodide(packages=["micropip"])  # type: ignore[misc]
    async def test_fn(
        selenium_coverage: typing.Any, http_host: str, http_port: int, https_port: int
    ) -> None:
        import micropip  # type: ignore[import-not-found]

        await micropip.install("requests")
        import requests

        r = requests.get(f"http://{http_host}:{http_port}/")
        assert r.status_code == 200
        assert r.text == "Dummy server!"
        json_data = {"woo": "yay"}
        # try posting some json with requests on https
        r = requests.post(f"https://{http_host}:{https_port}/echo_json", json=json_data)
        assert r.json() == json_data

    test_fn(
        selenium_coverage,
        testserver_http.http_host,
        testserver_http.http_port,
        testserver_http.https_port,
    )


def test_open_close(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        from http.client import ResponseNotReady

        import pytest

        from urllib3.connection import HTTPConnection

        conn = HTTPConnection(host, port)
        # initially connection should be closed
        assert conn.is_closed is True
        # connection should have no response
        with pytest.raises(ResponseNotReady):
            response = conn.getresponse()
        # now make the response
        conn.request("GET", f"http://{host}:{port}/")
        # we never connect to proxy (or if we do, browser handles it)
        assert conn.has_connected_to_proxy is False
        # now connection should be open
        assert conn.is_closed is False
        # and should have a response
        response = conn.getresponse()
        assert response is not None
        conn.close()
        # now it is closed
        assert conn.is_closed is True
        # closed connection shouldn't have any response
        with pytest.raises(ResponseNotReady):
            conn.getresponse()

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


# check that various ways that the worker may be broken
# throw exceptions nicely, by deliberately breaking things
# this is for coverage
@pytest.mark.webworkers
@pytest.mark.without_jspi
def test_break_worker_streaming(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
) -> None:
    worker_code = f"""
        import pytest
        import urllib3.contrib.emscripten.fetch
        import js
        import http.client

        await urllib3.contrib.emscripten.fetch.wait_for_streaming_ready()
        from urllib3.exceptions import TimeoutError
        from urllib3.connection import HTTPConnection
        conn = HTTPConnection("{testserver_http.http_host}", {testserver_http.http_port},timeout=1.0)
        # make the fetch worker return a bad response by:
        # 1) Clearing the int buffer
        #    in the receive stream
        with pytest.raises(http.client.HTTPException):
            conn.request("GET","/",preload_content=False)
            response = conn.getresponse()
            body_internal = response._response.body
            assert(body_internal.int_buffer!=None)
            body_internal.int_buffer=None
            data=response.read()
        # 2) Monkeypatch postMessage so that it just sets an
        #    exception status
        old_pm= body_internal.worker.postMessage
        with pytest.raises(http.client.HTTPException):
            conn.request("GET","/",preload_content=False)
            response = conn.getresponse()
            # make posted messages set an exception
            body_internal = response._response.body
            def set_exception(*args):
                body_internal.worker.postMessage = old_pm
                body_internal.int_buffer[1]=4
                body_internal.byte_buffer[0]=ord("W")
                body_internal.byte_buffer[1]=ord("O")
                body_internal.byte_buffer[2]=ord("O")
                body_internal.byte_buffer[3]=ord("!")
                body_internal.byte_buffer[4]=0
                js.Atomics.store(body_internal.int_buffer, 0, -4)
                js.Atomics.notify(body_internal.int_buffer,0)
            body_internal.worker.postMessage = set_exception
            data=response.read()
        # monkeypatch so it returns an unknown value for the magic number on initial fetch call
        with pytest.raises(http.client.HTTPException):
            # make posted messages set an exception
            worker=urllib3.contrib.emscripten.fetch._fetcher.js_worker
            def set_exception(self,*args):
                array=js.Int32Array.new(args[0].buffer)
                array[0]=-1234
            worker.postMessage=set_exception.__get__(worker,worker.__class__)
            conn.request("GET","/",preload_content=False)
            response = conn.getresponse()
            data=response.read()
        urllib3.contrib.emscripten.fetch._fetcher.js_worker.postMessage=old_pm
        # 3) Stopping the worker receiving any messages which should cause a timeout error
        #    in the receive stream
        with pytest.raises(TimeoutError):
            conn.request("GET","/",preload_content=False)
            response = conn.getresponse()
            # make posted messages not be send
            body_internal = response._response.body
            def ignore_message(*args):
                pass
            old_pm= body_internal.worker.postMessage
            body_internal.worker.postMessage = ignore_message
            data=response.read()
        body_internal.worker.postMessage = old_pm
"""
    run_from_server.run_webworker(worker_code)


def test_response_init_length(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import pytest

        import urllib3.exceptions
        from urllib3.connection import HTTPConnection
        from urllib3.response import BaseHTTPResponse

        conn = HTTPConnection(host, port)
        conn.request("GET", f"http://{host}:{port}/")
        response = conn.getresponse()
        assert isinstance(response, BaseHTTPResponse)
        # head shouldn't have length
        length = response._init_length("HEAD")
        assert length == 0
        # multiple inconsistent lengths - should raise invalid header
        with pytest.raises(urllib3.exceptions.InvalidHeader):
            response.headers["Content-Length"] = "4,5,6"
            length = response._init_length("GET")
        # non-numeric length - should return None
        response.headers["Content-Length"] = "anna"
        length = response._init_length("GET")
        assert length is None
        # numeric length - should return it
        response.headers["Content-Length"] = "54"
        length = response._init_length("GET")
        assert length == 54
        # negative length - should return None
        response.headers["Content-Length"] = "-12"
        length = response._init_length("GET")
        assert length is None
        # none -> None
        del response.headers["Content-Length"]
        length = response._init_length("GET")
        assert length is None

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


def test_response_close_connection(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        from urllib3.connection import HTTPConnection
        from urllib3.response import BaseHTTPResponse

        conn = HTTPConnection(host, port)
        conn.request("GET", f"http://{host}:{port}/")
        response = conn.getresponse()
        assert isinstance(response, BaseHTTPResponse)
        response.close()
        assert conn.is_closed

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


def test_read_chunked(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        from urllib3.connection import HTTPConnection

        conn = HTTPConnection(host, port)
        conn.request("GET", f"http://{host}:{port}/mediumfile", preload_content=False)
        response = conn.getresponse()
        count = 0
        for x in response.read_chunked(512):
            count += 1
            if count < 10:
                assert len(x) == 512

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


def test_retries(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import pytest

        import urllib3

        pool = urllib3.HTTPConnectionPool(
            host,
            port,
            maxsize=1,
            block=True,
            retries=urllib3.util.Retry(connect=5, read=5, redirect=5),
        )

        # monkeypatch connection class to count calls
        old_request = urllib3.connection.HTTPConnection.request
        count = 0

        def count_calls(self, *args, **argv):  # type: ignore[no-untyped-def]
            nonlocal count
            count += 1
            return old_request(self, *args, **argv)

        urllib3.connection.HTTPConnection.request = count_calls  # type: ignore[method-assign]
        with pytest.raises(urllib3.exceptions.MaxRetryError):
            pool.urlopen("GET", "/")
        # this should fail, but should have tried 6 times total
        assert count == 6

    pyodide_test(selenium_coverage, testserver_http.http_host, find_unused_port())


def test_redirects(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage: typing.Any, host: str, port: int) -> None:
        from urllib3 import request

        redirect_url = f"http://{host}:{port}/redirect"
        response = request("GET", redirect_url)
        assert response.status == 200

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


@pytest.mark.with_jspi
def test_disabled_redirects(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    """
    Test that urllib3 can control redirects in Node.js.
    """

    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage: typing.Any, host: str, port: int) -> None:
        import pytest

        from urllib3 import PoolManager, request
        from urllib3.contrib.emscripten.fetch import _is_node_js
        from urllib3.exceptions import MaxRetryError

        if not _is_node_js():
            pytest.skip("urllib3 does not control redirects in browsers.")

        redirect_url = f"http://{host}:{port}/redirect"

        with PoolManager(retries=0) as http:
            with pytest.raises(MaxRetryError):
                http.request("GET", redirect_url)

            response = http.request("GET", redirect_url, redirect=False)
            assert response.status == 303

        with PoolManager(retries=False) as http:
            response = http.request("GET", redirect_url)
            assert response.status == 303

        with pytest.raises(MaxRetryError):
            request("GET", redirect_url, retries=0)

        response = request("GET", redirect_url, redirect=False)
        assert response.status == 303

        response = request("GET", redirect_url, retries=0, redirect=False)
        assert response.status == 303

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


def test_insecure_requests_warning(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int, https_port: int) -> None:  # type: ignore[no-untyped-def]
        import warnings

        import urllib3
        import urllib3.exceptions

        http = urllib3.PoolManager()

        with warnings.catch_warnings(record=True) as w:
            http.request("GET", f"https://{host}:{https_port}")
        assert len(w) == 0

    pyodide_test(
        selenium_coverage,
        testserver_http.http_host,
        testserver_http.http_port,
        testserver_http.https_port,
    )


@pytest.mark.webworkers
def test_has_jspi_worker(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
    has_jspi: bool,
) -> None:
    worker_code = f"""
    import urllib3.contrib.emscripten.fetch
    assert(urllib3.contrib.emscripten.fetch.has_jspi() == {has_jspi})
    """

    run_from_server.run_webworker(worker_code)


def test_has_jspi(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo, has_jspi: bool
) -> None:
    @run_in_pyodide
    def pyodide_test(selenium, has_jspi):  # type: ignore[no-untyped-def]
        import urllib3.contrib.emscripten.fetch

        assert urllib3.contrib.emscripten.fetch.has_jspi() == has_jspi

    pyodide_test(selenium_coverage, has_jspi)


@pytest.mark.with_jspi
def test_timeout_jspi(
    selenium_coverage: typing.Any,
    testserver_http: PyodideServerInfo,
    run_from_server: ServerRunnerInfo,
) -> None:
    @run_in_pyodide
    def pyodide_test(selenium, host, port):  # type: ignore[no-untyped-def]
        import pytest

        import urllib3.contrib.emscripten.fetch
        from urllib3.connection import HTTPConnection
        from urllib3.exceptions import TimeoutError

        conn = HTTPConnection(host, port, timeout=0.1)
        assert urllib3.contrib.emscripten.fetch.has_jspi() is True
        with pytest.raises(TimeoutError):
            conn.request("GET", "/slow")
            conn.getresponse()

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


@pytest.mark.with_jspi
def test_streaming_jspi(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    bigfile_url = (
        f"http://{testserver_http.http_host}:{testserver_http.http_port}/dripfeed"
    )

    @run_in_pyodide
    def pyodide_test(selenium, host, port, bigfile_url):  # type: ignore[no-untyped-def]
        import time

        from urllib3.connection import HTTPConnection
        from urllib3.response import BaseHTTPResponse

        conn = HTTPConnection(host, port)
        start_time = time.time()
        conn.request("GET", bigfile_url, preload_content=False)
        response = conn.getresponse()
        assert isinstance(response, BaseHTTPResponse)
        # first data should be received before the timeout
        # on the server
        first_data = response.read(32768)
        assert time.time() - start_time < 2
        all_data = first_data + response.read()
        # make sure that the timeout on server side really happened
        # by checking that it took greater than the timeout
        assert time.time() - start_time > 2
        assert len(all_data.decode("utf-8")) == 17825792

    pyodide_test(
        selenium_coverage,
        testserver_http.http_host,
        testserver_http.http_port,
        bigfile_url,
    )


# another streaming test - uses chunked read
# and streaming to check that it works okay
# (see https://github.com/urllib3/urllib3/issues/3555 )
@pytest.mark.with_jspi
def test_streaming2_jspi(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    bigfile_url = (
        f"http://{testserver_http.http_host}:{testserver_http.http_port}/dripfeed"
    )

    @run_in_pyodide
    def pyodide_test(selenium, host, port, bigfile_url):  # type: ignore[no-untyped-def]
        from urllib3.connection import HTTPConnection
        from urllib3.response import BaseHTTPResponse

        conn = HTTPConnection(host, port)
        conn.request("GET", bigfile_url, preload_content=False)
        response = conn.getresponse()
        assert isinstance(response, BaseHTTPResponse)
        # get first data
        all_data = response.read(32768)
        # now get the rest in chunks
        # to make sure that streaming works
        # correctly even if the low level read doesn't
        # always return a full buffer (which it doesn't)
        while not response._response.body.closed:  # type: ignore[attr-defined]
            all_data += response.read(32768)
        assert len(all_data.decode("utf-8")) == 17825792

    pyodide_test(
        selenium_coverage,
        testserver_http.http_host,
        testserver_http.http_port,
        bigfile_url,
    )


@pytest.mark.node_without_jspi
def test_non_jspi_fail_in_node(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    if selenium_coverage.browser != "node":
        pytest.skip("node only test")

    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import http.client

        import pytest

        from urllib3.connection import HTTPConnection

        conn = HTTPConnection(host, port)
        url = f"http://{host}:{port}/"
        # check streaming and non-streaming requests both fail
        with pytest.raises(http.client.HTTPException):
            conn.request("GET", url)
            conn.getresponse()
        with pytest.raises(http.client.HTTPException):
            conn.request("GET", url, preload_content=False)
            conn.getresponse()

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


@pytest.mark.with_jspi
def test_jspi_fetch_error(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import http.client

        import pytest

        from urllib3.connection import HTTPConnection

        conn = HTTPConnection(host, port)
        url = f"sdfsdfsffhttp://{host}:{port}/"
        with pytest.raises(http.client.HTTPException):
            conn.request("GET", url)
            conn.getresponse()

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


@pytest.mark.with_jspi
def test_jspi_readstream_errors(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        import io
        from http.client import HTTPException

        import pytest

        import urllib3.contrib.emscripten.fetch
        from urllib3.connection import HTTPConnection
        from urllib3.exceptions import TimeoutError

        conn = HTTPConnection(host, port)
        url = f"http://{host}:{port}/"
        conn.request("GET", url, preload_content=False)
        response = conn.getresponse()
        assert isinstance(response._response.body, io.RawIOBase)  # type: ignore[attr-defined]
        old_run_sync = urllib3.contrib.emscripten.fetch._run_sync_with_timeout
        with pytest.raises(TimeoutError):

            def raise_timeout(*args, **argv):  # type: ignore[no-untyped-def]
                raise urllib3.contrib.emscripten.fetch._TimeoutError()

            urllib3.contrib.emscripten.fetch._run_sync_with_timeout = raise_timeout
            response.read()
        urllib3.contrib.emscripten.fetch._run_sync_with_timeout = old_run_sync
        conn.request("GET", url, preload_content=False)
        response = conn.getresponse()
        with pytest.raises(HTTPException):

            def raise_error(*args, **argv):  # type: ignore[no-untyped-def]
                raise urllib3.contrib.emscripten.fetch._RequestError()

            urllib3.contrib.emscripten.fetch._run_sync_with_timeout = raise_error
            response.read()

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )


@pytest.mark.with_jspi
def test_has_jspi_exception(
    selenium_coverage: typing.Any, testserver_http: PyodideServerInfo
) -> None:
    @run_in_pyodide  # type: ignore[misc]
    def pyodide_test(selenium_coverage, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        from unittest.mock import patch

        import pyodide.ffi  # type: ignore[import-not-found]

        if hasattr(pyodide.ffi, "can_run_sync"):

            @patch("pyodide.ffi.can_run_sync")
            def should_return_false(func):  # type: ignore[no-untyped-def]
                func.return_value = (20, False)
                func.side_effect = ImportError()
                from urllib3.contrib.emscripten.fetch import has_jspi

                assert has_jspi() is False

        else:
            from unittest.mock import patch

            @patch("pyodide_js._module")
            def should_return_false(func):  # type: ignore[no-untyped-def]
                from urllib3.contrib.emscripten.fetch import has_jspi

                assert has_jspi() is False

        should_return_false()

    pyodide_test(
        selenium_coverage, testserver_http.http_host, testserver_http.http_port
    )

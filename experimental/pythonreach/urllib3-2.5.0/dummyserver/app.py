from __future__ import annotations

import collections
import contextlib
import datetime
import email.utils
import gzip
import mimetypes
import zlib
from collections.abc import AsyncGenerator, Iterator
from io import BytesIO
from pathlib import Path

import trio
from quart import Response, make_response, request
from quart.typing import ResponseReturnValue
from quart_trio import QuartTrio

hypercorn_app = QuartTrio(__name__)

# Globals are not safe in Flask/Quart but work for our Hypercorn use case
RETRY_TEST_NAMES: collections.Counter[str] = collections.Counter()
LAST_RETRY_AFTER_REQ: datetime.datetime = datetime.datetime.min


pyodide_testing_app = QuartTrio(__name__)
DEFAULT_HEADERS = [
    # Allow cross-origin requests for emscripten
    ("Access-Control-Allow-Origin", "*"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("Feature-Policy", "sync-xhr *;"),
    ("Access-Control-Allow-Headers", "*"),
]


@hypercorn_app.route("/")
@pyodide_testing_app.route("/")
@pyodide_testing_app.route("/index")
async def index() -> ResponseReturnValue:
    return await make_response("Dummy server!")


@hypercorn_app.route("/alpn_protocol")
async def alpn_protocol() -> ResponseReturnValue:
    """Return the requester's certificate."""
    alpn_protocol = request.scope["extensions"]["tls"]["alpn_protocol"]
    return await make_response(alpn_protocol)


@hypercorn_app.route("/certificate")
async def certificate() -> ResponseReturnValue:
    """Return the requester's certificate."""
    subject = request.scope["extensions"]["tls"]["client_cert_name"]
    subject_as_dict = dict(part.split("=") for part in subject.split(", "))
    return await make_response(subject_as_dict)


@hypercorn_app.route("/specific_method", methods=["GET", "POST", "PUT"])
@pyodide_testing_app.route("/specific_method", methods=["GET", "POST", "PUT"])
async def specific_method() -> ResponseReturnValue:
    "Confirm that the request matches the desired method type"
    method_param = (await request.values).get("method", "")

    if request.method.upper() == method_param.upper():
        return await make_response("", 200)
    else:
        return await make_response(
            f"Wrong method: {method_param} != {request.method}", 400
        )


@hypercorn_app.route("/upload", methods=["POST"])
async def upload() -> ResponseReturnValue:
    "Confirm that the uploaded file conforms to specification"
    params = await request.form
    param = params.get("upload_param")
    filename_param = params.get("upload_filename")
    size = int(params.get("upload_size", "0"))
    files_ = (await request.files).getlist(param)
    assert files_ is not None

    if len(files_) != 1:
        return await make_response(
            f"Expected 1 file for '{param}', not {len(files_)}", 400
        )

    file_ = files_[0]
    # data is short enough to read synchronously without blocking the event loop
    with contextlib.closing(file_.stream) as stream:
        data = stream.read()

    if int(size) != len(data):
        return await make_response(f"Wrong size: {int(size)} != {len(data)}", 400)

    if filename_param != file_.filename:
        return await make_response(
            f"Wrong filename: {filename_param} != {file_.filename}", 400
        )

    return await make_response()


@hypercorn_app.route("/chunked")
async def chunked() -> ResponseReturnValue:
    def generate() -> Iterator[str]:
        for _ in range(4):
            yield "123"

    return await make_response(generate())


@hypercorn_app.route("/chunked_gzip")
async def chunked_gzip() -> ResponseReturnValue:
    def generate() -> Iterator[bytes]:
        compressor = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)

        for uncompressed in [b"123"] * 4:
            yield compressor.compress(uncompressed)
        yield compressor.flush()

    return await make_response(generate(), 200, [("Content-Encoding", "gzip")])


@hypercorn_app.route("/keepalive")
async def keepalive() -> ResponseReturnValue:
    if request.args.get("close", b"0") == b"1":
        headers = [("Connection", "close")]
        return await make_response("Closing", 200, headers)

    headers = [("Connection", "keep-alive")]
    return await make_response("Keeping alive", 200, headers)


@hypercorn_app.route("/echo", methods=["GET", "POST", "PUT"])
async def echo() -> ResponseReturnValue:
    "Echo back the params"
    if request.method == "GET":
        return await make_response(request.query_string)

    return await make_response(await request.get_data())


@hypercorn_app.route("/echo_json", methods=["POST"])
@pyodide_testing_app.route("/echo_json", methods=["POST", "OPTIONS"])
async def echo_json() -> ResponseReturnValue:
    "Echo back the JSON"
    if request.method == "OPTIONS":
        return await make_response("", 200)
    data = await request.get_data()
    return await make_response(data, 200, request.headers)


@hypercorn_app.route("/echo_uri/<path:rest>")
@hypercorn_app.route("/echo_uri", defaults={"rest": ""})
async def echo_uri(rest: str) -> ResponseReturnValue:
    "Echo back the requested URI"
    assert request.full_path is not None
    return await make_response(request.full_path)


@hypercorn_app.route("/echo_params")
async def echo_params() -> ResponseReturnValue:
    "Echo back the query parameters"
    await request.get_data()
    echod = sorted((k, v) for k, v in request.args.items())
    return await make_response(repr(echod))


@hypercorn_app.route("/headers", methods=["GET", "POST"])
async def headers() -> ResponseReturnValue:
    return await make_response(dict(request.headers.items()))


@hypercorn_app.route("/headers_and_params")
async def headers_and_params() -> ResponseReturnValue:
    return await make_response(
        {
            "headers": dict(request.headers),
            "params": request.args,
        }
    )


@hypercorn_app.route("/multi_headers", methods=["GET", "POST"])
async def multi_headers() -> ResponseReturnValue:
    return await make_response({"headers": list(request.headers)})


@hypercorn_app.route("/multi_redirect")
async def multi_redirect() -> ResponseReturnValue:
    "Performs a redirect chain based on ``redirect_codes``"
    params = request.args
    codes = params.get("redirect_codes", "200")
    head, tail = codes.split(",", 1) if "," in codes else (codes, None)
    assert head is not None
    status = head
    if not tail:
        return await make_response("Done redirecting", status)

    headers = [("Location", f"/multi_redirect?redirect_codes={tail}")]
    return await make_response("", status, headers)


@hypercorn_app.route("/encodingrequest")
async def encodingrequest() -> ResponseReturnValue:
    "Check for UA accepting gzip/deflate encoding"
    data = b"hello, world!"
    encoding = request.headers.get("Accept-Encoding", "")
    headers = []
    if encoding == "gzip":
        headers = [("Content-Encoding", "gzip")]
        file_ = BytesIO()
        with contextlib.closing(gzip.GzipFile("", mode="w", fileobj=file_)) as zipfile:
            zipfile.write(data)
        data = file_.getvalue()
    elif encoding == "deflate":
        headers = [("Content-Encoding", "deflate")]
        data = zlib.compress(data)
    elif encoding == "garbage-gzip":
        headers = [("Content-Encoding", "gzip")]
        data = b"garbage"
    elif encoding == "garbage-deflate":
        headers = [("Content-Encoding", "deflate")]
        data = b"garbage"
    return await make_response(data, 200, headers)


@hypercorn_app.route("/redirect", methods=["GET", "POST", "PUT"])
@pyodide_testing_app.route("/redirect", methods=["GET", "POST", "PUT"])
async def redirect() -> ResponseReturnValue:
    "Perform a redirect to ``target``"
    values = await request.values
    target = values.get("target", "/")
    status = values.get("status", "303 See Other")
    status_code = status.split(" ")[0]

    headers = [("Location", target)]
    return await make_response("", status_code, headers)


@hypercorn_app.route("/redirect_after")
async def redirect_after() -> ResponseReturnValue:
    "Perform a redirect to ``target``"
    params = request.args
    date = params.get("date")
    if date:
        dt = datetime.datetime.fromtimestamp(float(date), tz=datetime.timezone.utc)
        http_dt = email.utils.format_datetime(dt, usegmt=True)
        retry_after = str(http_dt)
    else:
        retry_after = "1"
    target = params.get("target", "/")
    headers = [("Location", target), ("Retry-After", retry_after)]
    return await make_response("", 303, headers)


@hypercorn_app.route("/retry_after")
async def retry_after() -> ResponseReturnValue:
    global LAST_RETRY_AFTER_REQ
    params = request.args
    if datetime.datetime.now() - LAST_RETRY_AFTER_REQ < datetime.timedelta(seconds=1):
        status = params.get("status", "429 Too Many Requests")
        status_code = status.split(" ")[0]

        return await make_response("", status_code, [("Retry-After", "1")])

    LAST_RETRY_AFTER_REQ = datetime.datetime.now()
    return await make_response("", 200)


@hypercorn_app.route("/status")
@pyodide_testing_app.route("/status")
async def status() -> ResponseReturnValue:
    values = await request.values
    status = values.get("status", "200 OK")
    status_code = status.split(" ")[0]
    return await make_response("", status_code)


@hypercorn_app.route("/source_address")
async def source_address() -> ResponseReturnValue:
    """Return the requester's IP address."""
    return await make_response(request.remote_addr)


@hypercorn_app.route("/successful_retry", methods=["GET", "PUT"])
async def successful_retry() -> ResponseReturnValue:
    """First return an error and then success

    It's not currently very flexible as the number of retries is hard-coded.
    """
    test_name = request.headers.get("test-name", None)
    if not test_name:
        return await make_response("test-name header not set", 400)

    RETRY_TEST_NAMES[test_name] += 1

    if RETRY_TEST_NAMES[test_name] >= 2:
        return await make_response("Retry successful!", 200)
    else:
        return await make_response("need to keep retrying!", 418)


@pyodide_testing_app.after_request
def apply_caching(response: Response) -> ResponseReturnValue:
    for header, value in DEFAULT_HEADERS:
        response.headers[header] = value
    return response


@pyodide_testing_app.route("/slow")
async def slow() -> ResponseReturnValue:
    await trio.sleep(10)
    return await make_response("TEN SECONDS LATER", 200)


@pyodide_testing_app.route("/dripfeed")
async def dripfeed() -> ResponseReturnValue:
    # great big text file which streams half the file
    # then pauses for 2 seconds and streams the rest
    async def generate() -> AsyncGenerator[bytes]:
        for x in range(8):
            if x == 4:
                await trio.sleep(2)
            yield b"WOOO YAY BOOYAKAH" * 131072

    response = await make_response(generate(), 200)
    if hasattr(response, "timeout"):
        response.timeout = None
    return response


@pyodide_testing_app.route("/bigfile")
async def bigfile() -> ResponseReturnValue:
    # great big text file, should force streaming
    # if supported
    bigdata = 1048576 * b"WOOO YAY BOOYAKAH"
    return await make_response(bigdata, 200)


@pyodide_testing_app.route("/mediumfile")
async def mediumfile() -> ResponseReturnValue:
    # quite big file
    bigdata = 1024 * b"WOOO YAY BOOYAKAH"
    return await make_response(bigdata, 200)


@pyodide_testing_app.route("/upload", methods=["POST", "OPTIONS"])
async def pyodide_upload() -> ResponseReturnValue:
    if request.method == "OPTIONS":
        return await make_response("", 200)
    spare_data = await request.get_data(parse_form_data=True)
    if len(spare_data) != 0:
        return await make_response("Bad upload data", 404)
    files = await request.files
    form = await request.form
    if form["upload_param"] != "filefield" or form["upload_filename"] != "lolcat.txt":
        return await make_response("Bad upload form values", 404)
    if len(files) != 1 or files.get("filefield") is None:
        return await make_response("Missing file in form", 404)
    file = files["filefield"]
    if file.filename != "lolcat.txt":
        return await make_response(f"File name incorrect {file.name}", 404)
    with contextlib.closing(file):
        data = file.read().decode("utf-8")
    if data != "I'm in ur multipart form-data, hazing a cheezburgr":
        return await make_response(f"File data incorrect {data}", 200)
    return await make_response("Uploaded file correct", 200)


def _find_built_wheel() -> Path | None:
    wheel_folder = Path(__file__).parent.parent / "dist"
    wheels = list(wheel_folder.glob("*.whl"))
    wheels = sorted(wheels, key=lambda w: w.stat().st_mtime)
    if len(wheels) > 0:
        return wheels[-1]  # newest wheel
    else:
        return None


def _get_pyodide_template(py_file: str) -> bytes | None:
    # serve code to run pyodide in a webworker, or html template
    # these are included in pytest_pyodide, but
    # we modify the webworker to automatically load our wheel
    # before anything else
    if py_file == "webworker_dev.js":
        return b"""
            importScripts("./pyodide.js");

            onmessage = async function (e) {
                try {
                    let code = e.data.python;
                    self.pyodide = await loadPyodide();
                    await self.pyodide.loadPackage("/dist/urllib3.whl");
                    await self.pyodide.loadPackagesFromImports(code);
                    let results = await self.pyodide.runPythonAsync(code);
                    self.postMessage({ results });
                } catch (e) {
                    self.postMessage({ error: e.message + "\\n" + e.stack });
                }
            };
        """
    elif py_file == "test.html":
        return b"""
            <!doctype html>
            <html>
            <head>
                <script type="text/javascript">
                window.logs = [];
                console.log = function (message) {
                    window.logs.push(message);
                };
                console.warn = function (message) {
                    window.logs.push(message);
                };
                console.info = function (message) {
                    window.logs.push(message);
                };
                console.error = function (message) {
                    window.logs.push(message);
                };
                console.debug = function (message) {
                    window.logs.push(message);
                };
                </script>
                <script src="./pyodide.js"></script>
            </head>
            <body></body>
            </html>
        """
    else:
        return None


@pyodide_testing_app.route("/pyodide/<py_file>")
async def pyodide(py_file: str) -> ResponseReturnValue:
    template_data = _get_pyodide_template(py_file)
    mime_type: str | None = None
    if template_data:
        mime_type, _encoding = mimetypes.guess_type(py_file)
        if not mime_type:
            mime_type = "text/plain"
        headers = [("Content-Type", mime_type)]
        return await make_response(template_data, 200, headers)
    file_path = Path(pyodide_testing_app.config["pyodide_dist_dir"], py_file)

    if file_path is not None and file_path.exists():
        if py_file.endswith(".whl"):
            mime_type = "application/x-wheel"
            headers = [
                ("Content-Disposition", f"inline; filename='{file_path.name}'"),
                ("Content-Type", mime_type),
            ]
        else:
            mime_type, _encoding = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = "text/plain"
            headers = [("Content-Type", mime_type)]
        return await make_response(file_path.read_bytes(), 200, headers)
    else:
        return await make_response("", 404)


@pyodide_testing_app.route("/dist/urllib3.whl")
async def wheel() -> ResponseReturnValue:
    file_path = _find_built_wheel()
    if not file_path:
        print("NO BUILT WHEEL?")
        return await make_response("", 404)

    mime_type = "application/x-wheel"
    headers = [
        ("Content-Disposition", f"inline; filename='{file_path.name}'"),
        ("Content-Type", mime_type),
    ]
    return await make_response(file_path.read_bytes(), 200, headers)

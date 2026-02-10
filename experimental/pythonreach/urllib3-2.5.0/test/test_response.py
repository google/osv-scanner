from __future__ import annotations

import contextlib
import http.client as httplib
import socket
import ssl
import typing
import zlib
from base64 import b64decode
from http.client import IncompleteRead as httplib_IncompleteRead
from io import BufferedReader, BytesIO, TextIOWrapper
from test import onlyBrotli, onlyZstd
from unittest import mock

import pytest

from urllib3 import HTTPHeaderDict
from urllib3.exceptions import (
    BodyNotHttplibCompatible,
    DecodeError,
    IncompleteRead,
    InvalidChunkLength,
    InvalidHeader,
    ProtocolError,
    ResponseNotChunked,
    SSLError,
)
from urllib3.response import (  # type: ignore[attr-defined]
    BaseHTTPResponse,
    BytesQueueBuffer,
    HTTPResponse,
    brotli,
)
from urllib3.util.response import is_fp_closed
from urllib3.util.retry import RequestHistory, Retry


def zstd_compress(data: bytes) -> bytes:
    try:
        from compression import zstd  # type: ignore[import-not-found] # noqa: F401
    except ImportError:
        import zstandard as zstd
    return zstd.compress(data)  # type: ignore[no-any-return]


class TestBytesQueueBuffer:
    def test_single_chunk(self) -> None:
        buffer = BytesQueueBuffer()
        assert len(buffer) == 0
        with pytest.raises(RuntimeError, match="buffer is empty"):
            assert buffer.get(10)

        assert buffer.get(0) == b""

        buffer.put(b"foo")
        with pytest.raises(ValueError, match="n should be > 0"):
            buffer.get(-1)

        assert buffer.get(1) == b"f"
        assert buffer.get(2) == b"oo"
        with pytest.raises(RuntimeError, match="buffer is empty"):
            assert buffer.get(10)

    def test_read_too_much(self) -> None:
        buffer = BytesQueueBuffer()
        buffer.put(b"foo")
        assert buffer.get(100) == b"foo"

    def test_multiple_chunks(self) -> None:
        buffer = BytesQueueBuffer()
        buffer.put(b"foo")
        buffer.put(b"bar")
        buffer.put(b"baz")
        assert len(buffer) == 9

        assert buffer.get(1) == b"f"
        assert len(buffer) == 8
        assert buffer.get(4) == b"ooba"
        assert len(buffer) == 4
        assert buffer.get(4) == b"rbaz"
        assert len(buffer) == 0

    def test_get_all_empty(self) -> None:
        q = BytesQueueBuffer()
        assert q.get_all() == b""
        assert len(q) == 0

    def test_get_all_single(self) -> None:
        q = BytesQueueBuffer()
        q.put(b"a")
        assert q.get_all() == b"a"
        assert len(q) == 0

    def test_get_all_many(self) -> None:
        q = BytesQueueBuffer()
        q.put(b"a")
        q.put(b"b")
        q.put(b"c")
        assert q.get_all() == b"abc"
        assert len(q) == 0

    @pytest.mark.parametrize(
        "get_func",
        (lambda b: b.get(len(b)), lambda b: b.get_all()),
        ids=("get", "get_all"),
    )
    @pytest.mark.limit_memory(
        "12.5 MB", current_thread_only=True
    )  # assert that we're not doubling memory usagelimit_mem
    def test_memory_usage(
        self, get_func: typing.Callable[[BytesQueueBuffer], str]
    ) -> None:
        # Allocate 10 1MiB chunks
        buffer = BytesQueueBuffer()
        for i in range(10):
            # This allocates 2MiB, putting the max at around 12MiB. Not sure why.
            buffer.put(bytes(2**20))

        assert len(get_func(buffer)) == 10 * 2**20

    @pytest.mark.limit_memory("10.01 MB", current_thread_only=True)
    def test_get_all_memory_usage_single_chunk(self) -> None:
        buffer = BytesQueueBuffer()
        chunk = bytes(10 * 2**20)  # 10 MiB
        buffer.put(chunk)
        assert buffer.get_all() is chunk


# A known random (i.e, not-too-compressible) payload generated with:
#    "".join(random.choice(string.printable) for i in range(512))
#    .encode("zlib").encode("base64")
# Randomness in tests == bad, and fixing a seed may not be sufficient.
ZLIB_PAYLOAD = b64decode(
    b"""\
eJwFweuaoQAAANDfineQhiKLUiaiCzvuTEmNNlJGiL5QhnGpZ99z8luQfe1AHoMioB+QSWHQu/L+
lzd7W5CipqYmeVTBjdgSATdg4l4Z2zhikbuF+EKn69Q0DTpdmNJz8S33odfJoVEexw/l2SS9nFdi
pis7KOwXzfSqarSo9uJYgbDGrs1VNnQpT9f8zAorhYCEZronZQF9DuDFfNK3Hecc+WHLnZLQptwk
nufw8S9I43sEwxsT71BiqedHo0QeIrFE01F/4atVFXuJs2yxIOak3bvtXjUKAA6OKnQJ/nNvDGKZ
Khe5TF36JbnKVjdcL1EUNpwrWVfQpFYJ/WWm2b74qNeSZeQv5/xBhRdOmKTJFYgO96PwrHBlsnLn
a3l0LwJsloWpMbzByU5WLbRE6X5INFqjQOtIwYz5BAlhkn+kVqJvWM5vBlfrwP42ifonM5yF4ciJ
auHVks62997mNGOsM7WXNG3P98dBHPo2NhbTvHleL0BI5dus2JY81MUOnK3SGWLH8HeWPa1t5KcW
S5moAj5HexY/g/F8TctpxwsvyZp38dXeLDjSQvEQIkF7XR3YXbeZgKk3V34KGCPOAeeuQDIgyVhV
nP4HF2uWHA=="""
)


@pytest.fixture
def sock() -> typing.Generator[socket.socket]:
    s = socket.socket()
    yield s
    s.close()


class TestLegacyResponse:
    def test_getheaders(self) -> None:
        headers = {"host": "example.com"}
        r = HTTPResponse(headers=headers)
        with pytest.warns(
            DeprecationWarning,
            match=r"HTTPResponse.getheaders\(\) is deprecated",
        ):
            assert r.getheaders() == HTTPHeaderDict(headers)

    def test_getheader(self) -> None:
        headers = {"host": "example.com"}
        r = HTTPResponse(headers=headers)
        with pytest.warns(
            DeprecationWarning,
            match=r"HTTPResponse.getheader\(\) is deprecated",
        ):
            assert r.getheader("host") == "example.com"


class TestResponse:
    def test_cache_content(self) -> None:
        r = HTTPResponse(b"foo")
        assert r._body == b"foo"
        assert r.data == b"foo"
        assert r._body == b"foo"

    def test_cache_content_preload_false(self) -> None:
        fp = BytesIO(b"foo")
        r = HTTPResponse(fp, preload_content=False)

        assert not r._body
        assert r.data == b"foo"
        assert r._body == b"foo"  # type: ignore[comparison-overlap]
        assert r.data == b"foo"

    def test_default(self) -> None:
        r = HTTPResponse()
        assert r.data is None

    def test_none(self) -> None:
        r = HTTPResponse(None)  # type: ignore[arg-type]
        assert r.data is None

    def test_preload(self) -> None:
        fp = BytesIO(b"foo")

        r = HTTPResponse(fp, preload_content=True)

        assert fp.tell() == len(b"foo")
        assert r.data == b"foo"

    def test_no_preload(self) -> None:
        fp = BytesIO(b"foo")

        r = HTTPResponse(fp, preload_content=False)

        assert fp.tell() == 0
        assert r.data == b"foo"
        assert fp.tell() == len(b"foo")

    def test_no_shutdown(self) -> None:
        r = HTTPResponse()
        with pytest.raises(
            ValueError, match="Cannot shutdown socket as self._sock_shutdown is not set"
        ):
            r.shutdown()

    def test_decode_bad_data(self) -> None:
        fp = BytesIO(b"\x00" * 10)
        with pytest.raises(DecodeError):
            HTTPResponse(fp, headers={"content-encoding": "deflate"})

    def test_reference_read(self) -> None:
        fp = BytesIO(b"foo")
        r = HTTPResponse(fp, preload_content=False)

        assert r.read(0) == b""
        assert r.read(1) == b"f"
        assert r.read(2) == b"oo"
        assert r.read() == b""
        assert r.read() == b""

    @pytest.mark.parametrize("read_args", ((), (None,), (-1,)))
    def test_reference_read_until_eof(self, read_args: tuple[typing.Any, ...]) -> None:
        fp = BytesIO(b"foo")
        r = HTTPResponse(fp, preload_content=False)
        assert r.read(*read_args) == b"foo"

    def test_reference_read1(self) -> None:
        fp = BytesIO(b"foobar")
        r = HTTPResponse(fp, preload_content=False)

        assert r.read1(0) == b""
        assert r.read1(1) == b"f"
        assert r.read1(2) == b"oo"
        assert r.read1() == b"bar"
        assert r.read1() == b""

    @pytest.mark.parametrize("read1_args", ((), (None,), (-1,)))
    def test_reference_read1_without_limit(
        self, read1_args: tuple[typing.Any, ...]
    ) -> None:
        fp = BytesIO(b"foo")
        r = HTTPResponse(fp, preload_content=False)
        assert r.read1(*read1_args) == b"foo"

    def test_reference_read1_nodecode(self) -> None:
        fp = BytesIO(b"foobar")
        r = HTTPResponse(fp, preload_content=False, decode_content=False)

        assert r.read1(0) == b""
        assert r.read1(1) == b"f"
        assert r.read1(2) == b"oo"
        assert r.read1() == b"bar"
        assert r.read1() == b""

    def test_decoding_read1(self) -> None:
        data = zlib.compress(b"foobar")

        fp = BytesIO(data)
        r = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )

        assert r.read1(1) == b"f"
        assert r.read1(2) == b"oo"
        assert r.read1() == b"bar"
        assert r.read1() == b""

    def test_decode_deflate(self) -> None:
        data = zlib.compress(b"foo")

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "deflate"})

        assert r.data == b"foo"

    def test_decode_deflate_case_insensitve(self) -> None:
        data = zlib.compress(b"foo")

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "DeFlAtE"})

        assert r.data == b"foo"

    def test_chunked_decoding_deflate(self) -> None:
        data = zlib.compress(b"foo")

        fp = BytesIO(data)
        r = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )

        assert r.read(1) == b"f"
        assert r.read(2) == b"oo"
        assert r.read() == b""
        assert r.read() == b""

    def test_chunked_decoding_deflate2(self) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
        data = compress.compress(b"foo")
        data += compress.flush()

        fp = BytesIO(data)
        r = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )

        assert r.read(1) == b"f"
        assert r.read(2) == b"oo"
        assert r.read() == b""
        assert r.read() == b""

    @pytest.mark.parametrize("content_encoding", ["gzip", "x-gzip"])
    def test_chunked_decoding_gzip(self, content_encoding: str) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        data = compress.compress(b"foo")
        data += compress.flush()

        fp = BytesIO(data)
        r = HTTPResponse(
            fp, headers={"content-encoding": content_encoding}, preload_content=False
        )

        assert r.read(1) == b"f"
        assert r.read(2) == b"oo"
        assert r.read() == b""
        assert r.read() == b""

    def test_decode_gzip_multi_member(self) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        data = compress.compress(b"foo")
        data += compress.flush()
        data = data * 3

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "gzip"})

        assert r.data == b"foofoofoo"

    def test_decode_gzip_error(self) -> None:
        fp = BytesIO(b"foo")
        with pytest.raises(DecodeError):
            HTTPResponse(fp, headers={"content-encoding": "gzip"})

    def test_decode_gzip_swallow_garbage(self) -> None:
        # When data comes from multiple calls to read(), data after
        # the first zlib error (here triggered by garbage) should be
        # ignored.
        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        data = compress.compress(b"foo")
        data += compress.flush()
        data = data * 3 + b"foo"

        fp = BytesIO(data)
        r = HTTPResponse(
            fp, headers={"content-encoding": "gzip"}, preload_content=False
        )
        ret = b""
        for _ in range(100):
            ret += r.read(1)
            if r.closed:
                break

        assert ret == b"foofoofoo"

    def test_chunked_decoding_gzip_swallow_garbage(self) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        data = compress.compress(b"foo")
        data += compress.flush()
        data = data * 3 + b"foo"

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "gzip"})

        assert r.data == b"foofoofoo"

    @onlyBrotli()
    def test_decode_brotli(self) -> None:
        data = brotli.compress(b"foo")

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "br"})
        assert r.data == b"foo"

    @onlyBrotli()
    def test_chunked_decoding_brotli(self) -> None:
        data = brotli.compress(b"foobarbaz")

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "br"}, preload_content=False)

        ret = b""
        for _ in range(100):
            ret += r.read(1)
            if r.closed:
                break
        assert ret == b"foobarbaz"

    @onlyBrotli()
    def test_decode_brotli_error(self) -> None:
        fp = BytesIO(b"foo")
        with pytest.raises(DecodeError):
            HTTPResponse(fp, headers={"content-encoding": "br"})

    @onlyZstd()
    def test_decode_zstd(self) -> None:
        data = zstd_compress(b"foo")

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "zstd"})
        assert r.data == b"foo"

    @onlyZstd()
    def test_decode_multiframe_zstd(self) -> None:
        data = (
            # Zstandard frame
            zstd_compress(b"foo")
            # skippable frame (must be ignored)
            + bytes.fromhex(
                "50 2A 4D 18"  # Magic_Number (little-endian)
                "07 00 00 00"  # Frame_Size (little-endian)
                "00 00 00 00 00 00 00"  # User_Data
            )
            # Zstandard frame
            + zstd_compress(b"bar")
        )

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "zstd"})
        assert r.data == b"foobar"

    @onlyZstd()
    def test_chunked_decoding_zstd(self) -> None:
        data = zstd_compress(b"foobarbaz")

        fp = BytesIO(data)
        r = HTTPResponse(
            fp, headers={"content-encoding": "zstd"}, preload_content=False
        )

        ret = b""

        for _ in range(100):
            ret += r.read(1)
            if r.closed:
                break
        assert ret == b"foobarbaz"

    decode_param_set = [
        b"foo",
        b"x" * 100,
    ]

    @onlyZstd()
    @pytest.mark.parametrize("data", decode_param_set)
    def test_decode_zstd_error(self, data: bytes) -> None:
        fp = BytesIO(data)

        with pytest.raises(DecodeError):
            HTTPResponse(fp, headers={"content-encoding": "zstd"})

    @onlyZstd()
    @pytest.mark.parametrize("data", decode_param_set)
    def test_decode_zstd_incomplete_preload_content(self, data: bytes) -> None:
        data = zstd_compress(data)
        fp = BytesIO(data[:-1])

        with pytest.raises(DecodeError):
            HTTPResponse(fp, headers={"content-encoding": "zstd"})

    @onlyZstd()
    @pytest.mark.parametrize("data", decode_param_set)
    def test_decode_zstd_incomplete_read(self, data: bytes) -> None:
        data = zstd_compress(data)
        fp = BytesIO(data[:-1])  # shorten the data to trigger DecodeError

        # create response object without(!) reading/decoding the content
        r = HTTPResponse(
            fp, headers={"content-encoding": "zstd"}, preload_content=False
        )

        # read/decode, expecting DecodeError
        with pytest.raises(DecodeError):
            r.read(decode_content=True)

    @onlyZstd()
    @pytest.mark.parametrize("data", decode_param_set)
    def test_decode_zstd_incomplete_read1(self, data: bytes) -> None:
        data = zstd_compress(data)
        fp = BytesIO(data[:-1])

        r = HTTPResponse(
            fp, headers={"content-encoding": "zstd"}, preload_content=False
        )

        # read/decode via read1(!), expecting DecodeError
        with pytest.raises(DecodeError):
            amt_decoded = 0
            # loop, as read1() may return just partial data
            while amt_decoded < len(data):
                part = r.read1(decode_content=True)
                amt_decoded += len(part)

    @onlyZstd()
    @pytest.mark.parametrize("data", decode_param_set)
    def test_decode_zstd_read1(self, data: bytes) -> None:
        encoded_data = zstd_compress(data)
        fp = BytesIO(encoded_data)

        r = HTTPResponse(
            fp, headers={"content-encoding": "zstd"}, preload_content=False
        )

        amt_decoded = 0
        decoded_data = b""
        # loop, as read1() may return just partial data
        while amt_decoded < len(data):
            part = r.read1(decode_content=True)
            amt_decoded += len(part)
            decoded_data += part
        assert decoded_data == data

    def test_multi_decoding_deflate_deflate(self) -> None:
        data = zlib.compress(zlib.compress(b"foo"))

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "deflate, deflate"})

        assert r.data == b"foo"

    def test_multi_decoding_deflate_gzip(self) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        data = compress.compress(zlib.compress(b"foo"))
        data += compress.flush()

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "deflate, gzip"})

        assert r.data == b"foo"

    def test_multi_decoding_gzip_gzip(self) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        data = compress.compress(b"foo")
        data += compress.flush()

        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        data = compress.compress(data)
        data += compress.flush()

        fp = BytesIO(data)
        r = HTTPResponse(fp, headers={"content-encoding": "gzip, gzip"})

        assert r.data == b"foo"

    def test_read_multi_decoding_deflate_deflate(self) -> None:
        msg = b"foobarbaz" * 42
        data = zlib.compress(zlib.compress(msg))

        fp = BytesIO(data)
        r = HTTPResponse(
            fp, headers={"content-encoding": "deflate, deflate"}, preload_content=False
        )

        assert r.read(3) == b"foo"
        assert r.read(3) == b"bar"
        assert r.read(3) == b"baz"
        assert r.read(9) == b"foobarbaz"
        assert r.read(9 * 3) == b"foobarbaz" * 3
        assert r.read(9 * 37) == b"foobarbaz" * 37
        assert r.read() == b""

    def test_body_blob(self) -> None:
        resp = HTTPResponse(b"foo")
        assert resp.data == b"foo"
        assert resp.closed

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
    def test_base_io(self) -> None:
        resp = BaseHTTPResponse(
            status=200,
            version=11,
            version_string="HTTP/1.1",
            reason=None,
            decode_content=False,
            request_url=None,
        )

        assert not resp.closed
        assert not resp.readable()
        assert not resp.writable()

        with pytest.raises(NotImplementedError):
            resp.read()
        with pytest.raises(NotImplementedError):
            resp.close()

    def test_io(self, sock: socket.socket) -> None:
        fp = BytesIO(b"foo")
        resp = HTTPResponse(fp, preload_content=False)

        assert not resp.closed
        assert resp.readable()
        assert not resp.writable()
        with pytest.raises(IOError):
            resp.fileno()

        resp.close()
        assert resp.closed

        # Try closing with an `httplib.HTTPResponse`, because it has an
        # `isclosed` method.
        try:
            hlr = httplib.HTTPResponse(sock)
            resp2 = HTTPResponse(hlr, preload_content=False)
            assert not resp2.closed
            resp2.close()
            assert resp2.closed
        finally:
            hlr.close()

        # also try when only data is present.
        resp3 = HTTPResponse("foodata")
        with pytest.raises(IOError):
            resp3.fileno()

        resp3._fp = 2
        # A corner case where _fp is present but doesn't have `closed`,
        # `isclosed`, or `fileno`.  Unlikely, but possible.
        assert resp3.closed
        with pytest.raises(IOError):
            resp3.fileno()

    def test_io_closed_consistently_by_read(self, sock: socket.socket) -> None:
        try:
            hlr = httplib.HTTPResponse(sock)
            hlr.fp = BytesIO(b"foo")  # type: ignore[assignment]
            hlr.chunked = 0  # type: ignore[assignment]
            hlr.length = 3
            with HTTPResponse(hlr, preload_content=False) as resp:
                assert not resp.closed
                assert resp._fp is not None
                assert not resp._fp.isclosed()
                assert not is_fp_closed(resp._fp)
                assert not resp.isclosed()
                resp.read()
                assert resp.closed
                assert resp._fp.isclosed()
                assert is_fp_closed(resp._fp)
                assert resp.isclosed()
        finally:
            hlr.close()

    @pytest.mark.parametrize("read_amt", (None, 3))
    @pytest.mark.parametrize("length_known", (True, False))
    def test_io_closed_consistently_by_read1(
        self, sock: socket.socket, length_known: bool, read_amt: int | None
    ) -> None:
        with httplib.HTTPResponse(sock) as hlr:
            hlr.fp = BytesIO(b"foo")  # type: ignore[assignment]
            hlr.chunked = 0  # type: ignore[assignment]
            hlr.length = 3 if length_known else None
            with HTTPResponse(hlr, preload_content=False) as resp:
                if length_known:
                    resp.length_remaining = 3
                assert not resp.closed
                assert resp._fp is not None
                assert not resp._fp.isclosed()
                assert not is_fp_closed(resp._fp)
                assert not resp.isclosed()
                resp.read1(read_amt)
                # If content length is unknown, IO is not closed until
                # the next read returning zero bytes.
                if not length_known:
                    assert not resp.closed
                    assert resp._fp is not None
                    assert not resp._fp.isclosed()
                    assert not is_fp_closed(resp._fp)
                    assert not resp.isclosed()
                    resp.read1(read_amt)
                assert resp.closed
                assert resp._fp.isclosed()
                assert is_fp_closed(resp._fp)
                assert resp.isclosed()

    @pytest.mark.parametrize("length_known", (True, False))
    def test_io_not_closed_until_all_data_is_read(
        self, sock: socket.socket, length_known: bool
    ) -> None:
        with httplib.HTTPResponse(sock) as hlr:
            hlr.fp = BytesIO(b"foo")  # type: ignore[assignment]
            hlr.chunked = 0  # type: ignore[assignment]
            length_remaining = 3
            hlr.length = length_remaining if length_known else None
            with HTTPResponse(hlr, preload_content=False) as resp:
                if length_known:
                    resp.length_remaining = length_remaining
                while length_remaining:
                    assert not resp.closed
                    assert resp._fp is not None
                    assert not resp._fp.isclosed()
                    assert not is_fp_closed(resp._fp)
                    assert not resp.isclosed()
                    data = resp.read(1)
                    assert len(data) == 1
                    length_remaining -= 1
                # If content length is unknown, IO is not closed until
                # the next read returning zero bytes.
                if not length_known:
                    assert not resp.closed
                    assert resp._fp is not None
                    assert not resp._fp.isclosed()
                    assert not is_fp_closed(resp._fp)
                    assert not resp.isclosed()
                    data = resp.read(1)
                    assert len(data) == 0
                assert resp.closed
                assert resp._fp.isclosed()  # type: ignore[union-attr]
                assert is_fp_closed(resp._fp)
                assert resp.isclosed()

    @pytest.mark.parametrize("length_known", (True, False))
    def test_io_not_closed_after_requesting_0_bytes(
        self, sock: socket.socket, length_known: bool
    ) -> None:
        with httplib.HTTPResponse(sock) as hlr:
            hlr.fp = BytesIO(b"foo")  # type: ignore[assignment]
            hlr.chunked = 0  # type: ignore[assignment]
            length_remaining = 3
            hlr.length = length_remaining if length_known else None
            with HTTPResponse(hlr, preload_content=False) as resp:
                if length_known:
                    resp.length_remaining = length_remaining
                assert not resp.closed
                assert resp._fp is not None
                assert not resp._fp.isclosed()
                assert not is_fp_closed(resp._fp)
                assert not resp.isclosed()
                data = resp.read(0)
                assert data == b""
                assert not resp.closed
                assert resp._fp is not None
                assert not resp._fp.isclosed()
                assert not is_fp_closed(resp._fp)
                assert not resp.isclosed()

    def test_io_bufferedreader(self) -> None:
        fp = BytesIO(b"foo")
        resp = HTTPResponse(fp, preload_content=False)
        br = BufferedReader(resp)  # type: ignore[arg-type]

        assert br.read() == b"foo"

        br.close()
        assert resp.closed

        # HTTPResponse.read() by default closes the response
        # https://github.com/urllib3/urllib3/issues/1305
        fp = BytesIO(b"hello\nworld")
        resp = HTTPResponse(fp, preload_content=False)
        with pytest.raises(ValueError, match="readline of closed file"):
            list(BufferedReader(resp))  # type: ignore[arg-type]

        b = b"fooandahalf"
        fp = BytesIO(b)
        resp = HTTPResponse(fp, preload_content=False)
        br = BufferedReader(resp, 5)  # type: ignore[arg-type]

        br.read(1)  # sets up the buffer, reading 5
        assert len(fp.read()) == (len(b) - 5)

        # This is necessary to make sure the "no bytes left" part of `readinto`
        # gets tested.
        while not br.closed:
            br.read(5)

    def test_io_not_autoclose_bufferedreader(self) -> None:
        fp = BytesIO(b"hello\nworld")
        resp = HTTPResponse(fp, preload_content=False, auto_close=False)
        reader = BufferedReader(resp)  # type: ignore[arg-type]
        assert list(reader) == [b"hello\n", b"world"]

        assert not reader.closed
        assert not resp.closed
        with pytest.raises(StopIteration):
            next(reader)

        reader.close()
        assert reader.closed
        assert resp.closed
        with pytest.raises(ValueError, match="readline of closed file"):
            next(reader)

    def test_io_textiowrapper(self) -> None:
        fp = BytesIO(b"\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f")
        resp = HTTPResponse(fp, preload_content=False)
        br = TextIOWrapper(resp, encoding="utf8")  # type: ignore[type-var]

        assert br.read() == "äöüß"

        br.close()
        assert resp.closed

        # HTTPResponse.read() by default closes the response
        # https://github.com/urllib3/urllib3/issues/1305
        fp = BytesIO(
            b"\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f\n\xce\xb1\xce\xb2\xce\xb3\xce\xb4"
        )
        resp = HTTPResponse(fp, preload_content=False)
        with pytest.raises(ValueError, match="I/O operation on closed file.?"):
            list(TextIOWrapper(resp))  # type: ignore[type-var]

    def test_io_not_autoclose_textiowrapper(self) -> None:
        fp = BytesIO(
            b"\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f\n\xce\xb1\xce\xb2\xce\xb3\xce\xb4"
        )
        resp = HTTPResponse(fp, preload_content=False, auto_close=False)
        reader = TextIOWrapper(resp, encoding="utf8")  # type: ignore[type-var]
        assert list(reader) == ["äöüß\n", "αβγδ"]

        assert not reader.closed
        assert not resp.closed
        with pytest.raises(StopIteration):
            next(reader)

        reader.close()
        assert reader.closed
        assert resp.closed
        with pytest.raises(ValueError, match="I/O operation on closed file.?"):
            next(reader)

    def test_read_with_illegal_mix_decode_toggle(self) -> None:
        data = zlib.compress(b"foo")

        fp = BytesIO(data)

        resp = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )

        assert resp.read(1) == b"f"

        with pytest.raises(
            RuntimeError,
            match=(
                r"Calling read\(decode_content=False\) is not supported after "
                r"read\(decode_content=True\) was called"
            ),
        ):
            resp.read(1, decode_content=False)

        with pytest.raises(
            RuntimeError,
            match=(
                r"Calling read\(decode_content=False\) is not supported after "
                r"read\(decode_content=True\) was called"
            ),
        ):
            resp.read(decode_content=False)

    def test_read1_with_illegal_mix_decode_toggle(self) -> None:
        data = zlib.compress(b"foo")

        fp = BytesIO(data)

        resp = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )

        assert resp.read1(1) == b"f"

        with pytest.raises(
            RuntimeError,
            match=(
                r"Calling read1\(decode_content=False\) is not supported after "
                r"read1\(decode_content=True\) was called"
            ),
        ):
            resp.read1(1, decode_content=False)

        with pytest.raises(
            RuntimeError,
            match=(
                r"Calling read1\(decode_content=False\) is not supported after "
                r"read1\(decode_content=True\) was called"
            ),
        ):
            resp.read1(decode_content=False)

    def test_read_with_mix_decode_toggle(self) -> None:
        data = zlib.compress(b"foo")

        fp = BytesIO(data)

        resp = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )
        assert resp.read(2, decode_content=False) is not None
        assert resp.read(1, decode_content=True) == b"f"

    def test_streaming(self) -> None:
        fp = BytesIO(b"foo")
        resp = HTTPResponse(fp, preload_content=False)
        stream = resp.stream(2, decode_content=False)

        assert next(stream) == b"fo"
        assert next(stream) == b"o"
        with pytest.raises(StopIteration):
            next(stream)

    def test_streaming_tell(self) -> None:
        fp = BytesIO(b"foo")
        resp = HTTPResponse(fp, preload_content=False)
        stream = resp.stream(2, decode_content=False)

        position = 0

        position += len(next(stream))
        assert 2 == position
        assert position == resp.tell()

        position += len(next(stream))
        assert 3 == position
        assert position == resp.tell()

        with pytest.raises(StopIteration):
            next(stream)

    def test_gzipped_streaming(self) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        data = compress.compress(b"foo")
        data += compress.flush()

        fp = BytesIO(data)
        resp = HTTPResponse(
            fp, headers={"content-encoding": "gzip"}, preload_content=False
        )
        stream = resp.stream(2)

        assert next(stream) == b"fo"
        assert next(stream) == b"o"
        with pytest.raises(StopIteration):
            next(stream)

    def test_gzipped_streaming_tell(self) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        uncompressed_data = b"foo"
        data = compress.compress(uncompressed_data)
        data += compress.flush()

        fp = BytesIO(data)
        resp = HTTPResponse(
            fp, headers={"content-encoding": "gzip"}, preload_content=False
        )
        stream = resp.stream()

        # Read everything
        payload = next(stream)
        assert payload == uncompressed_data

        assert len(data) == resp.tell()

        with pytest.raises(StopIteration):
            next(stream)

    def test_deflate_streaming_tell_intermediate_point(self) -> None:
        # Ensure that ``tell()`` returns the correct number of bytes when
        # part-way through streaming compressed content.
        NUMBER_OF_READS = 10
        PART_SIZE = 64

        class MockCompressedDataReading(BytesIO):
            """
            A BytesIO-like reader returning ``payload`` in ``NUMBER_OF_READS``
            calls to ``read``.
            """

            def __init__(self, payload: bytes, payload_part_size: int) -> None:
                self.payloads = [
                    payload[i * payload_part_size : (i + 1) * payload_part_size]
                    for i in range(NUMBER_OF_READS + 1)
                ]

                assert b"".join(self.payloads) == payload

            def read(self, _: int) -> bytes:  # type: ignore[override]
                # Amount is unused.
                if len(self.payloads) > 0:
                    return self.payloads.pop(0)
                return b""

            def read1(self, amt: int) -> bytes:  # type: ignore[override]
                return self.read(amt)

        uncompressed_data = zlib.decompress(ZLIB_PAYLOAD)

        payload_part_size = len(ZLIB_PAYLOAD) // NUMBER_OF_READS
        fp = MockCompressedDataReading(ZLIB_PAYLOAD, payload_part_size)
        resp = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )
        stream = resp.stream(PART_SIZE)

        parts_positions = [(part, resp.tell()) for part in stream]
        end_of_stream = resp.tell()

        with pytest.raises(StopIteration):
            next(stream)

        parts, positions = zip(*parts_positions)

        # Check that the payload is equal to the uncompressed data
        payload = b"".join(parts)
        assert uncompressed_data == payload

        # Check that the positions in the stream are correct
        # It is difficult to determine programmatically what the positions
        # returned by `tell` will be because the `HTTPResponse.read` method may
        # call socket `read` a couple of times if it doesn't have enough data
        # in the buffer or not call socket `read` at all if it has enough. All
        # this depends on the message, how it was compressed, what is
        # `PART_SIZE` and `payload_part_size`.
        # So for simplicity the expected values are hardcoded.
        expected = (92, 184, 230, 276, 322, 368, 414, 460)
        assert expected == positions

        # Check that the end of the stream is in the correct place
        assert len(ZLIB_PAYLOAD) == end_of_stream

        # Check that all parts have expected length
        expected_last_part_size = len(uncompressed_data) % PART_SIZE
        whole_parts = len(uncompressed_data) // PART_SIZE
        if expected_last_part_size == 0:
            expected_lengths = [PART_SIZE] * whole_parts
        else:
            expected_lengths = [PART_SIZE] * whole_parts + [expected_last_part_size]
        assert expected_lengths == [len(part) for part in parts]

    def test_deflate_streaming(self) -> None:
        data = zlib.compress(b"foo")

        fp = BytesIO(data)
        resp = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )
        stream = resp.stream(2)

        assert next(stream) == b"fo"
        assert next(stream) == b"o"
        with pytest.raises(StopIteration):
            next(stream)

    def test_deflate2_streaming(self) -> None:
        compress = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
        data = compress.compress(b"foo")
        data += compress.flush()

        fp = BytesIO(data)
        resp = HTTPResponse(
            fp, headers={"content-encoding": "deflate"}, preload_content=False
        )
        stream = resp.stream(2)

        assert next(stream) == b"fo"
        assert next(stream) == b"o"
        with pytest.raises(StopIteration):
            next(stream)

    def test_empty_stream(self) -> None:
        fp = BytesIO(b"")
        resp = HTTPResponse(fp, preload_content=False)
        stream = resp.stream(2, decode_content=False)

        with pytest.raises(StopIteration):
            next(stream)

    @pytest.mark.parametrize(
        "preload_content, amt, read_meth",
        [
            (True, None, "read"),
            (False, None, "read"),
            (False, 10 * 2**20, "read"),
            (False, None, "read1"),
            (False, 10 * 2**20, "read1"),
        ],
    )
    @pytest.mark.limit_memory("25 MB", current_thread_only=True)
    def test_buffer_memory_usage_decode_one_chunk(
        self, preload_content: bool, amt: int, read_meth: str
    ) -> None:
        content_length = 10 * 2**20  # 10 MiB
        fp = BytesIO(zlib.compress(bytes(content_length)))
        resp = HTTPResponse(
            fp,
            preload_content=preload_content,
            headers={"content-encoding": "deflate"},
        )
        data = resp.data if preload_content else getattr(resp, read_meth)(amt)
        assert len(data) == content_length

    @pytest.mark.parametrize(
        "preload_content, amt, read_meth",
        [
            (True, None, "read"),
            (False, None, "read"),
            (False, 10 * 2**20, "read"),
            (False, None, "read1"),
            (False, 10 * 2**20, "read1"),
        ],
    )
    @pytest.mark.limit_memory("10.5 MB", current_thread_only=True)
    def test_buffer_memory_usage_no_decoding(
        self, preload_content: bool, amt: int, read_meth: str
    ) -> None:
        content_length = 10 * 2**20  # 10 MiB
        fp = BytesIO(bytes(content_length))
        resp = HTTPResponse(fp, preload_content=preload_content, decode_content=False)
        data = resp.data if preload_content else getattr(resp, read_meth)(amt)
        assert len(data) == content_length

    def test_length_no_header(self) -> None:
        fp = BytesIO(b"12345")
        resp = HTTPResponse(fp, preload_content=False)
        assert resp.length_remaining is None

    def test_length_w_valid_header(self) -> None:
        headers = {"content-length": "5"}
        fp = BytesIO(b"12345")

        resp = HTTPResponse(fp, headers=headers, preload_content=False)
        assert resp.length_remaining == 5

    def test_length_w_bad_header(self) -> None:
        garbage = {"content-length": "foo"}
        fp = BytesIO(b"12345")

        resp = HTTPResponse(fp, headers=garbage, preload_content=False)
        assert resp.length_remaining is None

        garbage["content-length"] = "-10"
        resp = HTTPResponse(fp, headers=garbage, preload_content=False)
        assert resp.length_remaining is None

    def test_length_when_chunked(self) -> None:
        # This is expressly forbidden in RFC 7230 sec 3.3.2
        # We fall back to chunked in this case and try to
        # handle response ignoring content length.
        headers = {"content-length": "5", "transfer-encoding": "chunked"}
        fp = BytesIO(b"12345")

        resp = HTTPResponse(fp, headers=headers, preload_content=False)
        assert resp.length_remaining is None

    def test_length_with_multiple_content_lengths(self) -> None:
        headers = {"content-length": "5, 5, 5"}
        garbage = {"content-length": "5, 42"}
        fp = BytesIO(b"abcde")

        resp = HTTPResponse(fp, headers=headers, preload_content=False)
        assert resp.length_remaining == 5

        with pytest.raises(InvalidHeader):
            HTTPResponse(fp, headers=garbage, preload_content=False)

    def test_length_after_read(self) -> None:
        headers = {"content-length": "5"}

        # Test no defined length
        fp = BytesIO(b"12345")
        resp = HTTPResponse(fp, preload_content=False)
        resp.read()
        assert resp.length_remaining is None

        # Test our update from content-length
        fp = BytesIO(b"12345")
        resp = HTTPResponse(fp, headers=headers, preload_content=False)
        resp.read()
        assert resp.length_remaining == 0

        # Test partial read
        fp = BytesIO(b"12345")
        resp = HTTPResponse(fp, headers=headers, preload_content=False)
        data = resp.stream(2)
        next(data)
        assert resp.length_remaining == 3

    def test_mock_httpresponse_stream(self) -> None:
        # Mock out a HTTP Request that does enough to make it through urllib3's
        # read() and close() calls, and also exhausts and underlying file
        # object.
        class MockHTTPRequest:
            def __init__(self) -> None:
                self.fp: BytesIO | None = None

            def read(self, amt: int) -> bytes:
                assert self.fp is not None
                data = self.fp.read(amt)
                if not data:
                    self.fp = None

                return data

            def read1(self, amt: int) -> bytes:
                return self.read(1)

            def close(self) -> None:
                self.fp = None

        bio = BytesIO(b"foo")
        fp = MockHTTPRequest()
        fp.fp = bio
        resp = HTTPResponse(fp, preload_content=False)  # type: ignore[arg-type]
        stream = resp.stream(2)

        assert next(stream) == b"fo"
        assert next(stream) == b"o"
        with pytest.raises(StopIteration):
            next(stream)

    def test_mock_transfer_encoding_chunked(self) -> None:
        stream = [b"fo", b"o", b"bar"]
        fp = MockChunkedEncodingResponse(stream)
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        resp = HTTPResponse(
            r, preload_content=False, headers={"transfer-encoding": "chunked"}
        )

        for i, c in enumerate(resp.stream()):
            assert c == stream[i]

    def test_mock_gzipped_transfer_encoding_chunked_decoded(self) -> None:
        """Show that we can decode the gzipped and chunked body."""

        def stream() -> typing.Generator[bytes]:
            # Set up a generator to chunk the gzipped body
            compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
            data = compress.compress(b"foobar")
            data += compress.flush()
            for i in range(0, len(data), 2):
                yield data[i : i + 2]

        fp = MockChunkedEncodingResponse(list(stream()))
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        headers = {"transfer-encoding": "chunked", "content-encoding": "gzip"}
        resp = HTTPResponse(r, preload_content=False, headers=headers)

        data = b""
        for c in resp.stream(decode_content=True):
            data += c

        assert b"foobar" == data

    def test_mock_transfer_encoding_chunked_custom_read(self) -> None:
        stream = [b"foooo", b"bbbbaaaaar"]
        fp = MockChunkedEncodingResponse(stream)
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        r.chunked = True
        r.chunk_left = None
        resp = HTTPResponse(
            r, preload_content=False, headers={"transfer-encoding": "chunked"}
        )
        expected_response = [b"fo", b"oo", b"o", b"bb", b"bb", b"aa", b"aa", b"ar"]
        response = list(resp.read_chunked(2))
        assert expected_response == response

    @pytest.mark.parametrize("read_chunked_args", ((), (None,), (-1,)))
    def test_mock_transfer_encoding_chunked_unlmtd_read(
        self, read_chunked_args: tuple[typing.Any, ...]
    ) -> None:
        stream = [b"foooo", b"bbbbaaaaar"]
        fp = MockChunkedEncodingResponse(stream)
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        r.chunked = True
        r.chunk_left = None
        resp = HTTPResponse(
            r, preload_content=False, headers={"transfer-encoding": "chunked"}
        )
        assert stream == list(resp.read_chunked(*read_chunked_args))

    def test_read_not_chunked_response_as_chunks(self) -> None:
        fp = BytesIO(b"foo")
        resp = HTTPResponse(fp, preload_content=False)
        r = resp.read_chunked()
        with pytest.raises(ResponseNotChunked):
            next(r)

    def test_read_chunked_not_supported(self) -> None:
        fp = BytesIO(b"foo")
        resp = HTTPResponse(
            fp, preload_content=False, headers={"transfer-encoding": "chunked"}
        )
        r = resp.read_chunked()
        with pytest.raises(BodyNotHttplibCompatible):
            next(r)

    def test_buggy_incomplete_read(self) -> None:
        # Simulate buggy versions of Python (<2.7.4)
        # See http://bugs.python.org/issue16298
        content_length = 1337
        fp = BytesIO(b"")
        resp = HTTPResponse(
            fp,
            headers={"content-length": str(content_length)},
            preload_content=False,
            enforce_content_length=True,
        )
        with pytest.raises(ProtocolError) as ctx:
            resp.read(3)

        orig_ex = ctx.value.args[1]
        assert isinstance(orig_ex, IncompleteRead)
        assert orig_ex.partial == 0
        assert orig_ex.expected == content_length

    def test_incomplete_chunk(self) -> None:
        stream = [b"foooo", b"bbbbaaaaar"]
        fp = MockChunkedIncompleteRead(stream)
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        r.chunked = True
        r.chunk_left = None
        resp = HTTPResponse(
            r, preload_content=False, headers={"transfer-encoding": "chunked"}
        )
        with pytest.raises(ProtocolError) as ctx:
            next(resp.read_chunked())

        orig_ex = ctx.value.args[1]
        assert isinstance(orig_ex, httplib_IncompleteRead)

    def test_invalid_chunk_length(self) -> None:
        stream = [b"foooo", b"bbbbaaaaar"]
        fp = MockChunkedInvalidChunkLength(stream)
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        r.chunked = True
        r.chunk_left = None
        resp = HTTPResponse(
            r, preload_content=False, headers={"transfer-encoding": "chunked"}
        )
        with pytest.raises(ProtocolError) as ctx:
            next(resp.read_chunked())

        orig_ex = ctx.value.args[1]
        msg = (
            "(\"Connection broken: InvalidChunkLength(got length b'ZZZ\\\\r\\\\n', 0 bytes read)\", "
            "InvalidChunkLength(got length b'ZZZ\\r\\n', 0 bytes read))"
        )
        assert str(ctx.value) == msg
        assert isinstance(orig_ex, InvalidChunkLength)
        assert orig_ex.length == fp.BAD_LENGTH_LINE.encode()

    def test_truncated_before_chunk(self) -> None:
        stream = [b"foooo", b"bbbbaaaaar"]
        fp = MockChunkedNoChunks(stream)
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        r.chunked = True
        r.chunk_left = None
        resp = HTTPResponse(
            r, preload_content=False, headers={"transfer-encoding": "chunked"}
        )
        with pytest.raises(ProtocolError) as ctx:
            next(resp.read_chunked())

        assert str(ctx.value) == "Response ended prematurely"

    def test_chunked_response_without_crlf_on_end(self) -> None:
        stream = [b"foo", b"bar", b"baz"]
        fp = MockChunkedEncodingWithoutCRLFOnEnd(stream)
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        r.chunked = True
        r.chunk_left = None
        resp = HTTPResponse(
            r, preload_content=False, headers={"transfer-encoding": "chunked"}
        )
        assert stream == list(resp.stream())

    def test_chunked_response_with_extensions(self) -> None:
        stream = [b"foo", b"bar"]
        fp = MockChunkedEncodingWithExtensions(stream)
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        r.chunked = True
        r.chunk_left = None
        resp = HTTPResponse(
            r, preload_content=False, headers={"transfer-encoding": "chunked"}
        )
        assert stream == list(resp.stream())

    def test_chunked_head_response(self) -> None:
        r = httplib.HTTPResponse(MockSock, method="HEAD")  # type: ignore[arg-type]
        r.chunked = True
        r.chunk_left = None
        resp = HTTPResponse(
            "",
            preload_content=False,
            headers={"transfer-encoding": "chunked"},
            original_response=r,
        )
        assert resp.chunked is True

        setattr(resp, "supports_chunked_reads", lambda: True)
        setattr(resp, "release_conn", mock.Mock())
        for _ in resp.stream():
            continue
        resp.release_conn.assert_called_once_with()  # type: ignore[attr-defined]

    def test_get_case_insensitive_headers(self) -> None:
        headers = {"host": "example.com"}
        r = HTTPResponse(headers=headers)
        assert r.headers.get("host") == "example.com"
        assert r.headers.get("Host") == "example.com"

    def test_retries(self) -> None:
        fp = BytesIO(b"")
        resp = HTTPResponse(fp)
        assert resp.retries is None
        retry = Retry()
        resp = HTTPResponse(fp, retries=retry)
        assert resp.retries == retry

    def test_geturl(self) -> None:
        fp = BytesIO(b"")
        request_url = "https://example.com"
        resp = HTTPResponse(fp, request_url=request_url)
        assert resp.geturl() == request_url

    def test_url(self) -> None:
        fp = BytesIO(b"")
        request_url = "https://example.com"
        resp = HTTPResponse(fp, request_url=request_url)
        assert resp.url == request_url
        resp.url = "https://anotherurl.com"
        assert resp.url == "https://anotherurl.com"

    def test_geturl_retries(self) -> None:
        fp = BytesIO(b"")
        resp = HTTPResponse(fp, request_url="http://example.com")
        request_histories = (
            RequestHistory(
                method="GET",
                url="http://example.com",
                error=None,
                status=301,
                redirect_location="https://example.com/",
            ),
            RequestHistory(
                method="GET",
                url="https://example.com/",
                error=None,
                status=301,
                redirect_location="https://www.example.com",
            ),
        )
        retry = Retry(history=request_histories)
        resp = HTTPResponse(fp, retries=retry)
        assert resp.geturl() == "https://www.example.com"

    @pytest.mark.parametrize(
        ["payload", "expected_stream"],
        [
            (b"", []),
            (b"\n", [b"\n"]),
            (b"\n\n\n", [b"\n", b"\n", b"\n"]),
            (b"abc\ndef", [b"abc\n", b"def"]),
            (b"Hello\nworld\n\n\n!", [b"Hello\n", b"world\n", b"\n", b"\n", b"!"]),
        ],
    )
    def test__iter__(self, payload: bytes, expected_stream: list[bytes]) -> None:
        actual_stream = []
        for chunk in HTTPResponse(BytesIO(payload), preload_content=False):
            actual_stream.append(chunk)

        assert actual_stream == expected_stream

    def test__iter__decode_content(self) -> None:
        def stream() -> typing.Generator[bytes]:
            # Set up a generator to chunk the gzipped body
            compress = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
            data = compress.compress(b"foo\nbar")
            data += compress.flush()
            for i in range(0, len(data), 2):
                yield data[i : i + 2]

        fp = MockChunkedEncodingResponse(list(stream()))
        r = httplib.HTTPResponse(MockSock)  # type: ignore[arg-type]
        r.fp = fp  # type: ignore[assignment]
        headers = {"transfer-encoding": "chunked", "content-encoding": "gzip"}
        resp = HTTPResponse(r, preload_content=False, headers=headers)

        data = b""
        for c in resp:
            data += c

        assert b"foo\nbar" == data

    def test_non_timeout_ssl_error_on_read(self) -> None:
        mac_error = ssl.SSLError(
            "SSL routines", "ssl3_get_record", "decryption failed or bad record mac"
        )

        @contextlib.contextmanager
        def make_bad_mac_fp() -> typing.Generator[BytesIO]:
            fp = BytesIO(b"")
            with mock.patch.object(fp, "read") as fp_read:
                # mac/decryption error
                fp_read.side_effect = mac_error
                yield fp

        with make_bad_mac_fp() as fp:
            with pytest.raises(SSLError) as e:
                HTTPResponse(fp)
            assert e.value.args[0] == mac_error

        with make_bad_mac_fp() as fp:
            resp = HTTPResponse(fp, preload_content=False)
            with pytest.raises(SSLError) as e:
                resp.read()
            assert e.value.args[0] == mac_error

    def test_unexpected_body(self) -> None:
        with pytest.raises(ProtocolError) as excinfo:
            fp = BytesIO(b"12345")
            headers = {"content-length": "5"}
            resp = HTTPResponse(fp, status=204, headers=headers)
            resp.read(16)
        assert "Response may not contain content" in str(excinfo.value)

        with pytest.raises(ProtocolError):
            fp = BytesIO(b"12345")
            headers = {"content-length": "0"}
            resp = HTTPResponse(fp, status=204, headers=headers)
            resp.read(16)
        assert "Response may not contain content" in str(excinfo.value)

        with pytest.raises(ProtocolError):
            fp = BytesIO(b"12345")
            resp = HTTPResponse(fp, status=204)
            resp.read(16)
        assert "Response may not contain content" in str(excinfo.value)


class MockChunkedEncodingResponse:
    def __init__(self, content: list[bytes]) -> None:
        """
        content: collection of str, each str is a chunk in response
        """
        self.content = content
        self.index = 0  # This class iterates over self.content.
        self.closed = False
        self.cur_chunk = b""
        self.chunks_exhausted = False

    def _encode_chunk(self, chunk: bytes) -> bytes:
        # In the general case, we can't decode the chunk to unicode
        length = f"{len(chunk):X}\r\n"
        return length.encode() + chunk + b"\r\n"

    def _pop_new_chunk(self) -> bytes:
        if self.chunks_exhausted:
            return b""
        try:
            chunk = self.content[self.index]
        except IndexError:
            chunk = b""
            self.chunks_exhausted = True
        else:
            self.index += 1
        chunk = self._encode_chunk(chunk)
        if not isinstance(chunk, bytes):
            chunk = chunk.encode()
        assert isinstance(chunk, bytes)
        return chunk

    def pop_current_chunk(self, amt: int = -1, till_crlf: bool = False) -> bytes:
        if amt > 0 and till_crlf:
            raise ValueError("Can't specify amt and till_crlf.")
        if len(self.cur_chunk) <= 0:
            self.cur_chunk = self._pop_new_chunk()
        if till_crlf:
            try:
                i = self.cur_chunk.index(b"\r\n")
            except ValueError:
                # No CRLF in current chunk -- probably caused by encoder.
                self.cur_chunk = b""
                return b""
            else:
                chunk_part = self.cur_chunk[: i + 2]
                self.cur_chunk = self.cur_chunk[i + 2 :]
                return chunk_part
        elif amt <= -1:
            chunk_part = self.cur_chunk
            self.cur_chunk = b""
            return chunk_part
        else:
            try:
                chunk_part = self.cur_chunk[:amt]
            except IndexError:
                chunk_part = self.cur_chunk
                self.cur_chunk = b""
            else:
                self.cur_chunk = self.cur_chunk[amt:]
            return chunk_part

    def readline(self) -> bytes:
        return self.pop_current_chunk(till_crlf=True)

    def read(self, amt: int = -1) -> bytes:
        return self.pop_current_chunk(amt)

    def read1(self, amt: int = -1) -> bytes:
        return self.pop_current_chunk(amt)

    def flush(self) -> None:
        # Python 3 wants this method.
        pass

    def close(self) -> None:
        self.closed = True


class MockChunkedIncompleteRead(MockChunkedEncodingResponse):
    def _encode_chunk(self, chunk: bytes) -> bytes:
        return f"9999\r\n{chunk.decode()}\r\n".encode()


class MockChunkedInvalidChunkLength(MockChunkedEncodingResponse):
    BAD_LENGTH_LINE = "ZZZ\r\n"

    def _encode_chunk(self, chunk: bytes) -> bytes:
        return f"{self.BAD_LENGTH_LINE}{chunk.decode()}\r\n".encode()


class MockChunkedEncodingWithoutCRLFOnEnd(MockChunkedEncodingResponse):
    def _encode_chunk(self, chunk: bytes) -> bytes:
        return "{:X}\r\n{}{}".format(
            len(chunk),
            chunk.decode(),
            "\r\n" if len(chunk) > 0 else "",
        ).encode()


class MockChunkedEncodingWithExtensions(MockChunkedEncodingResponse):
    def _encode_chunk(self, chunk: bytes) -> bytes:
        return f"{len(chunk):X};asd=qwe\r\n{chunk.decode()}\r\n".encode()


class MockChunkedNoChunks(MockChunkedEncodingResponse):
    def _encode_chunk(self, chunk: bytes) -> bytes:
        return b""


class MockSock:
    @classmethod
    def makefile(cls, *args: typing.Any, **kwargs: typing.Any) -> None:
        return

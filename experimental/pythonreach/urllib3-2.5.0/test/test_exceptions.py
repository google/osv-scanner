from __future__ import annotations

import pickle
import socket
from email.errors import MessageDefect
from test import DUMMY_POOL

import pytest

from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import (
    ClosedPoolError,
    ConnectTimeoutError,
    EmptyPoolError,
    HeaderParsingError,
    HostChangedError,
    HTTPError,
    LocationParseError,
    MaxRetryError,
    NameResolutionError,
    NewConnectionError,
    ReadTimeoutError,
)


class TestPickle:
    @pytest.mark.parametrize(
        "exception",
        [
            HTTPError(None),
            MaxRetryError(DUMMY_POOL, "", None),
            MaxRetryError(DUMMY_POOL, "", Exception("Error occured")),
            LocationParseError(""),
            ConnectTimeoutError(None),
            HTTPError("foo"),
            HTTPError("foo", IOError("foo")),
            MaxRetryError(HTTPConnectionPool("localhost"), "/", None),
            LocationParseError("fake location"),
            ClosedPoolError(HTTPConnectionPool("localhost"), ""),
            EmptyPoolError(HTTPConnectionPool("localhost"), ""),
            HostChangedError(HTTPConnectionPool("localhost"), "/", 0),
            ReadTimeoutError(HTTPConnectionPool("localhost"), "/", ""),
            ReadTimeoutError(HTTPConnectionPool("localhost"), "/", "message"),
            NewConnectionError(HTTPConnection("localhost"), ""),
            NameResolutionError("", HTTPConnection("localhost"), socket.gaierror()),
            NameResolutionError(
                "host", HTTPConnection("localhost"), socket.gaierror("error")
            ),
        ],
    )
    def test_exceptions(self, exception: Exception) -> None:
        result = pickle.loads(pickle.dumps(exception))
        assert isinstance(result, type(exception))

        if hasattr(exception, "_message"):
            assert exception._message == result._message  # type: ignore[attr-defined]
            assert exception._message in str(result)

        if hasattr(exception, "_host"):
            # host is likely a string so directly comparable
            assert exception._host == result._host  # type: ignore[attr-defined]

        if hasattr(exception, "_reason"):
            # reason is likely an exception so do string comparison instead
            assert str(exception._reason) == str(result._reason)  # type: ignore[attr-defined]


class TestFormat:
    def test_header_parsing_errors(self) -> None:
        hpe = HeaderParsingError([MessageDefect("defects")], "unparsed_data")

        assert "defects" in str(hpe)
        assert "unparsed_data" in str(hpe)


class TestNewConnectionError:
    def test_pool_property_deprecation_warning(self) -> None:
        err = NewConnectionError(HTTPConnection("localhost"), "test")
        with pytest.warns(DeprecationWarning) as records:
            err_pool = err.pool

        assert err_pool is err.conn
        msg = (
            "The 'pool' property is deprecated and will be removed "
            "in urllib3 v2.1.0. Use 'conn' instead."
        )
        record = records[0]
        assert isinstance(record.message, Warning)
        assert record.message.args[0] == msg

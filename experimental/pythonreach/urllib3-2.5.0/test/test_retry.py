from __future__ import annotations

import datetime
from test import DUMMY_POOL
from unittest import mock

import pytest

from urllib3.exceptions import (
    ConnectTimeoutError,
    InvalidHeader,
    MaxRetryError,
    ReadTimeoutError,
    ResponseError,
    SSLError,
)
from urllib3.response import HTTPResponse
from urllib3.util.retry import RequestHistory, Retry


class TestRetry:
    def test_string(self) -> None:
        """Retry string representation looks the way we expect"""
        retry = Retry()
        assert (
            str(retry)
            == "Retry(total=10, connect=None, read=None, redirect=None, status=None)"
        )
        for _ in range(3):
            retry = retry.increment(method="GET")
        assert (
            str(retry)
            == "Retry(total=7, connect=None, read=None, redirect=None, status=None)"
        )

    def test_retry_both_specified(self) -> None:
        """Total can win if it's lower than the connect value"""
        error = ConnectTimeoutError()
        retry = Retry(connect=3, total=2)
        retry = retry.increment(error=error)
        retry = retry.increment(error=error)
        with pytest.raises(MaxRetryError) as e:
            retry.increment(error=error)
        assert e.value.reason == error

    def test_retry_higher_total_loses(self) -> None:
        """A lower connect timeout than the total is honored"""
        error = ConnectTimeoutError()
        retry = Retry(connect=2, total=3)
        retry = retry.increment(error=error)
        retry = retry.increment(error=error)
        with pytest.raises(MaxRetryError):
            retry.increment(error=error)

    def test_retry_higher_total_loses_vs_read(self) -> None:
        """A lower read timeout than the total is honored"""
        error = ReadTimeoutError(DUMMY_POOL, "/", "read timed out")
        retry = Retry(read=2, total=3)
        retry = retry.increment(method="GET", error=error)
        retry = retry.increment(method="GET", error=error)
        with pytest.raises(MaxRetryError):
            retry.increment(method="GET", error=error)

    def test_retry_total_none(self) -> None:
        """if Total is none, connect error should take precedence"""
        error = ConnectTimeoutError()
        retry = Retry(connect=2, total=None)
        retry = retry.increment(error=error)
        retry = retry.increment(error=error)
        with pytest.raises(MaxRetryError) as e:
            retry.increment(error=error)
        assert e.value.reason == error

        timeout_error = ReadTimeoutError(DUMMY_POOL, "/", "read timed out")
        retry = Retry(connect=2, total=None)
        retry = retry.increment(method="GET", error=timeout_error)
        retry = retry.increment(method="GET", error=timeout_error)
        retry = retry.increment(method="GET", error=timeout_error)
        assert not retry.is_exhausted()

    def test_retry_default(self) -> None:
        """If no value is specified, should retry connects 3 times"""
        retry = Retry()
        assert retry.total == 10
        assert retry.connect is None
        assert retry.read is None
        assert retry.redirect is None
        assert retry.other is None

        error = ConnectTimeoutError()
        retry = Retry(connect=1)
        retry = retry.increment(error=error)
        with pytest.raises(MaxRetryError):
            retry.increment(error=error)

        retry = Retry(connect=1)
        retry = retry.increment(error=error)
        assert not retry.is_exhausted()

        assert Retry(0).raise_on_redirect
        assert not Retry(False).raise_on_redirect

    def test_retry_other(self) -> None:
        """If an unexpected error is raised, should retry other times"""
        other_error = SSLError()
        retry = Retry(connect=1)
        retry = retry.increment(error=other_error)
        retry = retry.increment(error=other_error)
        assert not retry.is_exhausted()

        retry = Retry(other=1)
        retry = retry.increment(error=other_error)
        with pytest.raises(MaxRetryError) as e:
            retry.increment(error=other_error)
        assert e.value.reason == other_error

    def test_retry_read_zero(self) -> None:
        """No second chances on read timeouts, by default"""
        error = ReadTimeoutError(DUMMY_POOL, "/", "read timed out")
        retry = Retry(read=0)
        with pytest.raises(MaxRetryError) as e:
            retry.increment(method="GET", error=error)
        assert e.value.reason == error

    def test_status_counter(self) -> None:
        resp = HTTPResponse(status=400)
        retry = Retry(status=2)
        retry = retry.increment(response=resp)
        retry = retry.increment(response=resp)
        msg = ResponseError.SPECIFIC_ERROR.format(status_code=400)
        with pytest.raises(MaxRetryError, match=msg):
            retry.increment(response=resp)

    def test_backoff(self) -> None:
        """Backoff is computed correctly"""
        max_backoff = Retry.DEFAULT_BACKOFF_MAX

        retry = Retry(total=100, backoff_factor=0.2)
        assert retry.get_backoff_time() == 0  # First request

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 0  # First retry

        retry = retry.increment(method="GET")
        assert retry.backoff_factor == 0.2
        assert retry.total == 98
        assert retry.get_backoff_time() == 0.4  # Start backoff

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 0.8

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 1.6

        for _ in range(10):
            retry = retry.increment(method="GET")

        assert retry.get_backoff_time() == max_backoff

    def test_configurable_backoff_max(self) -> None:
        """Configurable backoff is computed correctly"""
        max_backoff = 1

        retry = Retry(total=100, backoff_factor=0.2, backoff_max=max_backoff)
        assert retry.get_backoff_time() == 0  # First request

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 0  # First retry

        retry = retry.increment(method="GET")
        assert retry.backoff_factor == 0.2
        assert retry.total == 98
        assert retry.get_backoff_time() == 0.4  # Start backoff

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 0.8

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == max_backoff

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == max_backoff

    def test_backoff_jitter(self) -> None:
        """Backoff with jitter is computed correctly"""
        max_backoff = 1
        jitter = 0.4
        retry = Retry(
            total=100,
            backoff_factor=0.2,
            backoff_max=max_backoff,
            backoff_jitter=jitter,
        )
        assert retry.get_backoff_time() == 0  # First request

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 0  # First retry

        retry = retry.increment(method="GET")
        assert retry.backoff_factor == 0.2
        assert retry.total == 98
        assert 0.4 <= retry.get_backoff_time() <= 0.8  # Start backoff

        retry = retry.increment(method="GET")
        assert 0.8 <= retry.get_backoff_time() <= max_backoff

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == max_backoff

        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == max_backoff

    def test_zero_backoff(self) -> None:
        retry = Retry()
        assert retry.get_backoff_time() == 0
        retry = retry.increment(method="GET")
        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 0

    def test_backoff_reset_after_redirect(self) -> None:
        retry = Retry(total=100, redirect=5, backoff_factor=0.2)
        retry = retry.increment(method="GET")
        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 0.4
        redirect_response = HTTPResponse(status=302, headers={"location": "test"})
        retry = retry.increment(method="GET", response=redirect_response)
        assert retry.get_backoff_time() == 0
        retry = retry.increment(method="GET")
        retry = retry.increment(method="GET")
        assert retry.get_backoff_time() == 0.4

    def test_sleep(self) -> None:
        # sleep a very small amount of time so our code coverage is happy
        retry = Retry(backoff_factor=0.0001)
        retry = retry.increment(method="GET")
        retry = retry.increment(method="GET")
        retry.sleep()

    def test_status_forcelist(self) -> None:
        retry = Retry(status_forcelist=range(500, 600))
        assert not retry.is_retry("GET", status_code=200)
        assert not retry.is_retry("GET", status_code=400)
        assert retry.is_retry("GET", status_code=500)

        retry = Retry(total=1, status_forcelist=[418])
        assert not retry.is_retry("GET", status_code=400)
        assert retry.is_retry("GET", status_code=418)

        # String status codes are not matched.
        retry = Retry(total=1, status_forcelist=["418"])  # type: ignore[list-item]
        assert not retry.is_retry("GET", status_code=418)

    def test_allowed_methods_with_status_forcelist(self) -> None:
        # Falsey allowed_methods means to retry on any method.
        retry = Retry(status_forcelist=[500], allowed_methods=None)
        assert retry.is_retry("GET", status_code=500)
        assert retry.is_retry("POST", status_code=500)

        # Criteria of allowed_methods and status_forcelist are ANDed.
        retry = Retry(status_forcelist=[500], allowed_methods=["POST"])
        assert not retry.is_retry("GET", status_code=500)
        assert retry.is_retry("POST", status_code=500)

    def test_exhausted(self) -> None:
        assert not Retry(0).is_exhausted()
        assert Retry(-1).is_exhausted()
        assert Retry(1).increment(method="GET").total == 0

    @pytest.mark.parametrize("total", [-1, 0])
    def test_disabled(self, total: int) -> None:
        with pytest.raises(MaxRetryError):
            Retry(total).increment(method="GET")

    def test_error_message(self) -> None:
        retry = Retry(total=0)
        with pytest.raises(MaxRetryError, match="read timed out") as e:
            retry = retry.increment(
                method="GET", error=ReadTimeoutError(DUMMY_POOL, "/", "read timed out")
            )
        assert "Caused by redirect" not in str(e.value)

        retry = Retry(total=1)
        retry = retry.increment("POST", "/")
        with pytest.raises(MaxRetryError, match=ResponseError.GENERIC_ERROR) as e:
            retry = retry.increment("POST", "/")
        assert "Caused by redirect" not in str(e.value)
        assert isinstance(e.value.reason, ResponseError)

        retry = Retry(total=1)
        response = HTTPResponse(status=500)
        msg = ResponseError.SPECIFIC_ERROR.format(status_code=500)
        retry = retry.increment("POST", "/", response=response)
        with pytest.raises(MaxRetryError, match=msg) as e:
            retry = retry.increment("POST", "/", response=response)
        assert "Caused by redirect" not in str(e.value)

        retry = Retry(connect=1)
        retry = retry.increment(error=ConnectTimeoutError("conntimeout"))
        with pytest.raises(MaxRetryError, match="conntimeout") as e:
            retry = retry.increment(error=ConnectTimeoutError("conntimeout"))
        assert "Caused by redirect" not in str(e.value)

    def test_history(self) -> None:
        retry = Retry(total=10, allowed_methods=frozenset(["GET", "POST"]))
        assert retry.history == tuple()
        connection_error = ConnectTimeoutError("conntimeout")
        retry = retry.increment("GET", "/test1", None, connection_error)
        test_history1 = (RequestHistory("GET", "/test1", connection_error, None, None),)
        assert retry.history == test_history1

        read_error = ReadTimeoutError(DUMMY_POOL, "/test2", "read timed out")
        retry = retry.increment("POST", "/test2", None, read_error)
        test_history2 = (
            RequestHistory("GET", "/test1", connection_error, None, None),
            RequestHistory("POST", "/test2", read_error, None, None),
        )
        assert retry.history == test_history2

        response = HTTPResponse(status=500)
        retry = retry.increment("GET", "/test3", response, None)
        test_history3 = (
            RequestHistory("GET", "/test1", connection_error, None, None),
            RequestHistory("POST", "/test2", read_error, None, None),
            RequestHistory("GET", "/test3", None, 500, None),
        )
        assert retry.history == test_history3

    def test_retry_method_not_allowed(self) -> None:
        error = ReadTimeoutError(DUMMY_POOL, "/", "read timed out")
        retry = Retry()
        with pytest.raises(ReadTimeoutError):
            retry.increment(method="POST", error=error)

    def test_retry_default_remove_headers_on_redirect(self) -> None:
        retry = Retry()

        assert retry.remove_headers_on_redirect == {
            "authorization",
            "proxy-authorization",
            "cookie",
        }

    def test_retry_set_remove_headers_on_redirect(self) -> None:
        retry = Retry(remove_headers_on_redirect=["X-API-Secret"])

        assert retry.remove_headers_on_redirect == {"x-api-secret"}

    @pytest.mark.parametrize("value", ["-1", "+1", "1.0", "\xb2"])  # \xb2 = ^2
    def test_parse_retry_after_invalid(self, value: str) -> None:
        retry = Retry()
        with pytest.raises(InvalidHeader):
            retry.parse_retry_after(value)

    @pytest.mark.parametrize(
        "value, expected", [("0", 0), ("1000", 1000), ("\t42 ", 42)]
    )
    def test_parse_retry_after(self, value: str, expected: int) -> None:
        retry = Retry()
        assert retry.parse_retry_after(value) == expected

    @pytest.mark.parametrize("respect_retry_after_header", [True, False])
    def test_respect_retry_after_header_propagated(
        self, respect_retry_after_header: bool
    ) -> None:
        retry = Retry(respect_retry_after_header=respect_retry_after_header)
        new_retry = retry.new()
        assert new_retry.respect_retry_after_header == respect_retry_after_header

    @pytest.mark.parametrize(
        "retry_after_header,respect_retry_after_header,sleep_duration",
        [
            ("3600", True, 3600),
            ("3600", False, None),
            # Will sleep due to header is 1 hour in future
            ("Mon, 3 Jun 2019 12:00:00 UTC", True, 3600),
            # Won't sleep due to not respecting header
            ("Mon, 3 Jun 2019 12:00:00 UTC", False, None),
            # Won't sleep due to current time reached
            ("Mon, 3 Jun 2019 11:00:00 UTC", True, None),
            # Won't sleep due to current time reached + not respecting header
            ("Mon, 3 Jun 2019 11:00:00 UTC", False, None),
            # Handle all the formats in RFC 7231 Section 7.1.1.1
            ("Mon, 03 Jun 2019 11:30:12 GMT", True, 1812),
            ("Monday, 03-Jun-19 11:30:12 GMT", True, 1812),
            # Assume that datetimes without a timezone are in UTC per RFC 7231
            ("Mon Jun  3 11:30:12 2019", True, 1812),
        ],
    )
    @pytest.mark.parametrize(
        "stub_timezone",
        [
            "UTC",
            "Asia/Jerusalem",
            None,
        ],
        indirect=True,
    )
    @pytest.mark.usefixtures("stub_timezone")
    def test_respect_retry_after_header_sleep(
        self,
        retry_after_header: str,
        respect_retry_after_header: bool,
        sleep_duration: int | None,
    ) -> None:
        retry = Retry(respect_retry_after_header=respect_retry_after_header)

        with (
            mock.patch(
                "time.time",
                return_value=datetime.datetime(
                    2019, 6, 3, 11, tzinfo=datetime.timezone.utc
                ).timestamp(),
            ),
            mock.patch("time.sleep") as sleep_mock,
        ):
            # for the default behavior, it must be in RETRY_AFTER_STATUS_CODES
            response = HTTPResponse(
                status=503, headers={"Retry-After": retry_after_header}
            )

            retry.sleep(response)

            # The expected behavior is that we'll only sleep if respecting
            # this header (since we won't have any backoff sleep attempts)
            if respect_retry_after_header and sleep_duration is not None:
                sleep_mock.assert_called_with(sleep_duration)
            else:
                sleep_mock.assert_not_called()

from __future__ import annotations

import http.cookiejar
import urllib
from unittest import mock

import pytest

import urllib3.http2
from urllib3.response import HTTPResponse


class TestCookiejar:
    def test_extract(self) -> None:
        request = urllib.request.Request("http://google.com")
        cookiejar = http.cookiejar.CookieJar()
        response = HTTPResponse()

        cookies = [
            "sessionhash=abcabcabcabcab; path=/; HttpOnly",
            "lastvisit=1348253375; expires=Sat, 21-Sep-2050 18:49:35 GMT; path=/",
        ]
        for c in cookies:
            response.headers.add("set-cookie", c)
        cookiejar.extract_cookies(response, request)  # type: ignore[arg-type]
        assert len(cookiejar) == len(cookies)


class TestInitialization:
    @mock.patch("urllib3.http2.version")
    def test_h2_version_check(self, mock_version: mock.MagicMock) -> None:
        try:
            mock_version.return_value = "4.1.0"
            urllib3.http2.inject_into_urllib3()

            mock_version.return_value = "3.9.9"
            with pytest.raises(
                ImportError, match="urllib3 v2 supports h2 version 4.x.x.*"
            ):
                urllib3.http2.inject_into_urllib3()

            mock_version.return_value = "5.0.0"
            with pytest.raises(
                ImportError, match="urllib3 v2 supports h2 version 4.x.x.*"
            ):
                urllib3.http2.inject_into_urllib3()
        finally:
            urllib3.http2.extract_from_urllib3()

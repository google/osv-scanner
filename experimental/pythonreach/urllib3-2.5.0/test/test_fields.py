from __future__ import annotations

import pytest

from urllib3.fields import (
    RequestField,
    format_header_param,
    format_header_param_html5,
    format_header_param_rfc2231,
    format_multipart_header_param,
    guess_content_type,
)


class TestRequestField:
    @pytest.mark.parametrize(
        "filename, content_types",
        [
            ("image.jpg", ["image/jpeg", "image/pjpeg"]),
            ("notsure", ["application/octet-stream"]),
            (None, ["application/octet-stream"]),
        ],
    )
    def test_guess_content_type(
        self, filename: str | None, content_types: list[str]
    ) -> None:
        assert guess_content_type(filename) in content_types

    def test_create(self) -> None:
        simple_field = RequestField("somename", "data")
        assert simple_field.render_headers() == "\r\n"
        filename_field = RequestField("somename", "data", filename="somefile.txt")
        assert filename_field.render_headers() == "\r\n"
        headers_field = RequestField(
            "somename", "data", headers={"Content-Length": "4"}
        )
        assert headers_field.render_headers() == "Content-Length: 4\r\n\r\n"

    def test_make_multipart(self) -> None:
        field = RequestField("somename", "data")
        field.make_multipart(content_type="image/jpg", content_location="/test")
        assert (
            field.render_headers()
            == 'Content-Disposition: form-data; name="somename"\r\n'
            "Content-Type: image/jpg\r\n"
            "Content-Location: /test\r\n"
            "\r\n"
        )

    def test_make_multipart_empty_filename(self) -> None:
        field = RequestField("somename", "data", "")
        field.make_multipart(content_type="application/octet-stream")
        assert (
            field.render_headers()
            == 'Content-Disposition: form-data; name="somename"; filename=""\r\n'
            "Content-Type: application/octet-stream\r\n"
            "\r\n"
        )

    def test_render_parts(self) -> None:
        field = RequestField("somename", "data")
        parts = field._render_parts({"name": "value", "filename": "value"})
        assert 'name="value"' in parts
        assert 'filename="value"' in parts
        parts = field._render_parts([("name", "value"), ("filename", "value")])
        assert parts == 'name="value"; filename="value"'

    @pytest.mark.parametrize(
        ("value", "expect"),
        [("näme", "filename*=utf-8''n%C3%A4me"), (b"name", 'filename="name"')],
    )
    def test_format_header_param_rfc2231_deprecated(
        self, value: bytes | str, expect: str
    ) -> None:
        with pytest.deprecated_call(match=r"urllib3 v2\.1\.0"):
            param = format_header_param_rfc2231("filename", value)

        assert param == expect

    def test_format_header_param_html5_deprecated(self) -> None:
        with pytest.deprecated_call(match=r"urllib3 v2\.1\.0"):
            param2 = format_header_param_html5("filename", "name")

        with pytest.deprecated_call(match=r"urllib3 v2\.1\.0"):
            param1 = format_header_param("filename", "name")

        assert param1 == param2

    @pytest.mark.parametrize(
        ("value", "expect"),
        [
            ("name", "name"),
            ("näme", "näme"),
            (b"n\xc3\xa4me", "näme"),
            ("ski ⛷.txt", "ski ⛷.txt"),
            ("control \x1A\x1B\x1C", "control \x1A\x1B\x1C"),
            ("backslash \\", "backslash \\"),
            ("quotes '\"", "quotes '%22"),
            ("newline \n\r", "newline %0A%0D"),
        ],
    )
    def test_format_multipart_header_param(
        self, value: bytes | str, expect: str
    ) -> None:
        param = format_multipart_header_param("filename", value)
        assert param == f'filename="{expect}"'

    def test_from_tuples(self) -> None:
        field = RequestField.from_tuples("file", ("スキー旅行.txt", "data"))
        cd = field.headers["Content-Disposition"]
        assert cd == 'form-data; name="file"; filename="スキー旅行.txt"'

    def test_from_tuples_rfc2231(self) -> None:
        with pytest.deprecated_call(match=r"urllib3 v2\.1\.0"):
            field = RequestField.from_tuples(
                "file", ("näme", "data"), header_formatter=format_header_param_rfc2231
            )

        cd = field.headers["Content-Disposition"]
        assert cd == "form-data; name=\"file\"; filename*=utf-8''n%C3%A4me"

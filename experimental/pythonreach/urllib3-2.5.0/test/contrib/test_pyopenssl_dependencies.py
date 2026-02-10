from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

try:
    from urllib3.contrib.pyopenssl import extract_from_urllib3, inject_into_urllib3
except ImportError:
    pass


def setup_module() -> None:
    try:
        from urllib3.contrib.pyopenssl import inject_into_urllib3

        inject_into_urllib3()
    except ImportError as e:
        pytest.skip(f"Could not import PyOpenSSL: {e!r}")


def teardown_module() -> None:
    try:
        from urllib3.contrib.pyopenssl import extract_from_urllib3

        extract_from_urllib3()
    except ImportError:
        pass


class TestPyOpenSSLInjection:
    """
    Tests for error handling in pyopenssl's 'inject_into urllib3'
    """

    def test_inject_validate_fail_cryptography(self) -> None:
        """
        Injection should not be supported if cryptography is too old.
        """
        try:
            with patch("cryptography.x509.extensions.Extensions") as mock:
                del mock.get_extension_for_class
                with pytest.raises(ImportError):
                    inject_into_urllib3()
        finally:
            # `inject_into_urllib3` is not supposed to succeed.
            # If it does, this test should fail, but we need to
            # clean up so that subsequent tests are unaffected.
            extract_from_urllib3()

    def test_inject_validate_fail_pyopenssl(self) -> None:
        """
        Injection should not be supported if pyOpenSSL is too old.
        """
        try:
            return_val = Mock()
            del return_val._x509
            with patch("OpenSSL.crypto.X509", return_value=return_val):
                with pytest.raises(ImportError):
                    inject_into_urllib3()
        finally:
            # `inject_into_urllib3` is not supposed to succeed.
            # If it does, this test should fail, but we need to
            # clean up so that subsequent tests are unaffected.
            extract_from_urllib3()

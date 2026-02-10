"""
Test what happens if Python was built without SSL

* Everything that does not involve HTTPS should still work
* HTTPS requests must fail with an error that points at the ssl module
"""

from __future__ import annotations

import sys
from test import ImportBlocker, ModuleStash

import pytest

ssl_blocker = ImportBlocker("ssl", "_ssl")
module_stash = ModuleStash("urllib3")


class TestWithoutSSL:
    @classmethod
    def setup_class(cls) -> None:
        sys.modules.pop("ssl", None)
        sys.modules.pop("_ssl", None)

        module_stash.stash()
        sys.meta_path.insert(0, ssl_blocker)

    @classmethod
    def teardown_class(cls) -> None:
        sys.meta_path.remove(ssl_blocker)
        module_stash.pop()


class TestImportWithoutSSL(TestWithoutSSL):
    def test_cannot_import_ssl(self) -> None:
        with pytest.raises(ImportError):
            import ssl  # noqa: F401

    def test_import_urllib3(self) -> None:
        import urllib3  # noqa: F401

from __future__ import annotations

import queue
from unittest import mock

import pytest

from urllib3 import HTTPConnectionPool
from urllib3.exceptions import EmptyPoolError


class BadError(Exception):
    """
    This should not be raised.
    """


class TestMonkeypatchResistance:
    """
    Test that connection pool works even with a monkey patched Queue module,
    see obspy/obspy#1599, psf/requests#3742, urllib3/urllib3#1061.
    """

    def test_queue_monkeypatching(self) -> None:
        with mock.patch.object(queue, "Empty", BadError):
            with HTTPConnectionPool(host="localhost", block=True) as http:
                http._get_conn()
                with pytest.raises(EmptyPoolError):
                    http._get_conn(timeout=0)

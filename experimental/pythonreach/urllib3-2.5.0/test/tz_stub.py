from __future__ import annotations

import datetime
import os
import time
import typing
import zoneinfo
from contextlib import contextmanager

import pytest


@contextmanager
def stub_timezone_ctx(tzname: str | None) -> typing.Generator[None]:
    """
    Switch to a locally-known timezone specified by `tzname`.
    On exit, restore the previous timezone.
    If `tzname` is `None`, do nothing.
    """
    if tzname is None:
        yield
        return

    # Only supported on Unix
    if not hasattr(time, "tzset"):
        pytest.skip("Timezone patching is not supported")

    # Make sure the new timezone exists
    try:
        zoneinfo.ZoneInfo(tzname)
    except zoneinfo.ZoneInfoNotFoundError:
        raise ValueError(f"Invalid timezone specified: {tzname!r}")

    # Get the current timezone
    old_tzname = datetime.datetime.now().astimezone().tzname()
    if old_tzname is None:
        raise OSError("Cannot determine current timezone")

    os.environ["TZ"] = tzname
    time.tzset()
    yield
    os.environ["TZ"] = old_tzname
    time.tzset()

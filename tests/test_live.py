"""Optional test against the real Pwned Passwords API.

Skipped by default so the test suite never depends on the network.
Run with:  FLYXPASS_LIVE_TESTS=1 python -m pytest -m live
"""

import os

import pytest

from flyxpass import pwned

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("FLYXPASS_LIVE_TESTS") != "1",
        reason="set FLYXPASS_LIVE_TESTS=1 to query the real API",
    ),
]


def test_famous_password_is_found():
    # "password" is in every breach list; only its hash prefix 5BAA6 is sent.
    assert pwned.pwned_count("password") > 1_000_000


def test_random_password_is_not_found():
    import secrets

    assert pwned.pwned_count(secrets.token_urlsafe(32)) == 0

import io
import urllib.error

import pytest

from flyxpass import pwned

# SHA-1("password") - a well-known test vector.
PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
PREFIX, SUFFIX = PASSWORD_SHA1[:5], PASSWORD_SHA1[5:]


class FakeResponse(io.BytesIO):
    """Minimal stand-in for the object returned by urlopen()."""


class FakeOpener:
    """Records every request and replays a scripted list of outcomes."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def __call__(self, request, timeout=None, context=None):
        self.calls.append({"request": request, "timeout": timeout, "context": context})
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResponse(outcome.encode("utf-8"))


def http_error(code):
    return urllib.error.HTTPError(
        pwned.API_URL + PREFIX, code, "error", hdrs=None, fp=io.BytesIO()
    )


def no_sleep(_seconds):
    pass


# --- hashing -----------------------------------------------------------------


def test_sha1_hex_matches_known_vector():
    assert pwned.sha1_hex("password") == PASSWORD_SHA1


def test_sha1_hex_uses_utf8():
    # SHA-1 of the UTF-8 bytes C3 A4 ("ä"), not of the Latin-1 byte E4
    assert pwned.sha1_hex("ä") == "961FA22F61A56E19F3F5F8867901AC8CF5E6D11F"


def test_split_hash():
    assert pwned.split_hash(PASSWORD_SHA1) == (PREFIX, SUFFIX)
    assert len(PREFIX) == 5 and len(SUFFIX) == 35


# --- parsing -----------------------------------------------------------------


RANGE_BODY = (
    "003D68EB55068C33ACE09247EE4C639306B:3\r\n"
    f"{SUFFIX}:52256179\r\n"
    "1E4C9B93F3F0682250B6CF8331B7EE68FD9:0\r\n"  # padding entry
    "garbage line without separator\r\n"
)


def test_count_in_range_finds_suffix():
    assert pwned.count_in_range(SUFFIX, RANGE_BODY) == 52256179


def test_count_in_range_is_case_insensitive():
    assert pwned.count_in_range(SUFFIX.lower(), RANGE_BODY) == 52256179
    assert pwned.count_in_range(SUFFIX, RANGE_BODY.lower()) == 52256179


def test_count_in_range_returns_zero_when_absent():
    assert pwned.count_in_range("F" * 35, RANGE_BODY) == 0
    assert pwned.count_in_range(SUFFIX, "") == 0


def test_padding_entries_count_as_not_found():
    assert pwned.count_in_range("1E4C9B93F3F0682250B6CF8331B7EE68FD9", RANGE_BODY) == 0


def test_malformed_count_raises():
    with pytest.raises(pwned.PwnedCheckError, match="malformed"):
        pwned.count_in_range(SUFFIX, f"{SUFFIX}:lots\r\n")


# --- privacy: only the prefix is sent ----------------------------------------


def test_pwned_count_sends_only_the_prefix(monkeypatch):
    sent = []

    def fake_fetch(prefix, *, timeout, retries):
        sent.append(prefix)
        return RANGE_BODY

    monkeypatch.setattr(pwned, "fetch_range", fake_fetch)

    assert pwned.pwned_count("password") == 52256179
    assert sent == [PREFIX]


def test_request_contains_only_prefix_and_padding_header():
    opener = FakeOpener(RANGE_BODY)
    pwned.fetch_range(PREFIX, opener=opener, timeout=4.5)

    call = opener.calls[0]
    request = call["request"]
    assert request.full_url == "https://api.pwnedpasswords.com/range/5BAA6"
    assert request.get_method() == "GET"
    assert request.data is None
    assert SUFFIX not in request.full_url
    assert request.get_header("Add-padding") == "true"
    assert request.get_header("User-agent").startswith("flyxpass/")
    assert call["timeout"] == 4.5
    assert call["context"].verify_mode.name == "CERT_REQUIRED"


@pytest.mark.parametrize("bad", ["", "5BAA", "5BAA61", "5baa6", "ZZZZZ", PASSWORD_SHA1])
def test_fetch_range_refuses_anything_but_a_prefix(bad):
    opener = FakeOpener()
    with pytest.raises(ValueError):
        pwned.fetch_range(bad, opener=opener)
    assert opener.calls == []


# --- error handling -----------------------------------------------------------


def test_timeout_is_retried_then_reported():
    opener = FakeOpener(
        urllib.error.URLError(TimeoutError("timed out")),
        TimeoutError(),
        urllib.error.URLError(TimeoutError()),
    )
    expected = r"timed out after 3 s \(3 attempts\)"
    with pytest.raises(pwned.PwnedCheckError, match=expected):
        pwned.fetch_range(PREFIX, opener=opener, timeout=3, retries=2, sleep=no_sleep)
    assert len(opener.calls) == 3


def test_connection_error_is_reported():
    opener = FakeOpener(urllib.error.URLError("Name or service not known"))
    with pytest.raises(pwned.PwnedCheckError, match="network error: Name or service"):
        pwned.fetch_range(PREFIX, opener=opener, retries=0, sleep=no_sleep)


def test_connection_reset_is_reported():
    opener = FakeOpener(ConnectionResetError("reset by peer"))
    with pytest.raises(pwned.PwnedCheckError, match="ConnectionResetError"):
        pwned.fetch_range(PREFIX, opener=opener, retries=0, sleep=no_sleep)


def test_transient_failure_then_success():
    sleeps = []
    opener = FakeOpener(
        http_error(503), urllib.error.URLError(TimeoutError()), RANGE_BODY
    )
    body = pwned.fetch_range(PREFIX, opener=opener, retries=2, sleep=sleeps.append)
    assert body == RANGE_BODY
    assert sleeps == [1.0, 2.0]  # linear back-off


@pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
def test_transient_http_errors_are_retried(code):
    opener = FakeOpener(http_error(code), http_error(code))
    with pytest.raises(pwned.PwnedCheckError, match=f"HTTP {code} \\(2 attempts\\)"):
        pwned.fetch_range(PREFIX, opener=opener, retries=1, sleep=no_sleep)


@pytest.mark.parametrize("code", [400, 403, 404])
def test_permanent_http_errors_are_not_retried(code):
    opener = FakeOpener(http_error(code), RANGE_BODY)
    with pytest.raises(pwned.PwnedCheckError, match=f"HTTP {code} \\(1 attempt\\)"):
        pwned.fetch_range(PREFIX, opener=opener, retries=3, sleep=no_sleep)
    assert len(opener.calls) == 1


def test_oversized_response_is_rejected():
    opener = FakeOpener("A" * (pwned.MAX_RESPONSE_BYTES + 10))
    with pytest.raises(pwned.PwnedCheckError, match="unexpectedly large"):
        pwned.fetch_range(PREFIX, opener=opener)


def test_binary_response_is_rejected():
    class BinaryOpener(FakeOpener):
        def __call__(self, request, timeout=None, context=None):
            return FakeResponse(b"\xff\xfe\x00")

    with pytest.raises(pwned.PwnedCheckError, match="not valid text"):
        pwned.fetch_range(PREFIX, opener=BinaryOpener())


def test_error_messages_never_contain_hash_or_suffix():
    opener = FakeOpener(urllib.error.URLError("boom"))
    with pytest.raises(pwned.PwnedCheckError) as excinfo:
        pwned.fetch_range(PREFIX, opener=opener, retries=0)
    assert SUFFIX not in str(excinfo.value)
    assert PASSWORD_SHA1 not in str(excinfo.value)

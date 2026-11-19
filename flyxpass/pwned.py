"""Look a password up in Have I Been Pwned's "Pwned Passwords" corpus.

The lookup uses the k-anonymity range API: the password is hashed locally
with SHA-1 and only the first five hex characters of that hash are sent to
``https://api.pwnedpasswords.com/range/<prefix>``. The server answers with
every hash suffix that shares the prefix (several hundred of them), and the
comparison with our own suffix happens here, on this machine. Neither the
password nor its full hash ever leaves the computer.

The ``Add-Padding`` header asks the server to mix in fake entries with a count
of 0, so the size of the encrypted response does not reveal which prefix was
requested.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from flyxpass import __version__

API_URL = "https://api.pwnedpasswords.com/range/"
PREFIX_LENGTH = 5
DEFAULT_TIMEOUT = 10.0  # seconds per attempt
DEFAULT_RETRIES = 2  # extra attempts after a transient failure
BACKOFF_SECONDS = 1.0  # wait 1 s, 2 s, ... between attempts
MAX_RESPONSE_BYTES = 1024 * 1024  # real responses are ~30-40 KB
USER_AGENT = f"flyxpass/{__version__} (+https://github.com/Butt3rFLYX/flyxpass)"

# HTTP status codes worth retrying: rate limiting and server-side hiccups.
TRANSIENT_HTTP_CODES = frozenset({408, 429, 500, 502, 503, 504})

_PREFIX_RE = re.compile(r"[0-9A-F]{5}")

Opener = Callable[..., Any]


class PwnedCheckError(Exception):
    """The breach database could not be queried (network error, timeout, ...)."""


def sha1_hex(password: str) -> str:
    """Upper-case hex SHA-1 of the UTF-8 encoded password.

    SHA-1 is used only because it is the lookup format of the Pwned Passwords
    corpus, not to protect anything; hence ``usedforsecurity=False`` (which
    also keeps the call working on FIPS-restricted systems).
    """
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False)
    return digest.hexdigest().upper()


def split_hash(hex_digest: str) -> tuple[str, str]:
    """Split a 40-character hash into the 5-character prefix and the rest."""
    return hex_digest[:PREFIX_LENGTH], hex_digest[PREFIX_LENGTH:]


def fetch_range(
    prefix: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    opener: Opener | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Download the list of hash suffixes for a 5-character *prefix*.

    Transient failures (timeouts, connection problems, HTTP 429/5xx) are
    retried *retries* times with a short back-off. Anything that still fails
    is raised as :class:`PwnedCheckError` with a human-readable message.
    """
    if not _PREFIX_RE.fullmatch(prefix):
        # Guard against ever sending more than the prefix by mistake.
        raise ValueError("prefix must be exactly 5 upper-case hex characters")

    if opener is None:
        opener = urllib.request.urlopen
    # The URL is always the fixed https:// API_URL plus a validated prefix.
    request = urllib.request.Request(  # noqa: S310
        API_URL + prefix,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )

    attempts = max(retries, 0) + 1
    problem = "unknown error"
    attempt = 0
    for attempt in range(1, attempts + 1):
        if attempt > 1:
            sleep(BACKOFF_SECONDS * (attempt - 1))
        try:
            context = ssl.create_default_context()  # verifies certificates
            with opener(request, timeout=timeout, context=context) as response:
                body: bytes = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            exc.close()
            problem = f"server answered with HTTP {exc.code}"
            if exc.code not in TRANSIENT_HTTP_CODES:
                break
            continue
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                problem = f"request timed out after {timeout:g} s"
            else:
                problem = f"network error: {exc.reason}"
            continue
        except TimeoutError:
            problem = f"request timed out after {timeout:g} s"
            continue
        except (OSError, http.client.HTTPException) as exc:
            problem = f"network error: {exc.__class__.__name__}: {exc}"
            continue

        if len(body) > MAX_RESPONSE_BYTES:
            raise PwnedCheckError("server response is unexpectedly large")
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            raise PwnedCheckError("server response is not valid text") from None

    tries = "1 attempt" if attempt == 1 else f"{attempt} attempts"
    raise PwnedCheckError(f"{problem} ({tries})")


def count_in_range(suffix: str, body: str) -> int:
    """Return how often *suffix* occurs in a range response, or 0 if absent.

    Each line of the response looks like ``<35 hex chars>:<count>``. Padding
    entries have a count of 0 and therefore never produce a false positive.
    """
    wanted = suffix.upper()
    for line in body.splitlines():
        candidate, separator, count = line.strip().partition(":")
        if not separator or candidate.upper() != wanted:
            continue
        try:
            return int(count)
        except ValueError:
            raise PwnedCheckError("server response is malformed") from None
    return 0


def pwned_count(
    password: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> int:
    """Return how often *password* appears in known breaches (0 = not found).

    Only the first five characters of the password's SHA-1 hash are sent over
    the network; the rest of the comparison happens locally.
    """
    prefix, suffix = split_hash(sha1_hex(password))
    body = fetch_range(prefix, timeout=timeout, retries=retries)
    return count_in_range(suffix, body)

"""Command-line interface for flyxpass.

Privacy rules this module follows:

* The password is never accepted as a command-line argument (arguments end up
  in the shell history and are visible to other users via ``ps``).
* It is read with :func:`getpass.getpass`, so it is not echoed.
* It is never printed, logged or written to disk, and no part of it (or of
  its full hash) appears in any message, including error messages.
"""

from __future__ import annotations

import argparse
import getpass
import math
import sys

from flyxpass import __version__, pwned
from flyxpass.strength import Rating, StrengthReport, assess

EXIT_OK = 0  # checked, not found in breaches (or --offline)
EXIT_PWNED = 1  # found in breaches
EXIT_USAGE = 2  # bad arguments or empty input
EXIT_CHECK_FAILED = 3  # breach lookup failed (network error, timeout, ...)
EXIT_INTERRUPTED = 130  # Ctrl+C

PROMPT = "Password (input hidden): "

ARGUMENT_REFUSED = (
    "flyxpass: unexpected argument(s) - not shown on purpose.\n"
    "flyxpass never takes the password as an argument, because arguments are\n"
    "saved in your shell history. Run 'flyxpass' and type it at the prompt.\n"
    "If you just typed a real password on the command line, treat it as exposed\n"
    "and remove it from your shell history."
)

ADVICE = {
    Rating.WEAK: "too short or too simple - use a longer password or a passphrase",
    Rating.MEDIUM: "acceptable, but longer would be better",
    Rating.STRONG: "good",
}


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not (value > 0 and math.isfinite(value)):
        raise argparse.ArgumentTypeError("must be a positive number")
    return value


def _non_negative_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flyxpass",
        description=(
            "Rate a password's strength and check whether it appears in known "
            "data breaches (Have I Been Pwned). The password is read without "
            "echo and never leaves your machine: only the first 5 characters "
            "of its SHA-1 hash are sent."
        ),
        epilog=(
            "exit codes: 0 not found / offline, 1 found in breaches, "
            "2 usage error, 3 breach check failed, 130 interrupted"
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="only rate the strength, skip the online breach check",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help=(
            "read the password from standard input instead of prompting "
            "(e.g. piped from a password manager)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=pwned.DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help="network timeout per attempt (default: %(default)g)",
    )
    parser.add_argument(
        "--retries",
        type=_non_negative_int,
        default=pwned.DEFAULT_RETRIES,
        metavar="N",
        help="extra attempts after a timeout or network error (default: %(default)s)",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def read_password(from_stdin: bool) -> str:
    """Read the password without echoing it.

    With *from_stdin* the first line of standard input is used (only the line
    break is stripped, other whitespace is part of the password).
    """
    if from_stdin:
        line = sys.stdin.readline()
        return line.removesuffix("\n").removesuffix("\r")
    return getpass.getpass(PROMPT)


def format_strength(report: StrengthReport) -> list[str]:
    classes = ", ".join(cls.name for cls in report.classes)
    return [
        f"Length:      {report.length} characters",
        f"Characters:  {classes} (pool size {report.pool_size})",
        f"Entropy:     {report.entropy_bits:.1f} bits"
        f"  = {report.length} x log2({report.pool_size})",
        f"Strength:    {report.rating}",
    ]


def format_breaches(count: int | None, error: str | None, offline: bool) -> str:
    if offline:
        return "Breaches:    not checked (--offline)"
    if error is not None:
        return f"Breaches:    check failed - {error}"
    if count:
        times = "time" if count == 1 else "times"
        return f"Breaches:    FOUND {count:,} {times} in known data breaches"
    return "Breaches:    not found in known data breaches"


def format_verdict(report: StrengthReport, count: int | None) -> str:
    if count:
        return (
            "Verdict:     UNSAFE - this password is public. "
            "Do not use it anywhere, change it where you do."
        )
    verdict = f"Verdict:     {report.rating} - {ADVICE[report.rating]}"
    if count is None:
        verdict += " (breach status unknown)"
    return verdict


def run(args: argparse.Namespace) -> int:
    try:
        password = read_password(args.stdin)
    except EOFError:
        print("\nflyxpass: no password given", file=sys.stderr)
        return EXIT_USAGE
    if not password:
        print("flyxpass: the password is empty", file=sys.stderr)
        return EXIT_USAGE

    report = assess(password)
    for line in format_strength(report):
        print(line)

    count: int | None = None
    error: str | None = None
    if not args.offline:
        print("Checking Have I Been Pwned (k-anonymity) ...", file=sys.stderr)
        try:
            count = pwned.pwned_count(
                password, timeout=args.timeout, retries=args.retries
            )
        except pwned.PwnedCheckError as exc:
            error = str(exc)

    # Drop our reference right away. Python cannot reliably wipe string memory,
    # but there is no reason to keep the password around any longer.
    del password

    print(format_breaches(count, error, args.offline))
    print(format_verdict(report, count))

    if count:
        return EXIT_PWNED
    if error is not None:
        return EXIT_CHECK_FAILED
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    if extra:
        # Do not echo the extra arguments: one of them may be a password.
        print(ARGUMENT_REFUSED, file=sys.stderr)
        return EXIT_USAGE
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())

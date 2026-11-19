import io

import pytest

from flyxpass import cli, pwned

SECRET = "Xk9#mQ2vLp8$w"  # 13 chars, all four classes -> strong


@pytest.fixture
def prompt(monkeypatch):
    """Make getpass return a chosen value (or raise) without a terminal."""

    def set_value(value):
        def fake_getpass(prompt=""):
            if isinstance(value, BaseException):
                raise value
            return value

        monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)

    return set_value


@pytest.fixture
def lookup(monkeypatch):
    """Replace the network lookup and record whether it was used."""
    calls = []

    def set_result(result):
        def fake_pwned_count(password, *, timeout, retries):
            calls.append({"timeout": timeout, "retries": retries})
            if isinstance(result, BaseException):
                raise result
            return result

        monkeypatch.setattr(pwned, "pwned_count", fake_pwned_count)
        return calls

    return set_result


def assert_secret_not_shown(capsys, secret=SECRET):
    out, err = capsys.readouterr()
    assert secret not in out
    assert secret not in err
    assert pwned.sha1_hex(secret) not in out + err
    return out, err


def test_password_is_not_accepted_as_argument(capsys, lookup):
    calls = lookup(0)
    assert cli.main([SECRET]) == cli.EXIT_USAGE
    _, err = assert_secret_not_shown(capsys)
    assert "never takes the password as an argument" in err
    assert calls == []


def test_unknown_option_is_not_echoed(capsys):
    assert cli.main(["--password=" + SECRET]) == cli.EXIT_USAGE
    assert_secret_not_shown(capsys)


def test_offline_rates_strength_without_network(capsys, prompt, lookup):
    prompt(SECRET)
    calls = lookup(RuntimeError("must not be called"))
    assert cli.main(["--offline"]) == cli.EXIT_OK
    out, _ = assert_secret_not_shown(capsys)
    assert "Length:      13 characters" in out
    assert "lowercase, uppercase, digits, special (pool size 95)" in out
    assert "85.4 bits" in out
    assert "Strength:    strong" in out
    assert "not checked (--offline)" in out
    assert calls == []


def test_not_found(capsys, prompt, lookup):
    prompt(SECRET)
    calls = lookup(0)
    assert cli.main(["--timeout", "2.5", "--retries", "1"]) == cli.EXIT_OK
    out, _ = assert_secret_not_shown(capsys)
    assert "not found in known data breaches" in out
    assert "Verdict:     strong" in out
    assert calls == [{"timeout": 2.5, "retries": 1}]


def test_found_overrides_rating(capsys, prompt, lookup):
    prompt(SECRET)
    lookup(1_234_567)
    assert cli.main([]) == cli.EXIT_PWNED
    out, _ = assert_secret_not_shown(capsys)
    assert "FOUND 1,234,567 times" in out
    assert "UNSAFE" in out


def test_found_once_uses_singular(capsys, prompt, lookup):
    prompt(SECRET)
    lookup(1)
    assert cli.main([]) == cli.EXIT_PWNED
    assert "FOUND 1 time in" in capsys.readouterr().out


def test_network_failure_still_shows_strength(capsys, prompt, lookup):
    prompt(SECRET)
    lookup(pwned.PwnedCheckError("request timed out after 10 s (3 attempts)"))
    assert cli.main([]) == cli.EXIT_CHECK_FAILED
    out, _ = assert_secret_not_shown(capsys)
    assert "Strength:    strong" in out
    assert "check failed - request timed out after 10 s (3 attempts)" in out
    assert "breach status unknown" in out


def test_weak_password_advice(capsys, prompt, lookup):
    prompt("abc")
    lookup(0)
    assert cli.main([]) == cli.EXIT_OK
    out, _ = assert_secret_not_shown(capsys, "abc")
    assert "Strength:    weak" in out
    assert "use a longer password or a passphrase" in out


def test_stdin_mode_strips_only_the_line_break(capsys, monkeypatch, lookup):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("  two spaces  \r\nignored\n"))
    lookup(0)
    assert cli.main(["--stdin", "--offline"]) == cli.EXIT_OK
    out, _ = assert_secret_not_shown(capsys, "  two spaces  ")
    assert "Length:      14 characters" in out


def test_empty_password_is_rejected(capsys, prompt, lookup):
    prompt("")
    calls = lookup(0)
    assert cli.main([]) == cli.EXIT_USAGE
    assert "empty" in capsys.readouterr().err
    assert calls == []


def test_eof_at_prompt(capsys, prompt):
    prompt(EOFError())
    assert cli.main([]) == cli.EXIT_USAGE


def test_ctrl_c_at_prompt(capsys, prompt):
    prompt(KeyboardInterrupt())
    assert cli.main([]) == cli.EXIT_INTERRUPTED
    assert "Aborted" in capsys.readouterr().err


def test_ctrl_c_during_lookup(capsys, prompt, lookup):
    prompt(SECRET)
    lookup(KeyboardInterrupt())
    assert cli.main([]) == cli.EXIT_INTERRUPTED
    assert_secret_not_shown(capsys)


@pytest.mark.parametrize(
    "argv",
    [
        ["--timeout", "0"],
        ["--timeout", "-1"],
        ["--timeout", "nan"],
        ["--retries", "-1"],
    ],
)
def test_invalid_option_values(argv):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(argv)
    assert excinfo.value.code == cli.EXIT_USAGE


def test_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.startswith("flyxpass ")

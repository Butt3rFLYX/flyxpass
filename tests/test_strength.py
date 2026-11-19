import math

import pytest

from flyxpass.strength import (
    DIGITS,
    LOWERCASE,
    SPECIAL,
    UPPERCASE,
    Rating,
    assess,
    character_classes,
    classify,
    entropy_bits,
    rate,
)


def test_class_sizes_add_up_to_printable_ascii():
    # 26 + 26 + 10 + 33 = the 95 printable ASCII characters incl. space
    assert LOWERCASE.size + UPPERCASE.size + DIGITS.size + SPECIAL.size == 95


@pytest.mark.parametrize(
    ("char", "expected"),
    [
        ("a", LOWERCASE),
        ("z", LOWERCASE),
        ("A", UPPERCASE),
        ("Z", UPPERCASE),
        ("0", DIGITS),
        ("9", DIGITS),
        ("!", SPECIAL),
        (" ", SPECIAL),
        ("~", SPECIAL),
        ("ä", SPECIAL),  # non-ASCII letters are not in a-z
        ("€", SPECIAL),
    ],
)
def test_classify(char, expected):
    assert classify(char) == expected


def test_character_classes_are_ordered_and_unique():
    assert character_classes("!!9Aa") == (LOWERCASE, UPPERCASE, DIGITS, SPECIAL)
    assert character_classes("aaaa") == (LOWERCASE,)
    assert character_classes("") == ()


@pytest.mark.parametrize(
    ("password", "pool"),
    [
        ("abcdef", 26),
        ("ABCDEF", 26),
        ("123456", 10),
        ("!@#$%^", 33),
        ("abcDEF", 52),
        ("abc123", 36),
        ("aB3!", 95),
    ],
)
def test_pool_size(password, pool):
    assert assess(password).pool_size == pool


def test_entropy_is_length_times_log2_pool():
    report = assess("Tr0ub4dor&3")
    assert report.length == 11
    assert report.pool_size == 95
    assert report.entropy_bits == pytest.approx(11 * math.log2(95))


def test_entropy_of_degenerate_input_is_zero():
    assert entropy_bits(0, 95) == 0.0
    assert entropy_bits(10, 0) == 0.0
    assert entropy_bits(10, 1) == 0.0
    assert assess("").entropy_bits == 0.0


@pytest.mark.parametrize(
    ("bits", "rating"),
    [
        (0.0, Rating.WEAK),
        (49.99, Rating.WEAK),
        (50.0, Rating.MEDIUM),
        (79.99, Rating.MEDIUM),
        (80.0, Rating.STRONG),
        (500.0, Rating.STRONG),
    ],
)
def test_rating_thresholds(bits, rating):
    assert rate(bits) is rating


@pytest.mark.parametrize(
    ("password", "rating"),
    [
        ("password", Rating.WEAK),  # 8 x log2(26) = 37.6
        ("123456", Rating.WEAK),  # 6 x log2(10) = 19.9
        ("Xk9#mQ2vLp", Rating.MEDIUM),  # 10 x log2(95) = 65.7
        ("Xk9#mQ2vLp8$w", Rating.STRONG),  # 13 x log2(95) = 85.4
        ("correct horse battery staple", Rating.STRONG),  # 28 x log2(59)
    ],
)
def test_assess_ratings(password, rating):
    assert assess(password).rating is rating


def test_report_does_not_contain_the_password():
    secret = "S3cret-Value!"
    assert secret not in repr(assess(secret))

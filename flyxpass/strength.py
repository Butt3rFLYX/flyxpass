"""Estimate password strength from the size of its character pool.

The estimate is the classic brute-force entropy::

    entropy = length * log2(pool size)

where the pool is the sum of the sizes of all character classes that occur in
the password. This is an *upper bound*: it assumes every character was picked
at random, so passwords built from words or patterns (``Summer2024!``) score
higher than they deserve. That is why flyxpass also looks the password up in
the Have I Been Pwned breach corpus.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class CharacterClass:
    """A group of characters an attacker would have to try."""

    name: str
    size: int


LOWERCASE = CharacterClass("lowercase", len(string.ascii_lowercase))  # 26
UPPERCASE = CharacterClass("uppercase", len(string.ascii_uppercase))  # 26
DIGITS = CharacterClass("digits", len(string.digits))  # 10
# The 32 ASCII punctuation characters plus the space character. Every
# character outside a-z, A-Z and 0-9 (including non-ASCII ones such as
# "ä" or "€") is counted as special.
SPECIAL = CharacterClass("special", len(string.punctuation) + 1)  # 33

ALL_CLASSES: tuple[CharacterClass, ...] = (LOWERCASE, UPPERCASE, DIGITS, SPECIAL)


class Rating(Enum):
    """Coarse strength rating derived from the entropy estimate."""

    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"

    def __str__(self) -> str:
        return self.value


# Minimum entropy (in bits) for each rating, checked from strongest to weakest.
#   < 50 bits  weak    e.g. 8 random lowercase letters (37.6 bits)
#   50-79 bits medium  e.g. 10 random chars from all four classes (65.7 bits)
#   >= 80 bits strong  e.g. 13 random chars from all four classes (85.4 bits)
RATING_THRESHOLDS: tuple[tuple[float, Rating], ...] = (
    (80.0, Rating.STRONG),
    (50.0, Rating.MEDIUM),
    (0.0, Rating.WEAK),
)


@dataclass(frozen=True)
class StrengthReport:
    """Result of :func:`assess`. Deliberately contains no part of the password."""

    length: int
    classes: tuple[CharacterClass, ...]
    pool_size: int
    entropy_bits: float
    rating: Rating


def classify(char: str) -> CharacterClass:
    """Return the character class a single character belongs to."""
    if char in string.ascii_lowercase:
        return LOWERCASE
    if char in string.ascii_uppercase:
        return UPPERCASE
    if char in string.digits:
        return DIGITS
    return SPECIAL


def character_classes(password: str) -> tuple[CharacterClass, ...]:
    """Return the classes used in *password*, in a fixed order."""
    used = {classify(char) for char in password}
    return tuple(cls for cls in ALL_CLASSES if cls in used)


def entropy_bits(length: int, pool_size: int) -> float:
    """Brute-force entropy: ``length * log2(pool_size)``."""
    if length <= 0 or pool_size <= 1:
        return 0.0
    return length * math.log2(pool_size)


def rate(bits: float) -> Rating:
    """Map an entropy value to a :class:`Rating`."""
    for minimum, rating in RATING_THRESHOLDS:
        if bits >= minimum:
            return rating
    return Rating.WEAK


def assess(password: str) -> StrengthReport:
    """Compute pool size, entropy and rating for *password*."""
    classes = character_classes(password)
    pool_size = sum(cls.size for cls in classes)
    length = len(password)
    bits = entropy_bits(length, pool_size)
    return StrengthReport(
        length=length,
        classes=classes,
        pool_size=pool_size,
        entropy_bits=bits,
        rating=rate(bits),
    )

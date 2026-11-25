"""Duration grammar and per-key range (interface.md, Config).

The same samples run through the code grammar and the schema's `duration` definition, so the
two cannot drift apart.
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from slack_notice.config import DURATION_RANGES, DurationError, check_duration, parse_duration
from tests.harness import schema_errors

ACCEPTED: list[tuple[Any, float]] = [
    (10, 10.0),
    (1, 1.0),
    (1.5, 1.5),
    ("10", 10.0),
    ("10s", 10.0),
    ("1m", 60.0),
    ("500ms", 0.5),
    ("1.5s", 1.5),
    ("0.5m", 30.0),
    ("00010s", 10.0),
    ("0.001", 0.001),
    ("120000ms", 120.0),
    ("3000ms", 3.0),
    (10**6, 1e6),
    (3.0000000000000004, 3.0000000000000004),
]

REFUSED: list[Any] = [
    "1h",
    "1e3",
    "1E3",
    "-1",
    "+1",
    "-1s",
    ".5",
    "5.",
    "1.s",
    "1,5",
    "1_0",
    "0x10",
    "1:30",
    "",
    " ",
    "s",
    "ms",
    "m",
    " 10",
    "10 ",
    "10 s",
    "10\n",
    "10s\n",
    "\n10s",
    "10\t",
    "10S",
    "10M",
    "10MS",
    "1m30s",
    "1s1ms",
    "1ms1",
    "10ss",
    "10sm",
    "nan",
    "inf",
    "infinity",
    "-inf",
    "0",
    "0s",
    "0.0",
    "0ms",
    "000",
    "１０",  # fullwidth digits
    "١٠",  # arabic-indic digits
    "10 s",  # no-break space
    "10​",  # zero-width space
    "10\x00",
    "1" * 5000 + "x",
    True,
    False,
    None,
    [],
    {},
    b"10",
    0,
    0.0,
    -0.0,
    -1,
    -1.5,
    math.nan,
    math.inf,
    -math.inf,
    10**400,
    1e308 * 10,
]


@pytest.mark.parametrize(("value", "seconds"), ACCEPTED)
def test_accepted_values_parse_to_seconds(value: Any, seconds: float) -> None:
    assert parse_duration(value) == seconds


@pytest.mark.parametrize("value", REFUSED, ids=lambda v: repr(v)[:40])
def test_refused_values_raise(value: Any) -> None:
    with pytest.raises(DurationError):
        parse_duration(value)


def test_error_is_a_value_error() -> None:
    assert issubclass(DurationError, ValueError)


def test_a_boolean_is_never_a_number() -> None:
    for value in (True, False):
        with pytest.raises(DurationError):
            parse_duration(value)
        with pytest.raises(DurationError):
            check_duration("timeout", value)


def test_huge_digit_strings_are_refused_not_crashed() -> None:
    # float() of 5000 digits is inf; the range check must still be false, never an exception.
    for value in ("9" * 5000, "9" * 5000 + "m", "9" * 5000 + "ms", "0." + "0" * 5000 + "1"):
        with pytest.raises(DurationError):
            check_duration("timeout", value)


def test_a_huge_integer_count_of_digits_is_not_a_float_overflow_crash() -> None:
    with pytest.raises(DurationError):
        check_duration("timeout", 10**5000)


# Per-key range: interface.md gives timeout 3s to 120s.


def test_ranges_come_from_the_interface() -> None:
    assert DURATION_RANGES == {"timeout": (3, 120)}


@pytest.mark.parametrize(
    ("value", "seconds"),
    [
        (10, 10.0),
        ("10s", 10.0),
        ("1m", 60.0),
        ("2m", 120.0),
        (3, 3.0),
        ("3s", 3.0),
        ("3000ms", 3.0),
        ("0.05m", 3.0),
        ("120", 120.0),
        ("120000ms", 120.0),
        (3.0, 3.0),
        (120.0, 120.0),
    ],
)
def test_timeout_in_range(value: Any, seconds: float) -> None:
    assert check_duration("timeout", value) == seconds


@pytest.mark.parametrize(
    "value",
    [
        "500ms",
        "2999ms",
        "2.9999999999999999999999999999999",  # exact, not rounded up to 3
        "2.9999999999999999999999999999999s",
        "2.99m",
        2.999,
        2,
        "120.0000000000000000000000000001",
        "120001ms",
        "2.0001m",
        121,
        "1h",
        "1e3",
        "0",
        "0.001",
        -1,
        math.nan,
        math.inf,
        True,
        "",
    ],
)
def test_timeout_out_of_range_or_invalid(value: Any) -> None:
    with pytest.raises(DurationError):
        check_duration("timeout", value)


def test_nan_is_refused_by_the_range_check_itself() -> None:
    # A check written as `not (x < lo or x > hi)` would accept NaN; ours is lo <= x <= hi.
    with pytest.raises(DurationError):
        check_duration("timeout", math.nan)


def test_message_names_key_and_rule_never_the_value() -> None:
    secret = "https://hooks.example.invalid/SECRET-TOKEN"
    for value in (secret, "500ms", 1e9, True):
        with pytest.raises(DurationError) as info:
            check_duration("timeout", value)
        text = str(info.value)
        assert "timeout" in text
        assert "SECRET" not in text
        assert str(value) not in text
        assert info.value.key == "timeout"


def test_unknown_key_is_a_programming_error() -> None:
    with pytest.raises(KeyError):
        check_duration("nope", 10)


# Code grammar and schema grammar agree.

AGREEMENT_SAMPLES: list[Any] = [
    v
    for v in [*(value for value, _ in ACCEPTED), *REFUSED]
    # JSON has no NaN or infinity; the schema cannot say "finite", the code does.
    if not (isinstance(v, float) and not math.isfinite(v))
]


def _schema_accepts(value: Any) -> bool:
    return not schema_errors("defs", value, definition="duration")


def _code_accepts(value: Any) -> bool:
    try:
        parse_duration(value)
    except DurationError:
        return False
    return True


@pytest.mark.parametrize("value", AGREEMENT_SAMPLES, ids=lambda v: repr(v)[:40])
def test_code_and_schema_agree(value: Any) -> None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 10**300:
        pytest.skip("huge integers: schema accepts any positive number, code refuses overflow")
    assert _code_accepts(value) == _schema_accepts(value)


def test_overlong_strings_are_refused_at_the_boundary() -> None:
    assert parse_duration("0" * 200 + "10") == 10.0  # 202 chars, within the cap
    with pytest.raises(DurationError):
        parse_duration("0" * 300 + "10")

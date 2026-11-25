"""Config, drop-ins, YAML and durations, and the home lookup.

TODO(#10): implement config loading. Report a file path in details.key so it can never equal the
reserved sentinel values `home` and `--config` (for example as an absolute path).
TODO(#11): implement config validation: validate `timeout` with `check_duration`; a DurationError
becomes exit 2 config_invalid, details.key its `key`; build the message from key and rule only
(Pydantic wraps ValueError and keeps the input in its error dict).
"""

from __future__ import annotations

import math
import re
from fractions import Fraction
from typing import TYPE_CHECKING, Any

from slack_notice.gateway import HomeLookupError

if TYPE_CHECKING:
    from slack_notice.gateway import Gateway

# One grammar for every duration key (interface.md, Config). It must agree with the `duration`
# definition in schemas/defs.json: ASCII digits only, no sign, no exponent, nothing around it.
# fullmatch is exact: unlike `$`, it does not accept a trailing newline.
_DURATION = re.compile(r"(?P<n>[0-9]+(?:\.[0-9]+)?)(?P<unit>ms|s|m)?", re.ASCII)
# A longer string is refused unread: no useful duration needs it, and parsing thousands of digits
# would hit Python's integer-string limit. The schema has no length bound (JSON Schema cannot
# say it for a pattern cheaply); the two agree on every string of at most this length.
_MAX_STRING = 256
_UNIT_SECONDS = {None: Fraction(1), "s": Fraction(1), "m": Fraction(60), "ms": Fraction(1, 1000)}

# Per-key range in seconds, inclusive, from interface.md (Config table). Add a key here only
# when the interface names its range.
DURATION_RANGES: dict[str, tuple[int, int]] = {"timeout": (3, 120)}


class DurationError(ValueError):
    """A value is not a duration, or is outside its key's range.

    The message holds the key and the rule only, never the value.
    """

    def __init__(self, key: str, rule: str) -> None:
        super().__init__(f"{key} {rule}")
        self.key = key


def _seconds(value: Any) -> Fraction | None:
    """Exact seconds for a valid duration, else None. Zero, negatives and non-finite are None."""
    if isinstance(value, bool):
        return None
    seconds: Fraction
    if isinstance(value, int):
        seconds = Fraction(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            return None
        seconds = Fraction(value)
    elif isinstance(value, str):
        if len(value) > _MAX_STRING:
            return None
        match = _DURATION.fullmatch(value)
        if match is None:
            return None
        seconds = Fraction(match["n"]) * _UNIT_SECONDS[match["unit"]]
    else:
        return None
    return seconds if seconds > 0 else None


def parse_duration(value: Any, key: str = "duration") -> float:
    """Seconds as a float for a number or a `[0-9]+(\\.[0-9]+)?(ms|s|m)?` string.

    A boolean, zero, a negative, a non-finite number or a value too large for a float is refused.
    """
    seconds = _seconds(value)
    if seconds is not None:
        try:
            result = float(seconds)
        except OverflowError:
            result = math.inf
        if math.isfinite(result):
            return result
    raise DurationError(
        key, "must be a duration: a positive number of seconds or like 10s, 500ms, 1m"
    )


def check_duration(key: str, value: Any) -> float:
    """Parse `value` and enforce the range of `key` with `lo <= x <= hi` (false for NaN).

    The comparison is exact (no rounding at the boundary). Raises KeyError for a key with no
    range, a programming error.
    """
    lo, hi = DURATION_RANGES[key]
    seconds = _seconds(value)
    if seconds is None or not (lo <= seconds <= hi):
        raise DurationError(key, f"must be a duration from {lo}s to {hi}s")
    return float(seconds)


class HomeUnusable(Exception):
    """The password-database home cannot be used (lookup failed; empty, relative, not a directory).

    The message is fixed; it never holds the path, and no cause is chained.
    """

    def __init__(self) -> None:
        super().__init__("home directory cannot be used")


def resolve_home(gateway: Gateway) -> str:
    """The home directory of the current uid from the password database, checked for use.

    Returned as found (no normalising; trailing slashes stay). HOME and XDG_* are never read:
    the only source is `gateway.home_dir()`. Refused: a failed lookup, an empty or relative path
    (so also `~` and `$HOME`, which are never expanded), a path with a NUL, and anything that is
    not an existing directory (a symlink to one is fine; a dangling link is not).
    """
    try:
        home = gateway.home_dir()
    except HomeLookupError:
        raise HomeUnusable from None
    # The absolute check is textual (no filesystem access here); a str with a NUL or surrogates
    # is refused without raising, and the directory test is the gateway's.
    if not isinstance(home, str) or not home or not home.startswith("/") or "\x00" in home:
        raise HomeUnusable
    if not gateway.is_directory(home):
        raise HomeUnusable
    return home

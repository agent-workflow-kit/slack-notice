"""Input reading, validation, sanitizer and link rule.

This part (issue #15) turns one input source into a decoded JSON object, or a refusal that
carries no input text:

- ``read_notification(gateway, source, remaining)`` reads through ``gateway.read_source`` (slices
  of at most 100 ms, a cap of ``MAX_INPUT_BYTES``) and maps its result.
- ``decode_notification(data)`` is the byte-level rules: no byte order mark, strict UTF-8, hardened
  JSON, a top-level object.

Errors are plain exceptions with fixed text; ``cli`` maps them to exit codes and the envelope.

TODO(#16): implement notification validation and flag combinations.
TODO(#17): implement the sanitizer (including lone surrogates that arrive as JSON escapes).
TODO(#18): implement the link rule.
"""

from __future__ import annotations

import json
from typing import Any, NoReturn

from slack_notice.gateway import Gateway, NotRegularFile, SourceRead

MAX_INPUT_BYTES = 1_048_576
UTF8_BOM = b"\xef\xbb\xbf"

# Reasons of InputRefused (all exit 20 invalid_payload, pointer ""), with their fixed messages.
REFUSAL_MESSAGES = {
    "too_large": f"input is larger than {MAX_INPUT_BYTES} bytes",
    "bom": "input starts with a byte order mark",
    "utf8": "input is not valid UTF-8",
    "invalid": (
        "input is not a JSON object (parse failure, duplicate key, number, NaN, Infinity,"
        " nesting or another top-level value)"
    ),
}


class InputRefused(Exception):  # noqa: N818
    """The input breaks a rule. Exit 20 ``invalid_payload`` with ``details.pointer`` ``""``."""

    pointer = ""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason

    @property
    def message(self) -> str:
        return REFUSAL_MESSAGES[self.reason]


class InputTimedOut(Exception):  # noqa: N818
    """Input did not reach its end in time: nothing was judged. Exit 12 ``unavailable``."""


class SourceUnusable(Exception):  # noqa: N818
    """A ``--file`` that does not exist, cannot be read or is not a regular file. Exit 2."""


class _Refused(ValueError):
    """Raised by a parser hook; carries no text."""


def _no_number(_text: str) -> NoReturn:
    # No field is a number, so every number is refused before an int or float is built (the
    # int digit limit of the running Python never matters).
    raise _Refused


def _no_constant(_text: str) -> NoReturn:
    raise _Refused  # NaN, Infinity, -Infinity


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Refused
        result[key] = value
    return result


def _parse(data: bytes) -> tuple[dict[str, Any] | None, str]:
    """Return ``(object, "")`` or ``(None, reason)``. Every exception ends here, so the caller
    can raise outside a handler and the refusal keeps no ``__context__`` (it would hold input)."""
    if data.startswith(UTF8_BOM):
        return None, "bom"
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, "utf8"
    try:
        value = json.loads(
            text,
            parse_int=_no_number,
            parse_float=_no_number,
            parse_constant=_no_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except (ValueError, RecursionError, OverflowError):
        return None, "invalid"
    if not isinstance(value, dict):
        return None, "invalid"
    return value, ""


def decode_notification(data: bytes) -> dict[str, Any]:
    """Decode and parse input bytes; raise ``InputRefused`` for anything but an object.

    Fields are not validated here (TODO(#16)). The refusal has no ``__cause__`` or
    ``__context__``: they would carry the input.
    """
    value, reason = _parse(data)
    if value is None:
        raise InputRefused(reason)
    return value


def read_notification(gateway: Gateway, source: int | str, remaining: float) -> dict[str, Any]:
    """Read one source (descriptor 0 or a path) and decode it.

    ``remaining`` is the seconds left of the deadline. A source that is not at its end in time is
    ``InputTimedOut`` whatever arrived. A path problem is ``SourceUnusable``. The input is
    never echoed in an error.
    """
    failed = False
    result: SourceRead | None = None
    try:
        result = gateway.read_source(source, MAX_INPUT_BYTES, remaining)
    except (OSError, NotRegularFile, ValueError):
        failed = True
    if failed or result is None:  # raised outside the handler: the error keeps no context
        raise SourceUnusable
    if result.timed_out:
        raise InputTimedOut
    if result.too_large:
        raise InputRefused("too_large")
    return decode_notification(result.data)

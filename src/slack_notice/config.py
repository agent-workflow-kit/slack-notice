"""Config, drop-ins, YAML and durations, and the home lookup.

Loading (interface.md, Config): ``load_config`` reads the config file and ``config.d/*.yaml``
through the gateway, parses each with a strict YAML loader and merges the maps. The result is
the raw merged mapping; ``resolve_settings`` layers it over the defaults (and flags over it).
Every failure is ``ConfigInvalid`` with a fixed message and a ``key`` that is ``--config`` (a
missing file named by the flag) or an absolute file path, never content, so it can never equal
the reserved sentinel values ``home`` and ``--config`` otherwise.

Validation (``validate_config``) checks the merged values with Pydantic: unknown keys first (refused
before their value is examined), then types and rules. A failure is ``ConfigInvalid`` whose ``key``
is a config key name (or ``?``) and whose ``message`` is built from the key path and the rule only:
Pydantic's input value is never used, and no Pydantic exception is kept as cause or context.
"""

from __future__ import annotations

import bisect
import copy
import math
import os
import re
import unicodedata
from collections.abc import Hashable
from fractions import Fraction
from typing import TYPE_CHECKING, Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, field_validator
from pydantic_core import PydanticCustomError
from yaml.events import AliasEvent, MappingStartEvent, SequenceStartEvent

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


# --- strict YAML ------------------------------------------------------------------------------

MAX_FILE_BYTES = 65536
# Collections nested deeper than this are refused (the config is two levels deep). It stops a
# `[[[[...` file long before the recursion limit.
MAX_DEPTH = 10
# A number longer than this is refused unconverted (no key needs one; int() of thousands of
# digits would hit Python's integer-string limit, which is not the same on every interpreter).
MAX_NUMBER_CHARS = 64
# A path in details.key is at most this long (schemas/defs.json); a longer one is reported as `?`.
MAX_KEY_CHARS = 4096
FIXED_MESSAGE = "configuration is invalid"


class YamlRefused(ValueError):
    """A document the strict loader refuses. The message is fixed: never the text or the cause."""

    def __init__(self) -> None:
        super().__init__(FIXED_MESSAGE)


class ConfigInvalid(Exception):
    """A config file or value cannot be used. ``key`` is ``--config``, the absolute path of the
    file (or directory), or a config key name (``?`` when it is not one); ``str()`` is the fixed
    message and no cause or context is kept. ``rule`` and ``message`` are set by validation only:
    ``rule`` is what the value must be, ``message`` is ``<key path> <rule>``; neither holds a
    value."""

    def __init__(self, key: str, rule: str = "", message: str = "") -> None:
        super().__init__(FIXED_MESSAGE)
        self.key = key
        self.rule = rule
        self.message = message


class _StrictLoader(yaml.SafeLoader):
    """PyYAML's SafeLoader with only the resolvers the interface keeps, and no tags, anchors,
    aliases, duplicate keys or keys that are not strings. (`<<: *alias` fails on the alias; a
    literal `<<` key is an ordinary string key.)"""

    # No inherited implicit resolver: the ones below are the only ones. (Class attribute: the
    # subclass owns its table, so the shared one in PyYAML is never changed.)
    yaml_implicit_resolvers: dict[Any, Any] = {}  # noqa: RUF012
    _depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        # Checked on the event, before anything is built: `!!int 0x10`, `&a`, `*a` and the like.
        if isinstance(event, AliasEvent) or event.anchor is not None or event.tag is not None:  # pyright: ignore[reportAttributeAccessIssue]
            raise YamlRefused
        nested = isinstance(event, SequenceStartEvent | MappingStartEvent)
        if nested:
            self._depth += 1
            if self._depth > MAX_DEPTH:
                raise YamlRefused
        try:
            return super().compose_node(parent, index)
        finally:
            if nested:
                self._depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Hashable, Any]:
        mapping: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str) or key in mapping:
                raise YamlRefused
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


# Only these plain scalars are not strings. The rest of what YAML 1.1 would turn into a boolean
# or date (no, off, yes, dates) stays a string, and number lookalikes are refused (below).
# `\Z`, not `$`: a trailing newline never matches.
_StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"\A(?:true|false)\Z"), list("tf")
)
_StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"\A-?(?:0|[1-9][0-9]*)\Z"), list("-0123456789")
)
_StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:float", re.compile(r"\A-?(?:0|[1-9][0-9]*)\.[0-9]+\Z"), list("-0123456789")
)
_StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:null", re.compile(r"\A(?:~|null|)\Z"), ["~", "n", ""]
)


def _refuse_node(_loader: Any, _node: Any) -> Any:
    raise YamlRefused


# A plain scalar that YAML 1.1 reads as a number but the two patterns above do not (010, 0x10,
# 0b1, 1_0, 1:30, +5, 5., .5, .inf, .nan) is refused, not kept as a string: `timeout: 010` as the
# string "010" would pass the duration grammar as ten seconds, where a YAML 1.1 loader says 8.
# The patterns are PyYAML's own, so the two never drift apart. They come after ours: the first
# match wins.
_REFUSED = "tag:slack-notice,refused-number"
for _first, _entries in yaml.resolver.Resolver.yaml_implicit_resolvers.items():
    for _tag, _regexp in _entries:
        if _tag in ("tag:yaml.org,2002:int", "tag:yaml.org,2002:float"):
            _StrictLoader.add_implicit_resolver(_REFUSED, _regexp, [_first])
# PyYAML's octal pattern is 0[0-7_]+, so 08, 09 and 0189 would stay strings (and pass the duration
# grammar as eight seconds); any other leading-zero integer lookalike is refused too.
_StrictLoader.add_implicit_resolver(_REFUSED, re.compile(r"\A[-+]?0[0-9_]+\Z"), list("-+0"))
_StrictLoader.add_constructor(_REFUSED, _refuse_node)


def _construct_int(loader: Any, node: Any) -> int:
    text = loader.construct_scalar(node)
    if len(text) > MAX_NUMBER_CHARS:
        raise YamlRefused
    return int(text)


def _construct_float(loader: Any, node: Any) -> float:
    text = loader.construct_scalar(node)
    if len(text) > MAX_NUMBER_CHARS:
        raise YamlRefused
    return float(text)


_StrictLoader.add_constructor("tag:yaml.org,2002:int", _construct_int)
_StrictLoader.add_constructor("tag:yaml.org,2002:float", _construct_float)


def parse_yaml(data: bytes) -> dict[str, Any]:
    """The mapping in one YAML document of strict UTF-8 text, or ``YamlRefused``.

    Refused: bytes that are not UTF-8 (so UTF-16 and UTF-32), a byte order mark, a NUL, control
    characters, more than one document, an empty document, a top level that is not a mapping,
    and every case ``_StrictLoader`` refuses. Any other failure of the parser (``RecursionError``,
    ``MemoryError``, ``ValueError`` from a conversion, ...) is refused the same way. The error
    carries no text from the input and no cause.
    """
    result: object = None
    refused = False
    try:
        text = data.decode("utf-8")
        if text.startswith("\ufeff") or "\x00" in text:
            refused = True
        else:
            result = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 (a strict subclass)
    except Exception:
        refused = True
    if refused or not isinstance(result, dict):
        raise YamlRefused
    return result


# --- defaults, merging and precedence ---------------------------------------------------------

# interface.md, Config table. Raw values: validate_config validates them and turns the timeout into
# seconds; until then it is the string "10s".
DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "webhook_env": "SLACK_WEBHOOK",
    "body_variable": "body",
    "level_prefix": {
        "info": "🔵 INFO",
        "warn": "🟠 WARN",
        "action": "🟡 ACTION",
        "error": "🔴 ERROR",
    },
    "max_chars": 3000,
    "timeout": "10s",
    "log": True,
}


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    """``over`` on ``base``: maps merge key by key, anything else in ``over`` replaces. New
    dicts all the way down: neither input is changed or shared with the result."""
    result = {key: copy.deepcopy(value) for key, value in base.items()}
    for key, value in over.items():
        current = result.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            result[key] = _merge(current, value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def resolve_settings(
    config_values: dict[str, Any], flags: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Precedence: flags, then config, then defaults. A flag that was not given is ``None``.

    There is no environment layer: nothing in the environment overrides a setting.
    """
    given = {key: value for key, value in (flags or {}).items() if value is not None}
    return _merge(_merge(DEFAULTS, config_values), given)


# --- loading ----------------------------------------------------------------------------------


def _display(gateway: Gateway, path: str) -> str:
    """A path for details.key: absolute (so never `home` or `--config`), `?` when too long or when
    it does not round-trip through UTF-8 (a non-UTF-8 name holds lone surrogates)."""
    shown = gateway.absolute_path(path)
    try:
        shown.encode("utf-8")
    except UnicodeEncodeError:
        return "?"
    return shown if len(shown) <= MAX_KEY_CHARS else "?"


def _is_dropin(name: str) -> bool:
    return name.endswith(".yaml") and not name.startswith(".")


def _read(gateway: Gateway, path: str) -> tuple[str, bytes]:
    """("ok", bytes), ("missing", b"") or ("bad", b"")."""
    try:
        return "ok", gateway.read_regular_file(path, MAX_FILE_BYTES)
    except (FileNotFoundError, NotADirectoryError):
        return "missing", b""
    except Exception:
        return "bad", b""


def config_file_key(gateway: Gateway, *, home: str | None, config_path: str | None) -> str:
    """The details.key naming the main config file (for a failure no single file explains)."""
    if config_path is not None:
        return _display(gateway, config_path)
    if home is None:
        return "?"
    return _display(gateway, os.path.join(home, ".config", "slack-notice", "config.yaml"))


def load_config(gateway: Gateway, *, home: str | None, config_path: str | None) -> dict[str, Any]:
    """The merged raw mapping of the config file and its drop-ins.

    ``config_path`` is the ``--config`` value (an empty string is a missing file); without it the
    file is ``.config/slack-notice/config.yaml`` under ``home``, and a missing one means no
    values. Drop-ins are ``config.d/*.yaml`` (not starting with a dot) in the directory that
    holds the file, in code point order. Raises ``ConfigInvalid``.
    """
    if config_path is None:
        if home is None:
            raise ValueError("a home or a config path is required")
        main = os.path.join(home, ".config", "slack-notice", "config.yaml")
    else:
        main = config_path
    merged: dict[str, Any] = {}
    status, raw = _read(gateway, main)
    if status == "missing" and config_path is not None:
        raise ConfigInvalid("--config")
    if status != "missing":
        merged = _add(gateway, merged, main, status, raw)
    directory = os.path.join(os.path.dirname(main) or ".", "config.d")
    status, names = _list(gateway, directory)
    if status != "ok":
        raise ConfigInvalid(_display(gateway, directory))
    for name in sorted(names):
        if _is_dropin(name):
            path = os.path.join(directory, name)
            status, raw = _read(gateway, path)
            merged = _add(gateway, merged, path, status, raw)  # a missing drop-in is bad too
    return merged


def _add(
    gateway: Gateway, merged: dict[str, Any], path: str, status: str, raw: bytes
) -> dict[str, Any]:
    """``merged`` with the file's mapping on top, or ``ConfigInvalid`` naming the file."""
    result = merged
    failed = status != "ok"
    if not failed:
        try:
            result = _merge(merged, parse_yaml(raw))
        except Exception:
            failed = True
    if failed:  # raised outside the handler: no cause or context is kept
        raise ConfigInvalid(_display(gateway, path))
    return result


def _list(gateway: Gateway, directory: str) -> tuple[str, list[str]]:
    try:
        return "ok", gateway.list_directory(directory)
    except (FileNotFoundError, NotADirectoryError):
        return "ok", []
    except Exception:
        return "bad", []


# --- validation -------------------------------------------------------------------------------

_KEY_NAME = re.compile(r"[A-Za-z0-9_]{1,64}", re.ASCII)
_RESERVED_KEYS = ("home", "--config")  # sentinel values of details.key: never a key name
_WEBHOOK_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}", re.ASCII)
_BODY_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}", re.ASCII)
_PREFIX_LENGTH = 16
_MAX_CHARS_RANGE = (2000, 12000)
_LEVELS = ("info", "warn", "action", "error")

# The invisible format and filler characters of the sanitizer table (interface.md, Sanitizer,
# step 3), as inclusive ranges.
_INVISIBLE = (
    (0x00AD, 0x00AD), (0x061C, 0x061C), (0x180E, 0x180E), (0x200B, 0x200B),
    (0x200E, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB), (0xE0000, 0xE007F), (0xE0100, 0xE01EF), (0x115F, 0x1160),
    (0x3164, 0x3164), (0xFFA0, 0xFFA0), (0x2800, 0x2800), (0x180B, 0x180D), (0x180F, 0x180F),
)  # fmt: skip


# Unassigned and noncharacter code points (category Cn) of Unicode 15.0, as inclusive ranges,
# generated with Python 3.12 (unicodedata.unidata_version == "15.0.0"). Pinned here, not read from
# the running Python, so the title rule gives the same answer on every supported interpreter
# (3.12 and 3.13 differ: U+2FFC to U+2FFF, U+31EF and U+2EBF0 to U+2EE5D are assigned in 15.1).
# TODO(#17): moves to the shared sanitizer module with the rest of the table.
_UNASSIGNED_15_0 = (
    (0x0378, 0x0379), (0x0380, 0x0383), (0x038B, 0x038B), (0x038D, 0x038D), (0x03A2, 0x03A2),
    (0x0530, 0x0530), (0x0557, 0x0558), (0x058B, 0x058C), (0x0590, 0x0590), (0x05C8, 0x05CF),
    (0x05EB, 0x05EE), (0x05F5, 0x05FF), (0x070E, 0x070E), (0x074B, 0x074C), (0x07B2, 0x07BF),
    (0x07FB, 0x07FC), (0x082E, 0x082F), (0x083F, 0x083F), (0x085C, 0x085D), (0x085F, 0x085F),
    (0x086B, 0x086F), (0x088F, 0x088F), (0x0892, 0x0897), (0x0984, 0x0984), (0x098D, 0x098E),
    (0x0991, 0x0992), (0x09A9, 0x09A9), (0x09B1, 0x09B1), (0x09B3, 0x09B5), (0x09BA, 0x09BB),
    (0x09C5, 0x09C6), (0x09C9, 0x09CA), (0x09CF, 0x09D6), (0x09D8, 0x09DB), (0x09DE, 0x09DE),
    (0x09E4, 0x09E5), (0x09FF, 0x0A00), (0x0A04, 0x0A04), (0x0A0B, 0x0A0E), (0x0A11, 0x0A12),
    (0x0A29, 0x0A29), (0x0A31, 0x0A31), (0x0A34, 0x0A34), (0x0A37, 0x0A37), (0x0A3A, 0x0A3B),
    (0x0A3D, 0x0A3D), (0x0A43, 0x0A46), (0x0A49, 0x0A4A), (0x0A4E, 0x0A50), (0x0A52, 0x0A58),
    (0x0A5D, 0x0A5D), (0x0A5F, 0x0A65), (0x0A77, 0x0A80), (0x0A84, 0x0A84), (0x0A8E, 0x0A8E),
    (0x0A92, 0x0A92), (0x0AA9, 0x0AA9), (0x0AB1, 0x0AB1), (0x0AB4, 0x0AB4), (0x0ABA, 0x0ABB),
    (0x0AC6, 0x0AC6), (0x0ACA, 0x0ACA), (0x0ACE, 0x0ACF), (0x0AD1, 0x0ADF), (0x0AE4, 0x0AE5),
    (0x0AF2, 0x0AF8), (0x0B00, 0x0B00), (0x0B04, 0x0B04), (0x0B0D, 0x0B0E), (0x0B11, 0x0B12),
    (0x0B29, 0x0B29), (0x0B31, 0x0B31), (0x0B34, 0x0B34), (0x0B3A, 0x0B3B), (0x0B45, 0x0B46),
    (0x0B49, 0x0B4A), (0x0B4E, 0x0B54), (0x0B58, 0x0B5B), (0x0B5E, 0x0B5E), (0x0B64, 0x0B65),
    (0x0B78, 0x0B81), (0x0B84, 0x0B84), (0x0B8B, 0x0B8D), (0x0B91, 0x0B91), (0x0B96, 0x0B98),
    (0x0B9B, 0x0B9B), (0x0B9D, 0x0B9D), (0x0BA0, 0x0BA2), (0x0BA5, 0x0BA7), (0x0BAB, 0x0BAD),
    (0x0BBA, 0x0BBD), (0x0BC3, 0x0BC5), (0x0BC9, 0x0BC9), (0x0BCE, 0x0BCF), (0x0BD1, 0x0BD6),
    (0x0BD8, 0x0BE5), (0x0BFB, 0x0BFF), (0x0C0D, 0x0C0D), (0x0C11, 0x0C11), (0x0C29, 0x0C29),
    (0x0C3A, 0x0C3B), (0x0C45, 0x0C45), (0x0C49, 0x0C49), (0x0C4E, 0x0C54), (0x0C57, 0x0C57),
    (0x0C5B, 0x0C5C), (0x0C5E, 0x0C5F), (0x0C64, 0x0C65), (0x0C70, 0x0C76), (0x0C8D, 0x0C8D),
    (0x0C91, 0x0C91), (0x0CA9, 0x0CA9), (0x0CB4, 0x0CB4), (0x0CBA, 0x0CBB), (0x0CC5, 0x0CC5),
    (0x0CC9, 0x0CC9), (0x0CCE, 0x0CD4), (0x0CD7, 0x0CDC), (0x0CDF, 0x0CDF), (0x0CE4, 0x0CE5),
    (0x0CF0, 0x0CF0), (0x0CF4, 0x0CFF), (0x0D0D, 0x0D0D), (0x0D11, 0x0D11), (0x0D45, 0x0D45),
    (0x0D49, 0x0D49), (0x0D50, 0x0D53), (0x0D64, 0x0D65), (0x0D80, 0x0D80), (0x0D84, 0x0D84),
    (0x0D97, 0x0D99), (0x0DB2, 0x0DB2), (0x0DBC, 0x0DBC), (0x0DBE, 0x0DBF), (0x0DC7, 0x0DC9),
    (0x0DCB, 0x0DCE), (0x0DD5, 0x0DD5), (0x0DD7, 0x0DD7), (0x0DE0, 0x0DE5), (0x0DF0, 0x0DF1),
    (0x0DF5, 0x0E00), (0x0E3B, 0x0E3E), (0x0E5C, 0x0E80), (0x0E83, 0x0E83), (0x0E85, 0x0E85),
    (0x0E8B, 0x0E8B), (0x0EA4, 0x0EA4), (0x0EA6, 0x0EA6), (0x0EBE, 0x0EBF), (0x0EC5, 0x0EC5),
    (0x0EC7, 0x0EC7), (0x0ECF, 0x0ECF), (0x0EDA, 0x0EDB), (0x0EE0, 0x0EFF), (0x0F48, 0x0F48),
    (0x0F6D, 0x0F70), (0x0F98, 0x0F98), (0x0FBD, 0x0FBD), (0x0FCD, 0x0FCD), (0x0FDB, 0x0FFF),
    (0x10C6, 0x10C6), (0x10C8, 0x10CC), (0x10CE, 0x10CF), (0x1249, 0x1249), (0x124E, 0x124F),
    (0x1257, 0x1257), (0x1259, 0x1259), (0x125E, 0x125F), (0x1289, 0x1289), (0x128E, 0x128F),
    (0x12B1, 0x12B1), (0x12B6, 0x12B7), (0x12BF, 0x12BF), (0x12C1, 0x12C1), (0x12C6, 0x12C7),
    (0x12D7, 0x12D7), (0x1311, 0x1311), (0x1316, 0x1317), (0x135B, 0x135C), (0x137D, 0x137F),
    (0x139A, 0x139F), (0x13F6, 0x13F7), (0x13FE, 0x13FF), (0x169D, 0x169F), (0x16F9, 0x16FF),
    (0x1716, 0x171E), (0x1737, 0x173F), (0x1754, 0x175F), (0x176D, 0x176D), (0x1771, 0x1771),
    (0x1774, 0x177F), (0x17DE, 0x17DF), (0x17EA, 0x17EF), (0x17FA, 0x17FF), (0x181A, 0x181F),
    (0x1879, 0x187F), (0x18AB, 0x18AF), (0x18F6, 0x18FF), (0x191F, 0x191F), (0x192C, 0x192F),
    (0x193C, 0x193F), (0x1941, 0x1943), (0x196E, 0x196F), (0x1975, 0x197F), (0x19AC, 0x19AF),
    (0x19CA, 0x19CF), (0x19DB, 0x19DD), (0x1A1C, 0x1A1D), (0x1A5F, 0x1A5F), (0x1A7D, 0x1A7E),
    (0x1A8A, 0x1A8F), (0x1A9A, 0x1A9F), (0x1AAE, 0x1AAF), (0x1ACF, 0x1AFF), (0x1B4D, 0x1B4F),
    (0x1B7F, 0x1B7F), (0x1BF4, 0x1BFB), (0x1C38, 0x1C3A), (0x1C4A, 0x1C4C), (0x1C89, 0x1C8F),
    (0x1CBB, 0x1CBC), (0x1CC8, 0x1CCF), (0x1CFB, 0x1CFF), (0x1F16, 0x1F17), (0x1F1E, 0x1F1F),
    (0x1F46, 0x1F47), (0x1F4E, 0x1F4F), (0x1F58, 0x1F58), (0x1F5A, 0x1F5A), (0x1F5C, 0x1F5C),
    (0x1F5E, 0x1F5E), (0x1F7E, 0x1F7F), (0x1FB5, 0x1FB5), (0x1FC5, 0x1FC5), (0x1FD4, 0x1FD5),
    (0x1FDC, 0x1FDC), (0x1FF0, 0x1FF1), (0x1FF5, 0x1FF5), (0x1FFF, 0x1FFF), (0x2065, 0x2065),
    (0x2072, 0x2073), (0x208F, 0x208F), (0x209D, 0x209F), (0x20C1, 0x20CF), (0x20F1, 0x20FF),
    (0x218C, 0x218F), (0x2427, 0x243F), (0x244B, 0x245F), (0x2B74, 0x2B75), (0x2B96, 0x2B96),
    (0x2CF4, 0x2CF8), (0x2D26, 0x2D26), (0x2D28, 0x2D2C), (0x2D2E, 0x2D2F), (0x2D68, 0x2D6E),
    (0x2D71, 0x2D7E), (0x2D97, 0x2D9F), (0x2DA7, 0x2DA7), (0x2DAF, 0x2DAF), (0x2DB7, 0x2DB7),
    (0x2DBF, 0x2DBF), (0x2DC7, 0x2DC7), (0x2DCF, 0x2DCF), (0x2DD7, 0x2DD7), (0x2DDF, 0x2DDF),
    (0x2E5E, 0x2E7F), (0x2E9A, 0x2E9A), (0x2EF4, 0x2EFF), (0x2FD6, 0x2FEF), (0x2FFC, 0x2FFF),
    (0x3040, 0x3040), (0x3097, 0x3098), (0x3100, 0x3104), (0x3130, 0x3130), (0x318F, 0x318F),
    (0x31E4, 0x31EF), (0x321F, 0x321F), (0xA48D, 0xA48F), (0xA4C7, 0xA4CF), (0xA62C, 0xA63F),
    (0xA6F8, 0xA6FF), (0xA7CB, 0xA7CF), (0xA7D2, 0xA7D2), (0xA7D4, 0xA7D4), (0xA7DA, 0xA7F1),
    (0xA82D, 0xA82F), (0xA83A, 0xA83F), (0xA878, 0xA87F), (0xA8C6, 0xA8CD), (0xA8DA, 0xA8DF),
    (0xA954, 0xA95E), (0xA97D, 0xA97F), (0xA9CE, 0xA9CE), (0xA9DA, 0xA9DD), (0xA9FF, 0xA9FF),
    (0xAA37, 0xAA3F), (0xAA4E, 0xAA4F), (0xAA5A, 0xAA5B), (0xAAC3, 0xAADA), (0xAAF7, 0xAB00),
    (0xAB07, 0xAB08), (0xAB0F, 0xAB10), (0xAB17, 0xAB1F), (0xAB27, 0xAB27), (0xAB2F, 0xAB2F),
    (0xAB6C, 0xAB6F), (0xABEE, 0xABEF), (0xABFA, 0xABFF), (0xD7A4, 0xD7AF), (0xD7C7, 0xD7CA),
    (0xD7FC, 0xD7FF), (0xFA6E, 0xFA6F), (0xFADA, 0xFAFF), (0xFB07, 0xFB12), (0xFB18, 0xFB1C),
    (0xFB37, 0xFB37), (0xFB3D, 0xFB3D), (0xFB3F, 0xFB3F), (0xFB42, 0xFB42), (0xFB45, 0xFB45),
    (0xFBC3, 0xFBD2), (0xFD90, 0xFD91), (0xFDC8, 0xFDCE), (0xFDD0, 0xFDEF), (0xFE1A, 0xFE1F),
    (0xFE53, 0xFE53), (0xFE67, 0xFE67), (0xFE6C, 0xFE6F), (0xFE75, 0xFE75), (0xFEFD, 0xFEFE),
    (0xFF00, 0xFF00), (0xFFBF, 0xFFC1), (0xFFC8, 0xFFC9), (0xFFD0, 0xFFD1), (0xFFD8, 0xFFD9),
    (0xFFDD, 0xFFDF), (0xFFE7, 0xFFE7), (0xFFEF, 0xFFF8), (0xFFFE, 0xFFFF), (0x1000C, 0x1000C),
    (0x10027, 0x10027), (0x1003B, 0x1003B), (0x1003E, 0x1003E), (0x1004E, 0x1004F),
    (0x1005E, 0x1007F), (0x100FB, 0x100FF), (0x10103, 0x10106), (0x10134, 0x10136),
    (0x1018F, 0x1018F), (0x1019D, 0x1019F), (0x101A1, 0x101CF), (0x101FE, 0x1027F),
    (0x1029D, 0x1029F), (0x102D1, 0x102DF), (0x102FC, 0x102FF), (0x10324, 0x1032C),
    (0x1034B, 0x1034F), (0x1037B, 0x1037F), (0x1039E, 0x1039E), (0x103C4, 0x103C7),
    (0x103D6, 0x103FF), (0x1049E, 0x1049F), (0x104AA, 0x104AF), (0x104D4, 0x104D7),
    (0x104FC, 0x104FF), (0x10528, 0x1052F), (0x10564, 0x1056E), (0x1057B, 0x1057B),
    (0x1058B, 0x1058B), (0x10593, 0x10593), (0x10596, 0x10596), (0x105A2, 0x105A2),
    (0x105B2, 0x105B2), (0x105BA, 0x105BA), (0x105BD, 0x105FF), (0x10737, 0x1073F),
    (0x10756, 0x1075F), (0x10768, 0x1077F), (0x10786, 0x10786), (0x107B1, 0x107B1),
    (0x107BB, 0x107FF), (0x10806, 0x10807), (0x10809, 0x10809), (0x10836, 0x10836),
    (0x10839, 0x1083B), (0x1083D, 0x1083E), (0x10856, 0x10856), (0x1089F, 0x108A6),
    (0x108B0, 0x108DF), (0x108F3, 0x108F3), (0x108F6, 0x108FA), (0x1091C, 0x1091E),
    (0x1093A, 0x1093E), (0x10940, 0x1097F), (0x109B8, 0x109BB), (0x109D0, 0x109D1),
    (0x10A04, 0x10A04), (0x10A07, 0x10A0B), (0x10A14, 0x10A14), (0x10A18, 0x10A18),
    (0x10A36, 0x10A37), (0x10A3B, 0x10A3E), (0x10A49, 0x10A4F), (0x10A59, 0x10A5F),
    (0x10AA0, 0x10ABF), (0x10AE7, 0x10AEA), (0x10AF7, 0x10AFF), (0x10B36, 0x10B38),
    (0x10B56, 0x10B57), (0x10B73, 0x10B77), (0x10B92, 0x10B98), (0x10B9D, 0x10BA8),
    (0x10BB0, 0x10BFF), (0x10C49, 0x10C7F), (0x10CB3, 0x10CBF), (0x10CF3, 0x10CF9),
    (0x10D28, 0x10D2F), (0x10D3A, 0x10E5F), (0x10E7F, 0x10E7F), (0x10EAA, 0x10EAA),
    (0x10EAE, 0x10EAF), (0x10EB2, 0x10EFC), (0x10F28, 0x10F2F), (0x10F5A, 0x10F6F),
    (0x10F8A, 0x10FAF), (0x10FCC, 0x10FDF), (0x10FF7, 0x10FFF), (0x1104E, 0x11051),
    (0x11076, 0x1107E), (0x110C3, 0x110CC), (0x110CE, 0x110CF), (0x110E9, 0x110EF),
    (0x110FA, 0x110FF), (0x11135, 0x11135), (0x11148, 0x1114F), (0x11177, 0x1117F),
    (0x111E0, 0x111E0), (0x111F5, 0x111FF), (0x11212, 0x11212), (0x11242, 0x1127F),
    (0x11287, 0x11287), (0x11289, 0x11289), (0x1128E, 0x1128E), (0x1129E, 0x1129E),
    (0x112AA, 0x112AF), (0x112EB, 0x112EF), (0x112FA, 0x112FF), (0x11304, 0x11304),
    (0x1130D, 0x1130E), (0x11311, 0x11312), (0x11329, 0x11329), (0x11331, 0x11331),
    (0x11334, 0x11334), (0x1133A, 0x1133A), (0x11345, 0x11346), (0x11349, 0x1134A),
    (0x1134E, 0x1134F), (0x11351, 0x11356), (0x11358, 0x1135C), (0x11364, 0x11365),
    (0x1136D, 0x1136F), (0x11375, 0x113FF), (0x1145C, 0x1145C), (0x11462, 0x1147F),
    (0x114C8, 0x114CF), (0x114DA, 0x1157F), (0x115B6, 0x115B7), (0x115DE, 0x115FF),
    (0x11645, 0x1164F), (0x1165A, 0x1165F), (0x1166D, 0x1167F), (0x116BA, 0x116BF),
    (0x116CA, 0x116FF), (0x1171B, 0x1171C), (0x1172C, 0x1172F), (0x11747, 0x117FF),
    (0x1183C, 0x1189F), (0x118F3, 0x118FE), (0x11907, 0x11908), (0x1190A, 0x1190B),
    (0x11914, 0x11914), (0x11917, 0x11917), (0x11936, 0x11936), (0x11939, 0x1193A),
    (0x11947, 0x1194F), (0x1195A, 0x1199F), (0x119A8, 0x119A9), (0x119D8, 0x119D9),
    (0x119E5, 0x119FF), (0x11A48, 0x11A4F), (0x11AA3, 0x11AAF), (0x11AF9, 0x11AFF),
    (0x11B0A, 0x11BFF), (0x11C09, 0x11C09), (0x11C37, 0x11C37), (0x11C46, 0x11C4F),
    (0x11C6D, 0x11C6F), (0x11C90, 0x11C91), (0x11CA8, 0x11CA8), (0x11CB7, 0x11CFF),
    (0x11D07, 0x11D07), (0x11D0A, 0x11D0A), (0x11D37, 0x11D39), (0x11D3B, 0x11D3B),
    (0x11D3E, 0x11D3E), (0x11D48, 0x11D4F), (0x11D5A, 0x11D5F), (0x11D66, 0x11D66),
    (0x11D69, 0x11D69), (0x11D8F, 0x11D8F), (0x11D92, 0x11D92), (0x11D99, 0x11D9F),
    (0x11DAA, 0x11EDF), (0x11EF9, 0x11EFF), (0x11F11, 0x11F11), (0x11F3B, 0x11F3D),
    (0x11F5A, 0x11FAF), (0x11FB1, 0x11FBF), (0x11FF2, 0x11FFE), (0x1239A, 0x123FF),
    (0x1246F, 0x1246F), (0x12475, 0x1247F), (0x12544, 0x12F8F), (0x12FF3, 0x12FFF),
    (0x13456, 0x143FF), (0x14647, 0x167FF), (0x16A39, 0x16A3F), (0x16A5F, 0x16A5F),
    (0x16A6A, 0x16A6D), (0x16ABF, 0x16ABF), (0x16ACA, 0x16ACF), (0x16AEE, 0x16AEF),
    (0x16AF6, 0x16AFF), (0x16B46, 0x16B4F), (0x16B5A, 0x16B5A), (0x16B62, 0x16B62),
    (0x16B78, 0x16B7C), (0x16B90, 0x16E3F), (0x16E9B, 0x16EFF), (0x16F4B, 0x16F4E),
    (0x16F88, 0x16F8E), (0x16FA0, 0x16FDF), (0x16FE5, 0x16FEF), (0x16FF2, 0x16FFF),
    (0x187F8, 0x187FF), (0x18CD6, 0x18CFF), (0x18D09, 0x1AFEF), (0x1AFF4, 0x1AFF4),
    (0x1AFFC, 0x1AFFC), (0x1AFFF, 0x1AFFF), (0x1B123, 0x1B131), (0x1B133, 0x1B14F),
    (0x1B153, 0x1B154), (0x1B156, 0x1B163), (0x1B168, 0x1B16F), (0x1B2FC, 0x1BBFF),
    (0x1BC6B, 0x1BC6F), (0x1BC7D, 0x1BC7F), (0x1BC89, 0x1BC8F), (0x1BC9A, 0x1BC9B),
    (0x1BCA4, 0x1CEFF), (0x1CF2E, 0x1CF2F), (0x1CF47, 0x1CF4F), (0x1CFC4, 0x1CFFF),
    (0x1D0F6, 0x1D0FF), (0x1D127, 0x1D128), (0x1D1EB, 0x1D1FF), (0x1D246, 0x1D2BF),
    (0x1D2D4, 0x1D2DF), (0x1D2F4, 0x1D2FF), (0x1D357, 0x1D35F), (0x1D379, 0x1D3FF),
    (0x1D455, 0x1D455), (0x1D49D, 0x1D49D), (0x1D4A0, 0x1D4A1), (0x1D4A3, 0x1D4A4),
    (0x1D4A7, 0x1D4A8), (0x1D4AD, 0x1D4AD), (0x1D4BA, 0x1D4BA), (0x1D4BC, 0x1D4BC),
    (0x1D4C4, 0x1D4C4), (0x1D506, 0x1D506), (0x1D50B, 0x1D50C), (0x1D515, 0x1D515),
    (0x1D51D, 0x1D51D), (0x1D53A, 0x1D53A), (0x1D53F, 0x1D53F), (0x1D545, 0x1D545),
    (0x1D547, 0x1D549), (0x1D551, 0x1D551), (0x1D6A6, 0x1D6A7), (0x1D7CC, 0x1D7CD),
    (0x1DA8C, 0x1DA9A), (0x1DAA0, 0x1DAA0), (0x1DAB0, 0x1DEFF), (0x1DF1F, 0x1DF24),
    (0x1DF2B, 0x1DFFF), (0x1E007, 0x1E007), (0x1E019, 0x1E01A), (0x1E022, 0x1E022),
    (0x1E025, 0x1E025), (0x1E02B, 0x1E02F), (0x1E06E, 0x1E08E), (0x1E090, 0x1E0FF),
    (0x1E12D, 0x1E12F), (0x1E13E, 0x1E13F), (0x1E14A, 0x1E14D), (0x1E150, 0x1E28F),
    (0x1E2AF, 0x1E2BF), (0x1E2FA, 0x1E2FE), (0x1E300, 0x1E4CF), (0x1E4FA, 0x1E7DF),
    (0x1E7E7, 0x1E7E7), (0x1E7EC, 0x1E7EC), (0x1E7EF, 0x1E7EF), (0x1E7FF, 0x1E7FF),
    (0x1E8C5, 0x1E8C6), (0x1E8D7, 0x1E8FF), (0x1E94C, 0x1E94F), (0x1E95A, 0x1E95D),
    (0x1E960, 0x1EC70), (0x1ECB5, 0x1ED00), (0x1ED3E, 0x1EDFF), (0x1EE04, 0x1EE04),
    (0x1EE20, 0x1EE20), (0x1EE23, 0x1EE23), (0x1EE25, 0x1EE26), (0x1EE28, 0x1EE28),
    (0x1EE33, 0x1EE33), (0x1EE38, 0x1EE38), (0x1EE3A, 0x1EE3A), (0x1EE3C, 0x1EE41),
    (0x1EE43, 0x1EE46), (0x1EE48, 0x1EE48), (0x1EE4A, 0x1EE4A), (0x1EE4C, 0x1EE4C),
    (0x1EE50, 0x1EE50), (0x1EE53, 0x1EE53), (0x1EE55, 0x1EE56), (0x1EE58, 0x1EE58),
    (0x1EE5A, 0x1EE5A), (0x1EE5C, 0x1EE5C), (0x1EE5E, 0x1EE5E), (0x1EE60, 0x1EE60),
    (0x1EE63, 0x1EE63), (0x1EE65, 0x1EE66), (0x1EE6B, 0x1EE6B), (0x1EE73, 0x1EE73),
    (0x1EE78, 0x1EE78), (0x1EE7D, 0x1EE7D), (0x1EE7F, 0x1EE7F), (0x1EE8A, 0x1EE8A),
    (0x1EE9C, 0x1EEA0), (0x1EEA4, 0x1EEA4), (0x1EEAA, 0x1EEAA), (0x1EEBC, 0x1EEEF),
    (0x1EEF2, 0x1EFFF), (0x1F02C, 0x1F02F), (0x1F094, 0x1F09F), (0x1F0AF, 0x1F0B0),
    (0x1F0C0, 0x1F0C0), (0x1F0D0, 0x1F0D0), (0x1F0F6, 0x1F0FF), (0x1F1AE, 0x1F1E5),
    (0x1F203, 0x1F20F), (0x1F23C, 0x1F23F), (0x1F249, 0x1F24F), (0x1F252, 0x1F25F),
    (0x1F266, 0x1F2FF), (0x1F6D8, 0x1F6DB), (0x1F6ED, 0x1F6EF), (0x1F6FD, 0x1F6FF),
    (0x1F777, 0x1F77A), (0x1F7DA, 0x1F7DF), (0x1F7EC, 0x1F7EF), (0x1F7F1, 0x1F7FF),
    (0x1F80C, 0x1F80F), (0x1F848, 0x1F84F), (0x1F85A, 0x1F85F), (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8AF), (0x1F8B2, 0x1F8FF), (0x1FA54, 0x1FA5F), (0x1FA6E, 0x1FA6F),
    (0x1FA7D, 0x1FA7F), (0x1FA89, 0x1FA8F), (0x1FABE, 0x1FABE), (0x1FAC6, 0x1FACD),
    (0x1FADC, 0x1FADF), (0x1FAE9, 0x1FAEF), (0x1FAF9, 0x1FAFF), (0x1FB93, 0x1FB93),
    (0x1FBCB, 0x1FBEF), (0x1FBFA, 0x1FFFF), (0x2A6E0, 0x2A6FF), (0x2B73A, 0x2B73F),
    (0x2B81E, 0x2B81F), (0x2CEA2, 0x2CEAF), (0x2EBE1, 0x2F7FF), (0x2FA1E, 0x2FFFF),
    (0x3134B, 0x3134F), (0x323B0, 0xE0000), (0xE0002, 0xE001F), (0xE0080, 0xE00FF),
    (0xE01F0, 0xEFFFF), (0xFFFFE, 0xFFFFF), (0x10FFFE, 0x10FFFF),
)  # fmt: skip
_UNASSIGNED_STARTS = tuple(low for low, _ in _UNASSIGNED_15_0)
# Control, surrogate and private use code points (Cc, Cs, Co): stable across Unicode versions.
# LF is a Cc character; _removed keeps it (the caller's lines depend on it).
_FIXED_REMOVED = (
    (0x0000, 0x001F), (0x007F, 0x009F), (0xD800, 0xDFFF), (0xE000, 0xF8FF),
    (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD),
)  # fmt: skip


def _in_ranges(code: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(low <= code <= high for low, high in ranges)


def _removed(char: str) -> bool:
    """Step 3 of the sanitizer: removed characters (Cc but LF, Cs, Co, Cn, the explicit list)."""
    code = ord(char)
    if char == "\n":
        return False
    if _in_ranges(code, _FIXED_REMOVED) or _in_ranges(code, _INVISIBLE):
        return True
    index = bisect.bisect_right(_UNASSIGNED_STARTS, code) - 1
    return index >= 0 and code <= _UNASSIGNED_15_0[index][1]


def _title_rule(text: str) -> str:
    """The title rule: sanitizer steps 2 to 5 (step 1, strict UTF-8, is the caller's).

    TODO(#17): the sanitizer of the payload module is the one shared rule; replace this copy of
    interface.md's steps by it when it exists (the tests pin both to the same table).
    """
    text = text.replace("\r\n", "\n")
    for char in ("\r", "\x85", "\u2028", "\u2029"):
        text = text.replace(char, "\n")
    text = text.replace("\t", " ")
    text = "".join(char for char in text if not _removed(char))
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    text = text.strip()
    text = text.replace("\n", " ")
    while "  " in text:
        text = text.replace("  ", " ")
    return text.strip()


def _empty(text: str) -> bool:
    """interface.md's definition: nothing but whitespace, U+200C, U+200D and Mn, Mc, Me marks."""
    return all(
        char.isspace() or char in "\u200c\u200d" or unicodedata.category(char) in ("Mn", "Mc", "Me")
        for char in text
    )


def _prefix_ok(text: str) -> bool:
    """1 to 16 code points that the title rule leaves unchanged (and valid UTF-8), and that are
    not empty by the definition under the sanitizer (such a prefix would render invisibly)."""
    if not 1 <= len(text) <= _PREFIX_LENGTH:
        return False
    try:
        text.encode("utf-8")  # step 1: a lone surrogate is refused
    except UnicodeEncodeError:
        return False
    return _title_rule(text) == text and not _empty(text)


def _name(pattern: re.Pattern[str], value: str) -> str:
    if pattern.fullmatch(value) is None:  # fullmatch: a trailing newline never passes
        raise PydanticCustomError("name", "bad name")
    return value


class _LevelPrefix(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    info: str
    warn: str
    action: str
    error: str

    @field_validator("*")
    @classmethod
    def _title_rule_unchanged(cls, value: str) -> str:
        if not _prefix_ok(value):
            raise PydanticCustomError("prefix", "bad prefix")
        return value


class _Settings(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    enabled: StrictBool
    webhook_env: str
    body_variable: str
    level_prefix: _LevelPrefix
    max_chars: Annotated[int, Field(ge=_MAX_CHARS_RANGE[0], le=_MAX_CHARS_RANGE[1])]
    timeout: Any
    log: StrictBool

    @field_validator("webhook_env")
    @classmethod
    def _webhook_env(cls, value: str) -> str:
        return _name(_WEBHOOK_ENV, value)

    @field_validator("body_variable")
    @classmethod
    def _body_variable(cls, value: str) -> str:
        return _name(_BODY_VARIABLE, value)

    @field_validator("timeout", mode="before")
    @classmethod
    def _timeout(cls, value: Any) -> float:
        try:
            return check_duration("timeout", value)
        except DurationError:
            raise PydanticCustomError("duration", "bad duration") from None


_INTEGER_RULE = f"must be an integer from {_MAX_CHARS_RANGE[0]} to {_MAX_CHARS_RANGE[1]}"
# Rule text by Pydantic error type. The text never depends on the input.
_RULES = {
    "bool_type": "must be true or false",
    "string_type": "must be a string",
    "int_type": _INTEGER_RULE,
    "int_parsing": _INTEGER_RULE,
    "int_from_float": _INTEGER_RULE,
    "greater_than_equal": _INTEGER_RULE,
    "less_than_equal": _INTEGER_RULE,
    "model_type": "must be a mapping",
    "dict_type": "must be a mapping",
    "name": "must be a variable name",
    "prefix": (
        f"must be one line of 1 to {_PREFIX_LENGTH} characters that the title rule leaves "
        "unchanged and that is not empty"
    ),
    "duration": f"must be a duration from {DURATION_RANGES['timeout'][0]}s "
    f"to {DURATION_RANGES['timeout'][1]}s",
    "extra_forbidden": "is not a known key",
    "missing": "is required",
}


def _key_label(key: object) -> str:
    """A key name for details.key: ASCII word characters, at most 64, never a sentinel."""
    if isinstance(key, str) and key not in _RESERVED_KEYS and _KEY_NAME.fullmatch(key):
        return key
    return "?"


_UNKNOWN_KEY_RULE = "is not a known key"
_UNKNOWN_LEVEL_RULE = f"has a key that is not a level ({', '.join(_LEVELS)})"


def _unknown_key(values: dict[Any, Any]) -> tuple[str, str] | None:
    """The label and rule of the first unknown key, looking at keys only, never at values."""
    for key in values:
        if key not in DEFAULTS:
            return _key_label(key), _UNKNOWN_KEY_RULE
    level_prefix = values.get("level_prefix")
    if isinstance(level_prefix, dict) and any(key not in _LEVELS for key in level_prefix):
        return "level_prefix", _UNKNOWN_LEVEL_RULE
    return None


def validate_config(values: dict[Any, Any], *, fallback_key: str = "?") -> dict[str, Any]:
    """The settings: ``values`` over the defaults, validated, with ``timeout`` in seconds.

    Order: unknown keys (named without looking at their values), then the first invalid known
    key in table order. Raises ``ConfigInvalid`` with ``key`` a config key name or ``?`` and
    ``message`` built from the key path and the rule. Any other failure of the machinery
    (``RecursionError``, ``MemoryError``, ...) is ``ConfigInvalid`` with ``fallback_key`` (the
    file the caller names). ``values`` is not changed.
    """
    failure: ConfigInvalid | None = None
    invalid: ValidationError | None = None
    result: dict[str, Any] = {}
    try:
        unknown = _unknown_key(values)
        if unknown is not None:
            failure = ConfigInvalid(unknown[0], unknown[1], f"{unknown[0]} {unknown[1]}")
        else:
            merged = resolve_settings(values, {})
            result = _Settings.model_validate(merged).model_dump()
    except ValidationError as error:
        invalid = error  # converted below, outside the handler
    except Exception:
        failure = _fallback(fallback_key)
    if invalid is not None:
        # Outside any handler, so a failure of the conversion has no ValidationError (which holds
        # the input) as context; the error object is dropped before anything is raised.
        broken = False
        try:
            failure = _failure_of(invalid)
        except Exception:
            broken = True
        invalid = None
        if broken:
            failure = _fallback(fallback_key)
    if failure is not None:  # raised outside the handlers: no cause or context is kept
        raise failure
    return result


def _fallback(key: str) -> ConfigInvalid:
    # Empty message: the caller prints the fixed text, so the key (a file path) stays in details.
    return ConfigInvalid(key, "is invalid", "")


def _failure_of(error: ValidationError) -> ConfigInvalid:
    """The first error (table order) as a ConfigInvalid; only ``loc`` and ``type`` are used."""
    first = error.errors(include_input=False, include_url=False, include_context=False)[0]
    path = [part for part in first["loc"] if part in DEFAULTS or part in _LEVELS]
    key = str(path[0]) if path and path[0] in DEFAULTS else "?"
    where = ".".join(str(part) for part in path) if key != "?" else "?"
    rule = _RULES.get(first["type"], "is invalid")
    return ConfigInvalid(key, rule, f"{where} {rule}")

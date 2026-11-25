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

# interface.md, Config table. Raw values: #11 validates them (the timeout is the string "10s").
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


def _removed(char: str) -> bool:
    """Step 3 of the sanitizer: removed characters (Cc but LF, Cs, Co, Cn, the explicit list)."""
    code = ord(char)
    if char != "\n" and unicodedata.category(char) in ("Cc", "Cs", "Co", "Cn"):
        return True
    return any(low <= code <= high for low, high in _INVISIBLE)


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


def _prefix_ok(text: str) -> bool:
    """1 to 16 code points that the title rule leaves unchanged (and valid UTF-8)."""
    if not 1 <= len(text) <= _PREFIX_LENGTH:
        return False
    try:
        text.encode("utf-8")  # step 1: a lone surrogate is refused
    except UnicodeEncodeError:
        return False
    return _title_rule(text) == text


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
        f"must be one line of 1 to {_PREFIX_LENGTH} characters that the title rule leaves unchanged"
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


def _unknown_key(values: dict[Any, Any]) -> str | None:
    """The label of the first unknown key, looking at keys only, never at values."""
    for key in values:
        if key not in DEFAULTS:
            return _key_label(key)
    level_prefix = values.get("level_prefix")
    if isinstance(level_prefix, dict) and any(key not in _LEVELS for key in level_prefix):
        return "level_prefix"
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
    result: dict[str, Any] = {}
    try:
        unknown = _unknown_key(values)
        if unknown is not None:
            failure = ConfigInvalid(unknown, "is not a known key", f"{unknown} is not a known key")
        else:
            merged = resolve_settings(values, {})
            result = _Settings.model_validate(merged).model_dump()
    except ValidationError as error:
        failure = _failure_of(error)
    except Exception:
        failure = ConfigInvalid(fallback_key, "is invalid", f"{fallback_key} is invalid")
    if failure is not None:  # raised outside the handlers: no cause or context is kept
        raise failure
    return result


def _failure_of(error: ValidationError) -> ConfigInvalid:
    """The first error (table order) as a ConfigInvalid; only ``loc`` and ``type`` are used."""
    first = error.errors(include_input=False, include_url=False, include_context=False)[0]
    path = [part for part in first["loc"] if part in DEFAULTS or part in _LEVELS]
    key = str(path[0]) if path and path[0] in DEFAULTS else "?"
    where = ".".join(str(part) for part in path) if key != "?" else "?"
    rule = _RULES.get(first["type"], "is invalid")
    return ConfigInvalid(key, rule, f"{where} {rule}")

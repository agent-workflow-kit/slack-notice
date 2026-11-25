"""Config, drop-ins, YAML and durations, and the home lookup.

Loading (interface.md, Config): ``load_config`` reads the config file and ``config.d/*.yaml``
through the gateway, parses each with a strict YAML loader and merges the maps. The result is
the raw merged mapping; ``resolve_settings`` layers it over the defaults (and flags over it).
Every failure is ``ConfigInvalid`` with a fixed message and a ``key`` that is ``--config`` (a
missing file named by the flag) or an absolute file path, never content, so it can never equal
the reserved sentinel values ``home`` and ``--config`` otherwise.

TODO(#11): validate the merged values (types, ranges, unknown keys; unknown keys are refused
before their value is examined).
TODO(#11): implement config validation: validate `timeout` with `check_duration`; a DurationError
becomes exit 2 config_invalid, details.key its `key`; build the message from key and rule only
(Pydantic wraps ValueError and keeps the input in its error dict).
"""

from __future__ import annotations

import copy
import math
import os
import re
from collections.abc import Hashable
from fractions import Fraction
from typing import TYPE_CHECKING, Any

import yaml
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
    """A config file cannot be used. ``key`` is ``--config`` or the absolute path of the file
    (or directory); the message is fixed and no cause or context is kept."""

    def __init__(self, key: str) -> None:
        super().__init__(FIXED_MESSAGE)
        self.key = key


class _StrictLoader(yaml.SafeLoader):
    """PyYAML's SafeLoader with only the resolvers the interface keeps, and no tags, anchors,
    aliases, merge keys, duplicate keys or keys that are not strings."""

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
    """A path for details.key: absolute (so never `home` or `--config`), `?` when too long."""
    shown = gateway.absolute_path(path)
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

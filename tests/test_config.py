"""Config loading (issue #10): strict YAML, file rules, drop-ins, precedence.

Validation of the loaded values (types, ranges, unknown keys) is issue #11: these tests pin what
the loader hands over, and that it hands over strings where YAML 1.1 would invent numbers.
"""

from __future__ import annotations

import io
import json
import os
import signal
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, config
from slack_notice.cli import CliError, Context, Streams, main
from slack_notice.config import (
    DEFAULTS,
    ConfigInvalid,
    check_duration,
    load_config,
    parse_yaml,
    resolve_settings,
)
from tests.fake_gateway import FakeGateway
from tests.harness import assert_valid

REPO = Path(__file__).resolve().parent.parent
SECRET = "https://hooks.slack.com/triggers/T0FAKE/0000/FAKESECRET"


@contextmanager
def no_hang(seconds: int = 5) -> Iterator[None]:
    """Fail (instead of hanging the run) when the block takes longer than `seconds`."""

    def fire(_signum: int, _frame: object) -> None:
        raise AssertionError("hung")

    previous = signal.signal(signal.SIGALRM, fire)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def home_of(gateway: FakeGateway) -> str:
    return gateway.home_dir()


def default_file(gateway: FakeGateway) -> Path:
    path = Path(home_of(gateway)) / ".config" / "slack-notice" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_default(gateway: FakeGateway, text: str | bytes) -> Path:
    path = default_file(gateway)
    if isinstance(text, str):
        text = text.encode()
    path.write_bytes(text)
    return path


def load_default(gateway: FakeGateway) -> dict[str, Any]:
    return load_config(gateway, home=home_of(gateway), config_path=None)


def load_at(gateway: FakeGateway, path: str | Path) -> dict[str, Any]:
    return load_config(gateway, home=None, config_path=str(path))


def invalid_key(gateway: FakeGateway, path: str | Path | None = None) -> str:
    """Load and return `details.key` of the ConfigInvalid it must raise."""
    with no_hang(), pytest.raises(ConfigInvalid) as raised:
        if path is None:
            load_default(gateway)
        else:
            load_at(gateway, path)
    return raised.value.key


# --- the strict loader: scalars ---------------------------------------------------------------


@pytest.mark.parametrize(
    "scalar",
    [
        "no", "No", "NO", "off", "Off", "yes", "Yes", "on", "On", "y", "n",
        "True", "TRUE", "False", "FALSE",
        "0o10", "1e3", "1E3", "1.5e3", "1,000", "2001-01-01", "2001-01-01T10:00:00Z",
        "=", "<<", "~~", "--5", "1.2.3", "Null", "NULL", "1m", "10s", "500ms", "1.5s",
    ],
)  # fmt: skip
def test_yaml_one_one_lookalikes_stay_strings(scalar: str) -> None:
    assert parse_yaml(f"key: {scalar}\n".encode()) == {"key": scalar}


@pytest.mark.parametrize(
    "scalar",
    [
        "010", "00", "007", "01.5", "1:30", "1:30:00", "0x10", "0xFF", "0b1", "1_0", "1_000",
        "+5", "+1.5", "5.", ".5", "0.", ".inf", "-.inf", "+.inf", ".Inf", ".INF", ".nan",
        ".NaN", ".NAN", "1_0.5", "190:20:30",
    ],
)  # fmt: skip
def test_number_lookalikes_are_refused_not_kept_as_strings(scalar: str) -> None:
    # "010" kept as a string would pass the duration grammar as ten seconds.
    with pytest.raises(ValueError):
        parse_yaml(f"key: {scalar}\n".encode())
    with pytest.raises(ValueError):
        parse_yaml(f"{scalar}: x\n".encode())
    assert parse_yaml(f"key: '{scalar}'\n".encode()) == {"key": scalar}
    assert parse_yaml(f'key: "{scalar}"\n'.encode()) == {"key": scalar}


@pytest.mark.parametrize(
    ("scalar", "expected"),
    [
        ("true", True), ("false", False),
        ("0", 0), ("10", 10), ("120", 120), ("-5", -5), ("-0", 0), ("3000", 3000),
        ("1.5", 1.5), ("0.5", 0.5), ("10.25", 10.25), ("-1.5", -1.5), ("0.0", 0.0),
        ("null", None), ("~", None),
    ],
)  # fmt: skip
def test_yaml_accepted_scalars(scalar: str, expected: object) -> None:
    value = parse_yaml(f"key: {scalar}\n".encode())["key"]
    assert value == expected
    assert type(value) is type(expected)


def test_an_empty_value_is_null_not_a_string() -> None:
    assert parse_yaml(b"key:\n") == {"key": None}


@pytest.mark.parametrize("scalar", ['"010"', "'1:30'", '"true"', "'10'", '"1.5"'])
def test_quoted_scalars_are_strings(scalar: str) -> None:
    assert isinstance(parse_yaml(f"key: {scalar}\n".encode())["key"], str)


def test_block_scalars_are_strings() -> None:
    assert parse_yaml(b"key: |\n  10\n")["key"] == "10\n"
    assert parse_yaml(b"key: >\n  true\n")["key"] == "true\n"


def test_unicode_digits_are_not_numbers() -> None:
    assert parse_yaml("key: ١٠\n".encode()) == {"key": "١٠"}
    assert parse_yaml("key: １０\n".encode()) == {"key": "１０"}


def test_overlong_numbers_are_refused_not_converted() -> None:
    for text in ("9" * 5000, "9" * 65, "1." + "0" * 70):
        with pytest.raises(ValueError):
            parse_yaml(f"key: {text}\n".encode())
    assert parse_yaml(("key: " + "9" * 18 + "\n").encode()) == {"key": 10**18 - 1}


def test_a_huge_decimal_does_not_become_infinite() -> None:
    with pytest.raises(ValueError):
        parse_yaml(("key: " + "9" * 400 + ".0\n").encode())


def test_the_strict_loader_table_stops_the_number_hazards_of_timeout() -> None:
    for text in ("010", "1:30", "0x10", "1_0", ".inf", ".nan"):
        with pytest.raises(ValueError):
            parse_yaml(f"timeout: {text}\n".encode())


def test_accepted_timeouts_pass_the_duration_check() -> None:
    assert check_duration("timeout", parse_yaml(b"timeout: 10\n")["timeout"]) == 10.0
    assert check_duration("timeout", parse_yaml(b"timeout: 3.5\n")["timeout"]) == 3.5


# --- the strict loader: structure -------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "a: 1\na: 2\n",
        "a: 1\na: 1\n",
        'a: 1\n"a": 2\n',
        "a: {b: 1, b: 2}\n",
        "a:\n  b: 1\n  b: 2\n",
        "level_prefix:\n  info: x\n  info: y\n",
        "{a: 1, a: 2}\n",
    ],
)
def test_a_duplicate_key_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_yaml(text.encode())


@pytest.mark.parametrize(
    "text",
    ["1: a\n", "true: a\n", "~: a\n", "1.5: a\n", "? [a]\n: b\n", "? {a: 1}\n: b\n", "null: a\n"],
)
def test_a_key_that_is_not_a_string_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_yaml(text.encode())


def test_a_merge_key_is_a_plain_string_key_not_a_merge() -> None:
    assert parse_yaml(b"<<: {a: 1}\nb: 2\n") == {"<<": {"a": 1}, "b": 2}


@pytest.mark.parametrize(
    "text",
    [
        "a: &a 1\n",
        "a: &a 1\nb: *a\n",
        "a: &a [*a]\n",
        "a: *a\n",
        "a: &a [x]\nb: *a\n",
        "&a a: 1\n",
        "a: &a {b: 1}\nc:\n  <<: *a\n",
    ],
)
def test_anchors_and_aliases_are_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_yaml(text.encode())


@pytest.mark.parametrize(
    "text",
    [
        "a: !!str x\n",
        "a: !!int '010'\n",
        "a: !!int 0x10\n",
        "a: !!float .inf\n",
        "a: !!bool yes\n",
        "a: !foo x\n",
        "a: ! x\n",
        "a: !!python/object/apply:os.system ['echo x']\n",
        "a: !!python/name:os.system\n",
        "a: !!set {x}\n",
        "a: !!binary eA==\n",
        "a: !!timestamp 2001-01-01\n",
        "!!map {a: 1}\n",
        "a: !<tag:yaml.org,2002:str> x\n",
        "%TAG ! tag:example.com,2000:\n---\na: !x y\n",
    ],
)
def test_explicit_tags_are_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_yaml(text.encode())


@pytest.mark.parametrize(
    "text",
    [
        "a: 1\n---\nb: 2\n",
        "---\na: 1\n---\nb: 2\n",
        "a: 1\n...\n---\nb: 2\n",
        "---\n---\na: 1\n",
    ],
)
def test_more_than_one_document_is_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_yaml(text.encode())


def test_one_explicit_document_is_fine() -> None:
    assert parse_yaml(b"---\na: 1\n...\n") == {"a": 1}


@pytest.mark.parametrize(
    "text",
    ["", "   \n", "# only a comment\n", "---\n", "null\n", "~\n", "[]\n", "- a\n", "a\n", "10\n",
     "true\n", "[a: 1]\n", '"a: 1"\n'],
)  # fmt: skip
def test_the_top_level_must_be_a_mapping(text: str) -> None:
    with pytest.raises(ValueError):
        parse_yaml(text.encode())


def test_an_empty_mapping_is_a_mapping() -> None:
    assert parse_yaml(b"{}\n") == {}


@pytest.mark.parametrize(
    "data",
    [
        b"\xff\xfe",
        b"a: \xff\n",
        b"a: \xc3\n",
        b"a: \xed\xa0\x80\n",  # an encoded surrogate
        b"a: \xc0\xaf\n",  # overlong
        b"\xef\xbb\xbfa: 1\n",  # BOM
        "a: 1\n".encode("utf-16"),
        "a: 1\n".encode("utf-16-le"),
        "a: 1\n".encode("utf-16-be"),
        "a: 1\n".encode("utf-32"),
        b"a: 1\x00\n",
        b"\x00",
        b"a: \x1b[31m\n",
        b"a: \x7f\n",
        b"a: \x08\n",
        b"a: \x85x\n",  # a raw C1 byte is invalid UTF-8
    ],
)
def test_input_that_is_not_plain_utf8_is_refused(data: bytes) -> None:
    with pytest.raises(ValueError):
        parse_yaml(data)


def test_non_ascii_text_is_kept() -> None:
    assert parse_yaml("level_prefix:\n  info: '🔵 INFO'\nname: é\n".encode()) == {
        "level_prefix": {"info": "🔵 INFO"},
        "name": "é",
    }


def test_crlf_line_ends_are_fine() -> None:
    assert parse_yaml(b"a: 1\r\nb: x\r\n") == {"a": 1, "b": "x"}


@pytest.mark.parametrize(
    "text",
    [
        "a: [",
        "a: [1, 2",
        "a: {",
        'a: "unterminated\n',
        "a: 'unterminated\n",
        "a: b: c\n",
        "a:\n\tb: 1\n",
        "a: @x\n",
        "a: `x\n",
        "a: %x\n",
        "a: ]\n",
        "- a\nb: 1\n",
        "a: 1\n  b: 2\n",
        "a: '\\x'\n" + 'b: "\\x"\n',
        "a: *\n",
        "a: &\n",
        "a: !\n!\n",
    ],
)
def test_parser_errors_are_refused(text: str) -> None:
    with pytest.raises(ValueError):
        parse_yaml(text.encode())


def test_nested_collections_are_limited_in_depth() -> None:
    assert parse_yaml(b"a:\n  b:\n    c: 1\n") == {"a": {"b": {"c": 1}}}
    for text in (
        "key: " + "[" * 1000,
        "[" * 1000,
        "key: " + "[" * 1000 + "]" * 1000,
        "key: " + "{a: " * 1000 + "1" + "}" * 1000,
        "".join("  " * i + "a:\n" for i in range(200)) + "  " * 200 + "a: 1\n",
        "".join("  " * i + "- \n" for i in range(200)),
        "- " * 1000 + "x",
        "? " * 500,
    ):
        with no_hang(), pytest.raises(ValueError):
            parse_yaml(text.encode())


def test_the_depth_limit_admits_the_documented_shape() -> None:
    text = "level_prefix:\n  info: x\nlist: [[1, [2]]]\n"
    assert parse_yaml(text.encode())["level_prefix"] == {"info": "x"}


def test_a_flow_bomb_without_aliases_is_just_a_big_file() -> None:
    # 64 KiB of flow sequence stays far below any limit that matters and parses fast.
    text = "a: [" + ",".join(["x"] * 20000) + "]\n"
    with no_hang():
        assert len(parse_yaml(text.encode())["a"]) == 20000


def test_an_alias_bomb_of_413_bytes_is_refused_fast() -> None:
    lines = ["a: &a [x,x,x,x,x,x,x,x,x]"]
    names = "a"
    for i in range(1, 9):
        name = chr(ord("a") + i)
        lines.append(f"{name}: &{name} [" + ",".join(f"*{names[-1]}" for _ in range(9)) + "]")
        names += name
    text = "\n".join(lines) + "\n"
    assert 200 <= len(text) <= 413
    with no_hang(2), pytest.raises(ValueError):
        parse_yaml(text.encode())


def test_every_parse_failure_is_a_fixed_message_without_content() -> None:
    for text in (
        f"a: [\nb: {SECRET}",
        f'a: "{SECRET}',
        f"a: 1\na: {SECRET}\n",
        f"a: !x {SECRET}\n",
    ):
        with pytest.raises(ValueError) as raised:
            parse_yaml(text.encode())
        assert "FAKESECRET" not in str(raised.value)
        assert "FAKESECRET" not in repr(raised.value)
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None


def test_errors_from_the_parser_internals_are_refused_too(monkeypatch: pytest.MonkeyPatch) -> None:
    for error in (RecursionError(), MemoryError(), KeyError("x"), OverflowError(), TypeError()):

        def explode(*_a: object, _error: BaseException = error, **_k: object) -> object:
            raise _error

        monkeypatch.setattr(config.yaml, "load", explode)
        with pytest.raises(ValueError):
            parse_yaml(b"a: 1\n")


# --- file rules --------------------------------------------------------------------------------


def test_a_missing_default_file_means_defaults(fake_gateway: FakeGateway) -> None:
    assert load_default(fake_gateway) == {}


def test_a_default_file_under_a_regular_file_is_missing_too(fake_gateway: FakeGateway) -> None:
    (Path(home_of(fake_gateway)) / ".config").write_text("x")
    assert load_default(fake_gateway) == {}


def test_a_dangling_default_link_is_missing(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    default_file(fake_gateway).symlink_to(tmp_path / "nowhere")
    assert load_default(fake_gateway) == {}


def test_the_default_path_is_under_the_given_home(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 15\n")
    assert load_default(fake_gateway) == {"timeout": 15}


def test_a_trailing_slash_in_the_home_is_fine(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 15\n")
    assert load_config(fake_gateway, home=home_of(fake_gateway) + "///", config_path=None) == {
        "timeout": 15
    }


def test_the_home_environment_is_not_consulted(
    fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = tmp_path / "hostile"
    (hostile / ".config" / "slack-notice").mkdir(parents=True)
    (hostile / ".config" / "slack-notice" / "config.yaml").write_text("enabled: false\n")
    monkeypatch.setenv("HOME", str(hostile))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(hostile / ".config"))
    assert load_default(fake_gateway) == {}


def test_a_file_of_65536_bytes_is_accepted_and_one_more_is_not(fake_gateway: FakeGateway) -> None:
    path = default_file(fake_gateway)
    head = b"timeout: 15\n"
    path.write_bytes(head + b"#" * (65536 - len(head) - 1) + b"\n")
    assert path.stat().st_size == 65536
    assert load_default(fake_gateway) == {"timeout": 15}
    path.write_bytes(head + b"#" * (65536 - len(head)) + b"\n")
    assert invalid_key(fake_gateway) == str(path)


def test_a_file_is_read_through_the_gateway_with_the_cap(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 15\n")
    load_default(fake_gateway)
    assert "read_regular_file" in fake_gateway.events


def test_a_fifo_as_the_config_file_is_refused_without_a_hang(fake_gateway: FakeGateway) -> None:
    path = default_file(fake_gateway)
    os.mkfifo(path)
    assert invalid_key(fake_gateway) == str(path)


def test_a_fifo_as_a_drop_in_is_refused_without_a_hang(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 15\n")
    drop = default_file(fake_gateway).parent / "config.d"
    drop.mkdir()
    os.mkfifo(drop / "x.yaml")
    assert invalid_key(fake_gateway) == str(drop / "x.yaml")


def test_a_link_to_a_fifo_is_refused_without_a_hang(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    os.mkfifo(tmp_path / "fifo")
    default_file(fake_gateway).symlink_to(tmp_path / "fifo")
    assert invalid_key(fake_gateway) == str(default_file(fake_gateway))


@pytest.mark.parametrize("device", ["/dev/zero", "/dev/null", "/dev/urandom"])
def test_a_device_is_not_a_config_file(fake_gateway: FakeGateway, device: str) -> None:
    assert invalid_key(fake_gateway, device) == device


def test_a_directory_is_not_a_config_file(fake_gateway: FakeGateway) -> None:
    path = default_file(fake_gateway)
    path.mkdir()
    assert invalid_key(fake_gateway) == str(path)


def test_a_symlink_to_a_regular_file_is_followed(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    (tmp_path / "real.yaml").write_text("timeout: 20\n")
    default_file(fake_gateway).symlink_to(tmp_path / "real.yaml")
    assert load_default(fake_gateway) == {"timeout": 20}


def test_a_symlink_loop_is_config_invalid(fake_gateway: FakeGateway) -> None:
    path = default_file(fake_gateway)
    path.symlink_to(path)
    assert invalid_key(fake_gateway) == str(path)


@pytest.mark.skipif(os.getuid() == 0, reason="root reads everything")
def test_an_unreadable_file_is_config_invalid(fake_gateway: FakeGateway) -> None:
    path = write_default(fake_gateway, "timeout: 15\n")
    path.chmod(0)
    assert invalid_key(fake_gateway) == str(path)


@pytest.mark.parametrize("mode", [0o666, 0o644, 0o600, 0o400])
def test_the_file_mode_is_not_a_rule_of_the_loader(fake_gateway: FakeGateway, mode: int) -> None:
    # Interface, threat model: the config is trusted (same-user boundary); no mode or owner rule.
    write_default(fake_gateway, "timeout: 15\n").chmod(mode)
    assert load_default(fake_gateway) == {"timeout": 15}


def test_a_read_error_injected_at_the_gateway_is_config_invalid(fake_gateway: FakeGateway) -> None:
    path = write_default(fake_gateway, "timeout: 15\n")
    for error in (
        PermissionError(13, "denied " + SECRET),
        OSError(5, "io " + SECRET),
        MemoryError(),
        RecursionError(),
        ValueError(SECRET),
    ):
        fake_gateway.file_errors[str(path)] = error
        assert invalid_key(fake_gateway) == str(path)


def test_the_error_holds_no_cause_context_or_text(fake_gateway: FakeGateway) -> None:
    path = write_default(fake_gateway, f"a: [\nb: {SECRET}")
    with pytest.raises(ConfigInvalid) as raised:
        load_default(fake_gateway)
    error = raised.value
    assert error.__cause__ is None
    assert error.__context__ is None
    assert str(error) == "configuration is invalid"
    assert SECRET not in repr(error) + str(error.args)
    assert error.key == str(path)
    fake_gateway.file_errors[str(path)] = OSError(SECRET)
    with pytest.raises(ConfigInvalid) as raised:
        load_default(fake_gateway)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


# --- --config ----------------------------------------------------------------------------------


def test_a_missing_config_file_names_the_flag(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    assert invalid_key(fake_gateway, tmp_path / "nope.yaml") == "--config"


def test_an_empty_config_path_is_a_missing_file(fake_gateway: FakeGateway) -> None:
    assert invalid_key(fake_gateway, "") == "--config"


def test_a_dangling_link_as_config_is_a_missing_file(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    (tmp_path / "l.yaml").symlink_to(tmp_path / "nowhere")
    assert invalid_key(fake_gateway, tmp_path / "l.yaml") == "--config"


def test_a_config_path_under_a_regular_file_is_a_missing_file(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    (tmp_path / "f").write_text("x")
    assert invalid_key(fake_gateway, tmp_path / "f" / "c.yaml") == "--config"


def test_a_nul_in_the_config_path_is_an_unreadable_file(fake_gateway: FakeGateway) -> None:
    key = invalid_key(fake_gateway, "/a\0b")
    assert key == "/a\0b"


def test_config_replaces_the_default_file(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    write_default(fake_gateway, "timeout: 99\nlog: false\n")
    (tmp_path / "other.yaml").write_text("timeout: 15\n")
    assert load_at(fake_gateway, tmp_path / "other.yaml") == {"timeout": 15}


def test_config_does_not_need_the_home(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    (tmp_path / "c.yaml").write_text("timeout: 15\n")
    assert load_config(fake_gateway, home=None, config_path=str(tmp_path / "c.yaml")) == {
        "timeout": 15
    }
    assert fake_gateway.home_lookups == 0


def test_neither_home_nor_config_is_a_programming_error(fake_gateway: FakeGateway) -> None:
    with pytest.raises(ValueError):
        load_config(fake_gateway, home=None, config_path=None)


def test_a_relative_config_path_is_reported_as_an_absolute_path(
    fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "bad.yaml").write_text("a: [\n")
    assert invalid_key(fake_gateway, "bad.yaml") == str(tmp_path / "bad.yaml")


@pytest.mark.parametrize("name", ["home", "--config", "?", "x"])
def test_a_file_path_never_equals_a_reserved_sentinel(
    fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.chdir(tmp_path)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    (cwd / name).write_text("a: [\n")
    key = invalid_key(fake_gateway, name)
    assert key == f"{cwd}/{name}"
    assert key not in ("home", "--config")


def test_a_missing_relative_file_named_home_is_still_the_flag_sentinel(
    fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    assert invalid_key(fake_gateway, "home") == "--config"


def test_a_path_too_long_for_the_envelope_is_reported_as_unknown(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    long = str(tmp_path) + "/" + "d/" * 3000 + "x.yaml"
    assert len(long) > 4096
    assert invalid_key(fake_gateway, long) == "?"  # ENAMETOOLONG is unreadable, not missing


def test_config_example_loads_to_the_stated_defaults(fake_gateway: FakeGateway) -> None:
    assert load_at(fake_gateway, REPO / "config.example.yaml") == DEFAULTS


# --- drop-ins ----------------------------------------------------------------------------------


def dropins(gateway: FakeGateway, **files: str) -> Path:
    directory = default_file(gateway).parent / "config.d"
    directory.mkdir(exist_ok=True)
    for name, text in files.items():
        (directory / name.replace("__", ".")).write_text(text)
    return directory


def test_dropins_apply_in_lexical_order(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\nlog: false\n")
    directory = default_file(fake_gateway).parent / "config.d"
    directory.mkdir()
    (directory / "20-b.yaml").write_text("timeout: 20\n")
    (directory / "10-a.yaml").write_text("timeout: 10\nmax_chars: 2500\n")
    (directory / "30-c.yaml").write_text("max_chars: 3500\n")
    assert load_default(fake_gateway) == {"timeout": 20, "log": False, "max_chars": 3500}


def test_lexical_means_code_point_order(fake_gateway: FakeGateway) -> None:
    directory = default_file(fake_gateway).parent / "config.d"
    directory.mkdir()
    for name in ("b.yaml", "B.yaml", "a.yaml", "10.yaml", "9.yaml", "é.yaml", "Z.yaml"):
        (directory / name).write_text(f"order: [{name[:-5]!r}]\n".replace("'", '"'))
    assert load_default(fake_gateway) == {"order": ["é"]}  # the last in code point order wins
    assert sorted(["b", "B", "a", "10", "9", "é", "Z"]) == ["10", "9", "B", "Z", "a", "b", "é"]


def test_each_dropin_overrides_what_came_before(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    directory = default_file(fake_gateway).parent / "config.d"
    directory.mkdir()
    for name in ("a.yaml", "b.yaml", "c.yaml"):
        (directory / name).write_text(f"timeout: {ord(name[0]) - 90}\n")
    assert load_default(fake_gateway) == {"timeout": 9}


def test_a_dropin_without_the_main_file(fake_gateway: FakeGateway) -> None:
    dropins(fake_gateway, a__yaml="timeout: 15\n")
    assert load_default(fake_gateway) == {"timeout": 15}


def test_only_visible_yaml_files_are_dropins(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    directory = dropins(fake_gateway, ok__yaml="max_chars: 2500\n")
    for name in (
        ".hidden.yaml",
        "x.yml",
        "x.yaml.bak",
        "x.YAML",
        "README",
        "x.yaml~",
        "yaml",
        ".yaml",
    ):
        (directory / name).write_text("this: [is not read\n")
    assert load_default(fake_gateway) == {"timeout": 5, "max_chars": 2500}


def test_a_missing_dropin_directory_is_fine(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    assert load_default(fake_gateway) == {"timeout": 5}


def test_a_dropin_directory_that_is_a_file_is_fine(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    (default_file(fake_gateway).parent / "config.d").write_text("x")
    assert load_default(fake_gateway) == {"timeout": 5}


def test_an_unlistable_dropin_directory_names_the_directory(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    directory = str(default_file(fake_gateway).parent / "config.d")
    fake_gateway.directory_errors[directory] = PermissionError(13, "denied " + SECRET)
    assert invalid_key(fake_gateway) == directory


def test_a_directory_named_like_a_dropin_is_refused(fake_gateway: FakeGateway) -> None:
    directory = dropins(fake_gateway)
    (directory / "d.yaml").mkdir()
    assert invalid_key(fake_gateway) == str(directory / "d.yaml")


def test_a_dangling_dropin_link_is_refused(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    directory = dropins(fake_gateway)
    (directory / "d.yaml").symlink_to(tmp_path / "nowhere")
    assert invalid_key(fake_gateway) == str(directory / "d.yaml")


def test_a_dropin_link_to_a_file_is_followed(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    directory = dropins(fake_gateway)
    (tmp_path / "real").write_text("timeout: 33\n")
    (directory / "d.yaml").symlink_to(tmp_path / "real")
    assert load_default(fake_gateway) == {"timeout": 33}


def test_a_dropin_over_the_cap_names_the_dropin(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    directory = dropins(fake_gateway)
    (directory / "big.yaml").write_bytes(b"#" * 65537)
    assert invalid_key(fake_gateway) == str(directory / "big.yaml")


def test_a_parse_error_in_a_dropin_names_the_dropin(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    directory = dropins(fake_gateway, a__yaml="a: 1\n", b__yaml=f"a: [\n{SECRET}")
    assert invalid_key(fake_gateway) == str(directory / "b.yaml")


def test_a_duplicate_key_in_the_main_file_and_in_a_dropin(fake_gateway: FakeGateway) -> None:
    path = write_default(fake_gateway, "timeout: 5\ntimeout: 6\n")
    assert invalid_key(fake_gateway) == str(path)
    write_default(fake_gateway, "timeout: 5\n")
    directory = dropins(fake_gateway, a__yaml="log: true\nlog: false\n")
    assert invalid_key(fake_gateway) == str(directory / "a.yaml")


def test_the_same_key_in_different_files_is_not_a_duplicate(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    dropins(fake_gateway, a__yaml="timeout: 6\n")
    assert load_default(fake_gateway) == {"timeout": 6}


def test_a_dropin_that_is_not_a_mapping_is_refused(fake_gateway: FakeGateway) -> None:
    directory = dropins(fake_gateway, a__yaml="- x\n")
    assert invalid_key(fake_gateway) == str(directory / "a.yaml")


def test_an_empty_dropin_is_refused(fake_gateway: FakeGateway) -> None:
    directory = dropins(fake_gateway, a__yaml="")
    assert invalid_key(fake_gateway) == str(directory / "a.yaml")


def test_maps_merge_and_everything_else_is_replaced(fake_gateway: FakeGateway) -> None:
    write_default(
        fake_gateway,
        "level_prefix:\n  info: A\n  warn: B\nlist: [1, 2]\nscalar: 1\nmap: {a: 1}\nname: x\n",
    )
    dropins(
        fake_gateway,
        a__yaml="level_prefix:\n  warn: C\n  error: D\nlist: [3]\nscalar: {a: 1}\nmap: 2\n",
    )
    assert load_default(fake_gateway) == {
        "level_prefix": {"info": "A", "warn": "C", "error": "D"},
        "list": [3],
        "scalar": {"a": 1},
        "map": 2,
        "name": "x",
    }


def test_a_later_null_replaces_an_earlier_value(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "timeout: 5\n")
    dropins(fake_gateway, a__yaml="timeout:\n")
    assert load_default(fake_gateway) == {"timeout": None}


def test_merging_does_not_alias_the_files_data(fake_gateway: FakeGateway) -> None:
    write_default(fake_gateway, "level_prefix: {info: A}\n")
    first = load_default(fake_gateway)
    first["level_prefix"]["info"] = "changed"
    assert load_default(fake_gateway) == {"level_prefix": {"info": "A"}}


def test_a_merge_error_is_config_invalid(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_default(fake_gateway, "a: 1\n")
    for error in (RecursionError(), MemoryError()):

        def explode(*_a: object, _error: BaseException = error, **_k: object) -> object:
            raise _error

        monkeypatch.setattr(config, "_merge", explode)
        assert invalid_key(fake_gateway) == str(path)


def test_config_plus_dropins_in_its_directory(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    write_default(fake_gateway, "timeout: 99\n")
    dropins(fake_gateway, z__yaml="log: false\n")  # beside the default file: must not be read
    other = tmp_path / "other"
    (other / "config.d").mkdir(parents=True)
    (other / "my.yaml").write_text("timeout: 15\nmax_chars: 2500\n")
    (other / "config.d" / "a.yaml").write_text("max_chars: 4000\n")
    assert load_at(fake_gateway, other / "my.yaml") == {"timeout": 15, "max_chars": 4000}


def test_a_relative_config_path_reads_dropins_beside_it(
    fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "c.yaml").write_text("timeout: 15\n")
    (tmp_path / "config.d").mkdir()
    (tmp_path / "config.d" / "a.yaml").write_text("log: false\n")
    assert load_at(fake_gateway, "c.yaml") == {"timeout": 15, "log": False}
    sub = tmp_path / "sub"
    (sub / "config.d").mkdir(parents=True)
    (sub / "c.yaml").write_text("timeout: 17\n")
    (sub / "config.d" / "b.yaml").write_text("max_chars: 2500\n")
    assert load_at(fake_gateway, "sub/c.yaml") == {"timeout": 17, "max_chars": 2500}


def test_a_dropin_of_a_named_config_file_error_never_echoes_content(
    fake_gateway: FakeGateway,
) -> None:
    dropins(fake_gateway, a__yaml=f"key: [\n  {SECRET}\n")
    with pytest.raises(ConfigInvalid) as raised:
        load_default(fake_gateway)
    assert "FAKESECRET" not in str(raised.value) + repr(raised.value) + raised.value.key


# --- precedence --------------------------------------------------------------------------------


def test_defaults_are_the_documented_ones() -> None:
    assert DEFAULTS == {
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


def test_flags_beat_config_and_config_beats_defaults() -> None:
    got = resolve_settings({"timeout": "20s", "log": False}, {"timeout": "5s"})
    assert got["timeout"] == "5s"
    assert got["log"] is False
    assert got["max_chars"] == 3000


def test_a_flag_that_was_not_given_does_not_override() -> None:
    assert resolve_settings({"timeout": "20s"}, {"timeout": None})["timeout"] == "20s"


def test_nested_maps_merge_across_the_three_layers() -> None:
    got = resolve_settings({"level_prefix": {"info": "I"}}, {"level_prefix": {"warn": "W"}})
    assert got["level_prefix"] == {
        "info": "I",
        "warn": "W",
        "action": "🟡 ACTION",
        "error": "🔴 ERROR",
    }


def test_resolving_never_changes_its_inputs_or_the_defaults() -> None:
    before = json.dumps(DEFAULTS, sort_keys=True)
    config_values = {"level_prefix": {"info": "I"}}
    got = resolve_settings(config_values, {})
    got["level_prefix"]["info"] = "changed"
    got["level_prefix"]["warn"] = "changed"
    assert config_values == {"level_prefix": {"info": "I"}}
    assert json.dumps(DEFAULTS, sort_keys=True) == before


def test_no_environment_variable_overrides_a_setting(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_default(fake_gateway, "timeout: 15\n")
    for name, value in (
        ("SLACK_NOTICE_TIMEOUT", "99"),
        ("SLACK_NOTICE_ENABLED", "false"),
        ("SLACK_NOTICE_CONFIG", "/nonexistent"),
        ("SLACK_NOTICE_WEBHOOK_ENV", "OTHER"),
        ("TIMEOUT", "99"),
        ("SLACK_WEBHOOK", SECRET),
    ):
        monkeypatch.setenv(name, value)
    fake_gateway._environment.update({"SLACK_NOTICE_TIMEOUT": "99", "SLACK_NOTICE_LOG": "false"})
    got = resolve_settings(load_default(fake_gateway), {})
    assert got["timeout"] == 15
    assert got["enabled"] is True
    assert got["log"] is True
    assert got["webhook_env"] == "SLACK_WEBHOOK"


# --- through the CLI ---------------------------------------------------------------------------


def run(
    argv: list[str], gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> tuple[int, str, str, list[Context], list[dict[str, Any]]]:
    seen: list[Context] = []
    loaded: list[dict[str, Any]] = []

    def handler(ctx: Context) -> int:
        seen.append(ctx)
        loaded.append(cli.load_settings(ctx))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    out, err = io.BytesIO(), io.BytesIO()
    code = main(argv, {}, gateway, Streams(out=out, err=err, stdin_is_tty=lambda: False))
    return code, out.getvalue().decode(), err.getvalue().decode(), seen, loaded


def test_the_cli_loads_the_default_file_from_the_context_home(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_default(fake_gateway, "timeout: 15\n")
    code, _, _, _, loaded = run(["validate"], fake_gateway, monkeypatch)
    assert code == 0
    assert loaded[0]["timeout"] == 15
    assert loaded[0]["max_chars"] == 3000


def test_the_cli_loads_config_without_a_home(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "c.yaml").write_text("timeout: 15\n")
    code, _, _, seen, loaded = run(
        ["send", "--dry-run", "--config", str(tmp_path / "c.yaml")], fake_gateway, monkeypatch
    )
    assert (code, seen[0].home, loaded[0]["timeout"]) == (0, None, 15)
    assert fake_gateway.home_lookups == 0


@pytest.mark.parametrize("flag", [["--config", ""], ["--config="]])
def test_an_empty_config_flag_is_config_invalid_not_usage(
    flag: list[str], fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, err, _, _ = run(["validate", "--json", *flag], fake_gateway, monkeypatch)
    assert code == 2
    document = assert_valid("cli/error", out)
    assert document["error"]["code"] == "config_invalid"
    assert document["error"]["details"] == {"key": "--config"}
    assert err == "config_invalid: configuration is invalid\n"


def test_an_empty_config_flag_on_a_dry_run_is_config_invalid_too(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _, seen, _ = run(
        ["send", "--dry-run", "--json", "--config="], fake_gateway, monkeypatch
    )
    assert code == 2
    assert seen[0].home is None
    assert json.loads(out)["error"]["details"] == {"key": "--config"}


def test_a_missing_config_file_through_the_cli(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, out, err, _, _ = run(
        ["validate", "--json", f"--config={tmp_path}/missing.yaml"], fake_gateway, monkeypatch
    )
    assert code == 2
    document = assert_valid("cli/error", out)
    assert document["error"]["details"] == {"key": "--config"}
    assert str(tmp_path) not in out + err


def test_a_broken_file_through_the_cli_names_the_path_and_nothing_else(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_default(fake_gateway, f'webhook_env: "{SECRET}\nother: [\n')
    code, out, err, _, _ = run(["validate", "--json"], fake_gateway, monkeypatch)
    assert code == 2
    document = assert_valid("cli/error", out)
    assert document["error"] == {
        "code": "config_invalid",
        "message": "configuration is invalid",
        "reason": None,
        "details": {"key": str(path)},
        "retryable": None,
        "retry_after_s": None,
        "unknown_outcome": None,
    }
    assert err == "config_invalid: configuration is invalid\n"
    for text in (out, err):
        assert "FAKESECRET" not in text
        assert "hooks.slack.com" not in text


@pytest.mark.parametrize(
    "content",
    [
        f"a: [\n{SECRET}\n",
        f'a: "{SECRET}\n',
        f"a: 1\na: {SECRET}\n",
        f"a: &x {SECRET}\nb: *x\n",
        f"a: !!python/object:os.system {SECRET}\n",
        f"{SECRET}\n",
        f"- {SECRET}\n",
        f"a: {SECRET}\n---\nb: {SECRET}\n",
        f"{SECRET}: [\n",
        f"a:\t{SECRET}\n\tb: 1\n",
        f"a: {SECRET}\x00\n",
    ],
)
def test_a_yaml_error_that_would_quote_a_secret_never_reaches_any_output(
    content: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_default(fake_gateway, content)
    code, out, err, _, _ = run(["validate", "--json", "--verbose"], fake_gateway, monkeypatch)
    assert code == 2
    for text in (out, err):
        assert "FAKESECRET" not in text
        assert "hooks.slack.com" not in text
    assert json.loads(out)["error"]["code"] == "config_invalid"


def test_a_cyclic_anchor_and_deep_nesting_through_the_cli(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    for content in ("a: &a [*a]\n", "k: " + "[" * 1000, "&a [*a]"):
        write_default(fake_gateway, content)
        with no_hang():
            code, out, _, _, _ = run(["validate", "--json"], fake_gateway, monkeypatch)
        assert code == 2
        assert json.loads(out)["error"]["code"] == "config_invalid"


def test_load_settings_wraps_the_error_class_only(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_default(fake_gateway, "a: [\n")
    raised: list[CliError] = []

    def handler(ctx: Context) -> int:
        try:
            cli.load_settings(ctx)
        except CliError as error:
            raised.append(error)
            raise
        return 0

    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    main(
        ["validate"],
        {},
        fake_gateway,
        Streams(out=io.BytesIO(), err=io.BytesIO(), stdin_is_tty=lambda: False),
    )
    assert raised[0].exit_code == 2
    assert raised[0].__cause__ is None
    assert raised[0].__context__ is None


def test_the_environment_given_to_the_cli_does_not_override_the_config(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_default(fake_gateway, "timeout: 15\nenabled: true\n")
    seen: list[dict[str, Any]] = []

    def handler(ctx: Context) -> int:
        seen.append(cli.load_settings(ctx))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    env = {"SLACK_NOTICE_TIMEOUT": "99", "SLACK_NOTICE_ENABLED": "false", "SLACK_WEBHOOK": SECRET}
    out = io.BytesIO()
    main(
        ["validate"],
        env,
        fake_gateway,
        Streams(out=out, err=io.BytesIO(), stdin_is_tty=lambda: False),
    )
    assert seen[0]["timeout"] == 15
    assert seen[0]["enabled"] is True


# --- speed -------------------------------------------------------------------------------------


def test_hostile_files_finish_fast(fake_gateway: FakeGateway) -> None:
    started = time.monotonic()
    for content in (
        "[" * 65000,
        "a: " + "[" * 60000,
        "{a: " * 15000,
        "- " * 30000,
        "a: &a [" + ",".join(["*a"] * 5000) + "]",
        "? " * 30000,
        "\n" * 65000,
        "a: " + "'" * 60001,
        "x: " + "9" * 60000,
    ):
        write_default(fake_gateway, content)
        invalid_key(fake_gateway)
    assert time.monotonic() - started < 10

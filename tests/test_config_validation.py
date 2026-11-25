"""Config value validation (issue #11): types, ranges, names, prefixes, unknown keys, messages."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, config
from slack_notice.cli import CliError, Context, Streams, main
from slack_notice.config import ConfigInvalid, config_file_key, validate_config
from slack_notice.sanitizer import is_removed
from tests.fake_gateway import FakeGateway
from tests.harness import schema_errors

# Recognizable fake leak marker, assembled from parts so it is not a credential-shaped literal.
CANARY = "/".join(["https:", "", "hooks.slack.com", "triggers", "T0FAKE", "0000", "FAKE" + "TOKEN"])
SAMPLES = Path(__file__).parent / "samples" / "config.json"


def refused(values: dict[Any, Any]) -> ConfigInvalid:
    with pytest.raises(ConfigInvalid) as raised:
        validate_config(values)
    return raised.value


def key_of(values: dict[Any, Any]) -> str:
    return refused(values).key


# --- defaults and accepted values --------------------------------------------------------------


def test_the_empty_config_gives_the_defaults_with_a_numeric_timeout() -> None:
    got = validate_config({})
    assert got["enabled"] is True
    assert got["webhook_env"] == "SLACK_WEBHOOK"
    assert got["body_variable"] == "body"
    assert got["level_prefix"] == config.DEFAULTS["level_prefix"]
    assert got["max_chars"] == 3000
    assert got["timeout"] == 10.0
    assert isinstance(got["timeout"], float)
    assert got["log"] is True


def test_validation_does_not_change_its_input() -> None:
    values: dict[str, Any] = {"timeout": "1m", "level_prefix": {"info": "I"}}
    validate_config(values)
    assert values == {"timeout": "1m", "level_prefix": {"info": "I"}}


def test_a_partial_level_prefix_keeps_the_other_defaults() -> None:
    got = validate_config({"level_prefix": {"info": "I"}})
    assert got["level_prefix"]["info"] == "I"
    assert got["level_prefix"]["warn"] == config.DEFAULTS["level_prefix"]["warn"]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("enabled", False),
        ("log", False),
        ("webhook_env", "A"),
        ("webhook_env", "_" + "a" * 127),
        ("body_variable", "_" + "b" * 63),
        ("max_chars", 2000),
        ("max_chars", 12000),
        ("timeout", 3),
        ("timeout", 120),
        ("timeout", 1.5 + 1.5),
        ("timeout", "3s"),
        ("timeout", "2m"),
        ("timeout", "3000ms"),
        ("timeout", "010"),  # quoted: a string on purpose, ten seconds (issue #11 decision)
    ],
)
def test_accepted_values(key: str, value: Any) -> None:
    assert validate_config({key: value})[key] is not None


def test_a_quoted_leading_zero_timeout_is_ten_seconds() -> None:
    assert validate_config({"timeout": "010"})["timeout"] == 10.0


def test_sixteen_one_code_point_emoji_are_a_valid_prefix() -> None:
    prefix = "\U0001f535" * 16
    assert validate_config({"level_prefix": {"info": prefix}})["level_prefix"]["info"] == prefix


# --- unknown keys ------------------------------------------------------------------------------


def test_an_unknown_key_is_refused_by_name() -> None:
    assert key_of({"nope": 1}) == "nope"


def test_an_unknown_key_of_5000_characters_is_a_question_mark() -> None:
    assert key_of({"k" * 5000: 1}) == "?"


@pytest.mark.parametrize(
    "name", ["a-b", "with space", "\u00fcn\u00ef", "x\n", "a" * 65, "", "k\x00", "<<"]
)
def test_an_unknown_key_that_is_not_a_key_name_is_a_question_mark(name: str) -> None:
    assert key_of({name: 1}) == "?"


def test_a_64_character_unknown_key_is_named() -> None:
    assert key_of({"a" * 64: 1}) == "a" * 64


@pytest.mark.parametrize("name", ["home", "--config"])
def test_an_unknown_key_never_equals_a_reserved_sentinel(name: str) -> None:
    assert key_of({name: 1}) == "?"


def test_a_literal_merge_key_is_an_ordinary_unknown_key() -> None:
    assert key_of({"<<": {"enabled": True}}) == "?"


def test_an_unknown_key_is_refused_before_its_value_is_examined() -> None:
    class Boom:
        def __getattribute__(self, name: str) -> Any:
            raise AssertionError("examined")

        def __eq__(self, other: object) -> bool:
            raise AssertionError("examined")

        __hash__ = None  # type: ignore[assignment]

    # an unknown key with a value that explodes when touched, next to an invalid known value
    assert key_of({"zzz": Boom(), "enabled": "no"}) == "zzz"


def test_an_unknown_key_wins_over_an_invalid_known_value() -> None:
    assert key_of({"enabled": "no", "zzz": 1}) == "zzz"


def test_an_unknown_level_prefix_level_is_refused_under_level_prefix() -> None:
    assert key_of({"level_prefix": {"debug": "D"}}) == "level_prefix"


def test_a_non_string_key_is_refused_as_a_question_mark() -> None:
    assert key_of({1: "x"}) == "?"


# --- null, empty and wrong types ---------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["enabled", "webhook_env", "body_variable", "level_prefix", "max_chars", "timeout", "log"],
)
@pytest.mark.parametrize("value", [None, "", [], {}, [1], 0, -1, 1.5, True, "no", b"x", {"a": 1}])
def test_a_hostile_value_is_refused_naming_the_key_or_accepted_only_when_right(
    key: str, value: Any
) -> None:
    ok = {
        "enabled": lambda v: v is True or v is False,
        "log": lambda v: v is True or v is False,
        "level_prefix": lambda v: v == {},
        "webhook_env": lambda v: v == "no",
        "body_variable": lambda v: v == "no",
        "max_chars": lambda v: False,
        "timeout": lambda v: False,
    }[key](value)
    if ok:
        validate_config({key: value})
    else:
        assert key_of({key: value}) == key


@pytest.mark.parametrize(
    "value", ["no", "yes", "off", "on", "True", "false", 1, 0, None, "", [True]]
)
@pytest.mark.parametrize("key", ["enabled", "log"])
def test_booleans_are_only_true_and_false(key: str, value: Any) -> None:
    assert key_of({key: value}) == key


@pytest.mark.parametrize(
    "value", [True, False, 3000.0, 2500.5, "3000", None, 1999, 12001, 10**30, -(10**30), 0, [3000]]
)
def test_max_chars_is_a_strict_integer_in_range(value: Any) -> None:
    assert key_of({"max_chars": value}) == "max_chars"


@pytest.mark.parametrize("value", [1999, 12001, 0, -5, 10**40])
def test_max_chars_out_of_range_says_the_range(value: int) -> None:
    assert "2000 to 12000" in refused({"max_chars": value}).rule


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        None,
        0,
        -1,
        2.999,
        120.001,
        10**30,
        float("nan"),
        float("inf"),
        "",
        "0",
        "0s",
        "2s",
        "121",
        "2m1s",
        "1h",
        "1e3",
        "-5",
        "+5",
        " 5",
        "5 ",
        "5\n",
        "5s\n",
        "\u0665",
        "\uff15s",
        "5S",
        "1_0",
        "x" * 300,
        "9" * 5000,
        [10],
        {"a": 1},
        "3 s",
        "0.0",
        ".5",
        "5.",
    ],
)
def test_timeout_outside_the_grammar_or_range_is_refused(value: Any) -> None:
    error = refused({"timeout": value})
    assert error.key == "timeout"
    assert "3s to 120s" in error.rule


def test_timeout_errors_come_from_the_duration_error_without_the_value() -> None:
    error = refused({"timeout": "7" * 40 + "s"})
    assert "7777" not in error.rule
    assert error.key == "timeout"


# --- names -------------------------------------------------------------------------------------


NAME_HOSTILE = [
    "",
    "1ABC",
    "a-b",
    "a b",
    "a.b",
    "SLACK_WEBHOOK\n",
    "\nSLACK_WEBHOOK",
    "A\x00B",
    "\x00",
    "A\u202eB",
    "\u200bA",
    "\uff21\uff22\uff23",  # fullwidth letters
    "\u00e9",
    "\u0663abc",  # arabic-indic digit start
    "a\u0663",  # arabic-indic digit inside
    "a" * 129,
    "a" * 5000,
    "https://hooks.example.test/triggers/x",
    CANARY,
    "\U0001f535",
]


@pytest.mark.parametrize("key", ["webhook_env", "body_variable"])
@pytest.mark.parametrize("value", NAME_HOSTILE)
def test_a_bad_name_is_refused(key: str, value: str) -> None:
    error = refused({key: value})
    assert error.key == key
    assert error.rule == "must be a variable name"


def test_body_variable_longer_than_64_is_refused_and_webhook_env_up_to_128_is_not() -> None:
    assert key_of({"body_variable": "b" * 65}) == "body_variable"
    assert validate_config({"webhook_env": "w" * 128})["webhook_env"] == "w" * 128
    assert key_of({"webhook_env": "w" * 129}) == "webhook_env"


def test_a_url_shaped_webhook_env_says_it_must_be_a_variable_name() -> None:
    assert refused({"webhook_env": CANARY}).rule == "must be a variable name"


# --- level_prefix ------------------------------------------------------------------------------


PREFIX_REFUSED = [
    "A\nB",
    "INFO  x",  # two spaces
    "",
    "x" * 17,
    "\U0001f535" * 17,
    " INFO",
    "INFO ",
    "\u00a0INFO",
    "INFO\u00a0",
    "A\tB",
    "A\rB",
    "A\x00B",
    "A\x7fB",
    "A\x85B",
    "A\u2028B",
    "A\u2029B",
    "A\u202eB",  # bidi override
    "A\u2066B",
    "A\u200bB",
    "A\u00adB",
    "\ufeffA",
    "A\u2800",
    "A\u3164B",
    "A\U000e0041B",
    "A\ue000B",  # private use
    "A\ufffeB",
    "A\U0010ffffB",
    "A\u0378B",  # unassigned
    "A\ud800B",  # lone surrogate
    "A\x0bB",
    "A\x0cB",
    "INFO\n",
]


@pytest.mark.parametrize("value", PREFIX_REFUSED)
def test_a_prefix_the_title_rule_would_change_is_refused(value: str) -> None:
    for level in ("info", "warn", "action", "error"):
        error = refused({"level_prefix": {level: value}})
        assert error.key == "level_prefix"
        assert error.message.startswith("level_prefix.")


@pytest.mark.parametrize(
    "value",
    [
        "A",
        "INFO x",
        "a b",
        "🔵 INFO",
        "\u00e9",
        "e\u0301",
        "A\u200dB",
        "A\ufe0f",
        "日本語",
        "x" * 16,
        "\u0600A",
        "A\u200cB",
        "[!]",
        "<b>",
        "a\\nb",
    ],
)
def test_a_prefix_the_title_rule_leaves_unchanged_is_accepted(value: str) -> None:
    assert validate_config({"level_prefix": {"info": value}})["level_prefix"]["info"] == value


@pytest.mark.parametrize("value", [None, 5, True, [], {}, 1.5, b"x", ["A"]])
def test_a_prefix_must_be_a_string(value: Any) -> None:
    assert key_of({"level_prefix": {"info": value}}) == "level_prefix"


def test_a_prefix_of_5000_characters_is_refused_quickly() -> None:
    assert key_of({"level_prefix": {"error": "x" * 5000}}) == "level_prefix"


def test_level_prefix_must_be_a_map() -> None:
    for value in ("INFO", ["info"], 1, True):
        assert key_of({"level_prefix": value}) == "level_prefix"


def test_prefix_messages_name_the_level_and_never_the_value() -> None:
    error = refused({"level_prefix": {"warn": "A\nB" + CANARY}})
    assert error.message.startswith("level_prefix.warn ")
    assert CANARY not in error.message
    assert "A" not in error.message.replace("level_prefix.warn", "")


# --- messages and key naming never leak ---------------------------------------------------------


@pytest.mark.parametrize(
    "values",
    [
        {"webhook_env": CANARY},
        {"body_variable": CANARY},
        {"enabled": CANARY},
        {"log": CANARY},
        {"max_chars": CANARY},
        {"timeout": CANARY},
        {"level_prefix": CANARY},
        {"level_prefix": {"info": CANARY}},
        {"level_prefix": {CANARY: "x"}},
        {CANARY: 1},
        {"timeout": [CANARY]},
        {"max_chars": {CANARY: CANARY}},
    ],
)
def test_nothing_of_the_input_reaches_the_message_key_or_chain(values: dict[str, Any]) -> None:
    error = refused(values)
    assert CANARY not in str(error)
    assert CANARY not in error.rule
    assert CANARY not in error.message
    assert CANARY not in error.key
    assert CANARY not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.key == "?" or error.key in config.DEFAULTS


def test_the_string_form_is_the_fixed_message() -> None:
    assert str(refused({"enabled": "no"})) == "configuration is invalid"


def test_a_failure_while_validating_is_config_invalid_not_an_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RecursionError

    monkeypatch.setattr(config._Settings, "model_validate", boom)
    error = refused({})
    assert error.key == "?"
    assert str(error) == "configuration is invalid"
    assert error.message == ""


# --- schema agreement --------------------------------------------------------------------------


def _samples() -> dict[str, Any]:
    return json.loads(SAMPLES.read_text(encoding="utf-8"))


@pytest.mark.parametrize("label", list(_samples()["valid"]))
def test_every_schema_valid_sample_is_accepted_by_the_code(label: str) -> None:
    instance = _samples()["valid"][label]
    assert schema_errors("config", instance) == []
    validate_config(instance)


@pytest.mark.parametrize("label", list(_samples()["invalid"]))
def test_every_schema_invalid_sample_is_refused_by_the_code_under_the_same_key(
    label: str,
) -> None:
    sample = _samples()["invalid"][label]
    instance = sample["instance"]
    top = sample["path"][0] if sample["path"] else None
    expected = top if isinstance(top, str) and top in config.DEFAULTS else None
    key = key_of(instance)
    if expected is not None:
        assert key == expected
    else:  # the unknown_key sample: the schema reports the object, the code names the key
        assert key == "webhook_url"


def test_the_code_is_never_wider_than_the_schema_for_a_table_of_values() -> None:
    """Whatever the code accepts, the schema must too (the schema is the coarse gate)."""
    candidates: list[dict[str, Any]] = []
    for value in [
        True,
        False,
        0,
        3,
        3.0,
        12000,
        2000,
        "3s",
        "120",
        "0.5m",
        "010",
        "1m",
        "no",
        None,
    ]:
        for key in ("enabled", "log", "max_chars", "timeout", "webhook_env", "body_variable"):
            candidates.append({key: value})
    for value in NAME_HOSTILE + ["A", "a_1"]:
        for key in ("webhook_env", "body_variable"):
            candidates.append({key: value})
    for value in PREFIX_REFUSED + ["A", "🔵 INFO"]:
        candidates.append({"level_prefix": {"info": value}})
    for instance in candidates:
        try:
            validate_config(instance)
        except ConfigInvalid:
            continue
        assert schema_errors("config", instance) == [], instance


def test_the_defaults_validate_against_the_schema() -> None:
    assert schema_errors("config", {k: v for k, v in config.DEFAULTS.items()}) == []


# --- through the CLI ---------------------------------------------------------------------------


def run(text: str, gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> tuple[int, str, str]:
    path = Path(gateway.home_dir()) / ".config" / "slack-notice" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    loaded: list[dict[str, Any]] = []

    def handler(ctx: Context) -> int:
        loaded.append(cli.load_settings(ctx))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    out, err = io.BytesIO(), io.BytesIO()
    code = main(
        ["validate", "--json"], {}, gateway, Streams(out=out, err=err, stdin_is_tty=lambda: False)
    )
    return code, out.getvalue().decode(), err.getvalue().decode()


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("enabled: no\n", "enabled"),
        ("enabled: off\n", "enabled"),
        ("enabled: yes\n", "enabled"),
        ("timeout:\n", "timeout"),
        ("timeout: ~\n", "timeout"),
        ("timeout: 2\n", "timeout"),
        ("timeout: 121\n", "timeout"),
        ('timeout: "1h"\n', "timeout"),
        ("max_chars: 1999\n", "max_chars"),
        ("webhook_env:\n", "webhook_env"),
        ('webhook_env: "A\\x00B"\n', "webhook_env"),
        ('body_variable: "a\\u202eb"\n', "body_variable"),
        ('level_prefix: {info: "a\\u202eb"}\n', "level_prefix"),
        ('level_prefix: {info: "A\\nB"}\n', "level_prefix"),
        ('level_prefix: {info: "INFO  x"}\n', "level_prefix"),
        ("level_prefix:\n", "level_prefix"),
        ("<<: {enabled: true}\n", "?"),
        ("nope: 1\n", "nope"),
        ("home: 1\n", "?"),
    ],
)
def test_the_cli_maps_a_bad_value_to_exit_2_config_invalid_with_the_key(
    text: str, key: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, err = run(text, fake_gateway, monkeypatch)
    assert code == 2
    error = json.loads(out)["error"]
    assert error["code"] == "config_invalid"
    assert error["message"].startswith(key)  # the key path, then the rule
    assert error["message"] != "configuration is invalid"
    assert error["details"] == {"key": key}
    assert error["retryable"] is None
    assert error["message"] in err


def test_a_value_in_a_dropin_that_breaks_a_rule_is_refused(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    drop = Path(fake_gateway.home_dir()) / ".config" / "slack-notice" / "config.d"
    drop.mkdir(parents=True)
    (drop / "a.yaml").write_text("log: 1\n", encoding="utf-8")
    code, out, _ = run("enabled: true\n", fake_gateway, monkeypatch)
    assert code == 2
    assert json.loads(out)["error"]["details"] == {"key": "log"}


def test_the_cli_refusal_carries_no_chain_and_no_value(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, err = run(f"webhook_env: '{CANARY}'\n", fake_gateway, monkeypatch)
    assert code == 2
    assert CANARY not in out + err
    assert json.loads(out)["error"]["details"] == {"key": "webhook_env"}


def test_load_settings_returns_validated_settings(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []
    path = Path(fake_gateway.home_dir()) / ".config" / "slack-notice" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("timeout: 1m\nenabled: false\n", encoding="utf-8")

    def handler(ctx: Context) -> int:
        seen.append(cli.load_settings(ctx))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    main(
        ["validate"],
        {},
        fake_gateway,
        Streams(out=io.BytesIO(), err=io.BytesIO(), stdin_is_tty=lambda: False),
    )
    assert seen[0]["timeout"] == 60.0
    assert seen[0]["enabled"] is False


def test_load_settings_error_has_no_chain(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = Path(fake_gateway.home_dir()) / ".config" / "slack-notice" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("enabled: no\n", encoding="utf-8")
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
    assert raised[0].__cause__ is None
    assert raised[0].__context__ is None


# --- the failure path of the conversion (no pydantic error stays reachable) ----------------------


def test_a_failure_of_the_error_conversion_is_the_fallback_key_with_no_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(_error: Any) -> Any:
        raise MemoryError

    monkeypatch.setattr(config, "_failure_of", boom)
    with pytest.raises(ConfigInvalid) as raised:
        validate_config({"enabled": CANARY}, fallback_key="/x")
    assert raised.value.key == "/x"
    assert raised.value.message == ""
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert CANARY not in repr(raised.value.message)


def test_a_machinery_failure_uses_the_fallback_key(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RecursionError

    monkeypatch.setattr(config._Settings, "model_validate", boom)
    with pytest.raises(ConfigInvalid) as raised:
        validate_config({}, fallback_key="/x")
    assert raised.value.key == "/x"
    assert raised.value.message == ""
    assert raised.value.__context__ is None


# --- the first invalid known key is the first in table order -------------------------------------


def test_the_first_invalid_known_key_in_table_order_is_named() -> None:
    values = {
        "log": 1,
        "timeout": "1h",
        "max_chars": 1,
        "level_prefix": {"info": "A\nB"},
        "body_variable": "a b",
        "webhook_env": "a b",
        "enabled": "no",
    }
    order = [
        "enabled",
        "webhook_env",
        "body_variable",
        "level_prefix",
        "max_chars",
        "timeout",
        "log",
    ]
    remaining = dict(reversed(list(values.items())))
    for expected in order:
        assert key_of(remaining) == expected
        del remaining[expected]


def test_level_prefix_comes_before_max_chars_in_table_order() -> None:
    assert key_of({"max_chars": 1, "level_prefix": {"info": ""}}) == "level_prefix"


# --- a nested unknown key -----------------------------------------------------------------------


def test_a_nested_unknown_key_says_it_is_not_a_level() -> None:
    error = refused({"level_prefix": {"fatal": "x"}})
    assert error.key == "level_prefix"
    assert error.rule == "has a key that is not a level (info, warn, action, error)"
    assert error.message == "level_prefix has a key that is not a level (info, warn, action, error)"


# --- empty prefixes -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["\u200c", "\u200d", "\u0301", "\ufe0f", "\u200c\u200d", "\u0301\ufe0f", "\u0903", "\u20dd"],
)
def test_a_prefix_that_is_empty_by_definition_is_refused(value: str) -> None:
    error = refused({"level_prefix": {"warn": value}})
    assert error.key == "level_prefix"
    assert error.message.startswith("level_prefix.warn ")
    assert error.rule == config._RULES["prefix"]


@pytest.mark.parametrize("value", [" ", "\u3000", "\u2003", "\u00a0", "\u2000\u0301"])
def test_a_whitespace_only_prefix_is_refused(value: str) -> None:
    assert key_of({"level_prefix": {"info": value}}) == "level_prefix"


@pytest.mark.parametrize("value", ["A", "\U0001f535 INFO", "x\u0301", "\u200cA"])
def test_a_prefix_with_a_visible_character_is_accepted(value: str) -> None:
    assert validate_config({"level_prefix": {"info": value}})["level_prefix"]["info"] == value


# --- the removal table, typed from interface.md (not from the code's table) ----------------------

INTERFACE_REMOVED = [
    0x00AD, 0x061C, 0x180E, 0x200B, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2061, 0x206E, 0x206F, 0xFEFF, 0xFFF9, 0xFFFA, 0xFFFB, 0xE0000, 0xE0001, 0xE007F,
    0xE0100, 0xE01EF, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x180B, 0x180C, 0x180D, 0x180F,
]  # fmt: skip
INTERFACE_KEPT = [
    0xFE00, 0xFE01, 0xFE0F, 0x200C, 0x200D, 0x0600, 0x0601, 0x0605, 0x06DD, 0x070F, 0x08E2,
]  # fmt: skip


@pytest.mark.parametrize("code", INTERFACE_REMOVED)
def test_every_removed_character_of_the_interface_list_makes_a_prefix_invalid(code: int) -> None:
    assert key_of({"level_prefix": {"info": f"a{chr(code)}b"}}) == "level_prefix"
    assert is_removed(chr(code))


@pytest.mark.parametrize("code", INTERFACE_KEPT)
def test_every_kept_character_of_the_interface_list_is_accepted_in_visible_text(code: int) -> None:
    text = f"a{chr(code)}b"
    assert validate_config({"level_prefix": {"info": text}})["level_prefix"]["info"] == text
    assert not is_removed(chr(code))


@pytest.mark.parametrize("code", [0x2FFC, 0x2FFF, 0x31EF, 0x2EBF0, 0x2EE5D])
def test_characters_assigned_after_unicode_15_0_are_refused_in_a_prefix(code: int) -> None:
    assert key_of({"level_prefix": {"info": f"a{chr(code)}"}}) == "level_prefix"


# --- fallback key through the CLI ----------------------------------------------------------------


def _recursion(*_a: Any, **_k: Any) -> Any:
    raise RecursionError


def _settings_key(
    argv: list[str], gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    monkeypatch.setattr(config._Settings, "model_validate", _recursion)
    caught: list[CliError] = []

    def handler(ctx: Context) -> int:
        try:
            cli.load_settings(ctx)
        except CliError as error:
            caught.append(error)
            raise
        return 0

    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    out, err = io.BytesIO(), io.BytesIO()
    assert main(argv, {}, gateway, Streams(out=out, err=err, stdin_is_tty=lambda: False)) == 2
    assert caught[0].__context__ is None
    return json.loads(out.getvalue().decode())["error"]


def test_a_machinery_failure_names_the_default_config_file(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = str(Path(fake_gateway.home_dir()) / ".config" / "slack-notice" / "config.yaml")
    error = _settings_key(["validate", "--json"], fake_gateway, monkeypatch)
    assert error["details"] == {"key": expected}
    assert error["message"] == "configuration is invalid"


def test_a_machinery_failure_names_an_absolute_config_flag(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("enabled: true\n", encoding="utf-8")
    error = _settings_key(["validate", "--json", f"--config={path}"], fake_gateway, monkeypatch)
    assert error["details"] == {"key": str(path)}


def test_a_machinery_failure_names_a_relative_config_flag_made_absolute(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "c.yaml").write_text("enabled: true\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    error = _settings_key(["validate", "--json", "--config=c.yaml"], fake_gateway, monkeypatch)
    assert error["details"] == {"key": str(tmp_path / "c.yaml")}


def test_config_file_key_cases(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    default = "/h/.config/slack-notice/config.yaml"
    assert config_file_key(fake_gateway, home="/h", config_path=None) == default
    assert config_file_key(fake_gateway, home=None, config_path=None) == "?"
    assert config_file_key(fake_gateway, home="/h", config_path="/a/b.yaml") == "/a/b.yaml"
    assert config_file_key(fake_gateway, home=None, config_path="/a/b.yaml") == "/a/b.yaml"
    assert config_file_key(fake_gateway, home="/h", config_path="x" * 5000) == "?"


# --- the message through the CLI: key and rule, never the value ----------------------------------


@pytest.mark.parametrize(
    ("text", "key", "rule"),
    [
        (f"enabled: '{CANARY}'\n", "enabled", "must be true or false"),
        (f"webhook_env: '{CANARY}'\n", "webhook_env", "must be a variable name"),
        (f"max_chars: '{CANARY}'\n", "max_chars", "must be an integer from 2000 to 12000"),
        (f"timeout: '{CANARY}'\n", "timeout", "must be a duration from 3s to 120s"),
        (f"level_prefix: '{CANARY}'\n", "level_prefix", "must be a mapping"),
        (f"level_prefix: {{info: '{CANARY}'}}\n", "level_prefix.info", config._RULES["prefix"]),
        (f"'{CANARY}': 1\n", "?", "is not a known key"),
        (f"nope: '{CANARY}'\n", "nope", "is not a known key"),
        (f"level_prefix: {{'{CANARY}': x}}\n", "level_prefix", config._UNKNOWN_LEVEL_RULE),
    ],
)
def test_the_cli_message_holds_the_key_and_the_rule_and_never_the_value(
    text: str, key: str, rule: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, err = run(text, fake_gateway, monkeypatch)
    assert code == 2
    error = json.loads(out)["error"]
    assert error["message"] == f"{key} {rule}"
    assert error["details"]["key"] == key.split(".")[0]
    assert CANARY not in out + err
    assert "FAKETOKEN" not in out + err
    assert "hooks.slack.com" not in out + err


def test_a_file_level_failure_keeps_the_fixed_message(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _ = run("a: [\n", fake_gateway, monkeypatch)
    assert code == 2
    assert json.loads(out)["error"]["message"] == "configuration is invalid"


def test_the_prefix_rule_text_says_it_must_not_be_empty() -> None:
    assert config._RULES["prefix"].endswith("leaves unchanged and that is not empty")

"""config.example.yaml (issue #12): loads, validates, matches the documented keys and defaults.

The file is read through the project's strict loader (never plain ``yaml.safe_load``) and checked
against ``schemas/config.json`` and ``validate_config``. The schema is only a coarse gate for
``level_prefix`` (the sanitizer-based rules live in the loader), so both checks run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from slack_notice.config import (
    DEFAULTS,
    ConfigInvalid,
    YamlRefused,
    load_config,
    parse_yaml,
    validate_config,
)
from tests.fake_gateway import FakeGateway
from tests.harness import ROOT, load_schema, schema_errors

EXAMPLE = ROOT / "config.example.yaml"
INTERFACE = ROOT / "docs" / "interface.md"
SAMPLES_KEYS = ("valid", "invalid")


def example_values() -> dict[str, Any]:
    return parse_yaml(EXAMPLE.read_bytes())


def parse_documented_keys(text: str) -> list[str]:
    """First column of the Config table in interface.md text (rows like ``| `key` | ...``).

    Fails with a clear message (never a bare IndexError) when the doc has drifted.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    parts = re.split(r"^## Config[ \t]*$", text, maxsplit=1, flags=re.MULTILINE)
    assert len(parts) == 2, "interface.md has no '## Config' heading"
    section = re.split(r"^## ", parts[1], maxsplit=1, flags=re.MULTILINE)[0]
    header = re.search(r"^\s*\|\s*Key\s*\|\s*Default\s*\|", section, flags=re.MULTILINE)
    assert header, "the Config section has no '| Key | Default |' table header"
    keys = re.findall(
        r"^\s*\|\s*`([A-Za-z0-9_]+)`\s*\|", section[header.end() :], flags=re.MULTILINE
    )
    assert keys, "the Config table has no rows with a backticked key in the first column"
    assert len(keys) == len(DEFAULTS), (
        f"the Config table has {len(keys)} rows but DEFAULTS has {len(DEFAULTS)} keys"
    )
    return keys


def documented_keys() -> list[str]:
    return parse_documented_keys(INTERFACE.read_text(encoding="utf-8"))


# --- the example through the strict loader, the schema and the validator -----------------------


def test_the_example_loads_through_the_strict_loader(fake_gateway: FakeGateway) -> None:
    loaded = load_config(fake_gateway, home=None, config_path=str(EXAMPLE))
    assert loaded == example_values()
    assert loaded == DEFAULTS  # a changed value in the example fails here, not only a changed key


def test_the_example_validates_against_the_config_schema() -> None:
    errors = schema_errors("config", example_values())
    assert [f"{list(e.absolute_path)}: {e.message}" for e in errors] == []


def test_the_example_passes_validate_config_including_the_prefix_rules() -> None:
    validate_config(example_values())  # raises ConfigInvalid on any sanitizer-based failure


def test_the_example_yields_the_stated_defaults() -> None:
    assert validate_config(example_values()) == validate_config({})
    assert example_values() == DEFAULTS


def test_the_example_matches_the_defaults_of_the_schema() -> None:
    props = load_schema("config")["properties"]
    example = example_values()
    assert {key: props[key]["default"] for key in props} == example


# --- every documented key appears ---------------------------------------------------------------


def test_the_documented_keys_are_the_config_table_of_interface_md() -> None:
    assert documented_keys() == list(DEFAULTS)  # a table row lost or added shows up here


def test_every_documented_key_appears_in_the_example_with_a_comment() -> None:
    lines = EXAMPLE.read_text(encoding="utf-8").splitlines()
    for key in documented_keys():
        at = [i for i, line in enumerate(lines) if line.startswith(f"{key}:")]
        assert len(at) == 1, key
        assert at[0] > 0, f"{key} is the first line, so there is no line above it"
        assert lines[at[0] - 1].startswith("#"), f"{key} has no comment line above it"


def test_every_schema_property_and_every_level_appears_in_the_example() -> None:
    schema = load_schema("config")["properties"]
    example = example_values()
    assert set(schema) == set(example)
    assert set(schema["level_prefix"]["properties"]) == set(example["level_prefix"])


# --- the example is a template: no secret, no real host -----------------------------------------

URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://|\bwww\.", re.IGNORECASE)
# Any dotted name whose last label is alphabetic (2+ letters) is a host, except the exact file names
# the example contains. Bare extensions are not exempt: "evil.md" or "db.key" is a hostname.
DOTTED = re.compile(r"\b[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.([a-z]{2,})\b", re.IGNORECASE)
EXAMPLE_FILENAMES = frozenset({"config.yaml", "details.key", "config.json", "log.jsonl"})
LOCALHOST = re.compile(r"\blocalhost\b", re.IGNORECASE)
HOST_PORT = re.compile(r"\b[a-z][a-z0-9-]*:\d{2,5}\b", re.IGNORECASE)
USER_AT_HOST = re.compile(r"\b[\w.+-]+@[\w-]+", re.IGNORECASE)
# Trade-off: a 32+ char run only counts as a token if it holds a capital or a digit, so path-like
# text does not trip it; an all-lowercase run (path-like or not) is deliberately not flagged.
TOKEN = re.compile(
    r"\bxox[a-z]-"
    r"|(?=[A-Za-z0-9+/_.=-]*[A-Z0-9])[A-Za-z0-9+/_.=-]{32,}"  # needs a capital or digit: not a path
    r"|\bT[0-9A-Z]{8,}/B[0-9A-Z]{8,}"
    r"|\b(?i:bearer)\s+\S{8,}"
)
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_H = r"[0-9a-f]{1,4}"
IPV6 = re.compile(
    rf"\[[0-9a-f:.]*:[0-9a-f:.]*:[0-9a-f:.]*\]"  # bracketed, at least two colons
    rf"|(?<![\w:])(?:{_H}:){{7}}{_H}(?![\w:])"  # full form
    rf"|(?<![\w:])(?:{_H}(?::{_H}){{0,6}})?::(?:{_H}(?::{_H}){{0,6}})?(?![\w:])",  # compressed
    re.IGNORECASE,
)
PLAIN_PATTERNS = (URL, LOCALHOST, HOST_PORT, USER_AT_HOST, TOKEN, IPV4, IPV6)


def leaks(text: str) -> list[str]:
    found = [m.group(0) for pattern in PLAIN_PATTERNS for m in pattern.finditer(text)]
    found += [
        m.group(0) for m in DOTTED.finditer(text) if m.group(0).lower() not in EXAMPLE_FILENAMES
    ]
    return found


def test_the_example_holds_no_url_hostname_ip_or_token_shaped_text() -> None:
    assert leaks(EXAMPLE.read_text(encoding="utf-8")) == []


def _dotted(*labels: str) -> str:
    return ".".join(labels)


@pytest.mark.parametrize(
    "text",
    [
        "webhook_env: " + "/".join(["https:", "", "example.test", "x"]),
        "# see " + _dotted("hooks", "slack", "com"),
        "token: " + "xox" + "b-1",
        "k: " + "A" * 32,
        "host: " + _dotted("10", "0", "0", "1"),
        "# " + _dotted("www", "example"),
        # hostnames outside any fixed TLD list
        "# " + _dotted("db", "internal"),
        "# " + _dotted("box", "local"),
        "# " + _dotted("box", "lan"),
        "# " + _dotted("a", "corp"),
        "# " + _dotted("a", "xyz"),
        "# " + _dotted("a", "test"),
        "# " + _dotted("a", "invalid"),
        "# " + _dotted("a", "cloud"),
        "# " + _dotted("a", "tech"),
        "# " + _dotted("a", "me"),
        "# " + _dotted("a", "sh"),
        "# " + _dotted("evil", "md"),
        "# " + _dotted("foo", "py"),
        "# " + _dotted("db", "key"),
        "# " + _dotted("a", "txt"),
        "# " + _dotted("a", "toml"),
        "# " + _dotted("a", "yml"),
        "# " + _dotted("a", "fr"),
        "# " + _dotted("a", "ru"),
        "# " + _dotted("a", "ch"),
        "# " + "local" + "host",
        "# " + "local" + "host" + ":" + "8080",
        "# " + "ops" + "@" + "box",
        "# " + "db" + ":" + "5432",
        # token alphabet with '.' and '=' and bearer credentials
        "CANARY: " + ".".join(["a" * 12, "b" * 12, "c" * 12]),
        "CANARY: " + "q" * 29 + "9==",
        "CANARY: " + "Bear" + "er " + "z" * 20,
        "CANARY: " + "bear" + "er " + "z" * 20,
        # IPv6
        "# [" + "::1" + "]",
        "# [" + "2001:db8::1" + "]:443",
        "# " + "2001:db8" + "::1",
        "# " + "fe80" + "::1",
        "# " + "::" + "1",
        "# " + ":".join(["2001", "db8", "0", "0", "0", "0", "0", "1"]),
    ],
)
def test_the_leak_scan_catches_what_it_is_for(text: str) -> None:
    assert leaks(text) != []


@pytest.mark.parametrize(
    "text",
    [
        "# .config/slack-notice/config.yaml, details.key, config.d/*.yaml, log.jsonl",
        "# schemas/config.json",
        "timeout: 10s  # 1:30 and 12:34 are not addresses",
        "# version 0.6.0 and 1.5 seconds",
        "# a short Bearer word",
        "level: 10",
        "# " + "/".join(["a" * 12, "b" * 12, "c" * 12]),  # 32+ lowercase path-like: not a token
    ],
)
def test_the_leak_scan_leaves_ordinary_text_alone(text: str) -> None:
    assert leaks(text) == []


def test_the_credential_is_named_by_variable_never_given() -> None:
    values = example_values()
    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", values["webhook_env"])
    assert values["webhook_env"] == DEFAULTS["webhook_env"]


# --- the doc parser fails loudly on drift --------------------------------------------------


def _doc() -> str:
    return INTERFACE.read_text(encoding="utf-8")


def test_the_doc_parser_accepts_the_real_doc_with_crlf_line_endings() -> None:
    assert parse_documented_keys(_doc().replace("\n", "\r\n")) == list(DEFAULTS)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("\n## Config\n", "\n## Settings\n"),
        lambda t: re.sub(r"^\| Key \|.*\n\|---\|.*\n", "", t, flags=re.MULTILINE),
        lambda t: t.replace("| `enabled` |", "| enabled |"),
        lambda t: re.sub(r"^\| (`\w+`) \| (`[^|]*`) \|", r"| \2 | \1 |", t, flags=re.MULTILINE),
        lambda t: t.replace("| `log` |", "| `log2` |", 1).replace("| `log2` |", "| x |"),
        lambda t: t.replace("| `enabled` |", "| `enabled` | `true` | x |\n| `extra` |", 1),
    ],
    ids=["renamed-heading", "no-table", "no-backticks", "swapped-columns", "row-lost", "row-added"],
)
def test_the_doc_parser_raises_on_a_drifted_doc(mutate: Any) -> None:
    mutated = mutate(_doc())
    assert mutated != _doc()
    with pytest.raises(AssertionError):
        parse_documented_keys(mutated)


# --- the negative side: the checks above can fail ------------------------------------------------


@pytest.mark.parametrize(
    "breakage",
    [
        {"unknown_key": 1},
        {"enabled": "yes"},
        {"webhook_env": 5},
        {"body_variable": ""},
        {"level_prefix": {"info": "x" * 17}},
        {"level_prefix": {"info": 5}},
        {"max_chars": 1999},
        {"max_chars": 12001},
        {"timeout": 0},
        {"timeout": "5x"},
        {"log": "no"},
    ],
    ids=lambda b: next(iter(b)) + "=" + repr(next(iter(b.values())))[:20],
)
def test_a_broken_copy_of_the_example_fails_each_check(breakage: dict[str, Any]) -> None:
    bad = {**example_values(), **breakage}
    assert schema_errors("config", bad)
    with pytest.raises(ConfigInvalid):
        validate_config(bad)


def test_the_schema_is_coarse_for_level_prefix_so_the_loader_check_is_needed() -> None:
    # A zero-width space passes the schema class but not the sanitizer-based rule.
    hidden = {**example_values(), "level_prefix": {"info": "I\u200bNFO"}}
    assert schema_errors("config", hidden) == []
    with pytest.raises(ConfigInvalid) as raised:
        validate_config(hidden)
    assert raised.value.key == "level_prefix"
    # Leading, trailing and doubled spaces likewise.
    for text in (" INFO", "INFO ", "IN  FO"):
        assert schema_errors("config", {"level_prefix": {"info": text}}) == []
        with pytest.raises(ConfigInvalid):
            validate_config({"level_prefix": {"info": text}})


def test_the_strict_loader_refuses_what_plain_yaml_would_accept() -> None:
    with pytest.raises(YamlRefused):
        parse_yaml(EXAMPLE.read_bytes() + b"enabled: false\n")  # duplicate key
    with pytest.raises(YamlRefused):
        parse_yaml(b"timeout: 010\n")


def test_every_config_key_has_a_positive_and_a_negative_schema_sample() -> None:
    import json

    samples = json.loads((ROOT / "tests" / "samples" / "config.json").read_text(encoding="utf-8"))
    positive = {key for case in samples["valid"].values() for key in case}
    negative = {case["path"][0] for case in samples["invalid"].values() if case["path"]}
    keys = set(load_schema("config")["properties"])
    assert keys <= positive
    assert keys <= negative


def test_the_example_is_a_regular_file_within_the_loader_limit() -> None:
    assert EXAMPLE.is_file() and not Path(EXAMPLE).is_symlink()
    assert EXAMPLE.stat().st_size <= 65536

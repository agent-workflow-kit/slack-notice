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


def documented_keys() -> list[str]:
    """First column of the Config table in interface.md (rows like ``| `key` | ...``)."""
    text = INTERFACE.read_text(encoding="utf-8")
    section = text.split("\n## Config\n", 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\| `([a-z_]+)` \|", section, flags=re.MULTILINE)


# --- the example through the strict loader, the schema and the validator -----------------------


def test_the_example_loads_through_the_strict_loader(fake_gateway: FakeGateway) -> None:
    loaded = load_config(fake_gateway, home=None, config_path=str(EXAMPLE))
    assert loaded == example_values()
    assert set(loaded) == set(DEFAULTS)


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
        assert lines[at[0] - 1].startswith("#"), f"{key} has no comment line above it"


def test_every_schema_property_and_every_level_appears_in_the_example() -> None:
    schema = load_schema("config")["properties"]
    example = example_values()
    assert set(schema) == set(example)
    assert set(schema["level_prefix"]["properties"]) == set(example["level_prefix"])


# --- the example is a template: no secret, no real host -----------------------------------------

URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://|\bwww\.", re.IGNORECASE)
HOSTNAME = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|dev|app|co|biz|info|edu|gov|us|uk|de|ai)\b",
    re.IGNORECASE,
)
TOKEN = re.compile(r"\bxox[a-z]-|\b[A-Za-z0-9+/_-]{32,}\b|\bT[0-9A-Z]{8,}/B[0-9A-Z]{8,}")
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
LEAKS = (URL, HOSTNAME, TOKEN, IPV4)


def leaks(text: str) -> list[str]:
    return [m.group(0) for pattern in LEAKS for m in pattern.finditer(text)]


def test_the_example_holds_no_url_hostname_ip_or_token_shaped_text() -> None:
    assert leaks(EXAMPLE.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "text",
    [
        "webhook_env: " + "/".join(["https:", "", "example.test", "x"]),
        "# see " + ".".join(["hooks", "slack", "com"]),
        "token: " + "xox" + "b-1",
        "k: " + "A" * 32,
        "host: " + ".".join(["10", "0", "0", "1"]),
        "# " + ".".join(["www", "example"]),
    ],
)
def test_the_leak_scan_catches_what_it_is_for(text: str) -> None:
    assert leaks(text) != []


def test_the_credential_is_named_by_variable_never_given() -> None:
    values = example_values()
    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", values["webhook_env"])
    assert values["webhook_env"] == DEFAULTS["webhook_env"]


# --- the negative side: the checks above can fail ------------------------------------------------


def test_a_broken_copy_of_the_example_fails_each_check() -> None:
    bad = {**example_values(), "timeout": 0}
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

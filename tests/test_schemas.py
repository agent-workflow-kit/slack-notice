"""Every schema loads, is draft 2020-12, accepts its positive samples and rejects its negatives.

Samples live in tests/samples/<schema name>.json:
  {"valid": {label: instance}, "invalid": {label: {"instance": ..., "path": [...], "keyword": k}}}
`path` is the instance location (list of keys/indexes) and `keyword` the schema keyword
(`required`, `pattern`, `const`, ...) of one reported error (errors inside oneOf/anyOf branches
included), so a negative sample must fail for the reason it names, not for some other one.
A sample whose keyword is `oneOf` or `anyOf` (the error of the whole choice) also names the
defect inside the branches as `"inner": {"path": [...], "keyword": k}`, so it cannot pass
because of some unrelated branch error.
defs.json holds shared definitions only: its labels are `<definition>.<case>` and each sample is
checked against that entry of `$defs`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from tests.harness import (
    assert_valid,
    load_schema,
    schema_error_pairs,
    schema_errors,
    schema_names,
)

SAMPLES = Path(__file__).parent / "samples"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
LF_SAFE_END = r"(?![\s\S])"
NAMES = schema_names()
EXPECTED_SCHEMAS = [
    "cli/error",
    "cli/send",
    "cli/validate",
    "config",
    "defs",
    "log",
    "notification",
]


def _target(name: str, key: str) -> str | None:
    """The `$defs` entry a sample is checked against (None: the schema as a whole)."""
    return key.split(".")[0] if name == "defs" else None


def _samples(name: str) -> dict[str, Any]:
    with (SAMPLES / f"{name}.json").open(encoding="utf-8") as fh:
        return json.load(fh)


def _cases(kind: str) -> list[Any]:
    return [pytest.param(n, k, id=f"{n}:{k}") for n in NAMES for k in _samples(n)[kind]]


def _patterns(node: Any, where: str = "") -> list[tuple[str, str]]:
    """Every `pattern` keyword as (location, pattern); a property named `pattern` is not one."""
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                found.append((where, value))
            elif key == "properties" and isinstance(value, dict):
                for prop, sub in value.items():
                    found += _patterns(sub, f"{where}/{prop}")
            else:
                found += _patterns(value, f"{where}/{key}")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            found += _patterns(item, f"{where}/{i}")
    return found


def test_the_schemas_are_the_expected_set() -> None:
    assert NAMES == EXPECTED_SCHEMAS


@pytest.mark.parametrize("name", NAMES)
def test_schema_is_a_valid_draft_2020_12_schema(name: str) -> None:
    schema = load_schema(name)
    assert schema["$schema"] == DRAFT
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("name", NAMES)
def test_schema_id_matches_its_path(name: str) -> None:
    assert load_schema(name)["$id"] == f"slack-notice/{name}.json"


@pytest.mark.parametrize("name", NAMES)
def test_every_ref_resolves_to_a_local_definition(name: str) -> None:
    # Resolution is exercised by validating a sample; this pins that no $ref leaves the repo.
    refs = re.findall(r'"\$ref":\s*"([^"]+)"', json.dumps(load_schema(name)))
    assert all(r.startswith(("#", "defs.json#", "../defs.json#")) for r in refs), refs


@pytest.mark.parametrize("name", NAMES)
def test_every_pattern_is_anchored_at_the_start_and_ends_lf_safe(name: str) -> None:
    # JSON Schema `$` accepts a trailing LF; every pattern must end with (?![\s\S]) instead.
    patterns = _patterns(load_schema(name))
    assert [(w, p) for w, p in patterns if not p.startswith("^")] == []
    assert [(w, p) for w, p in patterns if not p.endswith(LF_SAFE_END)] == []
    assert [(w, p) for w, p in patterns if "$" in re.sub(r"\\.", "", p)] == []


# One entry per pattern in the schemas, keyed by (schema, location): a value the pattern accepts
# and where it sits. The test below appends a LF and expects the pattern to reject it, and the
# coverage test fails when a pattern has no entry (or an entry has no pattern).
LF_CASES: dict[tuple[str, str], tuple[Any, list[str | int], str | None]] = {
    ("config", "/$defs/duration/anyOf/1"): ({"timeout": "10s"}, ["timeout"], None),
    ("config", "/webhook_env"): ({"webhook_env": "SLACK_WEBHOOK"}, ["webhook_env"], None),
    ("config", "/body_variable"): ({"body_variable": "body"}, ["body_variable"], None),
    ("config", "/level_prefix/info"): (
        {"level_prefix": {"info": "I"}},
        ["level_prefix", "info"],
        None,
    ),
    ("config", "/level_prefix/warn"): (
        {"level_prefix": {"warn": "W"}},
        ["level_prefix", "warn"],
        None,
    ),
    ("config", "/level_prefix/action"): (
        {"level_prefix": {"action": "A"}},
        ["level_prefix", "action"],
        None,
    ),
    ("config", "/level_prefix/error"): (
        {"level_prefix": {"error": "E"}},
        ["level_prefix", "error"],
        None,
    ),
    ("defs", "/$defs/duration/anyOf/1"): ("10s", [], "duration"),
    ("defs", "/$defs/ts"): ("2026-11-24T10:00:00.000Z", [], "ts"),
    ("defs", "/$defs/sha256_16"): ("0123456789abcdef", [], "sha256_16"),
    ("defs", "/$defs/actor"): ("human:alice", [], "actor"),
    ("defs", "/$defs/error_details/pointer"): (
        {"pointer": "/message"},
        ["pointer"],
        "error_details",
    ),
    ("defs", "/$defs/error_details/env"): ({"env": "SLACK_WEBHOOK"}, ["env"], "error_details"),
    ("defs", "/$defs/error_details/host_error"): (
        {"host_error": "invalid_payload"},
        ["host_error"],
        "error_details",
    ),
    ("notification", "/link"): ({"message": "m", "link": "https://example.com/"}, ["link"], None),
}


def _with_lf(instance: Any, path: list[str | int]) -> Any:
    if not path:
        return instance + "\n"
    out = json.loads(json.dumps(instance))
    node = out
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] += "\n"
    return out


def test_every_pattern_has_a_trailing_lf_case_and_every_case_a_pattern() -> None:
    found = {(n, w) for n in NAMES for w, _ in _patterns(load_schema(n))}
    assert found == set(LF_CASES)


@pytest.mark.parametrize(("name", "where"), sorted(LF_CASES))
def test_a_pattern_accepts_its_value_and_refuses_it_with_a_trailing_lf(
    name: str, where: str
) -> None:
    good, path, definition = LF_CASES[(name, where)]
    assert schema_errors(name, good, definition) == []
    bad = _with_lf(good, path)
    pairs = schema_error_pairs(name, bad, definition)
    assert pairs, "the value with a trailing LF was accepted"
    # A pattern inside anyOf (duration) reports the failure through its branch context.
    assert (tuple(path), "pattern") in pairs


@pytest.mark.parametrize("name", NAMES)
def test_a_schema_has_positive_and_negative_samples(name: str) -> None:
    samples = _samples(name)
    assert samples["valid"] and samples["invalid"]


def test_every_definition_of_defs_has_a_positive_and_a_negative_sample() -> None:
    samples = _samples("defs")
    for kind in ("valid", "invalid"):
        sampled = {key.split(".")[0] for key in samples[kind]}
        assert sampled == set(load_schema("defs")["$defs"]), kind


def test_every_sample_file_belongs_to_a_schema() -> None:
    files = {p.relative_to(SAMPLES).with_suffix("").as_posix() for p in SAMPLES.rglob("*.json")}
    assert files == set(NAMES)


@pytest.mark.parametrize(("name", "key"), _cases("valid"))
def test_positive_sample_validates(name: str, key: str) -> None:
    instance = _samples(name)["valid"][key]
    assert [e.message for e in schema_errors(name, instance, _target(name, key))] == []


@pytest.mark.parametrize(("name", "key"), _cases("invalid"))
def test_negative_sample_is_rejected_at_its_named_location_for_its_named_keyword(
    name: str, key: str
) -> None:
    sample = _samples(name)["invalid"][key]
    required = {"instance", "path", "keyword"}
    assert required <= set(sample) <= required | {"inner"}
    pairs = schema_error_pairs(name, sample["instance"], _target(name, key))
    assert pairs, "negative sample was accepted"
    assert (tuple(sample["path"]), sample["keyword"]) in pairs, (
        f"expected {sample['keyword']} at {sample['path']}, got {sorted(map(str, pairs))}"
    )
    if sample["keyword"] in ("oneOf", "anyOf"):
        assert "inner" in sample, "a oneOf/anyOf negative must name the inner defect"
    if "inner" in sample:
        assert set(sample["inner"]) == {"path", "keyword"}
        inner = (tuple(sample["inner"]["path"]), sample["inner"]["keyword"])
        assert inner in pairs, f"expected inner {inner}, got {sorted(map(str, pairs))}"


def test_every_trailing_lf_negative_sample_really_ends_in_lf() -> None:
    # The "trailing_lf" labels are the issue's named samples; guard against one losing its LF.
    count = 0
    for name in NAMES:
        for key, sample in _samples(name)["invalid"].items():
            if "trailing_lf" in key:
                count += 1
                value = sample["instance"]
                for step in sample["path"]:
                    value = value[step]
                assert isinstance(value, str) and value.endswith("\n"), (name, key)
    assert count >= 10


# The required samples named by the issue.


def test_the_log_schema_accepts_outcome_unknown_with_exit_1_and_code_internal() -> None:
    record = _samples("log")["valid"]["outcome_unknown_exit_1_internal"]
    assert (record["outcome"], record["exit"], record["code"]) == ("outcome_unknown", 1, "internal")
    assert schema_errors("log", record) == []


def test_the_log_schema_requires_exactly_the_fields_of_a_record() -> None:
    record = _samples("log")["valid"]["sent"]
    assert set(load_schema("log")["required"]) == set(record)
    assert set(load_schema("log")["properties"]) == set(record)


@pytest.mark.parametrize("field", sorted(_samples("log")["valid"]["sent"]))
def test_removing_any_field_of_a_log_record_fails_as_required(field: str) -> None:
    record = {k: v for k, v in _samples("log")["valid"]["sent"].items() if k != field}
    assert ((), "required") in schema_error_pairs("log", record)


def test_config_duration_matches_the_shared_definition() -> None:
    # config.json is self-contained, so its copy of `duration` must not drift from defs.json.
    shared = load_schema("defs")["$defs"]["duration"]
    own = load_schema("config")["$defs"]["duration"]
    assert own == shared


# The harness for real tool output.


def test_assert_valid_parses_text_and_returns_the_document() -> None:
    doc = assert_valid("cli/send", b'{"outcome": "disabled"}\n')
    assert doc == {"outcome": "disabled"}


def test_assert_valid_fails_on_output_that_breaks_the_schema() -> None:
    with pytest.raises(AssertionError):
        assert_valid("cli/send", '{"outcome": "queued"}')


def test_assert_valid_fails_on_output_that_is_not_json() -> None:
    with pytest.raises(json.JSONDecodeError):
        assert_valid("cli/send", "not json")


def test_assert_valid_accepts_a_definition() -> None:
    assert assert_valid("defs", '"warn"', "level") == "warn"
    with pytest.raises(AssertionError):
        assert_valid("defs", '"warn\\n"', "level")


# TODO(#12): validate config.example.yaml against schemas/config.json in the test suite (needs the
# YAML loader of #10); the shared awkit-ci python-ci.yml workflow (called from ci.yml) already
# runs check-jsonschema on it in its `schemas` job.

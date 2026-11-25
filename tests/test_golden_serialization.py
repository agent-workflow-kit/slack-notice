"""Golden serialization tests (#30): the bytes of request bodies, ``--json`` documents and log
lines, checked against the rule of docs/interface.md (Output): ``json.dumps(obj,
ensure_ascii=False, separators=(",", ":"))``, keys in the documented order, UTF-8.

The golden files are compared as raw bytes by ``test_golden_send``, ``test_render`` and
``test_log``; this file checks the *rules* on every golden file, then re-serializes each one with a
changed rule (default separators, ``ensure_ascii``, another key order, CRLF, a trailing space) and
asserts the result is not the golden, so a change to any of them fails a golden test.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from slack_notice import log, render
from tests.harness import assert_valid, load_schema

GOLDEN = Path(__file__).resolve().parent / "golden"


def files(pattern: str) -> list[Path]:
    found = sorted(GOLDEN.glob(pattern))
    assert found, pattern
    return found


BODIES = [*files("send/*.body"), *files("render/*.json")]
DOCUMENTS = files("send/*.stdout")
LOGS = [*files("send/*.log"), GOLDEN / "log.jsonl"]
ALL = [*BODIES, *DOCUMENTS, *LOGS]


def ids(paths: list[Path]) -> list[str]:
    return [str(p.relative_to(GOLDEN)) for p in paths]


def dump(value: Any, **over: Any) -> str:
    options: dict[str, Any] = {"ensure_ascii": False, "separators": (",", ":")} | over
    return json.dumps(value, **options)


def pairs(data: bytes) -> list[tuple[str, Any]]:
    """Every object of the text as a list of (key, value) in file order, never a dict."""
    return json.loads(data, object_pairs_hook=lambda kv: kv)


# --- rules that hold for every golden --------------------------------------------------------


@pytest.mark.parametrize("path", ALL, ids=ids(ALL))
def test_golden_is_strict_utf8_without_bom_or_cr_or_nul(path: Path) -> None:
    data = path.read_bytes()
    text = data.decode("utf-8")  # strict: a lone surrogate cannot be encoded, so cannot be here
    assert not data.startswith(b"\xef\xbb\xbf")
    assert "\r" not in text and "\x00" not in text
    assert not any(0xD800 <= ord(c) <= 0xDFFF for c in text)
    assert text.encode("utf-8") == data


@pytest.mark.parametrize("path", ALL, ids=ids(ALL))
def test_golden_text_is_compact_and_passes_non_ascii_through(path: Path) -> None:
    for line in path.read_bytes().decode("utf-8").splitlines():
        value = json.loads(line)
        assert line == dump(value), f"{path.name}: not ensure_ascii=False with compact separators"
        assert (
            "\\u" not in line
            or all(  # an escape is only for what JSON must escape
                line[i : i + 6].lower() < "\\u0080"
                for i in range(len(line) - 5)
                if line[i : i + 2] == "\\u"
            )
        )


@pytest.mark.parametrize("path", LOGS + DOCUMENTS, ids=ids(LOGS + DOCUMENTS))
def test_one_json_object_per_line_ending_in_exactly_one_lf(path: Path) -> None:
    data = path.read_bytes()
    assert data.endswith(b"\n") and not data.endswith(b"\n\n")
    for line in data.splitlines():
        assert line == line.rstrip(b" \t"), "no trailing space"
        assert line and isinstance(json.loads(line), dict)
    if path in DOCUMENTS:
        assert data.count(b"\n") == 1


@pytest.mark.parametrize("path", BODIES, ids=ids(BODIES))
def test_a_request_body_is_one_key_and_has_no_line_ending(path: Path) -> None:
    data = path.read_bytes()
    assert not data.endswith(b"\n") and b"\n" not in data  # a LF in the text is the escape \n
    ((key, value),) = pairs(data)
    assert isinstance(value, str) and key in {"body", "slack_text"}
    assert data == dump({key: value}).encode("utf-8")


# --- key order -------------------------------------------------------------------------------

LOG_ORDER = list(load_schema("log")["properties"])
SEND_ORDER = ["outcome", "tool", "level", "truncated", "bytes", "duration_ms", "http_status"]
ERROR_ORDER = [
    "code",
    "message",
    "reason",
    "details",
    "retryable",
    "retry_after_s",
    "unknown_outcome",
]


@pytest.mark.parametrize("path", LOGS, ids=ids(LOGS))
def test_log_lines_have_the_documented_key_order(path: Path) -> None:
    for line in path.read_bytes().splitlines():
        assert [k for k, _ in pairs(line)] == LOG_ORDER
        assert_valid("log", line)


@pytest.mark.parametrize("path", DOCUMENTS, ids=ids(DOCUMENTS))
def test_json_outputs_have_the_documented_key_order(path: Path) -> None:
    document = pairs(path.read_bytes())
    keys = [k for k, _ in document]
    if keys == ["error"]:
        assert [k for k, _ in document[0][1]] == ERROR_ORDER
        assert_valid("cli/error", path.read_bytes())
    elif keys == ["outcome"]:
        assert document == [("outcome", "disabled")]
    else:
        tail = ["dedupe_key", "rendered"] if document[0][1] == "dry_run" else ["dedupe_key"]
        assert keys == [*SEND_ORDER, *tail]
        assert_valid("cli/send", path.read_bytes())


def test_the_documented_orders_match_the_schema_files() -> None:
    send = list(load_schema("cli/send")["properties"])
    assert send == [*SEND_ORDER, "dedupe_key", "rendered"]
    error = list(load_schema("defs")["$defs"]["error"]["properties"])
    assert error == ERROR_ORDER


def test_the_golden_set_has_non_ascii_text_that_is_not_escaped() -> None:
    raw = [p for p in BODIES if any(b > 0x7F for b in p.read_bytes())]
    assert len(raw) >= 5
    for path in raw:
        assert b"\\u" not in path.read_bytes() or path.name == "escapes.json", path


def test_the_escapes_golden_pins_the_json_escapes() -> None:
    data = (GOLDEN / "render" / "escapes.json").read_bytes()
    assert data == b'{"slack_text":"\xf0\x9f\x94\xb5 INFO\\nq\\"uote \\\\ back\\nline"}'
    sent = (GOLDEN / "send" / "sent_escapes.body").read_bytes()
    assert b'\\"' in sent and b"\\\\" in sent and b"\\n" in sent and b"\\t" not in sent


def test_a_lone_surrogate_cannot_reach_a_serialized_line() -> None:
    for build in (
        lambda: render.serialize("body", "a\ud800b"),
        lambda: log.encode_record({"x": "a\udfffb"}),
    ):
        with pytest.raises(UnicodeEncodeError):
            build()


# --- the golden bytes change when the serialization rule changes -----------------------------

Mutation = Callable[[Any], str]


def reversed_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: reversed_keys(v) for k, v in reversed(list(value.items()))}
    return value


MUTATIONS: dict[str, Mutation] = {
    "default separators": lambda v: dump(v, separators=(", ", ": ")),
    "item separator only": lambda v: dump(v, separators=(", ", ":")),
    "key separator only": lambda v: dump(v, separators=(",", ": ")),
    "reversed key order": lambda v: dump(reversed_keys(v)),
    "sorted keys": lambda v: dump(v, sort_keys=True),
    "indent": lambda v: dump(v, indent=1),
}


def one_line(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines()


@pytest.mark.parametrize("name", sorted(MUTATIONS))
@pytest.mark.parametrize("path", ALL, ids=ids(ALL))
def test_a_changed_rule_would_change_the_golden_bytes(path: Path, name: str) -> None:
    for line in one_line(path):
        value = json.loads(line)
        changed = MUTATIONS[name](value).encode("utf-8")
        flat_single = len(value) == 1 and not any(
            isinstance(v, dict | list) for v in value.values()
        )
        if name in ("reversed key order", "sorted keys", "item separator only") and flat_single:
            continue  # one key: no second key to reorder or separate
        if name == "sorted keys" and json.dumps(value) == json.dumps(value, sort_keys=True):
            continue  # already in sorted order (nested objects included)
        assert changed != line, f"{path.name}: the {name} mutation produced the golden"


@pytest.mark.parametrize("path", ALL, ids=ids(ALL))
def test_ensure_ascii_true_changes_every_golden_that_holds_non_ascii(path: Path) -> None:
    for line in one_line(path):
        if any(b > 0x7F for b in line):
            assert dump(json.loads(line), ensure_ascii=True).encode() != line


@pytest.mark.parametrize("path", LOGS + DOCUMENTS, ids=ids(LOGS + DOCUMENTS))
def test_line_ending_and_trailing_space_variants_differ_from_the_golden(path: Path) -> None:
    data = path.read_bytes()
    for variant in (
        data.replace(b"\n", b"\r\n"),
        data + b"\n",
        data[:-1],
        data.replace(b"}\n", b"} \n"),
    ):
        assert variant != data


def test_the_serializers_produce_the_golden_bytes_and_the_mutations_do_not() -> None:
    """The two production serializers against their own golden, for one of each."""
    golden = (GOLDEN / "render" / "escapes.json").read_bytes()
    assert render.serialize("slack_text", '\U0001f535 INFO\nq"uote \\ back\nline') == golden
    line = (GOLDEN / "send" / "sent.log").read_bytes().rstrip(b"\n")
    record = json.loads(line)
    assert log.encode_record(record) == line + b"\n"
    assert log.encode_record(record) != (dump(record, separators=(", ", ": ")) + "\n").encode()
    assert log.encode_record(dict(reversed(list(record.items())))) != line + b"\n"

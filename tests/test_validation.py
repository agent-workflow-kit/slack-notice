"""Notification validation, flag combinations and pointers (issue #16).

Hostile input: every error carries a fixed message and a pointer, never an input value; the
validation never recurses over a value, so nesting costs nothing; a flag and a JSON field have
one rule and one pointer.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, payload
from slack_notice.cli import CliError, Context, Streams, main
from slack_notice.config import DEFAULTS
from slack_notice.gateway import SourceRead
from tests.fake_gateway import FakeGateway
from tests.harness import assert_valid

# Built from parts: planted in input, asserted absent from every output.
CANARY = "CAN" + "ARY-" + "91c4"


def refused(value: object) -> payload.FieldRefused:
    with pytest.raises(payload.FieldRefused) as info:
        payload.validate_notification(value)
    return info.value


# --- validate_notification ------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        {"message": "a"},
        {"title": "t", "message": "m", "level": "error", "link": "https://a.example/"},
        {"title": "", "message": ""},  # emptiness is the sanitizer's (#17)
        {"title": " \t\n", "message": "   "},
        {"message": "a\x00\x1b\U0001f535 \u202e"},  # control and bidi characters: the sanitizer's
        {"message": "é😀" * 10},
        {"link": "x" * 5000},  # the link rule is #18: only the type is judged here
        {"title": "only a title"},  # an absent message is empty_message (#17)
        {},
    ],
)
def test_structurally_valid_objects_are_returned_unchanged(value: dict[str, Any]) -> None:
    assert payload.validate_notification(value) == value


@pytest.mark.parametrize("level", list(payload.LEVELS))
def test_each_level_is_accepted(level: str) -> None:
    assert payload.validate_notification({"message": "a", "level": level})["level"] == level


@pytest.mark.parametrize(
    "level",
    [
        "",
        "INFO",
        "Info",
        "info ",
        " info",
        "info\n",
        "warning",
        "fatal",
        "debug",
        "in\x00fo",
        "ｉｎｆｏ",
    ],
)
def test_a_level_outside_the_four_is_refused_at_level(level: str) -> None:
    error = refused({"message": "a", "level": level})
    assert (error.pointer, error.rule) == ("/level", "level")


@pytest.mark.parametrize("field", ["title", "message", "level", "link"])
@pytest.mark.parametrize(
    "bad",
    [
        None,
        1,
        0,
        True,
        False,
        1.5,
        [],
        ["a"],
        {},
        {"a": "b"},
        pytest.param(10**5000, id="bigint"),
        b"a",
        ("a",),
    ],
)
def test_a_wrong_type_is_refused_at_the_field(field: str, bad: object) -> None:
    error = refused({"message": "a", field: bad} if field != "message" else {"message": bad})
    assert (error.pointer, error.rule) == (f"/{field}", "type")


@pytest.mark.parametrize("field", ["title", "message"])
def test_text_limit_is_100000_code_points(field: str) -> None:
    assert payload.validate_notification({"message": "a", field: "x" * 100_000})
    assert payload.validate_notification({"message": "a", field: "😀" * 100_000})  # not bytes
    error = refused({"message": "a", field: "x" * 100_001})
    assert (error.pointer, error.rule) == (f"/{field}", "length")
    assert refused({"message": "a", field: "😀" * 100_001}).pointer == f"/{field}"


def test_the_link_length_is_not_judged_here() -> None:
    # The link rule runs later, in sanitize_notification (check_link).
    assert payload.validate_notification({"message": "a", "link": "é" * 200_000})


@pytest.mark.parametrize(
    ("key", "pointer"),
    [
        ("extra", "/extra"),
        ("Level", "/Level"),
        ("x" * 64, "/" + "x" * 64),
        ("a-b_C9", "/a-b_C9"),
        ("x" * 65, "/?"),
        ("x" * 5000, "/?"),
        ("\x1b" * 5000, "/?"),
        ("", "/?"),
        ("a b", "/?"),
        ("a/b", "/?"),
        ("a~b", "/?"),
        ("a.b", "/?"),
        ("title\n", "/?"),
        ("\n", "/?"),
        ("é", "/?"),
        ("ｔｉｔｌｅ", "/?"),
        ("\ud800", "/?"),
        ("\udfff" * 3, "/?"),
        ("😀", "/?"),
        ("\x00", "/?"),
        ("\x1b[31m", "/?"),
        ("../..", "/?"),
        ('"}', "/?"),
        (CANARY + "!", "/?"),
    ],
)
def test_an_unknown_field_is_reported_by_a_safe_pointer(key: str, pointer: str) -> None:
    error = refused({"message": "a", key: "v"})
    assert (error.pointer, error.rule) == (pointer, "unknown")


def test_a_non_string_key_is_unknown_not_a_crash() -> None:
    assert refused({"message": "a", 1: "x", None: 2}).pointer == "/?"


def test_the_first_unknown_field_in_input_order_is_reported() -> None:
    assert refused({"zeta": 1, "alpha": 2, "message": "a"}).pointer == "/zeta"


def test_unknown_fields_come_before_wrong_types_and_known_fields_follow_the_table() -> None:
    assert refused({"message": None, "extra": 1}).pointer == "/extra"
    assert refused({"link": 1, "level": "bad", "message": 2, "title": 3}).pointer == "/title"
    assert refused({"link": 1, "level": "bad", "message": 2}).pointer == "/message"
    assert refused({"link": 1, "level": "bad"}).pointer == "/level"


@pytest.mark.parametrize("value", [[], None, "x", 1, True, [{"message": "a"}], ()])
def test_a_value_that_is_not_an_object_is_refused_at_the_root(value: object) -> None:
    error = refused(value)
    assert (error.pointer, error.rule) == ("", "not_object")


def test_errors_hold_no_input_and_no_exception_chain() -> None:
    hostile = {"message": "a", CANARY + "!": CANARY, "level": CANARY}
    for value in (hostile, {"message": CANARY * 100_000}, {"message": 1, "title": [CANARY]}):
        error = refused(value)
        texts = [str(error), repr(error), error.message, error.pointer, error.rule, *error.args]
        assert not any(CANARY in text for text in texts)
        assert error.__context__ is None
        assert error.__cause__ is None


def test_a_deeply_nested_value_is_one_wrong_type_with_no_recursion() -> None:
    # Parsed input can nest about 2000 levels; a bigger one is built here without recursion.
    for depth in (2000, 200_000):
        inner: list[Any] = []
        top = inner
        for _ in range(depth):
            nested: list[Any] = []
            inner.append(nested)
            inner = nested
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(max(len(_frames()) + 50, 100))
        try:
            assert refused({"message": "a", "title": top}).pointer == "/title"
            assert refused({"message": top}).pointer == "/message"
            assert refused({"message": "a", "extra": top}).pointer == "/extra"
        finally:
            sys.setrecursionlimit(old)
        del top, inner


def _frames() -> list[object]:
    frame = sys._getframe()
    frames = []
    while frame is not None:
        frames.append(frame)
        frame = frame.f_back
    return frames


def test_a_2000_level_parsed_value_is_a_pointer_not_a_crash() -> None:
    text = '{"message":"a","title":' + "[" * 2000 + "]" * 2000 + "}"
    value = payload.decode_notification(text.encode())
    assert refused(value).pointer == "/title"


def test_huge_arrays_and_objects_cost_nothing_to_judge() -> None:
    assert refused({"message": [0] * 2_000_000}).pointer == "/message"
    many = {f"k{i}": i for i in range(200_000)}
    assert refused({"message": "a", **many}).pointer == "/k0"
    assert refused({"message": "a", "title": many}).pointer == "/title"


def test_validation_does_not_change_its_input() -> None:
    value = {"title": "t", "message": "m", "level": "warn"}
    before = dict(value)
    payload.validate_notification(value)
    assert value == before


# --- notification_from_flags ----------------------------------------------------------------


def test_flags_form_the_object_with_only_the_given_flags() -> None:
    assert payload.notification_from_flags(title=None, message="m", level=None, link=None) == {
        "message": "m"
    }
    assert payload.notification_from_flags(
        title="t", message="m", level="warn", link="https://a.example/"
    ) == {"title": "t", "message": "m", "level": "warn", "link": "https://a.example/"}


def test_an_empty_flag_value_is_given_not_absent() -> None:
    assert payload.notification_from_flags(title="", message="", level=None, link=None) == {
        "title": "",
        "message": "",
    }
    with pytest.raises(payload.FieldRefused) as info:
        payload.notification_from_flags(title=None, message="m", level="", link=None)
    assert info.value.pointer == "/level"


@pytest.mark.parametrize(
    ("kwargs", "pointer"),
    [
        ({"level": "bogus"}, "/level"),
        ({"title": "x" * 100_001}, "/title"),
        ({"message": "x" * 100_001}, "/message"),
    ],
)
def test_flag_values_meet_the_json_rule_and_pointer(kwargs: dict[str, str], pointer: str) -> None:
    flags = {"title": None, "message": "m", "level": None, "link": None, **kwargs}
    with pytest.raises(payload.FieldRefused) as from_flags:
        payload.notification_from_flags(**flags)
    object_form = {name: text for name, text in flags.items() if text is not None}
    assert refused(object_form).pointer == from_flags.value.pointer == pointer
    assert refused(object_form).message == from_flags.value.message


# --- the command line ---------------------------------------------------------------------


class Result:
    def __init__(self, code: int, out: bytes, err: bytes, value: Any) -> None:
        self.code = code
        self.out = out.decode()
        self.err = err.decode()
        self.value = value

    @property
    def error(self) -> dict[str, Any]:
        assert_valid("cli/error", self.out)
        return json.loads(self.out)["error"]


def run(
    argv: list[str],
    gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    *,
    tty: bool = False,
    stdin: bytes | None = None,
    json_mode: bool = True,
) -> Result:
    """Run main with a handler that loads the notification (step 3) and records it."""
    seen: list[Any] = []

    def handler(ctx: Context) -> int:
        seen.append(cli.load_notification(ctx, 10.0))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    if stdin is not None:
        gateway.source_script.append(SourceRead(stdin))
    out, err = io.BytesIO(), io.BytesIO()
    streams = Streams(out=out, err=err, stdin_is_tty=lambda: tty)
    code = main([*argv, "--json"] if json_mode else argv, {}, gateway, streams)
    return Result(code, out.getvalue(), err.getvalue(), seen[0] if seen else None)


JSON_SOURCES = [["--stdin-json"], ["--file", "x.json"], ["--file", "-"], ["--file=-"]]
TEXT_FLAGS = [["--title", "t"], ["--message", "m"], ["--level", "warn"], ["--link", "https://a.b/"]]


@pytest.mark.parametrize("source", JSON_SOURCES)
@pytest.mark.parametrize("text", TEXT_FLAGS)
def test_a_json_source_with_a_text_flag_is_usage(
    source: list[str], text: list[str], fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", *source, *text], fake_gateway, monkeypatch)
    assert result.code == 2
    assert result.error["code"] == "usage"
    assert fake_gateway.source_reads == 0


@pytest.mark.parametrize("path", ["x.json", "/dev/null", "", "a b"])
def test_stdin_json_with_a_file_path_is_usage(
    path: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    for argv in (["--stdin-json", "--file", path], ["--file", path, "--stdin-json"]):
        result = run(["send", *argv], fake_gateway, monkeypatch)
        assert (result.code, result.error["code"]) == (2, "usage")


def test_stdin_json_with_file_dash_is_one_source(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(
        ["send", "--stdin-json", "--file", "-"], fake_gateway, monkeypatch, stdin=b'{"message":"a"}'
    )
    assert (result.code, result.value) == (0, {"message": "a"})


@pytest.mark.parametrize(
    "flags",
    [
        ["--title", "t"],
        ["--level", "warn"],
        ["--link", "https://a.b/"],
        ["--title", "t", "--level", "warn", "--link", "https://a.b/"],
        ["--title="],
        ["--level="],
    ],
)
@pytest.mark.parametrize("tty", [False, True])
def test_flags_without_message_are_usage(
    flags: list[str], tty: bool, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", *flags], fake_gateway, monkeypatch, tty=tty)
    assert (result.code, result.error["code"]) == (2, "usage")
    assert fake_gateway.source_reads == 0


@pytest.mark.parametrize("extra", [[], ["--dedupe-key=k"], ["--decision-id", "d"], ["--dry-run"]])
def test_send_on_a_terminal_with_no_source_and_no_message_is_usage(
    extra: list[str], fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", *extra], fake_gateway, monkeypatch, tty=True)
    assert (result.code, result.error["code"]) == (2, "usage")
    assert fake_gateway.source_reads == 0


def test_a_terminal_is_fine_with_a_message_or_a_file(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = run(["send", "--message", "hi"], fake_gateway, monkeypatch, tty=True)
    assert (result.code, result.value) == (0, {"message": "hi"})
    path = tmp_path / "n.json"
    path.write_text('{"message":"from file"}')
    result = run(["send", "--file", str(path)], fake_gateway, monkeypatch, tty=True)
    assert (result.code, result.value) == (0, {"message": "from file"})


def test_validate_on_a_terminal_is_not_a_send_combination(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "validate", lambda _ctx: 0)
    streams = Streams(io.BytesIO(), io.BytesIO(), lambda: True)
    assert main(["validate"], {}, fake_gateway, streams) == 0


def test_no_source_on_a_pipe_reads_stdin_as_json(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send"], fake_gateway, monkeypatch, stdin=b'{"message":"a","level":"warn"}')
    assert (result.code, result.value) == (0, {"message": "a", "level": "warn"})


def test_the_flags_are_the_source_and_stdin_is_never_read(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["send", "--message", "m", "--title", "t", "--level", "action", "--link", "https://a.b/"]
    result = run(argv, fake_gateway, monkeypatch, stdin=b'{"message":"stdin"}')
    assert result.value == {
        "message": "m",
        "title": "t",
        "level": "action",
        "link": "https://a.b/",
    }
    assert fake_gateway.source_reads == 0


def test_dedupe_key_and_decision_ids_are_accepted_and_ignored(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["send", "--message", "m", "--dedupe-key=-k", "--decision-id", "a", "--decision-id=b"]
    result = run(argv, fake_gateway, monkeypatch)
    assert (result.code, result.value) == (0, {"message": "m"})


@pytest.mark.parametrize(
    "key", ["k", "-", "é", "x" * 1024, "é" * 1024, "😀" * 1024, "a b\n", "\x00"]
)
def test_dedupe_key_accepts_one_to_1024_characters(
    key: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", "--message", "m", f"--dedupe-key={key}"], fake_gateway, monkeypatch)
    assert result.code == 0


@pytest.mark.parametrize(
    "key", ["", "x" * 1025, "é" * 1025, "\udcff", "ok\udc80", "\ud800", "x" * 1023 + "\udcff"]
)
def test_dedupe_key_outside_the_rule_is_usage(
    key: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", "--message", "m", f"--dedupe-key={key}"], fake_gateway, monkeypatch)
    assert (result.code, result.error["code"]) == (2, "usage")
    assert "\udcff" not in result.out
    assert "x" * 100 not in result.out + result.err


def test_a_dedupe_key_value_with_a_leading_dash_needs_the_equals_form(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", "--message", "m", "--dedupe-key", "-k"], fake_gateway, monkeypatch)
    assert result.code == 2
    assert run(["send", "--message", "m", "--dedupe-key=-k"], fake_gateway, monkeypatch).code == 0


def test_a_repeated_dedupe_key_is_usage(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["send", "--message", "m", "--dedupe-key=a", "--dedupe-key", "b"]
    assert run(argv, fake_gateway, monkeypatch).code == 2


def test_abbreviations_and_the_separator_stay_refused(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    for argv in (
        ["send", "--mess", "m"],
        ["send", "--message", "m", "--lev", "info"],
        ["send", "--message", "m", "--dedupe", "k"],
        ["send", "--message", "m", "--"],
        ["send", "--", "--message", "m"],
        ["send", "--std"],
    ):
        assert run(argv, fake_gateway, monkeypatch).code == 2, argv


# --- ordering: combination errors win over a disabled tool and over the home -------------------


def disabled_config(path: Path) -> str:
    path.write_text("enabled: false\n")
    return str(path)


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--stdin-json", "--file", "x", "--dedupe-key=k"],
        ["send", "--stdin-json", "--title", "t"],
        ["send", "--file", "x", "--message", "m"],
        ["send", "--level", "warn"],
    ],
)
def test_a_combination_error_exits_2_even_when_the_tool_is_disabled(
    argv: list[str], fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = disabled_config(tmp_path / "disabled.yaml")
    result = run([*argv, "--config", config], fake_gateway, monkeypatch)
    assert (result.code, result.error["code"]) == (2, "usage")
    assert "disabled" not in result.out
    assert fake_gateway.home_lookups == 0  # step 1 wins: the home was not even looked up


def test_a_combination_error_exits_2_on_a_terminal_with_a_disabled_config(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = disabled_config(tmp_path / "disabled.yaml")
    result = run(
        ["send", "--config", config, "--dedupe-key=k"], fake_gateway, monkeypatch, tty=True
    )
    assert (result.code, result.error["code"]) == (2, "usage")
    assert fake_gateway.home_lookups == 0


def test_a_good_combination_reaches_the_handler_after_the_home_lookup(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", "--message", "m"], fake_gateway, monkeypatch)
    assert result.code == 0
    assert fake_gateway.home_lookups == 1


# --- step 3: exit 20 with a pointer ---------------------------------------------------------


def error_of(result: Result) -> dict[str, Any]:
    error = result.error
    assert result.code == 20
    assert error["code"] == "refused"
    assert error["reason"] == "invalid_payload"
    assert error["retryable"] is None and error["unknown_outcome"] is None
    assert set(error["details"]) == {"pointer"}
    return error


def test_a_5000_character_key_gives_the_pointer_question_mark(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = json.dumps({"message": "a", "k" * 5000: 1}).encode()
    result = run(["send", "--stdin-json"], fake_gateway, monkeypatch, stdin=body)
    # A number is refused by the parser before any field is looked at (pointer "").
    assert error_of(result)["details"]["pointer"] == ""
    body = json.dumps({"message": "a", "k" * 5000: "v"}).encode()
    result = run(["send", "--stdin-json"], fake_gateway, monkeypatch, stdin=body)
    assert error_of(result)["details"]["pointer"] == "/?"
    body = json.dumps({"message": "a", "\x1b" * 5000: "v"}).encode()
    result = run(["send", "--stdin-json"], fake_gateway, monkeypatch, stdin=body)
    assert error_of(result)["details"]["pointer"] == "/?"


@pytest.mark.parametrize(
    ("body", "pointer"),
    [
        (b'{"message":"a","extra":"v"}', "/extra"),
        (b'{"message":"a","\\ud800":"v"}', "/?"),
        (b'{"message":"a","\\u0000":"v"}', "/?"),
        (b'{"message":"a","title":null}', "/title"),
        (b'{"message":null}', "/message"),
        (b'{"message":["a"]}', "/message"),
        (b'{"message":{"a":"b"}}', "/message"),
        (b'{"message":"a","level":true}', "/level"),
        (b'{"message":"a","level":"INFO"}', "/level"),
        (b'{"message":"a","link":["https://a.b/"]}', "/link"),
        (b'{"message":"a","title":"' + b"x" * 100_001 + b'"}', "/title"),
        (b'{"message":"' + b"x" * 100_001 + b'"}', "/message"),
        (b'{"message":"a","title":' + b"[" * 2000 + b"]" * 2000 + b"}", "/title"),
        (b'{"message":' + b'{"a":' * 1000 + b'"x"' + b"}" * 1000 + b"}", "/message"),
        (b'{"message":"a","a":' + b"[" * 2000 + b"]" * 2000 + b"}", "/a"),
    ],
)
def test_stdin_fields_are_refused_with_a_pointer(
    body: bytes, pointer: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", "--stdin-json"], fake_gateway, monkeypatch, stdin=body)
    assert error_of(result)["details"]["pointer"] == pointer
    assert "x" * 100 not in result.out + result.err


FLAG_CASES = [
    (["--level", "bogus"], "/level"),
    (["--level="], "/level"),
    (["--level", "INFO"], "/level"),
    (["--title", "x" * 100_001], "/title"),
]


@pytest.mark.parametrize(("flags", "pointer"), FLAG_CASES)
def test_flag_values_are_refused_with_the_json_pointer(
    flags: list[str], pointer: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", "--message", "m", *flags], fake_gateway, monkeypatch)
    assert error_of(result)["details"]["pointer"] == pointer


def test_a_too_long_message_flag_is_refused_at_message(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", "--message", "x" * 100_001], fake_gateway, monkeypatch)
    assert error_of(result)["details"]["pointer"] == "/message"
    assert fake_gateway.source_reads == 0


@pytest.mark.parametrize(
    ("flags", "fields"),
    [
        (["--level", "bogus"], {"level": "bogus"}),
        (["--level="], {"level": ""}),
        (["--title", "x" * 100_001], {"title": "x" * 100_001}),
    ],
)
def test_flag_and_stdin_input_give_the_same_error(
    flags: list[str],
    fields: dict[str, str],
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from_flags = run(["send", "--message", "m", *flags], fake_gateway, monkeypatch)
    body = json.dumps({"message": "m", **fields}).encode()
    from_stdin = run(["send", "--stdin-json"], fake_gateway, monkeypatch, stdin=body)
    assert from_flags.out == from_stdin.out
    assert from_flags.err == from_stdin.err


def test_flag_and_stdin_input_give_the_same_object(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    flags = ["--message", "m\né", "--title", "t", "--level", "error", "--link", "https://a.b/x"]
    obj = {"message": "m\né", "title": "t", "level": "error", "link": "https://a.b/x"}
    from_flags = run(["send", *flags], fake_gateway, monkeypatch)
    from_stdin = run(["send"], fake_gateway, monkeypatch, stdin=json.dumps(obj).encode())
    assert from_flags.value == from_stdin.value == obj


def test_empty_values_pass_this_step_for_the_sanitizer(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(["send", "--message=", "--title="], fake_gateway, monkeypatch)
    assert (result.code, result.value) == (0, {"message": "", "title": ""})


def test_no_output_ever_holds_an_input_value(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (argv, stdin, pointer_echo): a field name that matches the pattern is reported in the
    # pointer as the spec says; that pointer is the only place an input text may appear.
    cases: list[tuple[list[str], bytes | None, bool]] = [
        (["send", "--message", "m", "--level", CANARY], None, False),
        (["send", "--message", CANARY * 20_000], None, False),
        (["send", "--message", "m", "--title", CANARY * 20_000], None, False),
        (
            ["send", "--stdin-json"],
            json.dumps({"message": "a", CANARY + "!": CANARY}).encode(),
            False,
        ),
        (
            ["send", "--stdin-json"],
            json.dumps({"message": CANARY, "level": CANARY}).encode(),
            False,
        ),
        (
            ["send", "--stdin-json"],
            json.dumps({"message": [CANARY], CANARY: [CANARY]}).encode(),
            True,
        ),
        (["send", "--stdin-json"], json.dumps({CANARY: "v"}).encode(), True),
        (["send", "--message", "m", "--title", "t", "--stdin-json"], None, False),
        (["send", "--message", "m", f"--dedupe-key={'é' * 1025}{CANARY}"], None, False),
    ]
    for argv, stdin, pointer_echo in cases:
        for json_mode in (True, False):
            result = run(argv, fake_gateway, monkeypatch, stdin=stdin, json_mode=json_mode)
            assert result.code in (2, 20)
            text = result.out + result.err
            if pointer_echo:
                text = text.replace("/" + CANARY, "")
            assert CANARY not in text
    # a field name that matches the pattern is reported as the spec says: that is the one echo
    result = run(
        ["send", "--stdin-json"],
        fake_gateway,
        monkeypatch,
        stdin=json.dumps({CANARY: "v"}).encode(),
    )
    assert error_of(result)["details"]["pointer"] == "/" + CANARY
    assert CANARY not in error_of(result)["message"]


def test_the_stderr_line_is_fixed_and_names_the_reason(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = run(
        ["send", "--message", "m", "--level", "zzz"], fake_gateway, monkeypatch, json_mode=False
    )
    assert result.code == 20
    assert result.err == (
        "refused (invalid_payload): level must be one of info, warn, action, error\n"
    )


def test_the_refusal_has_no_exception_context(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    caught: list[CliError] = []

    def handler(ctx: Context) -> int:
        try:
            cli.load_notification(ctx, 10.0)
        except CliError as error:
            caught.append(error)
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    streams = Streams(io.BytesIO(), io.BytesIO(), lambda: False)
    main(["send", "--message", CANARY, "--level", CANARY], {}, fake_gateway, streams)
    assert len(caught) == 1
    assert caught[0].__cause__ is None and caught[0].__context__ is None


def test_an_input_that_is_not_an_object_keeps_its_root_pointer(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    for body in (b"[]", b"null", b"", b'"x"', b'{"message":1}'):
        result = run(["send", "--stdin-json"], fake_gateway, monkeypatch, stdin=body)
        assert error_of(result)["details"]["pointer"] == ""


# --- the refusal reasons of the envelope ------------------------------------------------------


@pytest.mark.parametrize(
    "reason", ["invalid_payload", "empty_message", "link_invalid", "link_scheme"]
)
def test_every_refusal_reason_is_a_valid_envelope(reason: str) -> None:
    # invalid_payload is produced here; empty_message (#17) and link_* (#18) reuse the envelope.
    pointer = {"pointer": "/message"} if reason == "invalid_payload" else None
    error = CliError(20, "refused", "fixed message", reason=reason, details=pointer)
    assert_valid("cli/error", json.dumps(error.envelope()))


# --- settings ---------------------------------------------------------------------------------


def test_settings_are_the_validated_config_with_timeout_in_seconds(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []

    def handler(ctx: Context) -> int:
        seen.append(cli.load_settings(ctx))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    streams = Streams(io.BytesIO(), io.BytesIO(), lambda: False)
    argv = ["send", "--message", "m", "--title", "t", "--level", "warn", "--link", "https://a.b/"]
    assert main(argv, {}, fake_gateway, streams) == 0
    settings = seen[0]
    assert set(settings) == set(DEFAULTS)  # no flag leaks in as a setting
    assert settings["timeout"] == 10.0 and isinstance(settings["timeout"], float)
    assert DEFAULTS["timeout"] == "10s"  # the raw default is not what callers use

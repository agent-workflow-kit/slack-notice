"""Input reading and limits (issue #15): bytes, UTF-8, the size cap, hardened JSON, exit codes.

The reading itself (slices, cap, timeout) is the gateway's and is tested in test_gateway.py;
these tests cover the mapping of its results and the parse rules, with hostile inputs.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, payload
from slack_notice.cli import Context, Streams, main
from slack_notice.gateway import SourceRead
from tests.fake_gateway import FakeGateway
from tests.harness import assert_valid

CAP = 1_048_576
# Built from parts: the tests plant this in input and assert it never comes out.
CANARY = "CAN" + "ARY-" + "7f3a"


# --- decode_notification: the hardened parser -------------------------------------------


def refusal(data: bytes) -> payload.InputRefused:
    with pytest.raises(payload.InputRefused) as info:
        payload.decode_notification(data)
    return info.value


def test_a_plain_object_is_returned() -> None:
    assert payload.decode_notification(b'{"title":"x","message":"y"}') == {
        "title": "x",
        "message": "y",
    }


@pytest.mark.parametrize(
    "data", [b"{}", b' \n\t{"message" : "a"}\r\n', '{"message":"é😀"}'.encode()]
)
def test_valid_objects_are_accepted(data: bytes) -> None:
    assert isinstance(payload.decode_notification(data), dict)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"   \n\t ",
        b"[]",
        b"null",
        b'"x"',
        b"true",
        b"[{}]",
        b'{"message":"a","message":"b"}',
        b'{"a":{"k":1,"k":2}}'.replace(b"1", b'"1"').replace(b"2", b'"2"'),
        b'{"message":NaN}',
        b'{"message":Infinity}',
        b'{"message":-Infinity}',
        b'{"message":1}',
        b'{"message":1.5}',
        b'{"message":-0}',
        b'{"message":1e5}',
        b'{"a":[1]}',
        b'{"message":"a"} trailing',
        b'{"message":"a"}{"message":"b"}',
        b'{"message":"a",}',
        b"{'message':'a'}",
        b'{"message":"a\x00"}',  # raw NUL inside a string
        b'{"message":"a\nb"}',  # raw control character inside a string
        b'{"message":"\\ud800"'  # truncated
        b"",
        b"\x00",
        b'{"message":"a"}\x00',
    ],
)
def test_unparseable_or_refused_json_is_invalid_payload(data: bytes) -> None:
    assert refusal(data).reason == "invalid"


def test_the_refusal_names_the_pointer_and_never_holds_input() -> None:
    err = refusal(('{"message":"' + CANARY + '","message":"b"}').encode())
    assert err.pointer == ""
    assert CANARY not in str(err) + repr(err) + err.args.__repr__()


@pytest.mark.parametrize(
    "data",
    [
        b"\xef\xbb\xbf{}",
        b"\xef\xbb\xbf",
        b"\xff\xfe{\x00}\x00",  # UTF-16 BOM
    ],
)
def test_a_byte_order_mark_is_refused(data: bytes) -> None:
    assert refusal(data).reason in {"bom", "utf8"}


def test_utf8_bom_is_reported_as_bom_not_as_parse_failure() -> None:
    assert refusal(b"\xef\xbb\xbf{}").reason == "bom"


@pytest.mark.parametrize(
    "data",
    [
        b'{"message":"\xff"}',
        b'{"message":"\xc3"}',  # truncated sequence
        b'{"message":"\xc0\xaf"}',  # overlong
        b'{"message":"\xed\xa0\x80"}',  # a lone surrogate encoded as UTF-8
        b'{"message":"\xed\xbf\xbf"}',
        b'{"message":"\xf4\x90\x80\x80"}',  # above U+10FFFF
        b'{"message":"\x80"}',
        b'{"\xff":"a"}',
    ],
)
def test_invalid_utf8_is_refused(data: bytes) -> None:
    assert refusal(data).reason == "utf8"


@pytest.mark.parametrize("depth", [100000, 500000])
def test_deep_nesting_is_refused_without_crashing(depth: int) -> None:
    data = b'{"a":' + b"[" * depth + b"]" * depth + b"}"
    assert refusal(data).reason == "invalid"


def test_deep_object_nesting_is_refused() -> None:
    data = b'{"a":' * 100000 + b"1" + b"}" * 100000
    assert refusal(data).reason == "invalid"


@pytest.mark.parametrize("digits", [5000, 100000, CAP - 20])
def test_huge_integers_are_refused(digits: int) -> None:
    data = b'{"message":' + b"9" * digits + b"}"
    assert refusal(data).reason == "invalid"


def test_a_one_mib_integer_string_is_refused_under_any_digit_limit() -> None:
    import sys

    saved = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)  # the limit is off: the parser must still never build the int
    try:
        data = b'{"message":' + b"9" * (CAP - 20) + b"}"
        assert refusal(data).reason == "invalid"
    finally:
        sys.set_int_max_str_digits(saved)


@pytest.mark.parametrize("exc", [ValueError, RecursionError, OverflowError])
def test_any_parser_exception_of_the_three_classes_is_refused(
    monkeypatch: pytest.MonkeyPatch, exc: type[Exception]
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise exc(CANARY)

    monkeypatch.setattr(payload.json, "loads", boom)
    err = refusal(b"{}")
    assert err.reason == "invalid"
    assert err.pointer == ""
    assert CANARY not in repr(err) + str(err)


def test_duplicate_keys_at_any_depth_are_refused() -> None:
    assert refusal(b'{"a":{"b":"x","b":"y"}}').reason == "invalid"
    assert refusal(b'{"a":[{"b":"x","b":"y"}]}').reason == "invalid"
    # An escaped spelling of the same key is the same key.
    assert refusal(b'{"message":"a","m\\u0065ssage":"b"}').reason == "invalid"


def test_distinct_keys_that_differ_only_in_case_are_fine() -> None:
    assert payload.decode_notification(b'{"a":"1","A":"2"}') == {"a": "1", "A": "2"}


def test_a_huge_single_line_within_the_cap_parses() -> None:
    data = b'{"message":"' + b"a" * (CAP - 20) + b'"}'
    assert len(payload.decode_notification(data)["message"]) == CAP - 20


def test_a_lone_surrogate_escape_is_left_to_validation() -> None:
    # validate_notification (#17) refuses it with a pointer; the parser passes it on.
    assert payload.decode_notification(b'{"message":"\\ud800"}')["message"] == "\ud800"


def test_empty_object_and_missing_message_are_left_to_validation() -> None:
    assert payload.decode_notification(b'{"title":"x"}') == {"title": "x"}


# --- read_notification: gateway results to errors --------------------------------------------


def read(gateway: FakeGateway, source: int | str, remaining: float = 5.0) -> dict[str, Any]:
    return payload.read_notification(gateway, source, remaining)


def test_the_size_cap_is_one_mib(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    exact = tmp_path / "exact.json"
    prefix = b'{"message":"'
    exact.write_bytes(prefix + b"a" * (CAP - len(prefix) - 2) + b'"}')
    assert exact.stat().st_size == CAP
    assert len(read(fake_gateway, str(exact))["message"]) == CAP - len(prefix) - 2
    over = tmp_path / "over.json"
    over.write_bytes(prefix + b"a" * (CAP - len(prefix) - 1) + b'"}')
    assert over.stat().st_size == CAP + 1
    with pytest.raises(payload.InputRefused) as info:
        read(fake_gateway, str(over))
    assert info.value.reason == "too_large"
    assert info.value.pointer == ""


def test_too_large_wins_over_the_content(fake_gateway: FakeGateway) -> None:
    fake_gateway.source_script.append(SourceRead(b"\xff" * CAP, too_large=True))
    with pytest.raises(payload.InputRefused) as info:
        read(fake_gateway, 0)
    assert info.value.reason == "too_large"


def test_a_timeout_is_not_judged(fake_gateway: FakeGateway) -> None:
    # Ten bytes that would be invalid UTF-8 and a stall: the bytes were not judged.
    fake_gateway.source_script.append(SourceRead(b"\xff" * 10, timed_out=True))
    with pytest.raises(payload.InputTimedOut):
        read(fake_gateway, 0)


def test_the_gateway_is_asked_for_the_cap_and_the_time_left(fake_gateway: FakeGateway) -> None:
    calls: list[tuple[Any, int, float]] = []
    real = fake_gateway.read_source

    def spy(source: Any, max_bytes: int, remaining: float) -> SourceRead:
        calls.append((source, max_bytes, remaining))
        return real(source, max_bytes, remaining)

    fake_gateway.read_source = spy  # type: ignore[method-assign]
    fake_gateway.source_script.append(SourceRead(b"{}"))
    read(fake_gateway, 0, 7.5)
    assert calls == [(0, CAP, 7.5)]


def test_a_closed_stdin_is_empty_input_hence_invalid(fake_gateway: FakeGateway) -> None:
    read_end, write_end = os.pipe()
    os.close(read_end)
    os.close(write_end)
    with pytest.raises(payload.InputRefused) as info:
        read(fake_gateway, read_end)  # the descriptor is closed: empty input
    assert info.value.reason == "invalid"


def test_a_passed_descriptor_is_not_closed(fake_gateway: FakeGateway) -> None:
    read_end, write_end = os.pipe()
    os.write(write_end, b"{}")
    os.close(write_end)
    try:
        assert read(fake_gateway, read_end) == {}
        os.fstat(read_end)  # still open
    finally:
        os.close(read_end)


def test_a_symlink_to_a_regular_file_is_accepted(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    target = tmp_path / "t.json"
    target.write_bytes(b'{"message":"x"}')
    link = tmp_path / "l.json"
    link.symlink_to(target)
    assert read(fake_gateway, str(link)) == {"message": "x"}


def test_an_empty_regular_file_is_empty_input(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    empty = tmp_path / "e"
    empty.write_bytes(b"")
    with pytest.raises(payload.InputRefused) as info:
        read(fake_gateway, str(empty))
    assert info.value.reason == "invalid"


def file_problem(gateway: FakeGateway, source: str) -> payload.SourceUnusable:
    with pytest.raises(payload.SourceUnusable) as info:
        read(gateway, source)
    return info.value


def test_file_problems(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    file_problem(fake_gateway, str(tmp_path / "missing"))
    file_problem(fake_gateway, str(tmp_path))  # a directory
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    file_problem(fake_gateway, str(fifo))  # no hang
    file_problem(fake_gateway, "/dev/zero")
    file_problem(fake_gateway, "/dev/null")
    file_problem(fake_gateway, "")
    file_problem(fake_gateway, "bad\x00name")
    blocked = tmp_path / "blocked"
    blocked.write_bytes(b"{}")
    blocked.chmod(0)
    if os.geteuid() != 0:
        file_problem(fake_gateway, str(blocked))
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    file_problem(fake_gateway, str(loop))
    long_name = str(tmp_path / ("n" * 5000))
    file_problem(fake_gateway, long_name)


def test_a_read_error_mid_file_is_a_file_problem(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.source_script.append(OSError(5, "I/O error " + CANARY))
    err = file_problem(fake_gateway, "/anything")
    assert CANARY not in repr(err) + str(err)


def test_the_cap_error_for_a_regular_file_is_exit_20_not_a_file_problem(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    big = tmp_path / "big"
    big.write_bytes(b" " * (CAP + 1))
    with pytest.raises(payload.InputRefused):
        read(fake_gateway, str(big))


# --- the CLI mapping ---------------------------------------------------------------------------


class Result:
    def __init__(self, code: int, out: bytes, err: bytes, value: Any) -> None:
        self.code = code
        self.out = out.decode()
        self.err = err.decode()
        self.value = value

    @property
    def error(self) -> dict[str, Any]:
        return json.loads(self.out)["error"]


def run_read(
    argv: list[str],
    gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    *,
    tty: bool = False,
    remaining: float = 10.0,
) -> Result:
    seen: list[Any] = []

    def handler(ctx: Context) -> int:
        seen.append(cli.read_input(ctx, remaining))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    out, err = io.BytesIO(), io.BytesIO()
    streams = Streams(out=out, err=err, stdin_is_tty=lambda: tty)
    code = main(argv, {}, gateway, streams)
    return Result(code, out.getvalue(), err.getvalue(), seen[0] if seen else None)


def test_stdin_is_read_from_descriptor_zero(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources: list[Any] = []
    real = fake_gateway.read_source

    def spy(source: Any, max_bytes: int, remaining: float) -> SourceRead:
        sources.append(source)
        return real(source, max_bytes, remaining)

    fake_gateway.read_source = spy  # type: ignore[method-assign]
    for argv in (["send", "--stdin-json"], ["send"], ["send", "--file", "-"]):
        fake_gateway.source_script.append(SourceRead(b'{"message":"x"}'))
        result = run_read(argv, fake_gateway, monkeypatch)
        assert result.code == 0
        assert result.value == {"message": "x"}
    assert sources == [0, 0, 0]


def test_file_path_is_read_as_a_path(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "n.json"
    path.write_bytes(b'{"message":"from file"}')
    result = run_read(["send", "--file", str(path)], fake_gateway, monkeypatch)
    assert (result.code, result.value) == (0, {"message": "from file"})


@pytest.mark.parametrize(
    ("data", "reason_text"),
    [
        (b"", "not a JSON object"),
        (b"[]", "not a JSON object"),
        (b"null", "not a JSON object"),
        (b'"x"', "not a JSON object"),
        (b"\xef\xbb\xbf{}", "byte order mark"),
        (b'{"message":"a","message":"b"}', "not a JSON object"),
        (b'{"message":NaN}', "not a JSON object"),
        (b"\xff", "UTF-8"),
    ],
)
def test_input_table_exit_20(
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    data: bytes,
    reason_text: str,
) -> None:
    fake_gateway.source_script.append(SourceRead(data))
    result = run_read(["send", "--json", "--stdin-json"], fake_gateway, monkeypatch)
    assert result.code == 20
    error = result.error
    assert error["code"] == "refused"
    assert error["reason"] == "invalid_payload"
    assert error["details"] == {"pointer": ""}
    assert error["retryable"] is None
    assert error["unknown_outcome"] is None
    assert reason_text in error["message"]
    assert_valid("cli/error", result.out)
    assert result.err.startswith("refused (invalid_payload): ")


def test_one_mib_plus_one_is_exit_20(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_gateway.source_script.append(SourceRead(b" " * CAP, too_large=True))
    result = run_read(["send", "--json", "--stdin-json"], fake_gateway, monkeypatch)
    assert result.code == 20
    assert result.error["reason"] == "invalid_payload"
    assert result.error["details"] == {"pointer": ""}
    assert "1048576" in result.error["message"]


def test_a_stall_is_exit_12_unavailable_input(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_gateway.source_script.append(SourceRead(b"0123456789", timed_out=True))
    result = run_read(["send", "--json", "--stdin-json"], fake_gateway, monkeypatch)
    assert result.code == 12
    error = result.error
    assert error["code"] == "unavailable"
    assert error["reason"] is None
    assert error["details"] == {"phase": "input"}
    assert error["retryable"] is True
    assert error["unknown_outcome"] is False
    assert error["retry_after_s"] is None
    assert_valid("cli/error", result.out)
    assert "0123456789" not in result.out + result.err


def test_a_timeout_with_no_time_left(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    read_end, write_end = os.pipe()
    os.write(write_end, b"{}")
    os.close(write_end)
    try:
        with pytest.raises(payload.InputTimedOut):
            payload.read_notification(fake_gateway, read_end, 0.0)
    finally:
        os.close(read_end)


@pytest.mark.parametrize("kind", ["missing", "directory", "fifo", "zero"])
def test_file_problems_are_exit_2_usage(
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    target = {
        "missing": str(tmp_path / "nope"),
        "directory": str(tmp_path),
        "fifo": str(tmp_path / "ff"),
        "zero": "/dev/zero",
    }[kind]
    if kind == "fifo":
        os.mkfifo(target)
    result = run_read(["send", "--json", "--file", target], fake_gateway, monkeypatch)
    assert result.code == 2
    assert result.error["code"] == "usage"
    assert result.error["details"] is None
    assert target not in result.out + result.err
    assert_valid("cli/error", result.out)


def test_a_regular_file_over_the_cap_is_exit_20(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (CAP + 1))
    result = run_read(["send", "--json", "--file", str(big)], fake_gateway, monkeypatch)
    assert result.code == 20
    assert result.error["reason"] == "invalid_payload"


@pytest.mark.parametrize("argv", [["send", "--stdin-json"], ["send", "--file", "-"]])
def test_a_json_source_on_a_terminal_is_exit_2(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    result = run_read([*argv, "--json"], fake_gateway, monkeypatch, tty=True)
    assert result.code == 2
    assert result.error["code"] == "usage"
    assert fake_gateway.source_reads == 0


def test_a_terminal_does_not_stop_a_named_file(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "n.json"
    path.write_bytes(b"{}")
    result = run_read(["send", "--file", str(path)], fake_gateway, monkeypatch, tty=True)
    assert result.code == 0


def test_the_terminal_check_runs_before_any_home_lookup(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    broken = FakeGateway(home=str(tmp_path / "gwhome"), home_error=True)
    result = run_read(["send", "--stdin-json", "--json"], broken, monkeypatch, tty=True)
    assert result.code == 2
    assert result.error["code"] == "usage"
    assert broken.home_lookups == 0
    assert broken.source_reads == 0


def test_input_text_never_reaches_stderr_or_stdout(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile: list[bytes] = [
        ('{"message":"' + CANARY + '","message":"x"}').encode(),
        ('{"message":"' + CANARY + '"').encode(),
        ("[" + '"' + CANARY + '"]').encode(),
        (CANARY + "\xff").encode("latin-1"),
        b"\xef\xbb\xbf" + CANARY.encode(),
        ('{"message":' + CANARY + "}").encode(),
        ('{"' + CANARY + '":NaN}').encode(),
    ]
    for data in hostile:
        fake_gateway.source_script.append(SourceRead(data))
        result = run_read(["send", "--json", "--stdin-json"], fake_gateway, monkeypatch)
        assert result.code == 20
        assert CANARY not in result.out + result.err


def test_timeout_and_cap_messages_are_fixed_strings(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def message_of(item: SourceRead) -> str:
        fake_gateway.source_script.append(item)
        result = run_read(["send", "--json", "--stdin-json"], fake_gateway, monkeypatch)
        return str(result.error["message"])

    timeouts = {message_of(SourceRead(b"x" * n, timed_out=True)) for n in (1, 50)}
    caps = {message_of(SourceRead(b"x" * n, too_large=True)) for n in (1, 50)}
    assert timeouts == {cli.INPUT_TIMEOUT_MESSAGE}
    assert caps == {payload.REFUSAL_MESSAGES["too_large"]}


@pytest.mark.parametrize("reason", sorted(payload.REFUSAL_MESSAGES))
def test_refusal_messages_are_fixed_per_reason(reason: str) -> None:
    assert payload.InputRefused(reason).message == payload.REFUSAL_MESSAGES[reason]
    assert len(set(payload.REFUSAL_MESSAGES.values())) == len(payload.REFUSAL_MESSAGES)


def test_a_closed_stdin_is_empty_input_not_too_large(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With fd 0 closed at start, sys.stdin is None and descriptor 0 may be reused by something
    # else: stdin is not read at all.
    monkeypatch.setattr("sys.stdin", None)
    for argv in (["send"], ["send", "--stdin-json"], ["send", "--file", "-"]):
        result = run_read([*argv, "--json"], fake_gateway, monkeypatch)
        assert result.code == 20
        assert result.error["reason"] == "invalid_payload"
        assert result.error["message"] == payload.REFUSAL_MESSAGES["invalid"]
    assert fake_gateway.source_reads == 0


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"\xef\xbb\xbf{}", "bom"),
        (CANARY.encode() + b"\xff", "utf8"),
        (b'{"message":"' + CANARY.encode() + b'"', "invalid"),
        (b'{"message":"' + CANARY.encode() + b'","message":"x"}', "invalid"),
        (b"[" + CANARY.encode() + b"]", "invalid"),
        (b'["' + CANARY.encode() + b'"]', "invalid"),
    ],
)
def test_refusals_keep_no_exception_chain(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, data: bytes, reason: str
) -> None:
    err = refusal(data)
    assert err.reason == reason
    assert err.__cause__ is None
    assert err.__context__ is None
    caught: list[cli.CliError] = []

    def handler(ctx: Context) -> int:
        try:
            cli.read_input(ctx, 10.0)
        except cli.CliError as error:
            caught.append(error)
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    fake_gateway.source_script.append(SourceRead(data))
    streams = Streams(io.BytesIO(), io.BytesIO(), lambda: False)
    main(["send", "--stdin-json"], {}, fake_gateway, streams)
    assert len(caught) == 1
    assert caught[0].__cause__ is None
    assert caught[0].__context__ is None


def test_read_input_is_not_called_by_parsing_alone(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", lambda _ctx: 0)
    out, err = io.BytesIO(), io.BytesIO()
    assert main(["send", "--stdin-json"], {}, fake_gateway, Streams(out, err, lambda: False)) == 0
    assert fake_gateway.source_reads == 0


@pytest.mark.parametrize(
    "script", [SourceRead(b"0123456789", timed_out=True), OSError(5, "I/O error")]
)
def test_timeout_and_unusable_errors_carry_no_exception_chain(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, script: SourceRead | OSError
) -> None:
    raised: list[cli.CliError] = []

    def handler(ctx: Context) -> int:
        try:
            cli.read_input(ctx, 10.0)
        except cli.CliError as error:
            raised.append(error)
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    fake_gateway.source_script.append(script)
    streams = Streams(out=io.BytesIO(), err=io.BytesIO(), stdin_is_tty=lambda: False)
    main(["send", "--json", "--stdin-json"], {}, fake_gateway, streams)
    assert len(raised) == 1
    assert raised[0].__cause__ is None
    assert raised[0].__context__ is None

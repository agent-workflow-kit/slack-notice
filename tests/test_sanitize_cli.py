"""The sanitizer through the command line: ``empty_message`` and lone surrogates (issue #17)."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from slack_notice import cli
from slack_notice.cli import Context, Streams, main
from slack_notice.gateway import SourceRead
from tests.fake_gateway import FakeGateway
from tests.harness import assert_valid

CANARY = "CAN" + "ARY-" + "5e17"


def run(
    argv: list[str], gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, stdin: bytes | None
) -> tuple[int, str, Any]:
    seen: list[Any] = []

    def handler(ctx: Context) -> int:
        seen.append(cli.sanitize_loaded(cli.load_notification(ctx, 10.0)))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    if stdin is not None:
        gateway.source_script.append(SourceRead(stdin))
    out = io.BytesIO()
    code = main([*argv, "--json"], {}, gateway, Streams(out, io.BytesIO(), lambda: False))
    return code, out.getvalue().decode(), seen[0] if seen else None


EMPTY_INPUTS = [
    b"{}",
    b'{"title":"x"}',
    b'{"message":""}',
    b'{"message":" \\n\\t "}',
    b'{"message":"\\u3164"}',
    b'{"message":"\\u200d"}',
    b'{"message":"\\u2d7f"}',
    b'{"message":"\\u0301"}',
    b'{"message":"\\ud804\\udc7f"}',
    b'{"message":"\\u3000"}',
]


@pytest.mark.parametrize("stdin", EMPTY_INPUTS)
def test_an_empty_message_is_refused_with_no_pointer(
    stdin: bytes, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, seen = run(["send"], fake_gateway, monkeypatch, stdin)
    assert code == 20 and seen is None
    assert_valid("cli/error", out)
    error = json.loads(out)["error"]
    assert error["code"] == "refused" and error["reason"] == "empty_message"
    assert not error.get("details")


def test_flags_that_are_empty_by_the_definition_are_refused_alike(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _ = run(["send", "--message", "\u3164\u200d"], fake_gateway, monkeypatch, None)
    assert code == 20 and json.loads(out)["error"]["reason"] == "empty_message"


def test_a_visible_message_passes_and_is_sanitized(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = json.dumps({"title": "a\nb", "message": "x\r\n \r\n \r\ny\u202e"}).encode()
    code, _, seen = run(["send"], fake_gateway, monkeypatch, body)
    assert code == 0
    assert (seen.title, seen.message, seen.level) == ("a b", "x\n\ny", "info")


@pytest.mark.parametrize(
    ("stdin", "pointer"),
    [
        (b'{"message":"\\ud800"}', "/message"),
        (b'{"message":"m","title":"\\udfff"}', "/title"),
        (b'{"message":"m","\\ud800":"v"}', "/?"),
    ],
)
def test_a_json_escaped_lone_surrogate_is_exit_20_with_the_pointer(
    stdin: bytes, pointer: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _ = run(["send"], fake_gateway, monkeypatch, stdin)
    assert code == 20
    assert_valid("cli/error", out)
    error = json.loads(out)["error"]
    assert error["reason"] == "invalid_payload" and error["details"]["pointer"] == pointer


def test_the_message_never_appears_in_the_refusal(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = json.dumps({"message": CANARY + "\ud800"}, ensure_ascii=True).encode()
    code, out, _ = run(["send"], fake_gateway, monkeypatch, body)
    assert code == 20 and CANARY not in out


def run_capturing(
    argv: list[str], gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> tuple[int, str, str]:
    def handler(ctx: Context) -> int:
        cli.sanitize_loaded(cli.load_notification(ctx, 10.0))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    out, err = io.BytesIO(), io.BytesIO()
    code = main([*argv, "--json"], {}, gateway, Streams(out, err, lambda: False))
    return code, out.getvalue().decode(), err.getvalue().decode()


@pytest.mark.parametrize("flag", ["message", "title", "link"])
def test_a_lone_surrogate_in_a_flag_is_exit_20_with_the_flag_pointer(
    flag: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["send", "--message", "m"] if flag != "message" else ["send"]
    code, out, err = run_capturing([*argv, f"--{flag}", "a\udc80b"], fake_gateway, monkeypatch)
    assert code == 20
    assert_valid("cli/error", out)
    error = json.loads(out)["error"]
    assert error["reason"] == "invalid_payload" and error["details"]["pointer"] == f"/{flag}"
    assert "\udc80" not in out + err


# Pins enum-first ordering and the no-echo behaviour; the surrogate check itself is
# pinned by the title/message/link cases above.
def test_a_bad_level_with_a_surrogate_fails_the_enum_rule_at_level_without_echo(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, err = run_capturing(
        ["send", "--message", "m", "--level", CANARY + "\udc80"], fake_gateway, monkeypatch
    )
    assert code == 20
    assert_valid("cli/error", out)
    error = json.loads(out)["error"]
    assert error["reason"] == "invalid_payload" and error["details"]["pointer"] == "/level"
    assert "\udc80" not in out + err and CANARY not in out + err

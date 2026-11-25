"""The webhook URL allowlist and credential handling (issue #22).

No URL here is a real or credential-shaped literal: every value is assembled at run time from
parts around a CANARY token, so a leak is found by searching for the token.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import http.client
import io
import logging
import traceback
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, webhook
from slack_notice.webhook import CredentialInvalid, Webhook, read_webhook
from tests.fake_gateway import FakeGateway

CANARY = "CAN" + "ARY" + "-22x"
SEG = CANARY.replace("-", "_") + "seg"  # inside [A-Za-z0-9_-]
HOST = "hooks" + ".slack" + ".com"
ENV = "SLACK_WEBHOOK"


def url(*segments: str, host: str = HOST, scheme: str = "https") -> str:
    return f"{scheme}://{host}/triggers/" + "/".join(segments)


def read(value: str | None, name: str = ENV) -> Webhook:
    env: dict[str, str] = {} if value is None else {name: value}
    return read_webhook(env, name)


def refused(value: str | None, name: str = ENV) -> CredentialInvalid:
    with pytest.raises(CredentialInvalid) as caught:
        read(value, name)
    return caught.value


# --- accepted ---------------------------------------------------------------------------------


@pytest.mark.parametrize("count", [1, 2, 3, 4])
def test_one_to_four_segments_are_accepted(count: int) -> None:
    segments = [f"{SEG}{i}" for i in range(count)]
    hook = read(url(*segments))
    assert hook.host == HOST
    assert hook.port == 443
    assert hook.path == "/triggers/" + "/".join(segments)


def test_the_whole_alphabet_is_accepted_in_a_segment() -> None:
    assert read(url("aZ09_-")).path == "/triggers/aZ09_-"


@pytest.mark.parametrize("pad", [" ", "\t", "\n", "\r\n", " \t\r\n\x0b\x0c"])
def test_surrounding_ascii_whitespace_is_trimmed(pad: str) -> None:
    assert read(pad + url(SEG) + pad).path == "/triggers/" + SEG


# --- refused ----------------------------------------------------------------------------------


def test_unset_is_refused_with_the_variable_name() -> None:
    error = refused(None, "MY_HOOK")
    assert error.env == "MY_HOOK"


@pytest.mark.parametrize("value", ["", " ", "\t\r\n", "\x0b\x0c "])
def test_empty_after_trimming_is_unset(value: str) -> None:
    assert refused(value).env == ENV


def _cases() -> dict[str, str]:
    ok = url(SEG)
    return {
        "query": ok + "?x=1",
        "query-empty": ok + "?",
        "fragment": ok + "#f",
        "port-443": f"https://{HOST}:443/triggers/{SEG}",
        "port-other": f"https://{HOST}:8443/triggers/{SEG}",
        "port-empty": f"https://{HOST}:/triggers/{SEG}",
        "userinfo": f"https://u{CANARY}@{HOST}/triggers/{SEG}",
        "userinfo-host-first": f"https://{HOST}@evil.example/triggers/{SEG}",
        "userinfo-password": f"https://a:{SEG}@{HOST}/triggers/{SEG}",
        "trailing-dot": f"https://{HOST}./triggers/{SEG}",
        "empty-segment": f"https://{HOST}/triggers/{SEG}//{SEG}",
        "empty-last-segment": ok + "/",
        "empty-first-segment": f"https://{HOST}/triggers//{SEG}",
        "no-segment": f"https://{HOST}/triggers/",
        "no-triggers": f"https://{HOST}/{SEG}",
        "five-segments": url(*[SEG] * 5),
        "other-host": url(SEG, host="evil.example"),
        "suffix-host": url(SEG, host=HOST + ".evil.example"),
        "prefix-host": url(SEG, host="evil." + HOST),
        "host-in-path": f"https://evil.example/{HOST}/triggers/{SEG}",
        "host-in-path2": f"https://evil.example/x/{HOST}/triggers/{SEG}",
        "subdomain": url(SEG, host="a." + HOST),
        "uppercase-host": url(SEG, host=HOST.upper()),
        "mixedcase-host": url(SEG, host="Hooks" + HOST[5:]),
        "uppercase-scheme": url(SEG, scheme="HTTPS"),
        "http": url(SEG, scheme="http"),
        "no-scheme": f"{HOST}/triggers/{SEG}",
        "scheme-relative": f"//{HOST}/triggers/{SEG}",
        "ftp": url(SEG, scheme="ftp"),
        "single-slash": f"https:/{HOST}/triggers/{SEG}",
        "backslash-host": f"https://{HOST}\\triggers\\{SEG}",
        "backslash-path": f"https://{HOST}/triggers/{SEG}\\{SEG}",
        "backslash-before-host": f"https:\\\\{HOST}/triggers/{SEG}",
        "percent-segment": url("%41" + SEG),
        "percent-host": f"https://hooks%2eslack.com/triggers/{SEG}",
        "percent-slash": f"https://{HOST}/triggers%2f{SEG}",
        "percent-triggers": f"https://{HOST}/trigger%73/{SEG}",
        "dotdot": f"https://{HOST}/triggers/../{SEG}",
        "dotdot-segment": url(SEG, ".."),
        "dot-segment": url(SEG, "."),
        "dot-in-segment": url(SEG + ".x"),
        "traversal-before": f"https://{HOST}/x/../triggers/{SEG}",
        "idn-host": url(SEG, host="h\u043eoks.slack.com"),  # Cyrillic o
        "punycode-host": url(SEG, host="xn--hooks-slack-com"),
        "fullwidth-dot": url(SEG, host="hooks.slack\uff0ecom"),
        "unicode-letter": url(SEG + "\u00e9"),
        "arabic-digit": url(SEG + "\u0663"),
        "fullwidth-letter": url("\uff21" + SEG),
        "kelvin": url("\u212a" + SEG),
        "space-in-segment": url(SEG + " x"),
        "space-around-slash": f"https://{HOST}/triggers/ {SEG}",
        "space-before-scheme-inner": "https ://" + HOST + "/triggers/" + SEG,
        "nbsp-edge": "\u00a0" + url(SEG),
        "nbsp-trailing": url(SEG) + "\u00a0",
        "line-sep-edge": url(SEG) + "\u2028",
        "ideographic-space-edge": "\u3000" + url(SEG),
        "next-line-edge": "\x85" + url(SEG),
        "nul": url(SEG + "\x00"),
        "nul-edge": url(SEG) + "\x00",
        "newline": url(SEG + "\nX"),
        "crlf-token": url(SEG + "\r\n" + SEG),
        "crlf-token-header": url(SEG + "\r\nHost: evil.example"),
        "crlf-token-mid": url(SEG + "\r\nX-A: b" + SEG),
        "cr-only": url(SEG + "\rX"),
        "crlf-between-segments": f"https://{HOST}/triggers/{SEG}\r\n/{SEG}",
        "lf-in-host": f"https://{HOST}\n/triggers/{SEG}",
        "tab-in-segment": url(SEG + "\tx"),
        "two-urls": url(SEG) + " " + url(SEG),
        "two-lines": url(SEG) + "\n" + url(SEG),
        "lone-surrogate": url(SEG + "\udcff"),
        "lone-surrogate-high": url(SEG + "\ud800"),
        "classic-incoming-webhook": f"https://{HOST}/services/T0{SEG}/B0{SEG}/{SEG}",
        "slash-in-triggers-case": f"https://{HOST}/Triggers/{SEG}",
        "double-scheme": "https://" + url(SEG),
        "quoted": '"' + url(SEG) + '"',
        "angle": "<" + url(SEG) + ">",
        "bearer": "Bearer " + url(SEG),
        "semicolon": url(SEG + ";x"),
        "at-sign-path": url(SEG + "@x"),
        "colon-path": url(SEG + ":x"),
        "equals": url(SEG + "=x"),
        "plus": url(SEG + "+x"),
        "just-canary": CANARY,
    }


@pytest.mark.parametrize("value", list(_cases().values()), ids=list(_cases()))
def test_every_hostile_value_is_refused(value: str) -> None:
    assert refused(value).env == ENV


def test_a_very_long_value_is_refused() -> None:
    assert refused(url("a" * 100_000)).env == ENV
    assert refused(url(*["a"] * 100_000)).env == ENV
    assert refused("x" * 1_000_000).env == ENV


def test_the_length_cap_is_exact() -> None:
    prefix = len(url(""))
    assert read(url("a" * (webhook.MAX_LENGTH - prefix)))
    assert refused(url("a" * (webhook.MAX_LENGTH - prefix + 1))).env == ENV


def test_the_length_cap_counts_after_trimming() -> None:
    prefix = len(url(""))
    assert read("  " + url("a" * (webhook.MAX_LENGTH - prefix)) + "\n")


def test_a_non_string_value_is_refused() -> None:
    bad: Any = {ENV: b"https://x"}
    with pytest.raises(CredentialInvalid):
        read_webhook(bad, ENV)
    none_value: Any = {ENV: None}
    with pytest.raises(CredentialInvalid):
        read_webhook(none_value, ENV)


def test_the_error_names_only_the_variable() -> None:
    error = refused(url(SEG, host="evil.example"), "OTHER_HOOK")
    assert error.env == "OTHER_HOOK"
    assert str(error) == webhook.INVALID_MESSAGE
    assert error.args == (webhook.INVALID_MESSAGE,)


# --- the environment is read lazily, by name, through the mapping ------------------------------


class Spy(Mapping[str, str]):
    def __init__(self, values: dict[str, str]) -> None:
        self.data = values
        self.reads: list[str] = []

    def __getitem__(self, key: str) -> str:
        self.reads.append(key)
        return self.data[key]

    def __iter__(self) -> Any:
        raise AssertionError("the whole environment must not be enumerated")

    def __len__(self) -> int:
        raise AssertionError("the whole environment must not be measured")


def test_only_the_named_variable_is_read() -> None:
    spy = Spy({ENV: url(SEG), "OTHER": "x"})
    read_webhook(spy, ENV)
    assert spy.reads == [ENV]


def test_nothing_is_read_before_the_call() -> None:
    spy = Spy({ENV: url(SEG)})
    assert spy.reads == []


def test_the_process_environment_is_not_consulted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV, url(SEG))
    assert refused(None).env == ENV


def test_the_module_never_touches_os_environ_or_a_url_parser() -> None:
    from tests.test_link import url_parser_uses

    source = Path(webhook.__file__).read_text(encoding="utf-8")
    assert url_parser_uses(source) == []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"environ", "getenv"}
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
            assert "os" not in names


def test_a_trailing_newline_is_not_accepted_by_dollar_semantics() -> None:
    # fullmatch, never `$`: an interior-or-trailing newline after trimming cannot sneak in.
    assert refused(url(SEG) + "\nx").env == ENV
    assert refused(url(SEG + "\n") + "x").env == ENV


# --- the value never shows a secret part -------------------------------------------------------


def parts(value: str) -> list[str]:
    return [CANARY, SEG, value, value.split("/triggers/")[1]]


def test_repr_str_format_and_friends_hide_the_path() -> None:
    value = url(SEG, SEG + "b")
    hook = read(value)
    shown = [
        repr(hook),
        str(hook),
        f"{hook}",
        f"{hook!r}",
        f"{hook!s}",
        "{} {!r}".format(hook, hook),  # noqa: UP032
        format(hook),
        repr([hook]),
        repr({"k": hook}),
        str(dataclasses.fields(hook)),
        repr(hook.__class__),
    ]
    for text in shown:
        assert CANARY not in text and "triggers" not in text and SEG not in text, text
    assert "hooks" in repr(hook)  # the host is not secret


def test_a_format_spec_error_does_not_show_the_path() -> None:
    hook = read(url(SEG))
    with pytest.raises(TypeError) as caught:
        format(hook, ">20")
    assert CANARY not in str(caught.value)


def test_pytest_style_comparison_failures_do_not_show_the_path() -> None:
    a, b = read(url(SEG)), read(url(SEG + "z"))
    with pytest.raises(AssertionError) as caught:
        assert a == b
    assert CANARY not in "".join(traceback.format_exception(caught.value))
    assert a != b and a == read(url(SEG))


def test_the_value_is_immutable() -> None:
    hook = read(url(SEG))
    with pytest.raises(dataclasses.FrozenInstanceError):
        hook.path = "/x"  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        hook.extra = 1  # type: ignore[attr-defined]


def test_the_value_has_no_instance_dict_and_hides_in_no_trace() -> None:
    hook = read(url(SEG))
    assert not hasattr(hook, "__dict__")
    assert copy.copy(hook) == hook  # copying works; repr still hides it
    assert CANARY not in repr(copy.deepcopy(hook))


def test_the_request_target_cannot_carry_a_line_break() -> None:
    for value in (url(SEG), url(SEG, SEG, SEG, SEG)):
        hook = read(value)
        assert all(c not in hook.path for c in "\r\n\0 \t?#%\\")
        assert hook.path.isascii() and hook.path.startswith("/triggers/")


def test_the_validated_authority_is_fixed() -> None:
    hook = read(url(SEG))
    assert (hook.host, hook.port) == ("hooks.slack.com", 443)


@pytest.mark.parametrize("value", list(_cases().values()), ids=list(_cases()))
def test_a_refusal_carries_no_part_of_the_value(value: str) -> None:
    error = refused(value)
    text = "".join(traceback.format_exception(error))
    for secret in (CANARY, SEG, value):
        assert secret not in text
        assert secret not in repr(error) and secret not in str(error)
    assert error.__cause__ is None and error.__context__ is None


def test_no_log_record_or_output_from_reading(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    read(url(SEG))
    refused(url(SEG, host="evil.example"))
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""
    assert caplog.records == []


def test_the_secret_is_not_in_the_module_state_after_a_read() -> None:
    read(url(SEG))
    for name in dir(webhook):
        obj = getattr(webhook, name)
        if isinstance(obj, str):
            assert CANARY not in obj


# --- the exit 1 path never prints an exception that carries the URL ---------------------------


def _raising(exc: BaseException) -> Any:
    def handler(ctx: Any) -> int:
        raise exc

    return handler


@pytest.mark.parametrize(
    "make",
    [
        lambda s: http.client.InvalidURL(f"URL can't contain control characters. {s!r}"),
        lambda s: ValueError(s),
        lambda s: http.client.InvalidURL(s),
        lambda s: UnicodeError(s),
        lambda s: OSError(2, s, s),
    ],
    ids=["InvalidURL-repr", "ValueError", "InvalidURL", "UnicodeError", "OSError"],
)
def test_injected_exceptions_carrying_the_url_never_reach_any_stream_or_the_log(
    make: Any,
    monkeypatch: pytest.MonkeyPatch,
    fake_gateway: FakeGateway,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    secret = url(SEG)
    monkeypatch.setitem(cli.HANDLERS, "send", _raising(make(secret)))
    caplog.set_level(logging.DEBUG)
    for flags in ([], ["--json"], ["--verbose"]):
        out, err = io.BytesIO(), io.BytesIO()
        streams = cli.Streams(out=out, err=err, stdin_is_tty=lambda: False)
        code = cli.main(["send", *flags], {ENV: secret}, fake_gateway, streams)
        assert code == 1
        everything = out.getvalue() + err.getvalue()
        assert CANARY.encode() not in everything and b"triggers" not in everything
    assert CANARY not in caplog.text
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert CANARY.encode() not in path.read_bytes()

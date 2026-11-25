"""The link rule (issue #18): the three-step check, with no URL parser."""

from __future__ import annotations

import ast
import io
import json
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, payload
from slack_notice.cli import Context, Streams, main
from slack_notice.gateway import SourceRead
from slack_notice.payload import LinkRefused, check_link
from tests.fake_gateway import FakeGateway
from tests.harness import assert_valid

CANARY = "CAN" + "ARY-" + "18ab"
# Built from parts so that no credential-looking literal sits in the source.
USERINFO = "us" + "er:" + "pw"

ACCEPTED = [
    ("https://a.example", "https://a.example"),
    ("HTTPS://x.example", "https://x.example"),
    ("HtTp://x.example/Path", "http://x.example/Path"),
    ("http://a.example", "http://a.example"),
    ("https://a.example/%41", "https://a.example/%41"),
    ("https://a.example/%41%42", "https://a.example/%41%42"),
    ("https://a.example/%aF", "https://a.example/%aF"),
    ("https://a.example:80?x", "https://a.example:80?x"),
    ("https://a.example:80#x", "https://a.example:80#x"),
    ("https://[1:2:3:4:5:6:1.2.3.4]/", "https://[1:2:3:4:5:6:1.2.3.4]/"),
    ("https://a.example/p'q(r)", "https://a.example/p'q(r)"),
    ("https://[::1]/", "https://[::1]/"),
    ("https://[2001:db8::1]:8443/x", "https://[2001:db8::1]:8443/x"),
    ("https://[::ffff:1.2.3.4]/", "https://[::ffff:1.2.3.4]/"),
    ("https://2130706433/", "https://2130706433/"),
    ("https://0x7f.1/", "https://0x7f.1/"),
    ("https://a.example:1/", "https://a.example:1/"),
    ("https://a.example:65535", "https://a.example:65535"),
    ("https://a.example?q=1&r=2", "https://a.example?q=1&r=2"),
    ("https://a.example/a/b?c=d#frag/ment?x", "https://a.example/a/b?c=d#frag/ment?x"),
    ("https://a.example#", "https://a.example#"),
    ("https://a.example/", "https://a.example/"),
    ("https://xn--bcher-kva.example/", "https://xn--bcher-kva.example/"),
    ("https://a.example/@x:y", "https://a.example/@x:y"),
    ("https://a.example/a//b", "https://a.example/a//b"),
    ("https://a-b.example/*+,;=$!~_.-", "https://a-b.example/*+,;=$!~_.-"),
    ("https://" + "a" * 1016, "https://" + "a" * 1016),  # exactly 1024
]

# (link, reason). Each row breaks one rule.
REFUSED = [
    # step 1: form
    ("", "link_invalid"),
    ("https://a.example\n", "link_invalid"),
    ("https://a.example\r\nX: y", "link_invalid"),
    ("https://a.example ", "link_invalid"),
    (" https://a.example", "link_invalid"),
    ("https://a.example/a b", "link_invalid"),
    ("https://a.example/\t", "link_invalid"),
    ("https://a.example/\x00", "link_invalid"),
    ("https://a.example/\x7f", "link_invalid"),
    ("https://a.example/\x1b[0m", "link_invalid"),
    ("https://a.example/\u00e9", "link_invalid"),
    ("https://b\u00fccher.example/", "link_invalid"),
    ("https://a.example/\u202e", "link_invalid"),
    ("https://a.example/\u200b", "link_invalid"),
    ("https://a.example/\u2028", "link_invalid"),
    ("https://a.example/\ufeff", "link_invalid"),
    ("https://\u0430.example/", "link_invalid"),  # Cyrillic a
    ("https://a.example/\U0001f600", "link_invalid"),
    ("https://" + "a" * 1017, "link_invalid"),  # 1025
    ("https://a.example/" + "a" * 5000, "link_invalid"),
    # step 3: structure
    ('https://a.example/"x', "link_invalid"),
    ("https://a.example/a|b", "link_invalid"),
    ("https://a.example/{x}", "link_invalid"),
    ("https://a.example/%zz", "link_invalid"),
    ("https://a.example/%4", "link_invalid"),
    ("https://a.example/%", "link_invalid"),
    ("https://a.example#a#b", "link_invalid"),
    ("https://a.example/<b>", "link_invalid"),
    ("https://a.example/>", "link_invalid"),
    ("https://a.example/a^b", "link_invalid"),
    ("https://a.example/a`b", "link_invalid"),
    ("https://a.example/a[b]", "link_invalid"),
    ("https://a.example/a\\b", "link_invalid"),
    ("https://a.example\\@evil.example", "link_invalid"),
    ("https://a.example\\.evil.example", "link_invalid"),
    ("https://" + USERINFO + "@a.example/", "link_invalid"),
    ("https://" + USERINFO.split(":")[0] + "@a.example/", "link_invalid"),
    ("https://a.example@evil.example/", "link_invalid"),
    ("https://@a.example/", "link_invalid"),
    ("https://:80/", "link_invalid"),
    ("https:///x", "link_invalid"),
    ("https://", "link_invalid"),
    ("https:/a.example", "link_invalid"),
    ("https:a.example", "link_invalid"),
    ("https:\\\\a.example", "link_invalid"),
    ("//a.example", "link_invalid"),
    ("a.example", "link_invalid"),
    ("/path", "link_invalid"),
    ("https://a.example:0/", "link_invalid"),
    ("https://a.example:65536/", "link_invalid"),
    ("https://a.example:99999/", "link_invalid"),
    ("https://a.example:123456/", "link_invalid"),
    ("https://a.example:/", "link_invalid"),
    ("https://a.example:80:80/", "link_invalid"),
    ("https://a.example:8o/", "link_invalid"),
    ("https://a.example:-1/", "link_invalid"),
    ("https://a_b.example/", "link_invalid"),
    ("https://a.example/ok#frag#", "link_invalid"),
    ("https://a.example./", "link_invalid"),
    ("https://a..example/", "link_invalid"),
    ("https://.a.example/", "link_invalid"),
    ("https://a.example:80x", "link_invalid"),
    ("https://a.example.:80:/", "link_invalid"),
    # IPv6
    ("https://[8]/", "link_invalid"),
    ("https://[a]/", "link_invalid"),
    ("https://[:]#x", "link_invalid"),
    ("https://[]/", "link_invalid"),
    ("https://[::1/", "link_invalid"),
    ("https://::1]/", "link_invalid"),
    ("https://[::1]x/", "link_invalid"),
    ("https://[::1%eth0]/", "link_invalid"),
    ("https://[::1%25eth0]/", "link_invalid"),
    ("https://[::g]/", "link_invalid"),
    ("https://[1:2:3:4:5:6:7:8:9]/", "link_invalid"),
    ("https://[1.2.3.4]/", "link_invalid"),
    ("https://[::1]:0/", "link_invalid"),
    ("https://[::1]:70000/", "link_invalid"),
    ("https://[[::1]]/", "link_invalid"),
    ("https://[::1]@a.example/", "link_invalid"),
    # step 2: scheme
    ("javascript:x", "link_scheme"),
    ("JAVASCRIPT:alert(1)", "link_scheme"),
    ("example.com:80/x", "link_scheme"),
    ("data:text/html;base64,AAAA", "link_scheme"),
    ("file:///etc/passwd", "link_scheme"),
    ("mailto:a@example.com", "link_scheme"),
    ("slack://channel?id=1", "link_scheme"),
    ("ftp://a.example/", "link_scheme"),
    ("ws://a.example/", "link_scheme"),
    ("httpss://a.example/", "link_scheme"),
    ("xhttps://a.example/", "link_scheme"),
    ("h+t.t-p://a.example/", "link_scheme"),
    ("a:b", "link_scheme"),
    ("tel:+1555", "link_scheme"),
    ("view-source:https://a.example/", "link_scheme"),
    ("javascript:%0aalert(1)", "link_scheme"),
]


@pytest.mark.parametrize(("link", "rendered"), ACCEPTED)
def test_an_accepted_link_is_returned_with_only_the_scheme_lowercased(
    link: str, rendered: str
) -> None:
    assert len(link) <= 1024
    assert check_link(link) == rendered


@pytest.mark.parametrize(("link", "reason"), REFUSED)
def test_a_refused_link_has_its_reason_and_a_fixed_message(link: str, reason: str) -> None:
    with pytest.raises(LinkRefused) as caught:
        check_link(link)
    assert caught.value.reason == reason
    assert caught.value.message == payload.LINK_MESSAGES[reason]
    assert caught.value.message == payload.LINK_MESSAGES[reason]
    assert not caught.value.args[1:]
    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_the_rule_is_ordered_form_then_scheme_then_structure() -> None:
    # Non-ASCII beats a bad scheme; a bad scheme beats a bad structure.
    for link, reason in [
        ("javascript:\u00e9", "link_invalid"),
        ("javascript:x y", "link_invalid"),
        ("ftp://a.example/\u00e9", "link_invalid"),
        ("ftp://a.example/{", "link_scheme"),
    ]:
        with pytest.raises(LinkRefused) as caught:
            check_link(link)
        assert caught.value.reason == reason


def test_the_length_limit_is_1024_characters() -> None:
    assert check_link("https://" + "a" * 1016)
    with pytest.raises(LinkRefused):
        check_link("https://" + "a" * 1017)


def test_a_trailing_newline_is_not_swallowed_by_the_end_of_the_pattern() -> None:
    with pytest.raises(LinkRefused):
        check_link("https://a.example\n")


def test_the_port_comes_from_the_match_not_from_a_parser() -> None:
    assert check_link("https://a.example:00080/")  # 1 to 5 digits whose value is 1 to 65535
    with pytest.raises(LinkRefused):
        check_link("https://a.example:00000/")


def test_a_lone_surrogate_is_invalid_payload_at_link_before_the_rule() -> None:
    with pytest.raises(payload.FieldRefused) as caught:
        payload.validate_notification({"link": "https://a.example/\ud800"})
    assert caught.value.pointer == "/link" and caught.value.rule == "surrogate"


_BANNED_ROOTS = {"urllib", "urllib3", "yarl", "http", "importlib"}
_BANNED_NAMES = {
    "urlparse",
    "urlsplit",
    "urlunparse",
    "urlunsplit",
    "urljoin",
    "urldefrag",
    "parse_url",
    "__import__",
    "import_module",
    "reload",
    "exec",
    "eval",
    "globals",
    "compile",
}


# The package version is read from the installed metadata: importlib.metadata cannot import code.
_ALLOWED_MODULES = {"importlib.metadata"}


def url_parser_uses(source: str) -> list[str]:
    """Every way the source could reach a URL parser, by import, name, getattr or string."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [
                a.name
                for a in node.names
                if a.name.split(".")[0] in _BANNED_ROOTS and a.name not in _ALLOWED_MODULES
            ]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.split(".")[0] in _BANNED_ROOTS and module not in _ALLOWED_MODULES:
                found.append(module)
        elif isinstance(node, ast.Name | ast.Attribute):
            name = node.id if isinstance(node, ast.Name) else node.attr
            is_re_compile = (
                isinstance(node, ast.Attribute)
                and node.attr == "compile"
                and isinstance(node.value, ast.Name)
                and node.value.id == "re"
            )  # re.compile builds a regex; it cannot run code
            if name in _BANNED_NAMES and not is_re_compile:
                found.append(name)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "getattr":
                second = node.args[1] if len(node.args) > 1 else None
                if not (isinstance(second, ast.Constant) and isinstance(second.value, str)):
                    found.append("getattr")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            root = value.split(".")[0]
            if " " not in value and root in _BANNED_ROOTS and value not in _ALLOWED_MODULES:
                found.append(value)
    return found


@pytest.mark.parametrize(
    "snippet",
    [
        "from urllib.parse import urljoin",
        "from urllib.parse import urlsplit as s",
        "import urllib.parse as u",
        "from http import client as c",
        "__import__('urllib.parse')",
        "import importlib\nimportlib.import_module('x')",
        "x = getattr(m, name)",
        "name = 'urllib.parse'",
        "m.urlparse(x)",
        "import importlib.metadata\nimportlib.import_module('url'+'lib.parse')",
        "from importlib import import_module\nimport_module('x')",
        "import importlib.metadata as im\nim.reload(m)",
        "exec('import urllib.parse')",
        "eval('1')",
        "globals()['__imp'+'ort__']('x')",
        "m.globals()",
        "compile('x', 'f', 'exec')",
        "import re as r\nr.compile('x')\nm.compile('x')",
        "builtins.exec(code)",
    ],
)
def test_the_url_parser_check_flags_evasive_code(snippet: str) -> None:
    assert url_parser_uses(snippet)


def test_the_url_parser_check_passes_clean_code() -> None:
    assert not url_parser_uses("import re\nx = getattr(m, 'a')\ny = re.compile('a.b')")


def test_no_code_path_calls_a_url_parser() -> None:
    paths = [p for p in Path(payload.__file__).parent.glob("*.py") if p.name != "gateway.py"]
    assert paths
    for path in paths:  # gateway.py is exempt: the transport's own URL, never the link
        assert not url_parser_uses(path.read_text()), path.name


# --- through the command line -----------------------------------------------------------------


def run(
    argv: list[str], gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, stdin: bytes | None
) -> tuple[int, str, str, Any]:
    seen: list[Any] = []

    def handler(ctx: Context) -> int:
        seen.append(cli.sanitize_loaded(cli.load_notification(ctx, 10.0)))
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    if stdin is not None:
        gateway.source_script.append(SourceRead(stdin))
    out, err = io.BytesIO(), io.BytesIO()
    code = main([*argv, "--json"], {}, gateway, Streams(out, err, lambda: False))
    return code, out.getvalue().decode(), err.getvalue().decode(), seen[0] if seen else None


@pytest.mark.parametrize(
    ("link", "reason"),
    [
        ("https://a.example/%zz", "link_invalid"),
        ("javascript:" + CANARY, "link_scheme"),
        ("https://" + CANARY + "@a.example/", "link_invalid"),
        ("https://a.example/" + CANARY + "\u00e9", "link_invalid"),
        ("", "link_invalid"),
    ],
)
def test_a_refused_link_is_exit_20_with_the_reason_and_no_echo_from_json(
    link: str, reason: str, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = json.dumps({"message": "m", "link": link}).encode()
    code, out, err, seen = run(["send"], fake_gateway, monkeypatch, body)
    assert code == 20 and seen is None
    assert_valid("cli/error", out)
    error = json.loads(out)["error"]
    assert error["code"] == "refused" and error["reason"] == reason
    assert error["message"] == payload.LINK_MESSAGES[reason]
    assert CANARY not in out + err
    assert err == f"refused ({reason}): {payload.LINK_MESSAGES[reason]}\n"


def test_a_refused_link_from_a_flag_is_the_same(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, err, _ = run(
        ["send", "--message", "m", "--link", "ftp://" + CANARY], fake_gateway, monkeypatch, None
    )
    assert code == 20 and CANARY not in out + err
    assert json.loads(out)["error"]["reason"] == "link_scheme"


def test_a_non_string_link_stays_invalid_payload_at_link(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _, _ = run(["send"], fake_gateway, monkeypatch, b'{"message":"m","link":true}')
    error = json.loads(out)["error"]
    assert code == 20 and error["reason"] == "invalid_payload"
    assert error["details"]["pointer"] == "/link"


def test_an_accepted_link_reaches_the_sanitized_notification_lowercased(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = json.dumps({"message": "m", "link": "HTTPS://x.example"}).encode()
    code, _, _, seen = run(["send"], fake_gateway, monkeypatch, body)
    assert code == 0 and seen.link == "https://x.example"


def test_no_link_stays_none(fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> None:
    code, _, _, seen = run(["send"], fake_gateway, monkeypatch, b'{"message":"m"}')
    assert code == 0 and seen.link is None


def test_empty_message_precedes_the_link_rule(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, out, _, _ = run(["send"], fake_gateway, monkeypatch, b'{"link":"javascript:x"}')
    assert code == 20 and json.loads(out)["error"]["reason"] == "empty_message"

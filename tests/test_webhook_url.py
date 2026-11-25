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
import os
import pickle
import subprocess
import sys
import traceback
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, webhook
from slack_notice.webhook import CredentialInvalid, Webhook, read_webhook
from tests.fake_gateway import FakeGateway

CANARY = "CAN" + "ARY" + "_22x"  # inside [A-Za-z0-9_-], so it survives into every built URL
SEG = CANARY + "seg"
HOST = "hooks" + ".slack" + ".com"
ENV = "SLACK_WEBHOOK"


def url(*segments: str, host: str = HOST, scheme: str = "https") -> str:
    return f"{scheme}://{host}/triggers/" + "/".join(segments)


def test_the_needle_is_really_inside_the_secret() -> None:
    # Every "not in" assertion below searches for CANARY or SEG: prove they can be found.
    built = url(SEG, SEG + "b")
    assert CANARY in built and SEG in built
    assert CANARY in read(built).path  # the unsanitized form of the secret part
    assert CANARY in "".join(url(SEG).split("/triggers/")[1:])


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


def test_segments_of_only_dash_or_underscore_are_accepted() -> None:
    assert read(url("-")).path == "/triggers/-"
    assert read(url("_", "-")).path == "/triggers/_/-"


def test_vt_ff_and_the_other_trim_characters_are_trimmed_at_the_edges() -> None:
    for pad in ("\x0b", "\x0c", "\x0b\x0c\r\n\t "):
        assert read(pad + url(SEG)).path == "/triggers/" + SEG
        assert read(url(SEG) + pad).path == "/triggers/" + SEG


# --- refused ----------------------------------------------------------------------------------


def test_unset_is_refused_with_the_variable_name() -> None:
    error = refused(None, "MY_HOOK")
    assert error.env == "MY_HOOK"


@pytest.mark.parametrize("value", ["", " ", "\t\r\n", "\x0b\x0c "])
def test_empty_after_trimming_is_unset(value: str) -> None:
    assert refused(value).env == ENV


def _cases() -> dict[str, str]:
    ok = url(SEG)
    cases = {
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
        "bom-edge": "\ufeff" + ok,
        "bom-trailing": ok + "\ufeff",
        "zwsp-edge": "\u200b" + ok,
        "zwsp-trailing": ok + "\u200b",
        "zwsp-inner": url(SEG + "\u200b"),
        "para-sep-edge": "\u2029" + ok,
        "para-sep-trailing": ok + "\u2029",
        "vt-interior": url(SEG + "\x0b" + SEG),
        "ff-interior": url(SEG + "\x0c" + SEG),
        "https-triple-slash": f"https:///triggers/{SEG}",
        "http-with-port": f"http://{HOST}:443/triggers/{SEG}",
        "query-right-after-triggers": f"https://{HOST}/triggers/?{SEG}",
        "fragment-right-after-triggers": f"https://{HOST}/triggers/#{SEG}",
        "nul-in-scheme": f"ht\x00tps://{HOST}/triggers/{SEG}",
        "esc-in-scheme": f"ht\x1btps://{HOST}/triggers/{SEG}",
        "nul-in-host": f"https://hooks.slack\x00.com/triggers/{SEG}",
        "esc-in-host": f"https://hooks\x1b.slack.com/triggers/{SEG}",
        "trimmed-plus-inner-violation": " " + url("a b") + " ",
        "trimmed-plus-inner-newline": "\n" + url("a\nb") + "\n",
        "non-trimmable-padding-1025": url("a" * (webhook.MAX_LENGTH - len(url("")) + 1)) + "\x1f",
    }
    for code in (0x1C, 0x1D, 0x1E, 0x1F):
        cases[f"c0-{code:x}-leading"] = chr(code) + ok
        cases[f"c0-{code:x}-trailing"] = ok + chr(code)
    for ch in "@[`{}|:/\x7f":  # neighbours of the alphabet ranges and the delimiters
        if ch != "/":  # an inner slash is a valid segment separator
            cases[f"neighbour-{ord(ch):x}-inner"] = url(SEG + ch + SEG)
        cases[f"neighbour-{ord(ch):x}-first"] = url(ch + SEG)
        cases[f"neighbour-{ord(ch):x}-last"] = url(SEG + ch)
    return cases


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


def test_a_padded_value_is_measured_after_trimming() -> None:
    prefix = len(url(""))
    exact = url("a" * (webhook.MAX_LENGTH - prefix))
    assert len(" " + exact + " ") > webhook.MAX_LENGTH
    assert read(" " + exact + "\x0b\x0c")
    assert refused(exact + "a").env == ENV
    assert refused(" " + exact + "a ").env == ENV


class LyingStr(str):
    def strip(self, chars: str | None = None) -> str:
        return url(SEG)


class Raising(Mapping[str, str]):
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def __getitem__(self, key: str) -> str:
        raise self.exc

    def __iter__(self) -> Any:
        return iter(())

    def __len__(self) -> int:
        return 0


@pytest.mark.parametrize(
    "value",
    [b"https://x", None, 7, 1.5, ["x"], LyingStr("x"), LyingStr(url(SEG))],
    ids=["bytes", "None", "int", "float", "list", "str-subclass", "str-subclass-valid"],
)
def test_a_value_that_is_not_exactly_a_str_is_refused(value: Any) -> None:
    error = refused(value)
    assert error.env == ENV and error.__context__ is None and error.__cause__ is None


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


def test_an_unset_variable_leaves_no_context() -> None:
    error = refused(None)
    assert error.__context__ is None and error.__cause__ is None


@pytest.mark.parametrize(
    "make",
    [lambda s: KeyError(s), lambda s: RuntimeError(s), lambda s: OSError(s)],
    ids=["KeyError", "RuntimeError", "OSError"],
)
def test_a_hostile_mapping_leaves_no_trace_of_its_exception(make: Any) -> None:
    secret = url(SEG)
    with pytest.raises(CredentialInvalid) as caught:
        read_webhook(Raising(make(secret)), ENV)
    error = caught.value
    assert error.__context__ is None and error.__cause__ is None
    text = "".join(traceback.format_exception(error))
    assert CANARY not in text and SEG not in text
    assert error.env == ENV


def test_the_process_environment_is_not_consulted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV, url(SEG))
    assert refused(None).env == ENV


def test_the_os_import_guard_catches_every_spelling() -> None:
    def hits(source: str) -> bool:
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                if any(n == "os" or n.startswith("os.") for n in names):
                    return True
        return False

    assert hits("import os") and hits("import os.path") and hits("from os import environ")
    assert hits("from os.path import join") and not hits("import re")


def test_the_module_never_touches_os_environ_or_a_url_parser() -> None:
    from tests.test_link import url_parser_uses

    source = Path(webhook.__file__).read_text(encoding="utf-8")
    assert url_parser_uses(source) == []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"environ", "getenv"}
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
            assert not any(n == "os" or n.startswith("os.") for n in names)


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
        repr(hook.__class__),
        repr(vars(Webhook).keys()),
    ]
    for text in shown:
        assert CANARY not in text and "triggers" not in text and SEG not in text, text
    assert repr(hook) == "Webhook(host='hooks.slack.com', port=443)"


def test_a_format_spec_error_does_not_show_the_path() -> None:
    hook = read(url(SEG))
    with pytest.raises(TypeError) as caught:
        format(hook, ">20")
    assert CANARY not in str(caught.value)


def test_equality_compares_the_path_and_only_against_its_own_type() -> None:
    a, b = read(url(SEG)), read(url(SEG + "z"))
    assert a == read(url(SEG)) and a != b
    assert hash(a) == hash(read(url(SEG)))
    assert a.__eq__(url(SEG)) is NotImplemented
    assert a != url(SEG) and a != a.path


_PYTEST_CHILD = """
import os
from slack_notice.webhook import read_webhook


def test_compare():
    base = os.environ["URL_BASE"]
    a = read_webhook({"V": base}, "V")
    b = read_webhook({"V": base + "z"}, "V")
    assert a == b
"""


def test_pytest_style_comparison_failures_do_not_show_the_path(tmp_path: Path) -> None:
    # A real pytest run of `assert a == b` that fails: its failure output must not hold the path.
    home = tmp_path / "child-home"
    home.mkdir()
    (tmp_path / "test_child.py").write_text(_PYTEST_CHILD, encoding="utf-8")
    src = Path(webhook.__file__).resolve().parent.parent
    env = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "xdg"),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(src),
        "URL_BASE": url(SEG),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--rootdir", str(tmp_path),
         "-c", os.devnull, "-q", "-vv", "test_child.py"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    output = done.stdout + done.stderr
    assert done.returncode == 1, output  # the comparison really failed ...
    assert "assert" in output and "Webhook(" in output  # ... and the introspection ran
    assert CANARY not in output and SEG not in output and "triggers" not in output


def test_the_value_is_immutable() -> None:
    hook = read(url(SEG))
    for name, value in (("path", "/x"), ("host", "evil.example"), ("port", 80), ("extra", 1)):
        with pytest.raises(AttributeError):
            setattr(hook, name, value)
    with pytest.raises(AttributeError):
        delattr(hook, "path")


def test_reinitialising_a_built_value_cannot_replace_the_path() -> None:
    hook = read(url(SEG))
    with pytest.raises(AttributeError):
        hook.__init__("/triggers/zzz")  # type: ignore[misc]
    assert hook == read(url(SEG))
    assert "zzz" not in hook.path


def test_getstate_does_not_return_the_secret() -> None:
    hook = read(url(SEG))
    with pytest.raises(TypeError) as caught:
        hook.__getstate__()
    assert SEG not in str(caught.value) and CANARY not in str(caught.value)


def test_host_and_port_are_not_constructor_arguments() -> None:
    with pytest.raises(TypeError):
        Webhook("/triggers/x", "evil.example", 80)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        Webhook(path="/triggers/x", host="evil.example")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "path",
    ["/x\r\n", "", "/triggers/", "/triggers/a b", "triggers/a",
     "/triggers/a?x", "/triggers/a/b/c/d/e", "/triggers/a\n", 7, None, b"/triggers/a"],
)  # fmt: skip
def test_the_constructor_revalidates_the_path_without_echoing_it(path: Any) -> None:
    with pytest.raises(ValueError) as caught:
        Webhook(path)
    assert caught.value.__context__ is None
    assert SEG not in str(caught.value) and SEG not in repr(caught.value)


def test_the_constructor_error_does_not_echo_the_secret_path() -> None:
    bad = "/triggers/" + SEG + "\r\n"
    with pytest.raises(ValueError) as caught:
        Webhook(bad)
    assert SEG in bad
    assert CANARY not in "".join(traceback.format_exception(caught.value))


def test_the_value_has_no_instance_dict() -> None:
    hook = read(url(SEG))
    assert not hasattr(hook, "__dict__")
    assert not dataclasses.is_dataclass(hook)


def test_asdict_astuple_pickle_and_copies_are_refused_without_the_secret() -> None:
    hook = read(url(SEG))
    attempts: list[Any] = [
        lambda: dataclasses.asdict(hook),  # type: ignore[arg-type]
        lambda: dataclasses.astuple(hook),  # type: ignore[arg-type]
        lambda: pickle.dumps(hook),
        lambda: pickle.dumps(hook, protocol=0),
        lambda: pickle.dumps(hook, protocol=pickle.HIGHEST_PROTOCOL),
        lambda: copy.copy(hook),
        lambda: copy.deepcopy(hook),
        lambda: hook.__reduce__(),
        lambda: hook.__reduce_ex__(4),
    ]
    for attempt in attempts:
        with pytest.raises(TypeError) as caught:
            attempt()
        text = "".join(traceback.format_exception(caught.value))
        assert CANARY not in text and SEG not in text and "triggers" not in text


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


def test_reading_leaves_no_secret_in_the_module_or_class_state() -> None:
    before = {n: getattr(webhook, n) for n in dir(webhook)}
    hook = read(url(SEG))
    for name in dir(webhook):
        assert getattr(webhook, name) is before[name]
    for owner in (webhook, Webhook):
        for name in dir(owner):
            obj = getattr(owner, name)
            if isinstance(obj, str):
                assert CANARY not in obj
    assert hook.path == "/triggers/" + SEG


def test_every_code_point_is_refused_unless_in_the_alphabet_or_an_edge_trim() -> None:
    # One bounded pass (about 2 s): the middle of a segment for every code point; the start and
    # end of a segment and both string edges for every code point below U+3100 and for one in 61
    # above it (full coverage of those placements would triple the run time).
    alphabet = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
    trim = frozenset(" \t\n\r\x0b\x0c")
    ok = url(SEG)
    head, tail = SEG[:4], SEG[4:]
    env: dict[str, str] = {}
    wrong: list[int] = []

    def accepted(value: str) -> bool:
        env[ENV] = value
        try:
            read_webhook(env, ENV)
        except CredentialInvalid:
            return False
        return True

    for cp in range(0x110000):
        ch = chr(cp)
        want = ch in alphabet
        # a slash in the middle is a segment separator, so it is valid there
        if accepted(url(head + ch + tail)) != (want or ch == "/"):
            wrong.append(cp)
        if cp < 0x3100 or cp % 61 == 0:
            # a trim character at the end of the segment is the end of the string: trimmed
            if accepted(url(ch + SEG)) != want or accepted(url(SEG + ch)) != (want or ch in trim):
                wrong.append(cp)
            if accepted(ch + ok) != (ch in trim) or accepted(ok + ch) != (want or ch in trim):
                wrong.append(cp)
    assert wrong == []


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
    assert CANARY in secret and CANARY not in " ".join(sys.argv)
    for flags in ([], ["--json"], ["--verbose"]):
        out, err = io.BytesIO(), io.BytesIO()
        streams = cli.Streams(out=out, err=err, stdin_is_tty=lambda: False)
        argv = ["send", *flags]
        code = cli.main(argv, {ENV: secret}, fake_gateway, streams)
        assert CANARY not in " ".join(sys.argv)
        assert code == 1
        everything = out.getvalue() + err.getvalue()
        assert CANARY.encode() not in everything and b"triggers" not in everything
    assert CANARY not in caplog.text
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert CANARY.encode() not in path.read_bytes()

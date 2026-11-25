"""Rendering, layout and truncation (issue #19): interface.md, Rendering and Output."""

from __future__ import annotations

import builtins
import json
import typing
from pathlib import Path
from typing import Any

import pytest

from slack_notice.config import DEFAULTS, validate_config
from slack_notice.payload import Sanitized
from slack_notice.render import MARKER, MAX_BODY_BYTES, TITLE_LIMIT, Rendered, render

GOLDEN = Path(__file__).parent / "golden" / "render"
EMOJI = "\U0001f600"  # four UTF-8 bytes, one code point


def settings(**over: Any) -> dict[str, Any]:
    values = {"max_chars": 3000, "body_variable": "body"}
    values.update(over)
    return validate_config(values)


def san(
    message: str = "m", title: str | None = None, level: str = "info", link: str | None = None
) -> Sanitized:
    return Sanitized(title=title, message=message, level=level, link=link)


def body_of(result: Rendered) -> dict[str, str]:
    return json.loads(result.body)


# --- layout -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "prefix"),
    [
        ("info", "\U0001f535 INFO"),
        ("warn", "\U0001f7e0 WARN"),
        ("action", "\U0001f7e1 ACTION"),
        ("error", "\U0001f534 ERROR"),
    ],
)
def test_default_prefixes_with_title(level: str, prefix: str) -> None:
    result = render(san("msg", title="T", level=level), settings())
    assert result.text == f"{prefix} T\nmsg"
    assert not result.truncated


def test_no_title_prefix_alone_without_trailing_space() -> None:
    assert render(san("msg"), settings()).text == "\U0001f535 INFO\nmsg"


def test_link_on_its_own_last_line() -> None:
    result = render(san("a\n\nb", title="T", link="https://a.example/x"), settings())
    assert result.text == "\U0001f535 INFO T\na\n\nb\nhttps://a.example/x"


def test_no_link_no_trailing_line() -> None:
    assert not render(san("msg"), settings()).text.endswith("\n")


def test_custom_prefix_used_verbatim() -> None:
    cfg = settings(level_prefix={"warn": "W!"})
    assert render(san("m", level="warn"), cfg).text == "W!\nm"
    assert render(san("m", level="info"), cfg).text.startswith("\U0001f535 INFO\n")


def test_message_only_and_title_only_shapes() -> None:
    assert render(san("only"), settings()).text.splitlines()[1:] == ["only"]
    # A title never replaces the message: the message line is always present.
    assert render(san("x", title="t"), settings()).text.count("\n") == 1


# --- no escaping (interface.md: the variable is plain text) -----------------------------------

HOSTILE = [
    "<!channel> <!here> <!everyone>",
    "<@U123ABC> <#C123|general> <!subteam^S1>",
    "<https://evil.example|click here> &amp; &lt;b&gt; & < >",
    "*bold* _it_ ~s~ `code` ```block``` > quote | pipe",
    ":tada: :+1: @channel @here",
    'quote " backslash \\ end',
]


@pytest.mark.parametrize("text", HOSTILE)
def test_markup_is_not_escaped_in_message_or_title(text: str) -> None:
    result = render(san(text, title=text), settings())
    assert result.text == f"\U0001f535 INFO {text}\n{text}"
    assert body_of(result)["body"] == result.text


def test_hostile_prefix_is_rendered_as_configured() -> None:
    cfg = settings(level_prefix={"info": "<!here>"})
    assert render(san("m"), cfg).text == "<!here>\nm"


# --- title cut --------------------------------------------------------------------------------


def test_title_limits_exact() -> None:
    for n, cut in [(255, False), (256, False), (257, True)]:
        result = render(san("m", title="t" * n), settings())
        title_line = result.text.splitlines()[0].split(" ", 2)[2]
        assert result.truncated is cut
        assert title_line == ("t" * 255 + "…" if cut else "t" * n)
        assert len(title_line) == (256 if cut else n)


def test_title_cut_keeps_message_whole_and_counts_in_budget() -> None:
    result = render(san("m" * 10, title="t" * 5000), settings())
    assert result.truncated
    assert result.text.endswith("\n" + "m" * 10)
    assert len(result.text) <= 3000


def test_title_cut_ends_with_ellipsis_not_stripped() -> None:
    title = "a" * 254 + " " + "b" * 10  # char 255 is a space
    line = render(san("m", title=title), settings()).text.splitlines()[0]
    assert line.endswith("a" * 254 + " …")


def test_title_cut_may_split_a_sequence() -> None:
    title = "x" * 254 + "e\u0301"  # 256 code points: fits
    assert not render(san("m", title=title), settings()).truncated
    title = "x" * 254 + "e\u0301y"  # 257: the cut keeps 254 x and the e
    line = render(san("m", title=title), settings()).text.splitlines()[0]
    assert line.endswith("x" * 254 + "e…")


# --- message budget ---------------------------------------------------------------------------


def message_line(result: Rendered) -> str:
    return result.text.split("\n")[1]


def budget(prefix_line: str, link: str | None, max_chars: int) -> int:
    return max_chars - len(prefix_line) - 1 - (1 + len(link) if link else 0)


@pytest.mark.parametrize("link", [None, "https://a.example/" + "p" * 40])
@pytest.mark.parametrize("title", [None, "Title"])
def test_budget_formula_both_boundaries(link: str | None, title: str | None) -> None:
    cfg = settings(max_chars=2000)
    prefix_line = "\U0001f535 INFO" + (f" {title}" if title else "")
    b = budget(prefix_line, link, 2000)
    for size, cut in [(b - 1, False), (b, False), (b + 1, True)]:
        result = render(san("m" * size, title=title, link=link), cfg)
        assert result.truncated is cut
        if cut:
            assert message_line(result) == "m" * (b - len(MARKER)) + MARKER
        else:
            assert message_line(result) == "m" * size
        assert len(result.text) <= 2000
    assert len(render(san("m" * b, title=title, link=link), cfg).text) == 2000


def test_cut_table_exact_outputs() -> None:
    link = "https://a.example/" + "p" * 40
    # (notification, settings, expected text); every budget is worked out in the comments.
    # Plain: prefix line "\U0001f535 INFO" is 6 characters, so the message budget at 2000 is
    # 2000 - 6 - 1 = 1993, and the cut keeps 1993 - 12 = 1981 characters before the marker.
    keep = 1981
    head = "\U0001f535 INFO\n"
    # Title and link: prefix line "\U0001f535 INFO T" is 8 characters and the link line adds
    # 1 + 58 = 59, so the budget is 2000 - 8 - 1 - 59 = 1932 and 1920 characters are kept.
    keep_tl = 1920
    # Byte cap (EMOJI is 4 bytes): at max_chars 12000 the byte limit binds first. Frame
    # {"body":""} is 11 bytes, the head is 4 + 5 + 2 (escaped LF) = 11, the marker is 3 + 11 = 14,
    # so (12000 - 36) // 4 = 2991 emoji are kept (exactly 12000 bytes).
    rows = [
        (san("x" * 1994), 2000, head + "x" * keep + MARKER),
        # trailing blanks dropped: the 1981-character prefix ends in 5 blanks after 1976 x
        (san("x" * 1976 + " " * 5 + "y" * 20), 2000, head + "x" * 1976 + MARKER),
        # a cut inside a run of blank lines drops the run (LF is whitespace)
        (san("x" * 1979 + "\n\n" + "z" * 50), 2000, head + "x" * 1979 + MARKER),
        (
            san("x" * 1933, title="T", link=link),
            2000,
            "\U0001f535 INFO T\n" + "x" * keep_tl + MARKER + "\n" + link,
        ),
        (san(EMOJI * 3000), 12000, head + EMOJI * 2991 + MARKER),
    ]
    for notification, max_chars, expected in rows:
        result = render(notification, settings(max_chars=max_chars))
        assert result.truncated
        assert result.text == expected
        assert len(result.body) <= MAX_BODY_BYTES


def test_cut_drops_trailing_whitespace_before_marker() -> None:
    cfg = settings(max_chars=2000)
    b = budget("\U0001f535 INFO", None, 2000)
    keep = b - len(MARKER)
    message = "x" * (keep - 3) + "   " + "y" * 100
    text = render(san(message), cfg).text
    assert text.endswith("x" * (keep - 3) + MARKER)


def test_trailing_whitespace_run_longer_than_budget() -> None:
    # The kept prefix is all blanks after the text: the cut still terminates and fits.
    message = "a" + " " * 5000 + "b"
    result = render(san(message), settings(max_chars=2000))
    assert result.text == "\U0001f535 INFO\na" + MARKER
    assert result.truncated


def test_repeated_newlines_cut_correctly() -> None:
    cfg = settings(max_chars=2000)
    message = ("a\n\n" * 1500).strip()  # 4498 characters, ends in "a"
    head = "\U0001f535 INFO\n"
    # Independent oracle: the largest k whose kept text (trailing whitespace removed) plus the
    # marker fits, by linear scan from the top.
    expected = next(
        head + message[:k].rstrip() + MARKER
        for k in range(len(message), -1, -1)
        if len(head + message[:k].rstrip() + MARKER) <= 2000
    )
    result = render(san(message), cfg)
    assert result.truncated
    assert result.text == expected
    assert result.text.endswith("a" + MARKER)


def test_long_single_word_and_100k_input() -> None:
    result = render(san("w" * 100_000), settings())
    assert result.truncated
    assert len(result.text) == 3000
    result = render(san(EMOJI * 100_000, title="t" * 100_000, link="https://a.example"), settings())
    assert result.truncated
    assert len(result.body) <= MAX_BODY_BYTES


def test_cut_may_split_sequences() -> None:
    cfg = settings(max_chars=2000)
    b = budget("\U0001f535 INFO", None, 2000)
    keep = b - len(MARKER)
    zwj = "\U0001f468\u200d\U0001f469\u200d\U0001f467"
    message = "x" * (keep - 2) + zwj + "tail" * 20
    text = render(san(message), cfg).text
    assert text.endswith("x" * (keep - 2) + "\U0001f468\u200d" + MARKER)
    message = "x" * (keep - 1) + "e\u0301" + "z" * 50
    assert render(san(message), cfg).text.endswith("x" * (keep - 1) + "e" + MARKER)
    # Never a lone surrogate: code points, not UTF-16 units.
    render(san(message), cfg).body.decode("utf-8")


# --- the 12000-byte cap -----------------------------------------------------------------------


def test_3000_four_byte_characters_are_cut_to_the_byte_cap() -> None:
    result = render(san(EMOJI * 3000), settings(max_chars=12000))
    assert result.truncated
    assert len(result.body) <= MAX_BODY_BYTES
    # Largest fit: one more character would exceed the cap.
    assert len(result.body) > MAX_BODY_BYTES - 4
    assert result.text.endswith(EMOJI + MARKER)


def test_four_byte_characters_with_a_1024_link_fit() -> None:
    # 2900 * 4 + 1025 exceeds 12000, so 2700 fits and 2900 is pinned as a cut with the link intact.
    link = "https://a.example/" + "p" * (1024 - len("https://a.example/"))
    assert len(link) == 1024
    result = render(san(EMOJI * 2700, link=link), settings(max_chars=12000))
    assert not result.truncated
    assert len(result.body) <= MAX_BODY_BYTES
    assert result.text.endswith("\n" + link)
    assert result.text.count(EMOJI) == 2700
    result = render(san(EMOJI * 2900, link=link), settings(max_chars=12000))
    assert result.truncated
    assert len(result.body) <= MAX_BODY_BYTES
    assert result.text.endswith(MARKER + "\n" + link)


def test_four_byte_boundary_with_a_1024_link() -> None:
    link = "https://a.example/" + "p" * (1024 - len("https://a.example/"))
    cfg = settings(max_chars=12000)
    frame = len(b'{"body":""}')  # 11
    head = len("\U0001f535 INFO\\n".encode())  # 4 + 5 + 2 (escaped LF)
    link_line = 2 + len(link)  # escaped LF plus the link
    n = (MAX_BODY_BYTES - frame - head - link_line) // 4
    result = render(san(EMOJI * n, link=link), cfg)
    assert not result.truncated
    assert len(result.body) <= MAX_BODY_BYTES
    assert result.text.count(EMOJI) == n
    over = render(san(EMOJI * (n + 1), link=link), cfg)
    assert over.truncated
    assert len(over.body) <= MAX_BODY_BYTES
    assert over.text.endswith(MARKER + "\n" + link)


def test_quote_and_backslash_message_stays_within_the_cap() -> None:
    for ch in ('"', "\\", "\n"):
        message = ("a" + ch) * 6000 if ch != "\n" else "a\n" * 6000
        result = render(san(message.strip()), settings(max_chars=12000))
        assert result.truncated
        assert len(result.body) <= MAX_BODY_BYTES
        assert len(result.text) <= 12000
    result = render(san('"' * 12000), settings(max_chars=12000))
    assert result.truncated
    assert MAX_BODY_BYTES - 2 <= len(result.body) <= MAX_BODY_BYTES


def test_byte_boundary_exact_fit_one_over() -> None:
    cfg = settings(max_chars=12000, body_variable="b")
    # Body is {"b":"<text>"} = 8 bytes of frame plus the text bytes.
    prefix = "\U0001f535 INFO\n"  # 6 + 4 ... counted below
    frame = len(json.dumps({"b": ""}, ensure_ascii=False, separators=(",", ":")).encode())
    room = MAX_BODY_BYTES - frame - len(prefix.replace("\n", "\\n").encode())
    fits = render(san("é" * (room // 2)), cfg)
    assert not fits.truncated
    assert len(fits.body) in (MAX_BODY_BYTES, MAX_BODY_BYTES - 1)
    over = render(san("é" * (room // 2 + 1)), cfg)
    assert over.truncated
    assert len(over.body) <= MAX_BODY_BYTES


def test_multibyte_near_cap_agrees_with_linear_oracle() -> None:
    cfg = settings(max_chars=12000)
    for ch, count in [("é", 7000), ("€", 5000), (EMOJI, 3500), ('"', 12000)]:
        message = ch * count
        result = render(san(message), cfg)
        # Oracle: the largest k whose rendering fits, by linear scan from the top.
        fits = None
        for k in range(count, -1, -1):
            kept = message[:k].rstrip()
            text = "\U0001f535 INFO\n" + (kept if k == count else kept + MARKER)
            data = json.dumps({"body": text}, ensure_ascii=False, separators=(",", ":"))
            if len(text) <= 12000 and len(data.encode()) <= MAX_BODY_BYTES:
                fits = text
                break
        assert fits is not None
        assert result.text == fits


def test_rendered_body_annotation_is_builtin_bytes() -> None:
    # The `bytes` property must not shadow the builtin in the class scope's annotations.
    assert typing.get_type_hints(Rendered)["body"] is builtins.bytes


def test_bytes_is_the_request_body_length() -> None:
    result = render(san("héllo €", title="t"), settings(body_variable="slack_text"))
    assert result.bytes == len(result.body)
    assert result.body.startswith(b'{"slack_text":"')


# --- serialization ----------------------------------------------------------------------------


def test_serialization_is_compact_non_ascii_utf8() -> None:
    result = render(san("café € \U0001f600", title="t"), settings())
    assert result.body == ('{"body":"\U0001f535 INFO t\\ncafé € \U0001f600"}'.encode())
    assert b" " not in result.body.split(b'"body":')[0]
    assert b"\\u" not in result.body


def test_control_and_separator_characters_are_escaped_by_json_only() -> None:
    result = render(san('a"b\\c\nd'), settings())
    assert result.body == ('{"body":"\U0001f535 INFO\\na\\"b\\\\c\\nd"}').encode()
    assert json.loads(result.body)["body"] == result.text


def test_body_variable_name_is_the_only_key() -> None:
    result = render(san("m"), settings(body_variable="My_var1"))
    assert list(body_of(result)) == ["My_var1"]


def test_serialization_has_no_nan_or_extra_whitespace() -> None:
    body = render(san("m" * 50), settings()).body
    json.loads(body, parse_constant=lambda name: pytest.fail(name))
    assert body.count(b'"') == 4


def test_render_is_pure_and_deterministic() -> None:
    notification = san("a" * 5000, title="t", link="https://a.example")
    cfg = settings()
    before = json.dumps(cfg, sort_keys=True)
    first, second = render(notification, cfg), render(notification, cfg)
    assert first == second
    assert json.dumps(cfg, sort_keys=True) == before


def test_link_is_rendered_as_given_and_never_cut() -> None:
    link = "https://x.example/%41%7E?q=a&b=c"
    result = render(san("m" * 9000, link=link), settings())
    assert result.truncated
    assert result.text.endswith("\n" + link)
    assert len(result.text) == 3000


# --- config range ----------------------------------------------------------------------------


@pytest.mark.parametrize("max_chars", [2000, 2001, 6000, 12000])
def test_max_chars_range_always_fits(max_chars: int) -> None:
    worst = san(
        EMOJI * 20000,
        title="t" * 300,
        level="action",
        link="https://" + "a" * 1016,
    )
    cfg = settings(max_chars=max_chars, level_prefix={"action": EMOJI * 16})
    result = render(worst, cfg)
    assert result.truncated
    assert len(result.text) <= max_chars
    assert len(result.body) <= MAX_BODY_BYTES
    assert result.text.endswith("\n" + "https://" + "a" * 1016)


def test_title_limit_constant() -> None:
    assert TITLE_LIMIT == 256
    assert MARKER == "…[truncated]"
    assert DEFAULTS["max_chars"] == 3000


# --- golden request bodies --------------------------------------------------------------------

LINK = "https://a.example/path?x=1&y=2#frag"
GOLDEN_CASES: dict[str, tuple[Sanitized, dict[str, Any]]] = {
    "info_title_link": (san("Build passed.", "CI", "info", LINK), {}),
    "warn_no_title": (san("Disk at 91%\n\nCheck soon.", None, "warn"), {}),
    "action_markup": (
        san("<!channel> <@U1> <https://e.example|x> & *b* `c` :tada:", "<!here> & co", "action"),
        {},
    ),
    "error_non_ascii": (san("café € \U0001f600 \u0301", "日本語", "error"), {}),
    "escapes": (san('q"uote \\ back\nline', None, "info"), {"body_variable": "slack_text"}),
    "message_cut": (san("word " * 1000, "T", "info", LINK), {"max_chars": 2000}),
    "title_cut": (san("m", "t" * 300, "warn"), {}),
    "byte_cut": (san(EMOJI * 3000, None, "error"), {"max_chars": 12000}),
}


@pytest.mark.parametrize("name", sorted(GOLDEN_CASES))
def test_golden_request_bodies(name: str) -> None:
    notification, over = GOLDEN_CASES[name]
    result = render(notification, settings(**over))
    path = GOLDEN / f"{name}.json"
    expected = path.read_bytes()
    assert result.body == expected
    assert result.truncated is name.endswith("_cut")


# The goldens were independently reproduced by a spec-literal reference; the two cut goldens are
# also checked here by arithmetic so a reader can verify them without trusting the file.


def test_byte_cut_golden_kept_length_by_arithmetic() -> None:
    frame = len(b'{"body":""}')  # 11
    head = len("\U0001f534 ERROR\\n".encode())  # 4 + 6 + 2 (escaped LF)
    marker = len(MARKER.encode())  # 3 + 11
    kept = (MAX_BODY_BYTES - frame - head - marker) // 4
    assert kept == 2990
    notification, over = GOLDEN_CASES["byte_cut"]
    result = render(notification, settings(**over))
    assert result.text == "\U0001f534 ERROR\n" + EMOJI * kept + MARKER
    assert json.loads(result.body) == {"body": result.text}
    assert result.body == (GOLDEN / "byte_cut.json").read_bytes()


def test_message_cut_golden_kept_length_by_arithmetic() -> None:
    head = "\U0001f535 INFO T\n"
    budget_chars = 2000 - (len(head) - 1) - 1 - (1 + len(LINK))
    keep = budget_chars - len(MARKER)
    kept = ("word " * 1000)[:keep].rstrip()
    notification, over = GOLDEN_CASES["message_cut"]
    result = render(notification, settings(**over))
    assert result.text == head + kept + MARKER + "\n" + LINK
    assert len(result.text) <= 2000
    assert result.body == (GOLDEN / "message_cut.json").read_bytes()

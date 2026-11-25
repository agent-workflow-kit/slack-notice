"""The sanitizer (interface.md, Sanitizer): steps 1 to 5 and the emptiness rule.

The expected values are typed from the interface text, not read from the code's tables.
"""

from __future__ import annotations

import random
import unicodedata

import pytest

from slack_notice import payload, sanitizer
from slack_notice.sanitizer import (
    has_lone_surrogate,
    is_empty,
    is_removed,
    sanitize_message,
    sanitize_title,
)

# --- the removal table, typed from interface.md step 3 ---

INVISIBLE_LIST = (
    (0x00AD, 0x00AD), (0x061C, 0x061C), (0x180E, 0x180E), (0x200B, 0x200B),
    (0x200E, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB), (0xE0000, 0xE007F), (0xE0100, 0xE01EF), (0x115F, 0x1160),
    (0x3164, 0x3164), (0xFFA0, 0xFFA0), (0x2800, 0x2800), (0x180B, 0x180D), (0x180F, 0x180F),
)  # fmt: skip


def _expected_removed() -> set[int]:
    """Every removed code point, built from the interface text only (Cn from the pinned data)."""
    removed: set[int] = set()
    removed.update(range(0x00, 0x20))  # Cc, C0
    removed.update(range(0x7F, 0xA0))  # Cc, DEL and C1
    removed.discard(0x0A)  # LF stays (the others became LF or a space in step 2)
    removed.update(range(0xD800, 0xE000))  # Cs
    removed.update(range(0xE000, 0xF900))  # Co, BMP
    removed.update(range(0xF0000, 0xFFFFE))  # Co, plane 15
    removed.update(range(0x100000, 0x10FFFE))  # Co, plane 16
    removed.update(range(0xFDD0, 0xFDF0))  # noncharacters
    for plane in range(17):
        removed.update((plane * 0x10000 + 0xFFFE, plane * 0x10000 + 0xFFFF))
    for low, high in INVISIBLE_LIST:
        removed.update(range(low, high + 1))
    for low, high in sanitizer.UNASSIGNED_15_0:
        removed.update(range(low, high + 1))
    return removed


def test_the_removal_table_is_the_interface_table_for_every_code_point() -> None:
    expected = _expected_removed()
    actual = {code for code in range(0x110000) if is_removed(chr(code))}
    assert actual == expected


def test_the_pinned_unassigned_table_agrees_with_the_running_python() -> None:
    pinned = {c for low, high in sanitizer.UNASSIGNED_15_0 for c in range(low, high + 1)}
    running = {c for c in range(0x110000) if unicodedata.category(chr(c)) == "Cn"}
    assert running <= pinned  # a newer Python assigns more characters; it never un-assigns one
    if unicodedata.unidata_version == "15.0.0":
        assert running == pinned
    else:
        assert {0x31EF, 0x2FFC, 0x2EBF0} <= pinned - running


def test_the_unassigned_table_is_sorted_disjoint_and_in_range() -> None:
    table = sanitizer.UNASSIGNED_15_0
    assert all(0 <= low <= high <= 0x10FFFF for low, high in table)
    assert all(a[1] < b[0] for a, b in zip(table, table[1:], strict=False))


def test_every_code_point_sanitizes_without_error_and_idempotently() -> None:
    # One pass over the whole code space, in one string per plane (fast: a regex per call).
    for plane in range(17):
        text = "".join(chr(plane * 0x10000 + i) for i in range(0x10000))
        once = sanitize_message(text)
        assert sanitize_message(once) == once
        assert sanitize_title(text) == sanitize_title(sanitize_title(text))
        assert not any(is_removed(char) for char in once)


# Code points by the interface's acceptance list: removed (alone between letters) and kept.
REMOVED_POINTS = [
    0x0000, 0x0001, 0x0008, 0x000B, 0x000C, 0x001B, 0x007F, 0x0080, 0x009F,  # controls, VT, FF
    0x061C, 0x200B, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi, ZWSP
    0x2066, 0x2067, 0x2068, 0x2069, 0x2060, 0x2061, 0x206F,  # isolates, word joiner
    0x00AD, 0xFEFF, 0xFFFE, 0xFFFF, 0xFDD0, 0xFDEF, 0x1FFFE, 0x10FFFF,
    0x180B, 0x180C, 0x180D, 0x180E, 0x180F, 0x2065, 0xFFF0, 0xFFF9, 0xFFFA, 0xFFFB,
    0xE0000, 0xE0001, 0xE0002, 0xE0041, 0xE007F, 0xE0100, 0xE01EF, 0xE01F0, 0xE0FFF,
    0x2800, 0xE000, 0xF8FF, 0xF0000, 0x100000, 0x115F, 0x1160, 0x3164, 0xFFA0,
    0xD800, 0xDBFF, 0xDC00, 0xDFFF,  # surrogates (the validator refuses them first)
    0x0378, 0x2FFC, 0x31EF, 0x2EBF0,  # Cn in 15.0 (some assigned in 15.1)
]  # fmt: skip
KEPT_POINTS = [
    0xFE00, 0xFE01, 0xFE0E, 0xFE0F, 0x200C, 0x200D, 0x0600, 0x0601, 0x0605, 0x06DD, 0x070F,
    0x08E2, 0x034F, 0x16FE4, 0x17B4, 0x0301, 0x1107F, 0x2D7F, 0x0041, 0x00E9, 0x1F535,
]  # fmt: skip


@pytest.mark.parametrize("code", REMOVED_POINTS)
def test_a_removed_point_vanishes_from_the_middle_of_a_word(code: int) -> None:
    assert sanitize_message(f"a{chr(code)}b") == "ab"
    assert sanitize_title(f"a{chr(code)}b") == "ab"


@pytest.mark.parametrize("code", KEPT_POINTS)
def test_a_kept_point_stays_in_the_middle_of_a_word(code: int) -> None:
    text = f"a{chr(code)}b"
    assert sanitize_message(text) == text
    assert sanitize_title(text) == text


def test_a_persian_word_with_zwnj_and_an_emoji_zwj_sequence_are_unchanged() -> None:
    for text in (
        "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
        "\U0001f468\u200d\U0001f469\u200d\U0001f467",
        "\u2764\ufe0f",
    ):
        assert sanitize_message(text) == text


def test_the_tag_block_makes_a_flag_its_base_emoji() -> None:
    flag = "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f"
    assert sanitize_message(flag) == "\U0001f3f4"


# --- step 2: line endings and tabs ---


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("a\r\nb", "a\nb"),
        ("a\rb", "a\nb"),
        ("a\x85b", "a\nb"),
        ("a\u2028b", "a\nb"),
        ("a\u2029b", "a\nb"),
        ("a\n\rb", "a\n\nb"),  # LF then CR: two breaks, not one
        ("a\r\r\nb", "a\n\nb"),  # CR, then CRLF
        ("a\r\n\r\nb", "a\n\nb"),
        ("a\tb", "a b"),
        ("a\t\tb", "a  b"),
        ("a\vb", "ab"),  # VT is removed, not a space
        ("a\fb", "ab"),  # FF too
    ],
)
def test_step_2_line_endings_and_tabs(raw: str, expected: str) -> None:
    assert sanitize_message(raw) == expected


def test_a_removed_character_between_cr_and_lf_does_not_pair_them() -> None:
    # Step 2 runs before step 3: CR and LF are separate when something stood between them.
    assert sanitize_message("a\r\u200b\nb") == "a\n\nb"


def test_no_line_separator_survives() -> None:
    out = sanitize_message("a\r\nb\rc\x85d\u2028e\u2029f")
    assert out == "a\nb\nc\nd\ne\nf"
    assert not any(c in out for c in "\r\x85\u2028\u2029")


# --- step 4: whitespace ---


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("a\n \n \nb", "a\n\nb"),  # acceptance case: whitespace-only lines are blank
        ("a   \nb", "a\nb"),
        ("a\u3000\nb", "a\nb"),  # Unicode whitespace is stripped from line ends
        ("a\n\n\n\n\nb", "a\n\nb"),
        ("a\n\nb", "a\n\nb"),
        ("a\nb", "a\nb"),
        ("\n\n a \n\n", "a"),  # leading whitespace of the text is stripped
        ("  \u3000a", "a"),
        ("a  b", "a  b"),  # interior spaces are kept in a message
        ("  a\n  b", "a\n  b"),  # a line's leading whitespace stays except at the text start
        ("a\n\n\n\n", "a"),
        ("a\u00a0\u2003\nb", "a\nb"),
    ],
)
def test_step_4_whitespace(raw: str, expected: str) -> None:
    assert sanitize_message(raw) == expected


def test_a_text_of_only_whitespace_is_empty_string() -> None:
    assert sanitize_message(" \n\t\u3000\n ") == ""


def test_a_very_long_run_of_line_feeds_collapses_in_linear_time() -> None:
    assert sanitize_message("a" + "\n" * 99_998 + "b") == "a\n\nb"
    assert sanitize_message("a" + " \n" * 50_000 + "b") == "a\n\nb"


# --- step 5: title only ---


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("a\nb", "a b"),
        ("a\n\n\nb", "a b"),
        ("a\u2028b", "a b"),  # acceptance case: LF and U+2028 end on one line
        ("a\n\u2028b", "a b"),
        ("a  b", "a b"),
        ("a\t \tb", "a b"),
        ("  a  ", "a"),
        ("\n\na\n\n", "a"),
        ("a \n b", "a b"),
        ("a\u3000b", "a\u3000b"),  # only spaces collapse, not other whitespace
    ],
)
def test_step_5_title_is_one_line(raw: str, expected: str) -> None:
    out = sanitize_title(raw)
    assert out == expected
    assert "\n" not in out


def test_a_message_is_not_flattened() -> None:
    assert sanitize_message("a\nb") == "a\nb"


# --- the emptiness rule ---


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " ",
        "\u3164",  # filler: removed, nothing left
        "\u200d",
        "\u200c",
        "\u2d7f",  # Mn (Tifinagh consonant joiner)
        "\u0301",
        "\U0001107f",  # Mn (Brahmi number joiner)
        "\u3000",  # fullwidth space
        "\u0903",  # Mc
        "\u20dd",  # Me
        "\ufe0f",
        "\u200c\u200d\u0301 \n",
        "\u200b\u2060\ufeff",  # removed, then nothing
        "\ue000\U000e0041",
    ],
)
def test_empty_by_the_definition(raw: str) -> None:
    assert is_empty(sanitize_message(raw))


@pytest.mark.parametrize(
    "raw", ["a\u0301", "a", "\u0600", "\u200da", "\U0001f535", "\u00ad\u2800a"]
)
def test_not_empty_when_a_visible_character_remains(raw: str) -> None:
    assert not is_empty(sanitize_message(raw))


def test_the_empty_definition_over_every_code_point() -> None:
    for code in range(0x110000):
        char = chr(code)
        category = unicodedata.category(char)
        expected = char.isspace() or char in "\u200c\u200d" or category in ("Mn", "Mc", "Me")
        assert is_empty(char) is expected, hex(code)


# --- step 1: lone surrogates ---


@pytest.mark.parametrize("text", ["\ud800", "a\udc00", "\udbff\udbff", "\udc00\ud800", "x\udfffy"])
def test_a_lone_surrogate_is_detected(text: str) -> None:
    assert has_lone_surrogate(text)


@pytest.mark.parametrize("text", ["", "abc", "\U0001f535", "\ue000", "\uffff", "\u00e9"])
def test_valid_text_has_no_lone_surrogate(text: str) -> None:
    assert not has_lone_surrogate(text)


def test_the_sanitizer_never_returns_a_surrogate_even_if_one_gets_in() -> None:
    assert sanitize_message("a\ud800b") == "ab"
    assert sanitize_title("a\udfffb") == "ab"


# --- hostile input ---


def test_a_combining_mark_flood_is_kept_and_is_not_slow() -> None:
    text = "a" + "\u0301" * 90_000
    assert sanitize_message(text) == text


def test_a_flood_of_joiners_only_is_empty() -> None:
    assert is_empty(sanitize_message("\u200d\u200c" * 40_000))


def test_bom_in_the_middle_is_removed() -> None:
    assert sanitize_message("a\ufeffb\ufeff") == "ab"


def test_nul_is_removed_not_a_terminator() -> None:
    assert sanitize_message("a\x00b") == "ab"
    assert sanitize_message("\x00\x00") == ""


def test_c1_controls_are_removed() -> None:
    assert sanitize_message("".join(chr(c) for c in range(0x80, 0xA0)) + "x") == "x"
    assert sanitize_message("a\x9bb") == "ab"  # a C1 CSI


def test_bidi_overrides_and_isolates_are_removed() -> None:
    assert sanitize_message("a\u202ecba\u202c b \u2066c\u2069") == "acba b c"


def test_ansi_escape_loses_its_escape_byte_only() -> None:
    assert sanitize_message("\x1b[31mred\x1b[0m") == "[31mred[0m"


def test_normalization_is_not_applied() -> None:
    for text in ("e\u0301", "\u00e9", "\u212b", "\ufb01", "\uff21", "A\u030a"):
        assert sanitize_message(text) == text


def test_private_use_unassigned_and_noncharacters_are_removed_in_every_plane() -> None:
    text = "".join(chr(p * 0x10000 + 0xFFFE) + chr(p * 0x10000 + 0xFFFF) for p in range(17))
    assert sanitize_message("a" + text + "b") == "ab"


def test_a_100000_character_input_of_mixed_hostile_text_is_fast_and_clean() -> None:
    unit = "a\u202e\x00\r\n\t\u200d\ue000 \u2028\U000e0041\u00e9"
    text = unit * (100_000 // len(unit))
    out = sanitize_message(text)
    assert not any(is_removed(c) for c in out)
    assert "\r" not in out


def test_the_output_is_deterministic_across_calls() -> None:
    text = "a\r\n\u202e b\u3000\n\n\n\n\t\U000e0041c"
    assert len({sanitize_message(text) for _ in range(3)}) == 1


def test_random_text_is_idempotent_and_clean() -> None:
    rng = random.Random(20260301)  # fixed seed: the same texts on every run
    alphabet = [
        "a", "b", " ", "\n", "\r", "\t", "\u3000", "\u00a0", "\u200b", "\u200c", "\u200d",
        "\u0301", "\x00", "\x85", "\u2028", "\ufe0f", "\ue000", "\u3164", "\u00e9", "\U0001f535",
        "\ud800", "\U000e0041", "\u0378",
    ]  # fmt: skip
    for _ in range(400):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 60)))
        message = sanitize_message(text)
        title = sanitize_title(text)
        assert sanitize_message(message) == message
        assert sanitize_title(title) == title
        assert "\n\n\n" not in message
        assert "\n" not in title
        assert "  " not in title
        assert message == message.strip()
        assert title == title.strip()
        assert not any(is_removed(c) for c in message + title)
        assert not has_lone_surrogate(message + title)


# --- payload: the sanitized notification and empty_message ---


def test_sanitize_notification_gives_the_sanitized_texts() -> None:
    result = payload.sanitize_notification(
        {
            "title": " a\u2028b ",
            "message": "x\r\n\r\n\r\n\r\ny",
            "level": "warn",
            "link": "https://L.example",
        }
    )
    assert (result.title, result.message, result.level, result.link) == (
        "a b",
        "x\n\ny",
        "warn",
        "https://L.example",
    )


def test_the_level_defaults_to_info_and_absent_fields_are_none_or_empty() -> None:
    result = payload.sanitize_notification({"message": "m"})
    assert (result.title, result.level, result.link) == (None, "info", None)
    assert result.title_text == ""  # what the log hash uses for an absent title


@pytest.mark.parametrize("title", ["", " ", "\u3164", "\u200d", "\u0301", "\n\u2028"])
def test_a_title_that_is_empty_by_the_definition_is_absent(title: str) -> None:
    assert payload.sanitize_notification({"title": title, "message": "m"}).title is None


@pytest.mark.parametrize(
    "notification",
    [
        {},
        {"title": "x"},
        {"message": ""},
        {"message": " \n\t "},
        {"message": "\u3164"},
        {"message": "\u200d"},
        {"message": "\u2d7f"},
        {"message": "\u0301"},
        {"message": "\U0001107f"},
        {"message": "\u3000"},
        {"message": "\u200b\ufeff\x00"},
        {"title": "t", "message": "\u202e"},
    ],
)
def test_an_empty_message_is_refused_with_a_fixed_text(notification: dict[str, str]) -> None:
    with pytest.raises(payload.EmptyMessage) as caught:
        payload.sanitize_notification(notification)
    assert caught.value.message == payload.EMPTY_MESSAGE_TEXT
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_a_letter_with_a_combining_mark_is_not_empty() -> None:
    assert payload.sanitize_notification({"message": "a\u0301"}).message == "a\u0301"


# --- payload: lone surrogates from JSON escapes ---


@pytest.mark.parametrize(
    "data, pointer",
    [
        (b'{"message":"\\ud800"}', "/message"),
        (b'{"message":"ok","title":"a\\udc00b"}', "/title"),
        (b'{"message":"a\\udfffz"}', "/message"),
        (b'{"message":"a","link":"\\ud800"}', "/link"),
        (b'{"message":"a","level":"\\ud800"}', "/level"),
        (b'{"message":"a","\\ud800":"x"}', "/?"),  # a key: reported as an unknown name
    ],
)
def test_json_escaped_lone_surrogates_are_refused_with_the_pointer(
    data: bytes, pointer: str
) -> None:
    value = payload.decode_notification(data)
    with pytest.raises(payload.FieldRefused) as caught:
        payload.validate_notification(value)
    assert caught.value.pointer == pointer
    assert "ud800" not in caught.value.message.lower()
    assert caught.value.__context__ is None


def test_a_valid_surrogate_pair_escape_is_one_character_and_is_accepted() -> None:
    value = payload.decode_notification(b'{"message":"\\ud83d\\udd35"}')
    assert payload.validate_notification(value)["message"] == "\U0001f535"


def test_the_length_rule_comes_before_the_surrogate_rule() -> None:
    value = {"message": "\ud800" * (payload.MAX_TEXT_CHARS + 1)}
    with pytest.raises(payload.FieldRefused) as caught:
        payload.validate_notification(value)
    assert caught.value.rule == "length"


def test_a_nesting_of_2000_is_refused_by_the_parser_not_walked() -> None:
    data = b'{"message":' + b"[" * 2000 + b"]" * 2000 + b"}"
    value = payload.decode_notification(data)
    with pytest.raises(payload.FieldRefused) as caught:
        payload.validate_notification(value)
    assert caught.value.rule == "type"

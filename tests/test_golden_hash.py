"""Golden hash tests (#30): the log hashes pinned to constants computed outside the code.

interface.md, Log: ``message_sha256`` is the first 16 hex characters of the SHA-256 of the UTF-8
bytes of the sanitized title (empty when absent), a LF and the sanitized message, before any cut,
prefix or link; ``dedupe_key_sha256`` is the same of the key's UTF-8 bytes.

Every expected value below is a hex constant that was computed once with ``hashlib`` alone from
the sentence above and the literal sanitized text written next to it (``expected_*``), never by
calling ``slack_notice.log``. The raw input goes through the real sanitizer and must come out as
exactly the literal text; the hash of that literal must be the constant. The mutation tests then
change the algorithm, the truncation, the encoding, the separator and the sanitized-text rule and
assert that the same check fails, so the goldens can fail for each thing the issue names.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from slack_notice import log
from slack_notice.config import DEFAULTS
from slack_notice.gateway import SourceRead
from slack_notice.payload import Sanitized, sanitize_notification
from slack_notice.render import render
from tests.fake_gateway import Attempt, FakeGateway
from tests.send_harness import SEND, go

ABSENT = None
"""A title that is not in the input."""


@dataclass(frozen=True)
class HashCase:
    name: str
    raw_title: str | None
    raw_message: str
    expected_title: str  # the sanitized title ("" when it is absent afterwards)
    expected_message: str
    sha: str  # message_sha256: 16 hex characters, computed with hashlib from the two above
    truncated: bool  # whether rendering with the default settings cuts the notification


def case(
    name: str,
    raw_title: str | None,
    raw_message: str,
    expected_title: str,
    expected_message: str,
    sha: str,
    truncated: bool = False,
) -> HashCase:
    return HashCase(name, raw_title, raw_message, expected_title, expected_message, sha, truncated)


ZWJ_FAMILY = "family \U0001f468\u200d\U0001f469\u200d\U0001f467 ok"
CASES = [
    case("ascii", "Build", "all green", "Build", "all green", "c6f7d65297ee1d17"),
    case("no title", ABSENT, "all green", "", "all green", "628aa11c3ed832e2"),
    # a title that is empty after the sanitizer is absent: the hash is the no-title hash
    case("empty title", "", "all green", "", "all green", "628aa11c3ed832e2"),
    case("blank title", "  \n\t \u2028 ", "all green", "", "all green", "628aa11c3ed832e2"),
    case(
        "invisible-only title",
        "\u200b\u202e\ufeff",
        "all green",
        "",
        "all green",
        "628aa11c3ed832e2",
    ),
    case(
        "non-ascii",
        "Caf\u00e9 \u2615",
        "na\u00efve \u65e5\u672c\u8a9e \U0001f680",
        "Caf\u00e9 \u2615",
        "na\u00efve \u65e5\u672c\u8a9e \U0001f680",
        "51bae740aa23265e",
    ),
    # ZWJ (U+200D) is kept by the sanitizer, so the sequence is hashed whole
    case("zwj sequence", ABSENT, ZWJ_FAMILY, "", ZWJ_FAMILY, "10d9604f36d358f9"),
    case(
        "emoji variation selector",
        ABSENT,
        "heart \u2764\ufe0f",
        "",
        "heart \u2764\ufe0f",
        "e8d6406cba508198",
    ),
    # the sanitizer changes the text: CRLF, tab, invisible and bidi characters, U+2028, blank runs
    case(
        "sanitizer changes the text",
        "  Deploy\u200b done\u202e \n ",
        "a\u200bb\r\nc\t d \u202e\n\n\n\nz\u2028 ",
        "Deploy done",
        "ab\nc  d\n\nz",
        "c69345dda6f02dac",
    ),
    case(
        "newline collapse",
        "Line one\n\n  line   two\r\n",
        "p1  \n\n\n\n\np2 \n",
        "Line one line two",
        "p1\n\np2",
        "c0f3562cb0c20ba2",
    ),
    case("composed accent", "caf\u00e9", "m", "caf\u00e9", "m", "b6e897364c3df061"),
    case("decomposed accent", "cafe\u0301", "m", "cafe\u0301", "m", "9fe3db65b891a41f"),
    # exactly the message budget: 3000 - len("\U0001f535 INFO") - 1 = 2993 characters, not cut
    case("message at the cap", ABSENT, "x" * 2993, "", "x" * 2993, "20be9c5eff9b2711"),
    # one more character: the body is cut, the hash is still of the whole message
    case("message over the cap", ABSENT, "x" * 2994, "", "x" * 2994, "c956c856c6a063e7", True),
    case("message far over the cap", ABSENT, "m" * 5000, "", "m" * 5000, "2a65e796221acfeb", True),
    # a title over 256 characters is cut when rendered, never when hashed
    case("title over 256", "t" * 300, "m", "t" * 300, "m", "2dc72990dcc7161a", True),
    case("largest message", ABSENT, "y" * 100000, "", "y" * 100000, "119835561ed91e70", True),
    case("message with one inner LF", ABSENT, "a\nb", "", "a\nb", "6e18b662b03d65f6"),
]

DEDUPE_KEYS: dict[str, tuple[str, str]] = {
    "ascii": ("dedupe-1", "32611fbe419dcd68"),
    "non-ascii": ("cl\u00e9-\u65e5\u672c-\U0001f680", "a8fc0a3628ff488f"),
    "inner LF": ("a\nb", "7e18f737311b2dc3"),  # the key is hashed as given, never sanitized
    "trailing space": ("key ", "f7ba81db8e661ff7"),
    "leading dash": ("-lead", "54e05a0bef38bd81"),
    "1024 characters": ("z" * 1024, "1a165b0441c13a4a"),
}

IDS = [c.name for c in CASES]


def sanitized(c: HashCase) -> Sanitized:
    fields: dict[str, Any] = {"message": c.raw_message}
    if c.raw_title is not None:
        fields["title"] = c.raw_title
    return sanitize_notification(fields)


Hasher = Callable[[str | None, str], str]
Sanitize = Callable[[HashCase], tuple[str | None, str]]


def real_sanitize(c: HashCase) -> tuple[str | None, str]:
    result = sanitized(c)
    return result.title_text, result.message


def check(
    c: HashCase, hasher: Hasher = log.message_sha256, sanitize: Sanitize = real_sanitize
) -> None:
    title, message = sanitize(c)
    assert (title, message) == (c.expected_title, c.expected_message), (
        f"{c.name}: the sanitizer output changed (the sanitized-text rule)"
    )
    assert hasher(title, message) == c.sha, (
        f"{c.name}: message_sha256 changed from the golden {c.sha}: the algorithm, the "
        "16-character truncation, the encoding, the title/LF/message "
        "layout or the sanitized-text rule moved. "
        "If that is intended, recompute the constant independently with hashlib "
        "from interface.md "
        "(Log) and review the change by hand."
    )


@pytest.mark.parametrize("c", CASES, ids=IDS)
def test_message_sha256_golden(c: HashCase) -> None:
    check(c)


def test_every_golden_is_a_distinct_16_hex_value_except_the_no_title_family() -> None:
    shas = [c.sha for c in CASES]
    assert all(len(s) == 16 and s == s.lower() and int(s, 16) >= 0 for s in shas)
    by_sha: dict[str, list[str]] = {}
    for c in CASES:
        by_sha.setdefault(c.sha, []).append(c.name)
    duplicated = {names[0]: names for names in by_sha.values() if len(names) > 1}
    assert set(map(tuple, duplicated.values())) == {
        ("no title", "empty title", "blank title", "invisible-only title")
    }


def test_composed_and_decomposed_accents_hash_differently() -> None:
    """No Unicode normalization anywhere: the hash is of the code points as given."""
    by_name = {c.name: c for c in CASES}
    assert by_name["composed accent"].sha != by_name["decomposed accent"].sha


def test_the_hash_is_of_the_message_before_any_cut() -> None:
    settings = {
        "max_chars": 3000,
        "body_variable": "body",
        "level_prefix": DEFAULTS["level_prefix"],
    }
    for c in CASES:
        rendered = render(sanitized(c), settings)
        assert rendered.truncated is c.truncated, c.name
    full = {c.name: c for c in CASES}
    # the cut body of the 5000-character message is not what is hashed
    assert full["message far over the cap"].expected_message == "m" * 5000


# --- the hash through the real send path ------------------------------------------------------


@pytest.mark.parametrize("c", CASES, ids=IDS)
def test_the_logged_hash_is_the_golden(c: HashCase, fake_gateway: FakeGateway) -> None:
    fake_gateway.script(Attempt())
    body: dict[str, str] = {"message": c.raw_message}
    if c.raw_title is not None:
        body["title"] = c.raw_title
    sent = go(SEND, fake_gateway, stdin=json.dumps(body).encode())
    assert sent.code == 0, sent.stderr
    (record,) = sent.records
    assert record["message_sha256"] == c.sha, c.name
    assert record["truncated"] is c.truncated, c.name


# --- dedupe keys ------------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(DEDUPE_KEYS))
def test_dedupe_key_sha256_golden(name: str) -> None:
    key, expected = DEDUPE_KEYS[name]
    assert log.dedupe_key_sha256(key) == expected, (
        f"dedupe_key_sha256({name}) changed from the golden {expected}"
    )


@pytest.mark.parametrize("name", sorted(DEDUPE_KEYS))
def test_the_logged_dedupe_hash_is_the_golden_and_the_key_is_never_logged(
    name: str, fake_gateway: FakeGateway
) -> None:
    key, expected = DEDUPE_KEYS[name]
    fake_gateway.script(Attempt())
    sent = go([*SEND, f"--dedupe-key={key}"], fake_gateway, stdin=b'{"message":"m"}')
    assert sent.code == 0, sent.stderr
    (record,) = sent.records
    assert record["dedupe_key_sha256"] == expected
    assert sent.document["dedupe_key"] == key  # the output echoes the caller's own key
    escaped = json.dumps(key, ensure_ascii=False)[1:-1].encode()  # as it would be written
    assert len(escaped) >= 4, "a shorter key could match by chance"
    for line in sent.state_files["log.jsonl"].split(b"\n")[:-1]:
        assert escaped not in line and key.encode() not in line  # the log is hash-only


def test_a_message_hash_never_equals_the_dedupe_hash_of_the_same_text() -> None:
    # the message hash includes the LF separator, so "\nm" and "m" are different inputs
    assert log.message_sha256(None, "m") != log.dedupe_key_sha256("m")


# --- mutation self-checks: the golden test must fail for each change the issue names --------


def full(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mutant(build: Callable[[str, str], str]) -> Hasher:
    return lambda title, message: build(title or "", message)


MUTANTS: dict[str, Hasher] = {
    "algorithm sha1": mutant(
        lambda t, m: hashlib.sha1(f"{t}\n{m}".encode()).hexdigest()[:16]  # noqa: S324
    ),
    "algorithm sha512": mutant(lambda t, m: hashlib.sha512(f"{t}\n{m}".encode()).hexdigest()[:16]),
    "algorithm blake2": mutant(lambda t, m: hashlib.blake2b(f"{t}\n{m}".encode()).hexdigest()[:16]),
    "truncation 15": mutant(lambda t, m: full(f"{t}\n{m}".encode())[:15]),
    "truncation 17": mutant(lambda t, m: full(f"{t}\n{m}".encode())[:17]),
    "truncation 64": mutant(lambda t, m: full(f"{t}\n{m}".encode())),
    "last 16 instead of first 16": mutant(lambda t, m: full(f"{t}\n{m}".encode())[-16:]),
    "encoding utf-16": mutant(lambda t, m: full(f"{t}\n{m}".encode("utf-16-le"))[:16]),
    "encoding ascii backslashreplace": mutant(
        lambda t, m: full(f"{t}\n{m}".encode("ascii", "backslashreplace"))[:16]
    ),
    "separator CRLF": mutant(lambda t, m: full(f"{t}\r\n{m}".encode())[:16]),
    "separator space": mutant(lambda t, m: full(f"{t} {m}".encode())[:16]),
    "no separator": mutant(lambda t, m: full(f"{t}{m}".encode())[:16]),
    "message first": mutant(lambda t, m: full(f"{m}\n{t}".encode())[:16]),
    "uppercase hex": mutant(lambda t, m: full(f"{t}\n{m}".encode())[:16].upper()),
    "no leading separator for an absent title": mutant(
        lambda t, m: full((f"{t}\n{m}" if t else m).encode())[:16]
    ),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_a_changed_hash_function_fails_the_golden(name: str) -> None:
    # the non-ASCII case notices an encoding change, the no-title case a layout change
    by_name = {c.name: c for c in CASES}
    for key in ("non-ascii", "no title"):
        try:
            check(by_name[key], hasher=MUTANTS[name])
        except AssertionError as error:
            assert "changed from the golden" in str(error)
            return
    pytest.fail(f"mutant {name!r} was not noticed")


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_each_mutant_is_noticed_by_most_cases(name: str) -> None:
    noticed = 0
    for c in CASES:
        try:
            check(c, hasher=MUTANTS[name])
        except AssertionError:
            noticed += 1
    # "no leading separator" only differs for an absent title, "uppercase" for hex with a letter
    assert noticed >= 5, name


def test_hashing_the_unsanitized_text_gives_a_different_value_than_the_golden() -> None:
    """The sanitized-text rule: for every input the sanitizer changes, the hash of the raw text
    is not the golden (so a change that hashes the raw input fails the golden test)."""
    changed = [
        c
        for c in CASES
        if (c.raw_title or "", c.raw_message) != (c.expected_title, c.expected_message)
    ]
    assert {c.name for c in changed} >= {
        "blank title",
        "invisible-only title",
        "sanitizer changes the text",
        "newline collapse",
    }
    for c in changed:
        assert log.message_sha256(c.raw_title, c.raw_message) != c.sha, c.name

    def raw(c: HashCase) -> tuple[str | None, str]:
        return c.raw_title, c.raw_message

    for c in changed:
        with pytest.raises(AssertionError, match="sanitizer output changed"):
            check(c, sanitize=raw)


def test_hashing_a_partly_sanitized_text_is_also_different() -> None:
    by_name = {c.name: c for c in CASES}
    c = by_name["sanitizer changes the text"]
    # sanitizing only the message, or only the title, is not the rule either
    assert log.message_sha256(c.raw_title, c.expected_message) != c.sha
    assert log.message_sha256(c.expected_title, c.raw_message) != c.sha


def test_a_title_cut_before_hashing_would_fail_the_golden() -> None:
    by_name = {c.name: c for c in CASES}
    c = by_name["title over 256"]
    cut = c.expected_title[:255] + "\u2026"
    assert log.message_sha256(cut, c.expected_message) != c.sha


def test_a_message_cut_before_hashing_would_fail_the_golden() -> None:
    by_name = {c.name: c for c in CASES}
    c = by_name["message over the cap"]
    cut = c.expected_message[:2000] + "\u2026[truncated]"
    assert log.message_sha256(None, cut) != c.sha


def test_a_rendered_body_hash_would_fail_the_golden() -> None:
    by_name = {c.name: c for c in CASES}
    c = by_name["ascii"]
    prefixed = "\U0001f7e0 WARN Build\nall green"
    assert log.message_sha256(None, prefixed) != c.sha


def test_a_lone_surrogate_cannot_be_hashed() -> None:
    """Strict UTF-8: there is no hash of a lone surrogate, so a record can never carry one."""
    with pytest.raises(UnicodeEncodeError):
        log.message_sha256(None, "a\ud800b")
    with pytest.raises(UnicodeEncodeError):
        log.dedupe_key_sha256("\udfff")


def test_a_lone_surrogate_in_the_input_is_refused_before_any_hash(
    fake_gateway: FakeGateway,
) -> None:
    sent = go(SEND, fake_gateway, stdin=b'{"message":"a\\ud800b"}')
    assert sent.code == 20
    (record,) = sent.records
    assert (record["message_sha256"], record["dedupe_key_sha256"]) == (None, None)


def test_the_read_of_stdin_is_not_the_hash_source(fake_gateway: FakeGateway) -> None:
    # a timed-out input has no text and so no hash
    sent = go(SEND, fake_gateway, stdin=SourceRead(b'{"messag', timed_out=True))
    (record,) = sent.records
    assert record["message_sha256"] is None

"""README.md (issue #34): its examples run, its tables match the interface, and it stays clean.

Block convention (a marker comment, then a blank line, then a fenced block):

- ``<!-- test -->``: a shell block whose lines are run through ``cli.main`` with the fake gateway.
  A line is ``[printf '%s' '<json>' | ]slack-notice <args>``; ``printf`` supplies stdin. A trailing
  ``# exit N`` comment is the expected exit code (default 0). A file ``notice.json`` holding the
  README's first example exists in the working directory. A real send gets one scripted OK answer.
- ``<!-- expect -->``: the block must equal the stdout of the last command of the block before.
- ``<!-- expect-stderr -->``: the same for stderr (stdout must then be empty).
- ``<!-- test-config -->``: a YAML block written as the config; ``validate --json`` must pass.
- ``<!-- manual -->``: not run (installation, live Slack, shell setup).

Every fenced block must carry exactly one of these markers.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from slack_notice import cli
from tests.fake_gateway import Attempt, FakeGateway
from tests.harness import ROOT, assert_valid, load_schema
from tests.send_harness import Sent, go, write_config

README = (ROOT / "README.md").read_text(encoding="utf-8")
INTERFACE = (ROOT / "docs" / "interface.md").read_text(encoding="utf-8")
MARKERS = ("test", "expect", "expect-stderr", "test-config", "manual")
NOTICE = {"title": "Build", "message": "all green", "level": "warn", "link": "https://a.example/x"}


@dataclass
class Block:
    marker: str
    lang: str
    text: str
    line: int


FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")


def blocks() -> list[Block]:
    found: list[Block] = []
    lines = README.split("\n")
    i = 0
    while i < len(lines):
        opening = FENCE.match(lines[i])
        if opening:
            fence, lang = opening.group(1), opening.group(2).strip()
            start = i
            body: list[str] = []
            i += 1
            while True:
                if i >= len(lines):
                    raise AssertionError(f"README line {start + 1}: fenced block is never closed")
                if lines[i].strip().startswith(fence) and not lines[i].strip().strip(fence[0]):
                    break
                body.append(lines[i])
                i += 1
            previous = (
                lines[start - 2].strip() if start > 1 and not lines[start - 1].strip() else ""
            )
            marker = ""
            if previous.startswith("<!-- ") and previous.endswith(" -->"):
                name = previous[len("<!-- ") : -len(" -->")]
                if re.fullmatch(r"[a-z-]+", name):
                    marker = name
            found.append(Block(marker, lang, "\n".join(body) + "\n", start + 1))
        i += 1
    return found


def test_every_fenced_block_is_marked() -> None:
    for block in blocks():
        assert block.marker in MARKERS, f"README line {block.line}: block has no marker"


def test_scanner_handles_indented_and_tilde_fences_and_unclosed_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys.modules[__name__],
        "README",
        "<!-- manual -->\n\n  ~~~sh\n  echo a\n  ~~~\n\n<!-- test -->\n\n```sh\nx\n```\n",
    )
    found = blocks()
    assert [(b.marker, b.text) for b in found] == [("manual", "  echo a\n"), ("test", "x\n")]
    monkeypatch.setattr(sys.modules[__name__], "README", "<!-- manual -->\n\n```sh\nx\n")
    with pytest.raises(AssertionError, match="never closed"):
        blocks()


def commands(block: Block) -> list[tuple[list[str], bytes | None, int]]:
    result = []
    for raw in block.text.splitlines():
        if not raw.strip():
            continue
        exit_match = re.search(r"\s+#\s*exit (\d+)\s*$", raw)
        expected = int(exit_match.group(1)) if exit_match else 0
        line = raw[: exit_match.start()] if exit_match else raw
        lexer = shlex.shlex(line, posix=True, punctuation_chars="|")
        lexer.whitespace_split = True
        words = list(lexer)
        stdin: bytes | None = None
        if "|" in words:
            cut = words.index("|")
            left, words = words[:cut], words[cut + 1 :]
            assert left[:2] == ["printf", "%s"] and len(left) == 3, raw
            stdin = left[2].encode()
        assert words[0] == "slack-notice", raw
        assert "--config" not in words, f"README line {block.line}: examples must not pass --config"
        result.append((words[1:], stdin, expected))
    return result


COMMAND_POSITION = re.compile(r"(?:^|[|;&(]\s*)slack-notice(?:\s|$)")


def test_manual_blocks_hold_no_slack_notice_command() -> None:
    # A command that could run offline must not be hidden from the test run by a manual marker.
    for block in blocks():
        if block.marker == "manual":
            for line in block.text.splitlines():
                assert not COMMAND_POSITION.search(line), f"README line {block.line}: {line}"


def schema_for(argv: list[str], code: int) -> str:
    if code in (1, 2, 20) or (code == 12 and argv[0] == "send"):
        return "cli/error"
    return f"cli/{argv[0]}"


def run_block(block: Block, gateway: FakeGateway, tmp_path: Path) -> Sent:
    config = write_config(tmp_path)
    run = commands(block)
    assert run, f"README line {block.line}: a test block must hold a slack-notice command"
    last: Sent | None = None
    for argv, stdin, expected in run:
        sends = (argv[0] == "send" and "--dry-run" not in argv) or "--test-message" in argv
        if sends and expected == 0:
            gateway.script(Attempt())
        last = go(argv, gateway, stdin=stdin, config=config)
        assert last.code == expected, (block.line, argv, last.stderr)
        if "--json" in argv:
            assert_valid(schema_for(argv, last.code), last.out)
    assert last is not None
    return last


def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fresh working directory holding the notice.json that the README has the reader make."""
    work = tmp_path / "work"
    work.mkdir()
    (work / "notice.json").write_text(json.dumps(NOTICE), encoding="utf-8")
    monkeypatch.chdir(work)
    return work


EXEC = [b for b in blocks() if b.marker == "test"]
PAIRS = [
    (all_blocks[i - 1], b)
    for all_blocks in [blocks()]
    for i, b in enumerate(all_blocks)
    if b.marker in ("expect", "expect-stderr")
]
# Exact counts of the README's executable blocks and expect pairs. Update these
# when the README's executable blocks change.
EXPECTED_EXEC_BLOCKS = 10
MIN_PAIRS = 3


def test_enough_examples_are_executed() -> None:
    assert len(EXEC) == EXPECTED_EXEC_BLOCKS
    assert sum(len(commands(b)) for b in EXEC) >= EXPECTED_EXEC_BLOCKS
    assert len(PAIRS) >= MIN_PAIRS


@pytest.mark.parametrize("block", EXEC, ids=[f"line{b.line}" for b in EXEC])
def test_example_blocks_run(
    block: Block, fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workdir(tmp_path, monkeypatch)
    run_block(block, fake_gateway, tmp_path)
    fake_gateway.assert_script_consumed()


@pytest.mark.parametrize("pair", PAIRS, ids=[f"line{e.line}" for _, e in PAIRS])
def test_expect_blocks_match_the_output(
    pair: tuple[Block, Block],
    fake_gateway: FakeGateway,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous, expect = pair
    assert previous.marker == "test", f"README line {expect.line}: expect must follow a test block"
    workdir(tmp_path, monkeypatch)
    sent = run_block(previous, fake_gateway, tmp_path)
    if expect.marker == "expect":
        assert sent.stdout == expect.text, expect.line
    else:
        assert sent.stderr == expect.text, expect.line
        assert sent.stdout == "", expect.line  # without --json, stdout stays empty
    fake_gateway.assert_script_consumed()


def test_config_blocks_validate(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    configs = [b for b in blocks() if b.marker == "test-config"]
    assert len(configs) == 1
    for block in configs:
        assert yaml.safe_load(block.text) == {
            "webhook_env": "SLACK_WEBHOOK",
            "body_variable": "message_text",
            "timeout": "20s",
        }
        path = write_config(tmp_path, block.text)
        sent = go(["validate", "--json"], fake_gateway, config=path)
        assert sent.code == 0, sent.stdout
        assert assert_valid("cli/validate", sent.out)["ok"] is True


def test_notice_json_block_creates_the_notice_the_harness_uses() -> None:
    created = [b for b in blocks() if b.marker == "manual" and "> notice.json" in b.text]
    assert len(created) == 1
    words = shlex.split(created[0].text)
    assert words[:2] == ["printf", "%s"] and json.loads(words[2]) == NOTICE


def test_validate_prose_claims(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    unset = go(["validate"], fake_gateway, env={}, config=write_config(tmp_path))
    assert unset.code == 12 and unset.stdout == ""
    assert unset.stderr.splitlines()[-1].startswith("credential: failed (")
    quiet = go(["validate", "--quiet"], fake_gateway, env={}, config=write_config(tmp_path))
    assert quiet.code == 12 and quiet.stderr.splitlines() == [unset.stderr.splitlines()[-1]]
    bad = go(["validate"], fake_gateway, config=write_config(tmp_path, "bogus: 1\n"))
    assert bad.code == 2
    off = go(
        ["validate", "--json"], fake_gateway, config=write_config(tmp_path, "enabled: false\n")
    )
    assert off.code == 0 and assert_valid("cli/validate", off.out)["enabled"] is False
    disabled = go(
        ["send", "--message", "x"], fake_gateway, config=write_config(tmp_path, "enabled: false\n")
    )
    assert disabled.code == 22


# --- tables -------------------------------------------------------------------------------------


def table(text: str, first_header: str) -> list[list[str]]:
    lines = text.split("\n")
    start = next(i for i, ln in enumerate(lines) if re.match(rf"\|\s*{first_header}\s*\|", ln))
    rows = []
    for ln in lines[start + 2 :]:
        if not ln.startswith("|"):
            break
        rows.append([c.strip() for c in ln.strip().strip("|").split("|")])
    return rows


def exit_table(text: str) -> dict[int, set[str]]:
    return {
        int(row[0]): set(re.findall(r"`([a-z_]+)`", row[2]))
        for row in table(text, "Exit")
        if row[0].isdigit()
    }


def test_exit_code_table_matches_the_interface() -> None:
    readme = exit_table(README.split("## 7. Exit codes")[1])
    interface = exit_table(INTERFACE.split("## Exit codes")[1])
    assert readme == interface
    assert set(readme) == set(cli.ERROR_EXIT_CODES) | {0, 22}
    assert "128 plus the signal number" in FLAT


def test_in_a_script_column_agrees_with_the_interface() -> None:
    rows = {
        int(row[0]): row[3].lower()
        for row in table(README.split("## 7. Exit codes")[1], "Exit")
        if row[0].isdigit()
    }
    assert "no-op" in rows[22] and "successful" in rows[22]
    assert "never retry" in rows[20] and "do not retry" in rows[2]
    assert "`retryable`" in rows[12] and "`unknown_outcome`" in rows[12]
    automation = INTERFACE.split("## Calling from automation")[1]
    assert (
        "successful no-op" in automation and "Do not retry; surface once per reason" in automation
    )


def codes_in(text: str, known: set[str]) -> set[str]:
    return {c for c in re.findall(r"[a-z_]+", text) if c in known}


def section(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    assert m, pattern
    return m.group(1)


def test_retryable_bullets_match_the_error_envelope() -> None:
    known = exit_table(README.split("## 7. Exit codes")[1])[12]
    envelope = INTERFACE.split("### Error envelope")[1]
    spec_ff = codes_in(section(r"\(false, false\): ([^;]*);", envelope), known)
    spec_tf = codes_in(section(r"\(true, false\): ([^;]*);", envelope), known)
    spec_ft = codes_in(section(r"\(false, true\): ([^.]*)\.", envelope), known)
    assert "network_error (false, false when details.tls is true)" in envelope
    bullets = {
        key: re.search(rf"^- `{key}`.*?\((.*?)\):", README, re.M)
        for key in (
            "retryable: true` and `unknown_outcome: false",
            "retryable: false` and `unknown_outcome: false",
            "unknown_outcome: true",
        )
    }
    got = [codes_in(m.group(1), known) for m in bullets.values() if m]
    assert len(got) == 3
    assert got[0] == spec_tf
    assert got[1] == spec_ff | {"network_error"}
    assert got[2] == spec_ft


def test_config_keys_in_the_readme_exist_in_the_schema() -> None:
    keys = [row[0].strip("`") for row in table(README, "Key")]
    properties = set(load_schema("config")["properties"])
    assert set(keys) == properties
    for block in blocks():
        if block.marker == "test-config":
            for line in block.text.splitlines():
                name = re.match(r"([a-z_]+):", line)
                assert name and name.group(1) in properties


# --- content rules ------------------------------------------------------------------------------


FLAT = " ".join(README.split())  # one reflow of the prose cannot break a phrase check


def test_sent_means_accepted_not_delivered() -> None:
    assert "mean only that Slack accepted the request" in FLAT
    assert "do not mean the message was delivered or read" in FLAT


def test_unsupported_proxy_and_ca_are_stated() -> None:
    assert "Proxy settings are not supported in 0.x" in FLAT
    assert "`SSL_CERT_FILE`" in FLAT
    assert re.search(r"hooks\.slack\.com", FLAT)


def test_nothing_private_and_no_url_like_trigger() -> None:
    lowered = README.lower()
    assert not re.search(r"\b[a-z]+ctl\b", lowered)  # no sibling command words
    assert "triggers/" not in README
    assert not re.search(r"hooks\.slack\.com/", README)
    assert not re.search(r"xox[a-z]-", lowered)
    assert not re.search(r"(?<![\w.])/(?:home|storage|Users)/", README)


def test_this_test_file_names_no_sibling_tool() -> None:
    assert not re.search(r"\b[a-z]+ctl\b", Path(__file__).read_text(encoding="utf-8"))


def test_paragraphs_are_single_lines() -> None:
    # A wrapped paragraph would show up as two consecutive non-blank prose lines.
    fenced = False
    previous = ""
    for number, line in enumerate(README.split("\n"), 1):
        if FENCE.match(line):
            fenced = not fenced
            previous = ""
            continue
        if fenced:
            continue
        prose = bool(line.strip()) and not re.match(r"\s*([-*]|\d+\.|\||#|<!--)", line)
        if prose and previous:
            raise AssertionError(f"README line {number} continues a paragraph")
        previous = line if prose else ""

"""README.md (issue #34): its examples run, its tables match the interface, and it stays clean.

Block convention (a marker comment, then a blank line, then a fenced block):

- ``<!-- test -->``: a shell block whose lines are run through ``cli.main`` with the fake gateway.
  A line is ``[printf '%s' '<json>' | ]slack-notice <args>``; ``printf`` supplies stdin. A trailing
  ``# exit N`` comment is the expected exit code (default 0). A file ``notice.json`` holding the
  README's first example exists in the working directory. A real send gets one scripted OK answer.
- ``<!-- expect -->``: the block must equal the stdout of the last command of the block before.
- ``<!-- test-config -->``: a YAML block written as the config; ``validate --json`` must pass.
- ``<!-- manual -->``: not run (installation, live Slack, shell setup).

Every fenced block must carry exactly one of these markers.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

import pytest

from slack_notice import cli
from tests.fake_gateway import Attempt, FakeGateway
from tests.harness import ROOT, assert_valid, load_schema
from tests.send_harness import go, write_config

README = (ROOT / "README.md").read_text(encoding="utf-8")
INTERFACE = (ROOT / "docs" / "interface.md").read_text(encoding="utf-8")
MARKERS = ("test", "expect", "test-config", "manual")
NOTICE = {"title": "Build", "message": "all green", "level": "warn", "link": "https://a.example/x"}


@dataclass
class Block:
    marker: str
    lang: str
    text: str
    line: int


def blocks() -> list[Block]:
    found: list[Block] = []
    lines = README.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].startswith("```"):
            lang = lines[i][3:].strip()
            start = i
            body: list[str] = []
            i += 1
            while not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            previous = lines[start - 2] if start > 1 and not lines[start - 1].strip() else ""
            match = re.fullmatch(r"<!-- ([a-z-]+) -->", previous)
            marker = match.group(1) if match else ""
            found.append(Block(marker, lang, "\n".join(body) + "\n", start + 1))
        i += 1
    return found


def test_every_fenced_block_is_marked() -> None:
    for block in blocks():
        assert block.marker in MARKERS, f"README line {block.line}: block has no marker"


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
        result.append((words[1:], stdin, expected))
    return result


def schema_for(argv: list[str], code: int) -> str:
    if code in (1, 2, 20) or (code == 12 and argv[0] == "send"):
        return "cli/error"
    return f"cli/{argv[0]}"


def run_block(block: Block, gateway: FakeGateway, tmp_path: Path) -> bytes:
    config = write_config(tmp_path)
    last = b""
    for argv, stdin, expected in commands(block):
        sends = (argv[0] == "send" and "--dry-run" not in argv) or "--test-message" in argv
        if sends and expected == 0:
            gateway.script(Attempt())
        sent = go(argv, gateway, stdin=stdin, config=config)
        assert sent.code == expected, (block.line, argv, sent.stderr)
        if "--json" in argv:
            assert_valid(schema_for(argv, sent.code), sent.out)
        last = sent.out
    return last


EXEC = [b for b in blocks() if b.marker == "test"]


@pytest.mark.parametrize("block", EXEC, ids=[f"line{b.line}" for b in EXEC])
def test_example_blocks_run(
    block: Block, fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "notice.json").write_text(json.dumps(NOTICE), encoding="utf-8")
    monkeypatch.chdir(work)
    run_block(block, fake_gateway, tmp_path)
    fake_gateway.assert_script_consumed()


def test_expect_blocks_match_the_output(
    fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    all_blocks = blocks()
    pairs = [(all_blocks[i - 1], b) for i, b in enumerate(all_blocks) if b.marker == "expect"]
    assert pairs
    for previous, expect in pairs:
        assert previous.marker == "test"
        out = run_block(previous, fake_gateway, tmp_path)
        assert out.decode() == expect.text, expect.line


def test_config_blocks_validate(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    configs = [b for b in blocks() if b.marker == "test-config"]
    assert configs
    for block in configs:
        path = write_config(tmp_path, block.text)
        sent = go(["validate", "--json"], fake_gateway, config=path)
        assert sent.code == 0, sent.stdout
        assert assert_valid("cli/validate", sent.out)["ok"] is True


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
    assert "128 plus the signal number" in README


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


def test_sent_means_accepted_not_delivered() -> None:
    assert "mean only that Slack accepted the request" in README
    assert "do not mean the message was delivered or read" in README


def test_unsupported_proxy_and_ca_are_stated() -> None:
    assert "Proxy settings are not supported in 0.x" in README
    assert "`SSL_CERT_FILE`" in README


def test_no_sibling_tool_and_no_url_like_trigger() -> None:
    lowered = README.lower()
    for word in ("awkit", "wtctl", "termctl", "jobsctl", "memoctl", "forgectl"):
        assert word not in lowered
    assert "triggers/" not in README
    assert not re.search(r"https?://hooks\.slack\.com", README)
    assert "xoxb" not in lowered


def test_paragraphs_are_single_lines() -> None:
    # A wrapped paragraph would show up as two consecutive non-blank prose lines.
    fenced = False
    previous = ""
    for number, line in enumerate(README.split("\n"), 1):
        if line.startswith("```"):
            fenced = not fenced
            previous = ""
            continue
        if fenced:
            continue
        prose = bool(line.strip()) and not re.match(r"\s*([-*]|\d+\.|\||#|<!--)", line)
        if prose and previous:
            raise AssertionError(f"README line {number} continues a paragraph")
        previous = line if prose else ""

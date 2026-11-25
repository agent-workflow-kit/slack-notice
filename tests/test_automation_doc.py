"""docs/automation.md (issue #35): its examples run, its table matches the interface.

Block convention (a marker comment, a blank line, then a fenced block):

- ``<!-- test-cron -->``: crontab lines. Each command is run through ``/bin/sh -c`` as cron does,
  in a real child process with a private HOME, a guard that ends the child with exit 97 on any
  connect or name lookup, and a stand-in ``slack-notice`` that runs ``python -m slack_notice``
  with ``--config <tmp config>`` (and ``--dry-run`` for a send) appended.
- ``<!-- test-sh -->``: a shell snippet run in ``sh`` against a stub ``slack-notice``.
- ``<!-- test-py -->``: Python code executed in-process against a stub ``slack-notice``.
- ``<!-- golden <path under tests/golden> -->``: the block equals that golden file.
- ``<!-- manual -->``: not run (sets up files on the reader's machine).

Every fenced block must carry exactly one of these markers. No test here reaches the network.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.harness import ROOT, assert_valid
from tests.send_harness import ENV_NAME, URL
from tests.test_secrets_env import guarded_env

DOC = (ROOT / "docs" / "automation.md").read_text(encoding="utf-8")
INTERFACE = (ROOT / "docs" / "interface.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
DESIGN = (ROOT / "docs" / "design.md").read_text(encoding="utf-8")
MARKERS = ("test-cron", "test-sh", "test-py", "golden", "manual")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
MARK = re.compile(r"<!-- ([a-z-]+)(?: (\S+))? -->")
FLAT = " ".join(DOC.split())
PYTHON3 = Path(sys.executable)
SPAWNED: list[subprocess.Popen[bytes]] = []


@dataclass
class Block:
    marker: str
    arg: str
    lang: str
    text: str
    line: int


def blocks() -> list[Block]:
    found: list[Block] = []
    lines = DOC.split("\n")
    i = 0
    while i < len(lines):
        opening = FENCE.match(lines[i])
        if opening:
            fence, lang, start = opening.group(1), opening.group(2).strip(), i
            body: list[str] = []
            i += 1
            while not (lines[i].strip().startswith(fence) and not lines[i].strip().strip("`~")):
                body.append(lines[i])
                i += 1
            previous = (
                lines[start - 2].strip() if start > 1 and not lines[start - 1].strip() else ""
            )
            m = MARK.fullmatch(previous)
            found.append(
                Block(
                    m.group(1) if m else "",
                    (m.group(2) or "") if m else "",
                    lang,
                    "\n".join(body) + "\n",
                    start + 1,
                )
            )
        i += 1
    return found


def of(marker: str) -> list[Block]:
    return [b for b in blocks() if b.marker == marker]


# --- structure ----------------------------------------------------------------------------------


def test_every_fenced_block_is_marked() -> None:
    for block in blocks():
        assert block.marker in MARKERS, f"automation.md line {block.line}: block has no marker"


def test_the_blocks_are_the_expected_ones() -> None:
    assert len(of("test-cron")) == 1 and len(of("test-sh")) == 1 and len(of("test-py")) == 1
    assert sorted(b.arg for b in of("golden")) == [
        "send/credential_invalid.stdout",
        "send/disabled.stdout",
        "send/network_error_deadline_cuts_wait.stdout",
        "send/rate_limited.stdout",
        "validate/credential_unset.stdout",
        "validate/ok.stdout",
    ]
    assert len(of("manual")) == 1


COMMAND_POSITION = re.compile(r"(?:^|[|;&(]\s*|\s)(?:\S*/)?slack-notice(?:\s|$)")


def test_manual_blocks_hold_no_slack_notice_command() -> None:
    for block in of("manual"):
        for line in block.text.splitlines():
            assert not COMMAND_POSITION.search(line), f"line {block.line}: {line}"


def test_paragraphs_are_single_lines() -> None:
    fenced = False
    previous = ""
    for number, line in enumerate(DOC.split("\n"), 1):
        if FENCE.match(line):
            fenced = not fenced
            previous = ""
            continue
        if fenced:
            continue
        prose = bool(line.strip()) and not re.match(r"\s*([-*]|\d+\.|\||#|<!--)", line)
        assert not (prose and previous), f"automation.md line {number} continues a paragraph"
        previous = line if prose else ""


def test_nothing_private_and_no_url_like_trigger() -> None:
    marker = "trigger" + "s/"
    for text in (DOC, Path(__file__).read_text(encoding="utf-8")):
        assert not re.search(r"\b[a-z]+ctl\b", text.lower())
        assert not re.search(r"xox[a-z]-", text.lower())
        assert not re.search(r"(?<![\w.])/(?:home|storage|Users)/", text)
    assert marker not in DOC
    assert "hooks" + ".slack" not in DOC


def test_the_doc_is_linked_from_the_readme_and_the_design() -> None:
    assert "(docs/automation.md)" in README
    assert "(automation.md)" in DESIGN


# --- golden examples ----------------------------------------------------------------------------


@pytest.mark.parametrize("block", of("golden"), ids=lambda b: b.arg)
def test_golden_blocks_equal_the_golden_files(block: Block) -> None:
    path = ROOT / "tests" / "golden" / block.arg
    assert block.text == path.read_text(encoding="utf-8")
    kind = "validate" if block.arg.startswith("validate/") else "send"
    if '"error"' in block.text:
        assert_valid("cli/error", block.text)
    else:
        assert_valid(f"cli/{kind}", block.text)


# --- the exit-code table (criterion b) ----------------------------------------------------------


def table(text: str) -> list[list[str]]:
    lines = text.split("\n")
    start = next(i for i, ln in enumerate(lines) if ln.startswith("| Exit |"))
    rows = []
    for ln in lines[start + 2 :]:
        if not ln.startswith("|"):
            break
        rows.append([c.strip() for c in ln.strip().strip("|").split("|")])
    return rows


def test_the_exit_code_table_equals_the_one_of_calling_from_automation() -> None:
    spec = INTERFACE.split("## Calling from automation")[1].split("\n## ")[0]
    assert table(DOC) == table(spec)
    assert len(table(spec)) == 8


# --- sentences (criterion c) --------------------------------------------------------------------


def test_the_doc_says_one_machine_is_serialized_but_the_caller_sends_one_at_a_time() -> None:
    assert (
        "the tool serializes one machine's sends, but the caller still sends one notification "
        "at a time" in FLAT
    )
    assert "Across machines nothing is coordinated" in FLAT


def test_the_doc_states_the_kill_and_stdin_rules() -> None:
    assert "no less than `timeout` plus 10 s" in FLAT
    assert "must ignore EPIPE (and SIGPIPE)" in FLAT
    assert "Do not put it in a frequent cron line" in FLAT
    assert "must be mode 0600" in FLAT and "A file that others can read" in FLAT
    assert "`\\%`" in FLAT and "does not read your profile" in FLAT


def test_the_doc_states_the_remaining_wordings() -> None:
    assert "It checks `unknown_outcome` before `retryable`" in FLAT
    assert "a burst of 12 requests in about 3 seconds got 429 in testing" in FLAT
    assert "the result print waits at most 1 s for a stalled reader" in FLAT
    assert "the process ends within `timeout` plus 3 s regardless" in FLAT
    assert "`details.timeout` is true when a connection attempt itself timed out" in FLAT
    assert "the deadline arrived before any failure had been recorded" in FLAT
    assert "do not depend on the order of the keys inside `details`" in FLAT
    assert "reopened" not in FLAT and "/dev/null" not in FLAT
    assert "`unexpected-exit`" in FLAT and "137 (SIGKILL) means that something killed" in FLAT
    assert "SIGTERM after the send started yields the deadline result" in FLAT
    assert "a dry run carries the rendered message" in FLAT


def test_the_cron_lines_join_the_env_file_and_the_tool_with_and_and() -> None:
    for kind in ("send", "validate"):
        line = cron_line(kind)
        assert '. "$HOME/.config/slack-notice/env" && "$HOME/.local/bin/slack-notice" ' in line
        assert ";" not in line.split('slack-notice" ')[0]
    guard = '|| { rc=$?; [ "$rc" = 22 ] || echo "slack-notice failed: $rc" >&2; }'
    assert guard in cron_line("send")


def test_the_env_file_recipe_exports_and_keeps_the_secret_off_the_command_line() -> None:
    recipe = of("manual")[0].text
    assert re.search(r"export SLACK_WEBHOOK=", recipe)
    assert re.search(r"\(\n\s+umask 077\n(?:.*\n)*?\)", recipe)  # in a subshell
    assert "rm -f" in recipe and "chmod 600" in recipe and "ls -l" in recipe
    assert "IFS= read -r url" in recipe
    for line in recipe.splitlines():  # the secret only ever sits in a shell built-in's argument
        if "$url" in line:
            assert line.lstrip().startswith("printf ")


@pytest.mark.parametrize("preexisting", [False, True])
def test_the_env_file_recipe_makes_a_0600_file_that_exports(
    tmp_path: Path, preexisting: bool
) -> None:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(tmp_path / "xdg"), "PATH": "/usr/bin:/bin"}
    target = home / ".config" / "slack-notice" / "env"
    if preexisting:
        target.parent.mkdir(parents=True)
        target.write_text("old\n", encoding="utf-8")
        target.chmod(0o644)
    code, _, err = run(["/bin/sh", "-c", of("manual")[0].text], env, tmp_path, URL.encode() + b"\n")
    assert code == 0, err
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    probe = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", f'. "{target}" && /usr/bin/env'],
        env=env, capture_output=True, text=True, timeout=30, check=True,
    )  # fmt: skip
    assert f"{ENV_NAME}={URL}" in probe.stdout.splitlines()


# --- real processes -----------------------------------------------------------------------------


def run(
    argv: list[str], env: dict[str, str], cwd: Path, stdin: bytes = b""
) -> tuple[int, str, str]:
    """Run a real child, keep its Popen handle, never signal anything but that exact handle."""
    process = subprocess.Popen(
        argv, env=env, cwd=str(cwd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )  # fmt: skip
    SPAWNED.append(process)
    try:
        out, err = process.communicate(stdin, timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()  # this exact handle, never a pattern
        process.communicate()
        raise
    return process.returncode, out.decode(), err.decode()


def cron_commands() -> list[tuple[str, str]]:
    """(schedule, command) of each crontab line; the command is what cron hands to /bin/sh."""
    result = []
    for raw in of("test-cron")[0].text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        fields = raw.split(None, 5)
        assert len(fields) == 6, raw
        assert not re.search(r"(?<!\\)%", fields[5]), "an unescaped percent sign in a crontab line"
        result.append((" ".join(fields[:5]), fields[5]))
    return result


@dataclass
class Machine:
    home: Path
    env: dict[str, str]
    envfile: Path
    log: Path


def machine(
    tmp_path: Path, *, extra: str, exported: bool = True, with_envfile: bool = True
) -> Machine:
    home = tmp_path / "home"
    (home / ".config" / "slack-notice").mkdir(parents=True)
    (home / ".local" / "bin").mkdir(parents=True)
    (home / ".local" / "state").mkdir(parents=True)
    config = tmp_path / "config.yaml"
    config.write_text("log: false\n", encoding="utf-8")
    wrapper = home / ".local" / "bin" / "slack-notice"
    wrapper.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -m slack_notice "$@" '
        f"--config {shlex.quote(str(config))} {extra}\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    (home / ".config" / "slack-notice" / "nightly.json").write_text(
        json.dumps({"title": "Nightly", "message": "report finished"}), encoding="utf-8"
    )
    envfile = home / ".config" / "slack-notice" / "env"
    if with_envfile:
        fd = os.open(envfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"{'export ' if exported else ''}{ENV_NAME}='{URL}'\n")
        envfile.chmod(0o600)
    env = guarded_env(home, tmp_path)
    env["PATH"] = "/usr/bin:/bin"  # cron's minimal PATH
    return Machine(home, env, envfile, home / ".local" / "state" / "slack-notice-cron.out")


def cron_line(kind: str) -> str:
    return next(c for _, c in cron_commands() if f" {kind} " in c)


def test_the_cron_lines_have_five_schedule_fields() -> None:
    assert [s for s, _ in cron_commands()] == ["30 2 * * *", "*/30 * * * *"]


def test_the_env_file_of_the_test_is_mode_0600(tmp_path: Path) -> None:
    m = machine(tmp_path, extra="")
    assert stat.S_IMODE(m.envfile.stat().st_mode) == 0o600


def test_the_documented_nightly_line_runs_with_an_env_file_of_mode_0600(tmp_path: Path) -> None:
    m = machine(tmp_path, extra="--dry-run")
    code, out, err = run(["/bin/sh", "-c", cron_line("send")], m.env, m.home)
    assert code == 0 and out == "" and err == "", (out, err)
    document = assert_valid("cli/send", m.log.read_text(encoding="utf-8"))
    assert document["outcome"] == "dry_run" and document["rendered"]


def test_a_failing_send_writes_its_exit_code_to_stderr_for_cron_to_mail(tmp_path: Path) -> None:
    m = machine(tmp_path, extra="--no-such-flag")
    code, out, err = run(["/bin/sh", "-c", cron_line("send")], m.env, m.home)
    assert (code, out, err) == (0, "", "slack-notice failed: 2\n")
    assert m.log.read_text(encoding="utf-8")  # the details stay in the file


def test_a_disabled_tool_exit_22_is_not_mailed_by_the_nightly_line(tmp_path: Path) -> None:
    m = machine(tmp_path, extra="")
    stub = m.home / ".local" / "bin" / "slack-notice"
    stub.write_text("#!/bin/sh\nexit 22\n", encoding="utf-8")
    code, out, err = run(["/bin/sh", "-c", cron_line("send")], m.env, m.home)
    assert (code, out, err) == (0, "", "")


def test_the_doc_lists_exit_1_with_a_idle_gate_among_the_unlogged_outcomes() -> None:
    assert "Exit 1 while the gate is not writing, exit codes 2 and 22" in FLAT


def test_the_documented_health_line_reads_the_credential_from_the_env_file(tmp_path: Path) -> None:
    m = machine(tmp_path, extra="")
    code, out, err = run(["/bin/sh", "-c", cron_line("validate")], m.env, m.home)
    assert (code, out, err) == (0, "", "")  # --quiet: nothing when ok


def test_without_the_env_file_credential_the_health_line_fails(tmp_path: Path) -> None:
    # The environment of cron has no variable: the plain call fails with exit 12.
    m = machine(tmp_path, extra="", with_envfile=False)
    plain = cron_line("validate").replace('. "$HOME/.config/slack-notice/env" && ', "")
    code, out, err = run(["/bin/sh", "-c", plain], m.env, m.home)
    assert code == 12 and out == "" and err.startswith("credential: failed (")


def test_a_plain_assignment_without_export_does_not_reach_the_tool(tmp_path: Path) -> None:
    m = machine(tmp_path, extra="", exported=False)
    code, _, err = run(["/bin/sh", "-c", cron_line("validate")], m.env, m.home)
    assert code == 12 and err.startswith("credential: failed (")


def test_a_missing_env_file_stops_the_line_before_the_tool_runs(tmp_path: Path) -> None:
    m = machine(tmp_path, extra="", with_envfile=False)
    code, out, err = run(["/bin/sh", "-c", cron_line("send")], m.env, m.home)
    assert code != 0 and out == ""
    assert not m.log.exists()  # the tool never ran, so nothing was written by it
    assert "slack-notice" not in err.replace(str(m.envfile), "")  # only the shell complains


# --- the shell snippet (criterion d) ------------------------------------------------------------


def stub_dir(tmp_path: Path, body: str) -> Path:
    directory = tmp_path / "stubs"
    directory.mkdir(exist_ok=True)
    (directory / "python3").symlink_to(PYTHON3)
    stub = directory / "slack-notice"
    stub.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    stub.chmod(0o755)
    return directory


GOLDEN = ROOT / "tests" / "golden" / "send"


def golden(name: str) -> str:
    return (GOLDEN / name).read_text(encoding="utf-8").rstrip("\n")


SNIPPET_CASES = [
    (0, '{"outcome":"sent"}', "sent", 0),
    (22, '{"outcome":"disabled"}', "disabled", 0),
    (20, golden("refused_link_invalid.stdout"), "refused", 20),
    (12, golden("rate_limited.stdout"), "retry-later", 12),
    (12, golden("network_error.stdout"), "retry-later", 12),
    (12, golden("credential_invalid.stdout"), "surface", 12),
    (12, golden("outcome_unknown_reset.stdout"), "possibly-sent", 12),
    (12, golden("upstream_error.stdout"), "possibly-sent", 12),
    (12, "not json at all", "surface", 12),
    (12, "", "surface", 12),
    (1, "", "internal-outcome-unknown", 1),
    (2, golden("usage_unknown_flag.stdout"), "deployment-fault", 2),
    (143, "", "stopped-by-signal", 143),
    (130, "", "stopped-by-signal", 130),
    (129, "", "stopped-by-signal", 129),
    (137, "", "unexpected-exit", 137),
    (127, "", "unexpected-exit", 127),
    (12, "[" * 5000, "surface", 12),  # nests deeper than the parser allows
]


@pytest.mark.parametrize("case", SNIPPET_CASES, ids=[f"rc{c[0]}-{c[2]}" for c in SNIPPET_CASES])
def test_the_shell_snippet_handles_each_exit_code(
    case: tuple[int, str, str, int], tmp_path: Path
) -> None:
    rc, stdout, action, final = case
    stubs = stub_dir(tmp_path, 'cat >/dev/null\nprintf "%s\\n" "$STUB_OUT"\nexit "$STUB_RC"\n')
    env = {"PATH": f"{stubs}:/usr/bin:/bin", "STUB_OUT": stdout, "STUB_RC": str(rc)}
    code, out, err = run(["/bin/sh", "-c", of("test-sh")[0].text], env, tmp_path)
    assert (code, out, err) == (final, f"action={action}\n", ""), (out, err)


@pytest.mark.parametrize("rc", [0, 12, 20, 22, 143])
def test_the_shell_snippet_is_safe_under_set_e(rc: int, tmp_path: Path) -> None:
    stubs = stub_dir(tmp_path, 'cat >/dev/null\nprintf "%s\\n" "$STUB_OUT"\nexit "$STUB_RC"\n')
    out = golden("rate_limited.stdout")
    env = {"PATH": f"{stubs}:/usr/bin:/bin", "STUB_OUT": out, "STUB_RC": str(rc)}
    code, out, err = run(["/bin/sh", "-e", "-c", of("test-sh")[0].text], env, tmp_path)
    assert out.startswith("action="), (code, out, err)
    assert code == (0 if rc in (0, 22) else rc)


def test_the_shell_snippet_passes_the_payload_on_stdin_and_never_in_argv(tmp_path: Path) -> None:
    record = tmp_path / "record"
    stubs = stub_dir(tmp_path, f'printf "%s" "$*" > {record}.argv\ncat > {record}.stdin\nexit 0\n')
    env = {"PATH": f"{stubs}:/usr/bin:/bin"}
    code, _, _ = run(["/bin/sh", "-c", of("test-sh")[0].text], env, tmp_path)
    assert code == 0
    assert json.loads(Path(f"{record}.stdin").read_text()) == {
        "title": "Nightly",
        "message": "report finished",
    }
    argv = Path(f"{record}.argv").read_text()
    assert argv == "send --stdin-json --json --actor auto:nightly" and "report" not in argv


# --- the Python function ------------------------------------------------------------------------


def load_notify(monkeypatch: pytest.MonkeyPatch, stubs: Path) -> Any:
    monkeypatch.setenv("PATH", f"{stubs}:/usr/bin:/bin")
    namespace: dict[str, Any] = {}
    exec(compile(of("test-py")[0].text, "automation.md", "exec"), namespace)  # noqa: S102
    return namespace["notify"]


def test_the_python_function_survives_a_tool_that_does_not_read_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = golden("credential_invalid.stdout")
    stubs = stub_dir(tmp_path, f"printf '%s\\n' '{body}'\nexit 12\n")
    notify = load_notify(monkeypatch, stubs)
    code, document, timed_out = notify({"message": "x" * 3_000_000}, 10.0)  # more than a pipe holds
    assert code == 12 and document is not None and not timed_out
    assert document["error"]["code"] == "credential_invalid"


def test_the_python_function_takes_the_exit_code_the_tool_gives_after_sigterm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # before the send started: the tool exits 143 with nothing on stdout
    stubs = stub_dir(tmp_path, "trap 'exit 143' TERM\nwhile :; do sleep 0.1; done\n")
    code, document, timed_out = load_notify(monkeypatch, stubs)({"message": "hi"}, -9.7)
    assert (code, document, timed_out) == (143, None, True)


def test_the_python_function_returns_the_deadline_result_after_sigterm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = golden("network_error.stdout")
    script = f"trap 'printf \"%s\\n\" '\\''{body}'\\''; exit 12' TERM\n"
    stubs = stub_dir(tmp_path, script + "while :; do sleep 0.1; done\n")
    code, document, timed_out = load_notify(monkeypatch, stubs)({"message": "hi"}, -9.7)
    assert code == 12 and timed_out and document is not None
    assert document["error"]["code"] == "network_error"


def test_the_python_function_kills_only_a_tool_that_ignores_sigterm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stubs = stub_dir(tmp_path, "trap '' TERM\nwhile :; do sleep 0.1; done\n")
    notify = load_notify(monkeypatch, stubs)
    notify.__globals__["GRACE_S"] = 0.3
    assert notify({"message": "hi"}, -0.2) == (None, None, True)


def test_the_python_function_returns_none_for_output_that_is_not_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stubs = stub_dir(tmp_path, "cat >/dev/null\necho '[1]'\nexit 0\n")
    code, document, _ = load_notify(monkeypatch, stubs)({"message": "hi"}, 10.0)
    assert code == 0 and document is None


def test_the_python_function_survives_output_nested_too_deeply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stubs = stub_dir(tmp_path, "cat >/dev/null\nprintf '%05000d' 0 | tr 0 '['\nexit 12\n")
    code, document, _ = load_notify(monkeypatch, stubs)({"message": "hi"}, 10.0)
    assert code == 12 and document is None


# --- last: runs after every test above that spawned a child -------------------------------------


def test_no_child_is_left_behind() -> None:
    assert all(p.poll() is not None for p in SPAWNED)

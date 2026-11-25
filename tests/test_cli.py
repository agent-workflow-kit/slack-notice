"""CLI skeleton: parsing, global flags, output rules, exit-code mapping (issue #7).

Every test runs ``cli.main(argv, env, gateway, streams)`` in-process with in-memory byte
streams; one subprocess test checks the real entry point with its own private HOME and XDG.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli
from slack_notice.cli import CliError, Context, Streams, main
from tests.fake_gateway import FakeGateway
from tests.harness import assert_valid

ROOT = Path(__file__).resolve().parent.parent
SECRET = "https://hooks.slack.com/triggers/T0SECRET/B0SECRET/xyzSECRET"


class Run:
    """The result of one in-process run."""

    def __init__(self, code: int, out: bytes, err: bytes) -> None:
        self.code = code
        self.out = out
        self.err = err

    @property
    def stdout(self) -> str:
        return self.out.decode("utf-8")

    @property
    def stderr(self) -> str:
        return self.err.decode("utf-8")


class FailingSink:
    """A stream whose write (or flush) fails."""

    def __init__(self, exc: Exception, *, fail_flush: bool = False) -> None:
        self.exc = exc
        self.fail_flush = fail_flush
        self.writes = 0
        self.flushes = 0

    def write(self, data: bytes) -> int:
        self.writes += 1
        if not self.fail_flush:
            raise self.exc
        return len(data)

    def flush(self) -> None:
        self.flushes += 1
        raise self.exc


def run(
    argv: list[str],
    gateway: FakeGateway,
    *,
    tty: bool = False,
    env: dict[str, str] | None = None,
    out: Any = None,
    err: Any = None,
) -> Run:
    out_sink = io.BytesIO() if out is None else out
    err_sink = io.BytesIO() if err is None else err
    streams = Streams(out=out_sink, err=err_sink, stdin_is_tty=lambda: tty)
    code = main(argv, {} if env is None else env, gateway, streams)
    return Run(
        code,
        out_sink.getvalue() if isinstance(out_sink, io.BytesIO) else b"",
        err_sink.getvalue() if isinstance(err_sink, io.BytesIO) else b"",
    )


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[Context]:
    """Replace both handlers with a recorder that succeeds, so parsing can be observed."""
    seen: list[Context] = []

    def handler(ctx: Context) -> int:
        seen.append(ctx)
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    return seen


def raising(exc: BaseException) -> Callable[[Context], int]:
    def handler(_ctx: Context) -> int:
        raise exc

    return handler


# --- --version and --help -----------------------------------------------------------------


def expected_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


@pytest.mark.parametrize(
    "argv",
    [
        ["--version"],
        ["--json", "--version"],  # exempt from the JSON envelope
        ["send", "--version"],  # a global flag after the subcommand
        ["validate", "--json", "--version"],
        ["--version", "--bogus"],  # taken as soon as it is seen
    ],
)
def test_version_is_one_line_on_stdout(argv: list[str], fake_gateway: FakeGateway) -> None:
    result = run(argv, fake_gateway)
    assert (result.code, result.stdout, result.err) == (
        0,
        f"slack-notice {expected_version()}\n",
        b"",
    )


@pytest.mark.parametrize("argv", [["--help"], ["-h"], ["send", "--help"], ["validate", "--help"]])
def test_help_goes_to_stdout_and_exits_zero(argv: list[str], fake_gateway: FakeGateway) -> None:
    result = run(argv, fake_gateway)
    assert result.code == 0
    assert result.stdout.startswith("usage: slack-notice")
    assert result.err == b""


def test_help_text_does_not_depend_on_the_terminal_width(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    # argparse would read COLUMNS; the interface says no other variable is read.
    monkeypatch.setenv("COLUMNS", "20")
    narrow = run(["send", "--help"], fake_gateway).out
    monkeypatch.setenv("COLUMNS", "200")
    assert run(["send", "--help"], fake_gateway).out == narrow


def test_help_lists_the_exact_flags(fake_gateway: FakeGateway) -> None:
    send_help = run(["send", "--help"], fake_gateway).stdout
    for flag in (
        "--stdin-json",
        "--file",
        "--title",
        "--message",
        "--level",
        "--link",
        "--dedupe-key",
        "--decision-id",
        "--json",
        "--config",
        "--dry-run",
        "--actor",
        "--verbose",
        "--quiet",
        "--version",
    ):
        assert flag in send_help
    assert "--test-message" in run(["validate", "--help"], fake_gateway).stdout


# --- usage errors -------------------------------------------------------------------------

USAGE_LINE = "usage: invalid command line (see slack-notice --help)\n"

BAD_COMMAND_LINES = [
    pytest.param([], id="no-command"),
    pytest.param(["--json"], id="no-command-with-json"),
    pytest.param(["bogus"], id="unknown-command"),
    pytest.param(["SEND"], id="command-is-case-sensitive"),
    pytest.param(["se"], id="abbreviated-command"),
    pytest.param(["send", "stray"], id="positional"),
    pytest.param(["send", "--bogus"], id="unknown-flag"),
    pytest.param(["--bogus", "send"], id="unknown-global-flag"),
    pytest.param(["send", "--mess", "x"], id="abbreviated-long-option"),
    pytest.param(["send", "--message"], id="missing-value"),
    pytest.param(["send", "--message", "--json"], id="dash-value-needs-equals"),
    pytest.param(["send", "--dedupe", "x"], id="abbreviated-dedupe"),
    pytest.param(["--dry", "send"], id="abbreviated-dry-run"),
    pytest.param(["--ver"], id="abbreviated-version"),
    pytest.param(["--js", "send"], id="abbreviated-json"),
    pytest.param(["send", "--json=1"], id="json-takes-no-value"),
    pytest.param(["send", "-x"], id="short-option"),
    pytest.param(["validate", "--title", "x"], id="send-flag-on-validate"),
    pytest.param(["send", "--test-message"], id="validate-flag-on-send"),
    pytest.param(["send", "--"], id="double-dash"),
    pytest.param(["--", "send"], id="leading-double-dash"),
    pytest.param(["send", "--message", "--", "x"], id="double-dash-after-flag"),
    pytest.param(["--verbose", "--quiet", "send"], id="verbose-and-quiet"),
    pytest.param(["send", "--quiet", "--verbose"], id="verbose-and-quiet-after"),
    pytest.param(["--verbose", "send", "--quiet"], id="verbose-before-quiet-after"),
    pytest.param(["send", "--actor", "auto:a", "--actor", "auto:b"], id="repeated-actor"),
    pytest.param(["--actor", "auto:a", "send", "--actor", "auto:b"], id="actor-before-and-after"),
    pytest.param(["--actor=auto:a", "--actor", "auto:b", "send"], id="repeated-actor-forms"),
    pytest.param(["--config", "a", "send", "--config=b"], id="repeated-config"),
    pytest.param(["send", "--message", "a", "--message=b"], id="repeated-message"),
    pytest.param(["send", "--level", "info", "--level", "warn"], id="repeated-level"),
]


@pytest.mark.parametrize("argv", BAD_COMMAND_LINES)
def test_usage_error_exits_two_with_one_fixed_stderr_line(
    argv: list[str], fake_gateway: FakeGateway
) -> None:
    result = run(argv, fake_gateway)
    assert result.code == 2
    if not cli.json_requested(argv):
        assert result.out == b""
    assert result.stderr.count("\n") == 1
    assert result.stderr.startswith("usage: ")


@pytest.mark.parametrize("argv", BAD_COMMAND_LINES)
def test_usage_error_with_json_prints_the_envelope(
    argv: list[str], fake_gateway: FakeGateway
) -> None:
    result = run([*argv, "--json"], fake_gateway)
    assert result.code == 2
    document = assert_valid("cli/error", result.out)
    assert document["error"]["code"] == "usage"
    assert document["error"]["reason"] is None
    assert document["error"]["details"] is None
    assert document["error"]["retryable"] is None
    assert document["error"]["unknown_outcome"] is None
    assert result.stderr.startswith("usage: ")
    assert result.stderr.count("\n") == 1


def test_usage_envelope_is_compact_utf8_with_keys_in_the_documented_order(
    fake_gateway: FakeGateway,
) -> None:
    result = run(["--json", "bogus"], fake_gateway)
    assert result.out.endswith(b"\n")
    text = result.out[:-1].decode("utf-8")
    assert " " not in text.replace("invalid command line (see slack-notice --help)", "")
    assert list(json.loads(text)["error"]) == [
        "code",
        "message",
        "reason",
        "details",
        "retryable",
        "retry_after_s",
        "unknown_outcome",
    ]


def test_usage_error_text_contains_no_input(fake_gateway: FakeGateway) -> None:
    marker = "UNIQUE-MARKER-Ω"
    for argv in (
        [f"--{marker}"],
        ["send", f"--message={marker}", f"--{marker}"],
        [marker],
        ["--actor", marker, "send"],
        ["--json", f"--config={marker}", "bogus"],
    ):
        result = run(argv, fake_gateway)
        assert marker not in result.stderr
        assert marker not in result.stdout


def test_usage_error_message_for_argparse_failures_is_the_fixed_line(
    fake_gateway: FakeGateway,
) -> None:
    assert run(["send", "--bogus"], fake_gateway).stderr == USAGE_LINE


def test_json_is_found_in_argv_before_parsing(fake_gateway: FakeGateway) -> None:
    # --json after an unparsable flag still produces the envelope.
    result = run(["--bogus", "--json"], fake_gateway)
    assert result.code == 2
    assert_valid("cli/error", result.out)


def test_json_inside_a_flag_value_is_not_the_flag(fake_gateway: FakeGateway) -> None:
    result = run(["--bogus", "--title=--json"], fake_gateway)
    assert result.code == 2
    assert result.out == b""


@pytest.mark.parametrize("spelling", ["--json=x", "--json=true", "--json="])
def test_json_equals_spellings_get_the_usage_envelope(
    spelling: str, fake_gateway: FakeGateway
) -> None:
    # argparse rejects the spelling (a switch takes no value); the envelope is still printed.
    result = run([spelling, "send"], fake_gateway)
    assert result.code == 2
    assert assert_valid("cli/error", result.out)["error"]["code"] == "usage"


def test_a_flag_value_that_merely_starts_with_json_equals_is_not_json_mode(
    fake_gateway: FakeGateway,
) -> None:
    result = run(["--bogus", "--title=--json=x"], fake_gateway)
    assert result.code == 2
    assert result.out == b""


def test_empty_config_path_is_parsed_and_reaches_the_handler(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    # An empty path is a missing file (config_invalid, details.key --config), judged by config
    # loading (#10), not a usage error.
    assert run(["--config=", "send"], fake_gateway).code == 0
    assert captured[0].config == ""
    assert run(["--config", "", "validate"], fake_gateway).code == 0
    assert captured[1].config == ""


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--title", "-5"],
        ["send", "--message", "-x y"],
        ["send", "--message", "--title=a b", "--title", "t"],
        ["--actor", "-x", "send"],
        ["send", "--title", "--message", "m"],
        ["send", "--message", "--"],
    ],
)
def test_a_separate_value_starting_with_a_dash_is_a_usage_error(
    argv: list[str], fake_gateway: FakeGateway
) -> None:
    assert run(argv, fake_gateway).code == 2


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--file", "-"],
        ["send", "--title", "a", "--message", "b", "--decision-id", "x", "--decision-id", "y"],
        ["send", "--message=--title=a", "--title", "t"],
        ["send", "--message", "title is text"],
        ["send", "--dry-run", "--dry-run", "--json", "--json"],
    ],
)
def test_values_are_skipped_when_repeats_are_counted(
    argv: list[str], captured: list[Context], fake_gateway: FakeGateway
) -> None:
    assert run(argv, fake_gateway).code == 0


# --- global flags ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--json", "send"], {"json": True}),
        (["send", "--json"], {"json": True}),
        (["--dry-run", "send"], {"dry_run": True}),
        (["send", "--dry-run"], {"dry_run": True}),
        (["--verbose", "send"], {"verbose": True}),
        (["send", "--verbose"], {"verbose": True}),
        (["--quiet", "validate"], {"quiet": True}),
        (["validate", "--quiet"], {"quiet": True}),
        (["--config", "/x/c.yaml", "send"], {"config": "/x/c.yaml"}),
        (["send", "--config", "/x/c.yaml"], {"config": "/x/c.yaml"}),
        (["--config=/x/c.yaml", "send"], {"config": "/x/c.yaml"}),
        (["send", "--config=/x/c.yaml"], {"config": "/x/c.yaml"}),
        (["--actor", "auto:a", "send"], {"actor": "auto:a", "actor_source": "flag"}),
        (["send", "--actor=auto:a"], {"actor": "auto:a", "actor_source": "flag"}),
        (["validate", "--dry-run"], {"dry_run": True}),  # accepted, no effect on validate
    ],
)
def test_global_flags_are_accepted_before_or_after_the_subcommand(
    argv: list[str], expected: dict[str, Any], captured: list[Context], fake_gateway: FakeGateway
) -> None:
    assert run(argv, fake_gateway).code == 0
    (ctx,) = captured
    for name, value in expected.items():
        assert getattr(ctx if hasattr(ctx, name) else ctx.args, name) == value


def test_a_global_flag_before_the_subcommand_is_not_overwritten_by_its_default(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    argv = [
        "--json",
        "--dry-run",
        "--verbose",
        "--config",
        "/x/c.yaml",
        "--actor",
        "auto:before",
        "send",
        "--message=m",
    ]
    assert run(argv, fake_gateway).code == 0
    (ctx,) = captured
    assert (ctx.json, ctx.dry_run, ctx.args.verbose, ctx.args.quiet) == (True, True, True, False)
    assert (ctx.config, ctx.actor, ctx.actor_source) == ("/x/c.yaml", "auto:before", "flag")


def test_defaults_when_no_global_flag_is_given(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    run(["send"], fake_gateway)
    (ctx,) = captured
    assert (ctx.json, ctx.dry_run, ctx.args.verbose, ctx.args.quiet, ctx.config) == (
        False,
        False,
        False,
        False,
        None,
    )


def test_flag_equals_value_is_the_same_as_flag_space_value(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    run(["send", "--title", "t", "--message", "m", "--level", "warn", "--link", "l"], fake_gateway)
    run(["send", "--title=t", "--message=m", "--level=warn", "--link=l"], fake_gateway)
    first, second = captured
    assert vars(first.args) == vars(second.args)


def test_a_value_starting_with_a_dash_needs_the_equals_form(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    assert run(["send", "--message=-x", "--title=--y"], fake_gateway).code == 0
    assert captured[0].args.message == "-x"
    assert captured[0].args.title == "--y"
    assert run(["send", "--message", "-x"], fake_gateway).code == 2


def test_file_dash_is_a_value_not_an_option(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    assert run(["send", "--file", "-"], fake_gateway).code == 0
    assert captured[0].args.file == "-"


def test_send_and_validate_flags_are_parsed(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    argv = [
        "send",
        "--title=t",
        "--message=m",
        "--level=warn",
        "--link=https://example.com/",
        "--dedupe-key=-k",
        "--decision-id=a",
        "--decision-id",
        "b",
    ]
    assert run(argv, fake_gateway).code == 0
    args = captured[0].args
    assert (args.command, args.stdin_json, args.file, args.title, args.message) == (
        "send",
        False,
        None,
        "t",
        "m",
    )
    assert run(["send", "--stdin-json", "--file=f"], fake_gateway).code == 2
    assert run(["send", "--stdin-json", "--file=-"], fake_gateway).code == 0
    assert (captured[1].args.stdin_json, captured[1].args.file) == (True, "-")
    assert (args.level, args.link, args.dedupe_key, args.decision_id) == (
        "warn",
        "https://example.com/",
        "-k",
        ["a", "b"],
    )
    assert run(["validate", "--test-message"], fake_gateway).code == 0
    assert captured[2].args.test_message is True
    assert run(["send", "--stdin-json"], fake_gateway).code == 0
    assert (captured[3].args.stdin_json, captured[3].args.file) == (True, None)
    assert run(["send", "--file=f"], fake_gateway).code == 0
    assert (captured[4].args.stdin_json, captured[4].args.file) == (False, "f")


@pytest.mark.parametrize("value", ["bogus", "", "INFO"])
def test_flag_values_are_not_judged_by_the_parser(
    value: str, captured: list[Context], fake_gateway: FakeGateway
) -> None:
    # A flag value is checked like the same JSON field (exit 20 with a pointer) in step 3.
    assert run(["send", "--message=m", f"--level={value}"], fake_gateway).code == 0
    assert captured[0].args.level == value


def test_verbose_and_quiet_each_alone_are_fine(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    assert run(["--verbose", "send", "--verbose"], fake_gateway).code == 0
    assert run(["--quiet", "send", "--quiet"], fake_gateway).code == 0


# --- --actor ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "actor",
    [
        "human:a",
        "auto:a",
        "auto:" + "a" * 64,
        "auto:a.b_c@d-e/f",
        "human:UPPER.lower-09",
        "auto:/",
        "auto:-",
        "auto:@",
    ],
)
def test_actor_matching_the_pattern_is_accepted(
    actor: str, captured: list[Context], fake_gateway: FakeGateway
) -> None:
    assert run(["send", f"--actor={actor}"], fake_gateway).code == 0
    assert captured[0].actor == actor
    assert captured[0].actor_source == "flag"


@pytest.mark.parametrize(
    "actor",
    [
        "",
        "auto:",
        "human:",
        "auto:" + "a" * 65,
        "robot:a",
        "AUTO:a",
        "auto",
        "a",
        ":a",
        "auto:a b",
        "auto:a\n",  # `$` would accept a trailing newline
        "auto:a\nb",
        "\nauto:a",
        "auto:ä",
        "auto:a:b",
        "auto:a\x00",
        "auto:a;b",
        "auto:a\udcff",  # invalid UTF-8 in argv arrives as a lone surrogate
        "auto:١٢٣",  # non-ASCII digits
    ],
)
def test_actor_failing_the_pattern_exits_two(actor: str, fake_gateway: FakeGateway) -> None:
    result = run([f"--actor={actor}", "send"], fake_gateway)
    assert result.code == 2
    assert result.out == b""
    assert result.stderr.startswith("usage: ")
    assert result.stderr == "usage: --actor must be human:<name> or auto:<name>\n"


def test_actor_error_with_json_is_the_usage_envelope(fake_gateway: FakeGateway) -> None:
    result = run(["--json", "--actor=bad", "send"], fake_gateway)
    assert result.code == 2
    assert assert_valid("cli/error", result.out)["error"]["code"] == "usage"


def test_default_actor_is_auto_unknown_when_stdin_is_not_a_terminal(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    run(["send"], fake_gateway, tty=False)
    assert (captured[0].actor, captured[0].actor_source) == ("auto:unknown", "default")


def test_default_actor_is_human_user_on_a_terminal(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    run(["send", "--message=m"], fake_gateway, tty=True)
    assert (captured[0].actor, captured[0].actor_source) == ("human:tester", "tty")


def test_actor_flag_wins_over_a_terminal(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    run(["send", "--message=m", "--actor=auto:x"], fake_gateway, tty=True)
    assert (captured[0].actor, captured[0].actor_source) == ("auto:x", "flag")


@pytest.mark.parametrize(
    ("login", "expected"),
    [
        ("alice", "alice"),
        ("a.b_c@d-e", "a.b_c@d-e"),
        ("Jane Doe", "Jane_Doe"),
        ("a/b", "a_b"),  # `/` is allowed in --actor but not in the login name
        ("a:b", "a_b"),
        ("é", "_"),
        ("日本語", "___"),  # one underscore per character, not per byte
        ("a\nb", "a_b"),
        ("a\udcffb", "a_b"),
        ("😀x", "_x"),
        ("x" * 64, "x" * 64),
        ("x" * 100, "x" * 64),
        ("é" * 100, "_" * 64),
        ("." * 70, "." * 64),
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_login_name_is_sanitized_and_cut_to_64(
    login: str | None, expected: str, captured: list[Context], tmp_path: Path
) -> None:
    gateway = FakeGateway(home=str(tmp_path), login_name=login)
    run(["send", "--message=m"], gateway, tty=True)
    assert captured[0].actor == f"human:{expected}"
    assert captured[0].actor_source == "tty"
    assert_valid("defs", json.dumps(captured[0].actor), "actor")


def test_login_name_is_not_looked_up_without_a_terminal_or_with_a_flag(
    captured: list[Context], tmp_path: Path
) -> None:
    class Exploding(FakeGateway):
        def login_name(self) -> str | None:
            raise AssertionError("login_name must not be called")

    gateway = Exploding(home=str(tmp_path))
    assert run(["send"], gateway, tty=False).code == 0
    assert run(["send", "--message=m", "--actor=auto:x"], gateway, tty=True).code == 0


# --- dispatch, exit 1 and the exit-code mapping ------------------------------------------------


def test_main_passes_argv_env_and_gateway_to_the_handler(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    env = {"SLACK_WEBHOOK": SECRET}
    run(["send"], fake_gateway, env=env)
    (ctx,) = captured
    assert ctx.gateway is fake_gateway
    assert ctx.env == env


def test_handler_return_value_is_the_exit_code(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", lambda _ctx: 22)
    assert run(["send"], fake_gateway).code == 22


def test_validate_test_message_is_an_internal_error_until_its_issue_lands(
    fake_gateway: FakeGateway,
) -> None:
    # TODO(#32): remove when validate --test-message is implemented.
    result = run(["validate", "--test-message"], fake_gateway)
    assert result.code == 1
    assert result.stderr == "internal: internal error (NotImplementedError)\n"


class CustomError(Exception):
    pass


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError(f"secret {SECRET}"),
        ValueError(SECRET),
        KeyError(SECRET),
        OSError(2, SECRET, SECRET),
        CustomError(f"Ω {SECRET}"),
        RecursionError(SECRET),
        MemoryError(SECRET),
        UnicodeEncodeError("utf-8", SECRET, 0, 1, SECRET),
    ],
)
def test_exit_one_prints_only_the_class_name_and_a_fixed_message(
    exc: Exception, monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", raising(exc))
    result = run(["send"], fake_gateway)
    assert result.code == 1
    assert result.out == b""
    assert result.stderr == f"internal: internal error ({type(exc).__name__})\n"
    assert "SECRET" not in result.stderr


def test_exit_one_with_json_prints_the_internal_envelope(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", raising(RuntimeError(SECRET)))
    result = run(["send", "--json"], fake_gateway)
    assert result.code == 1
    error = assert_valid("cli/error", result.out)["error"]
    assert error == {
        "code": "internal",
        "message": "internal error",
        "reason": None,
        "details": None,
        "retryable": False,
        "retry_after_s": None,
        "unknown_outcome": False,
    }
    assert "SECRET" not in result.stdout + result.stderr


def test_exit_one_after_the_gate_moved_to_writing_says_unknown_outcome(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    # The send sets this flag from the deadline's verdict; the skeleton only carries it.
    def handler(ctx: Context) -> int:
        ctx.gate_writing = True
        raise RuntimeError(SECRET)

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    error = assert_valid("cli/error", run(["send", "--json"], fake_gateway).out)["error"]
    assert (error["retryable"], error["unknown_outcome"]) == (False, True)


def test_exit_one_with_a_class_name_that_is_not_an_identifier_is_generic(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    weird = type("Bad Name\n" + SECRET, (Exception,), {})
    monkeypatch.setitem(cli.HANDLERS, "send", raising(weird()))
    assert run(["send"], fake_gateway).stderr == "internal: internal error (Exception)\n"


def test_exit_one_survives_a_broken_stderr(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", raising(RuntimeError("x")))
    result = run(["send"], fake_gateway, err=FailingSink(BrokenPipeError()))
    assert result.code == 1


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), SystemExit(143)])
def test_signal_like_exits_are_not_swallowed_by_the_exit_one_handler(
    exc: BaseException, monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    # A signal-driven exit raised from a handler must reach the interpreter untouched, with
    # nothing printed (the real handlers are in cli._exit_on_signal, tests/test_signals.py).
    monkeypatch.setitem(cli.HANDLERS, "send", raising(exc))
    out, err = io.BytesIO(), io.BytesIO()
    streams = Streams(out=out, err=err, stdin_is_tty=lambda: False)
    with pytest.raises(type(exc)):
        main(["send", "--json"], {}, fake_gateway, streams)
    assert (out.getvalue(), err.getvalue()) == (b"", b"")


@pytest.mark.parametrize(
    ("error", "stderr_line", "retryable", "unknown"),
    [
        (CliError(2, "config_invalid", "configuration is invalid", details={"key": "timeout"}),
         "config_invalid: configuration is invalid\n", None, None),
        (CliError(12, "rate_limited", "rate limited", retryable=True, unknown_outcome=False,
                  retry_after_s=2, details={"http_status": 429}),
         "rate_limited: rate limited\n", True, False),
        (CliError(12, "outcome_unknown", "outcome unknown", retryable=False,
                  unknown_outcome=True),
         "outcome_unknown: outcome unknown\n", False, True),
        (CliError(20, "refused", "message is empty", reason="empty_message"),
         "refused (empty_message): message is empty\n", None, None),
    ],
)  # fmt: skip
def test_cli_error_maps_to_exit_code_stderr_line_and_envelope(
    error: CliError,
    stderr_line: str,
    retryable: bool | None,
    unknown: bool | None,
    monkeypatch: pytest.MonkeyPatch,
    fake_gateway: FakeGateway,
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", raising(error))
    plain = run(["send"], fake_gateway)
    assert (plain.code, plain.out, plain.stderr) == (error.exit_code, b"", stderr_line)
    machine = run(["send", "--json"], fake_gateway)
    assert machine.code == error.exit_code
    assert machine.stderr == stderr_line  # errors always print one line on stderr
    document = assert_valid("cli/error", machine.out)["error"]
    assert document["code"] == error.code
    assert document["reason"] == error.reason
    assert document["details"] == error.details
    assert (document["retryable"], document["unknown_outcome"]) == (retryable, unknown)
    assert document["retry_after_s"] == error.retry_after_s


def test_errors_are_printed_under_quiet(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    monkeypatch.setitem(
        cli.HANDLERS, "send", raising(CliError(20, "refused", "m", reason="invalid_payload"))
    )
    result = run(["--quiet", "send"], fake_gateway)
    assert result.stderr == "refused (invalid_payload): m\n"
    assert run(["--quiet", "bogus"], fake_gateway).stderr == USAGE_LINE


def test_cli_error_rejects_an_exit_code_the_interface_does_not_use() -> None:
    for bad in (3, 10, 11, 13, 21, 22, 128 + 15):
        with pytest.raises(ValueError, match="exit code"):
            CliError(bad, "usage", "m")


# --- output rules --------------------------------------------------------------------------


def test_stdout_and_stderr_are_utf8_with_errors_replaced(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    def handler(ctx: Context) -> int:
        ctx.output.out("ok Ω 😀 \udcff\n")
        ctx.output.err("é \ud800\n")
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    monkeypatch.setenv("LC_ALL", "C")
    result = run(["send"], fake_gateway)
    assert result.out == "ok Ω 😀 ?\n".encode()
    assert result.err == "é ?\n".encode()


def test_each_write_is_flushed(fake_gateway: FakeGateway) -> None:
    class Counting(io.BytesIO):
        flushes = 0

        def flush(self) -> None:
            self.flushes += 1
            super().flush()

    out, err = Counting(), Counting()
    streams = Streams(out=out, err=err, stdin_is_tty=lambda: False)
    output = cli.Output(streams, verbose=False, quiet=False)
    output.out("a")
    output.err("b")
    assert (out.flushes, err.flushes) == (1, 1)


@pytest.mark.parametrize("exc", [BrokenPipeError(32, "x"), OSError(5, "x"), ValueError("closed")])
def test_a_usage_error_keeps_exit_two_when_stdout_fails(
    exc: Exception, fake_gateway: FakeGateway
) -> None:
    err = io.BytesIO()
    result = run(["--json", "bogus"], fake_gateway, out=FailingSink(exc), err=err)
    assert result.code == 2
    assert result.stderr == USAGE_LINE


@pytest.mark.parametrize("exc", [BrokenPipeError(32, "x"), OSError(5, "x"), ValueError("closed")])
def test_a_usage_error_keeps_exit_two_when_stderr_fails_and_stdout_still_gets_the_envelope(
    exc: Exception, fake_gateway: FakeGateway
) -> None:
    out = io.BytesIO()
    result = run(["--json", "bogus"], fake_gateway, out=out, err=FailingSink(exc))
    assert result.code == 2
    assert assert_valid("cli/error", result.out)["error"]["code"] == "usage"


def test_a_usage_error_keeps_exit_two_when_both_streams_fail(fake_gateway: FakeGateway) -> None:
    out, err = FailingSink(OSError(5, "x")), FailingSink(OSError(5, "x"))
    assert run(["--json", "bogus"], fake_gateway, out=out, err=err).code == 2
    assert (out.writes, err.writes) == (1, 1)


def test_a_handler_error_keeps_its_exit_code_when_a_stream_fails(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    error = CliError(20, "refused", "m", reason="invalid_payload")
    monkeypatch.setitem(cli.HANDLERS, "send", raising(error))
    out = FailingSink(BrokenPipeError(32, "x"))
    assert run(["--json", "send"], fake_gateway, out=out).code == 20


def test_a_help_write_failure_is_exit_one(fake_gateway: FakeGateway) -> None:
    result = run(["--help"], fake_gateway, out=FailingSink(OSError(5, "x")))
    assert result.code == 1
    assert result.stderr == "internal: internal error (OSError)\n"


@pytest.mark.parametrize("exc", [BrokenPipeError(32, "x"), OSError(5, "x"), ValueError("closed")])
def test_a_write_failure_before_the_result_is_an_internal_error(
    exc: Exception, monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    def handler(ctx: Context) -> int:
        ctx.output.out("result\n")
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    result = run(["send"], fake_gateway, out=FailingSink(exc))
    assert result.code == 1
    assert result.stderr == f"internal: internal error ({type(exc).__name__})\n"


@pytest.mark.parametrize("exc", [BrokenPipeError(32, "x"), OSError(5, "x"), ValueError("closed")])
def test_a_write_failure_after_step_six_is_ignored(
    exc: Exception, monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    def handler(ctx: Context) -> int:
        ctx.output.result_printed()  # the point after which write failures are ignored
        ctx.output.out("result\n")
        ctx.output.err("line\n")
        return 12

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    out, err = FailingSink(exc), FailingSink(exc)
    result = run(["send"], fake_gateway, out=out, err=err)
    assert result.code == 12
    assert (out.writes, err.writes) == (1, 1)


def test_one_final_flush_attempt_of_each_stream_even_when_they_fail(
    monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    def handler(ctx: Context) -> int:
        ctx.output.result_printed()
        ctx.output.out("x")
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    out = FailingSink(BrokenPipeError(), fail_flush=True)
    err = FailingSink(OSError(5, "x"), fail_flush=True)
    assert run(["send"], fake_gateway, out=out, err=err).code == 0
    assert out.flushes >= 1
    assert err.flushes >= 1


def test_quiet_suppresses_info_lines_but_not_errors_or_warnings(fake_gateway: FakeGateway) -> None:
    err = io.BytesIO()
    streams = Streams(out=io.BytesIO(), err=err, stdin_is_tty=lambda: False)
    quiet = cli.Output(streams, verbose=False, quiet=True)
    quiet.info("sent (info, 1 ms)")
    quiet.warning("warning line")
    quiet.error_line("error line")
    assert err.getvalue() == b"warning line\nerror line\n"


def test_verbose_lines_only_with_verbose(fake_gateway: FakeGateway) -> None:
    for verbose, expected in ((False, b""), (True, b"input: 12 ms\n")):
        err = io.BytesIO()
        streams = Streams(out=io.BytesIO(), err=err, stdin_is_tty=lambda: False)
        cli.Output(streams, verbose=verbose, quiet=False).phase("input", 12)
        assert err.getvalue() == expected


def test_info_lines_are_printed_by_default() -> None:
    err = io.BytesIO()
    streams = Streams(out=io.BytesIO(), err=err, stdin_is_tty=lambda: False)
    cli.Output(streams, verbose=False, quiet=False).info("disabled in config")
    assert err.getvalue() == b"disabled in config\n"


def test_json_documents_are_compact_unescaped_utf8() -> None:
    out = io.BytesIO()
    streams = Streams(out=out, err=io.BytesIO(), stdin_is_tty=lambda: False)
    cli.Output(streams, verbose=False, quiet=False).json_document({"b": "é😀", "a": [1, None]})
    assert out.getvalue() == '{"b":"é😀","a":[1,null]}\n'.encode()


# --- the real entry point ----------------------------------------------------------------------


def run_module(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    home = tmp_path / "subhome"
    home.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_STATE_HOME": str(home / ".state"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".data"),
        "COLUMNS": "20",
    }
    return subprocess.run(
        [sys.executable, "-m", "slack_notice", *args],
        env=env,
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
    )


def test_python_dash_m_version(tmp_path: Path) -> None:
    result = run_module(tmp_path, "--version")
    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        f"slack-notice {expected_version()}\n".encode(),
        b"",
    )


def test_python_dash_m_usage_error_with_json(tmp_path: Path) -> None:
    result = run_module(tmp_path, "--json", "send", "--nope")
    assert result.returncode == 2
    assert assert_valid("cli/error", result.stdout)["error"]["code"] == "usage"
    assert result.stderr == USAGE_LINE.encode()


def test_python_dash_m_version_with_closed_stdout_is_exit_one(tmp_path: Path) -> None:
    # --version has no result code to keep: a closed stdout (EBADF) while printing it is an
    # internal error (exit 1), and must not turn into the interpreter's 120 at shutdown.
    home = tmp_path / "subhome2"
    home.mkdir()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    result = subprocess.run(
        [sys.executable, "-c", "import os,sys; os.close(1); from slack_notice.cli import main;"
         " sys.exit(main(['--version']))"],
        env=env,
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
    )  # fmt: skip
    assert result.returncode == 1
    assert result.stderr == b"internal: internal error (OSError)\n"


def test_python_dash_m_usage_error_with_closed_stdout_keeps_exit_two(tmp_path: Path) -> None:
    home = tmp_path / "subhome3"
    home.mkdir()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    result = subprocess.run(
        [sys.executable, "-c", "import os,sys; os.close(1); from slack_notice.cli import main;"
         " sys.exit(main(['--json', 'bogus']))"],
        env=env,
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
    )  # fmt: skip
    assert result.returncode == 2
    assert result.stderr == USAGE_LINE.encode()


def test_repr_of_the_context_holds_no_environment_value(
    captured: list[Context], fake_gateway: FakeGateway
) -> None:
    assert run(["send"], fake_gateway, env={"SLACK_WEBHOOK": SECRET}).code == 0
    assert "T0SECRET" not in repr(captured[0])
    assert captured[0].env == {"SLACK_WEBHOOK": SECRET}


@pytest.mark.parametrize(
    "variables",
    [
        {"NO_COLOR": "1"},
        {"FORCE_COLOR": "1"},
        {"TERM": "xterm-256color", "FORCE_COLOR": "1"},
        {"TERM": "dumb"},
        {"COLUMNS": "20"},
    ],
)
def test_help_text_does_not_depend_on_color_or_terminal_variables(
    variables: dict[str, str], monkeypatch: pytest.MonkeyPatch, fake_gateway: FakeGateway
) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TERM", "COLUMNS"):
        monkeypatch.delenv(name, raising=False)
    plain = [run(argv, fake_gateway).out for argv in (["--help"], ["send", "--help"])]
    for name, value in variables.items():
        monkeypatch.setenv(name, value)
    assert [run(argv, fake_gateway).out for argv in (["--help"], ["send", "--help"])] == plain
    assert all(b"\x1b" not in text for text in plain)


def test_env_defaults_to_the_gateways_environment(captured: list[Context], tmp_path: Path) -> None:
    gateway = FakeGateway(home=str(tmp_path), environment={"SLACK_WEBHOOK": SECRET})
    streams = Streams(out=io.BytesIO(), err=io.BytesIO(), stdin_is_tty=lambda: False)
    assert main(["send"], None, gateway, streams) == 0
    assert captured[0].env == {"SLACK_WEBHOOK": SECRET}

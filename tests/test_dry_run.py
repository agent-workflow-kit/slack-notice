"""``send --dry-run``: input to rendered output with no network, no credential, no state (#20).

Every test runs ``cli.main`` in-process with a fake gateway. The dry run must leave no trace in
the gateway: no connection, no state directory, no lock, no sleep and no read of the environment
(the credential lives there). Output shapes are checked against ``schemas/cli/send.json`` and
``schemas/cli/error.json``.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from types import FrameType
from typing import Any

import pytest

from slack_notice import cli
from slack_notice.cli import Streams, main
from slack_notice.gateway import SourceRead
from tests.fake_gateway import Attempt, FakeGateway, FakeProcessExit
from tests.harness import assert_valid

CANARY = "CAN" + "ARY-" + "d20c"
CRED_URL = "https://hooks.slack.com/" + "triggers/" + "T0" + "ZZ/" + "B0" + "ZZ/" + "xyz" + "ZZ"
# What a dry run may touch: input (stdin or a file) and config files, nothing else.
ALLOWED_EVENTS = {"read_source", "read_regular_file", "list_directory"}


class WatchedEnv(Mapping[str, str]):
    """An environment that records every access: a dry run must not read it at all."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values
        self.accessed: list[str] = []

    def __getitem__(self, key: str) -> str:
        self.accessed.append(key)
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        self.accessed.append("<iter>")
        return iter(self._values)

    def __len__(self) -> int:
        self.accessed.append("<len>")
        return len(self._values)


class Result:
    def __init__(self, code: int, out: bytes, err: bytes, env: WatchedEnv) -> None:
        self.code, self.env = code, env
        self.stdout, self.stderr = out.decode("utf-8"), err.decode("utf-8")


def write_config(tmp_path: Path, text: str = "{}\n") -> str:
    path = tmp_path / "cfg" / "config.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def dry(
    argv: list[str],
    gateway: FakeGateway,
    *,
    stdin: bytes | None = None,
    config: str | None = None,
    out: Any = None,
    err: Any = None,
) -> Result:
    """Run main in-process; ``out`` and ``err`` replace the capturing sinks (a failing stream)."""
    if stdin is not None:
        gateway.source_script.append(SourceRead(stdin))
    kept_out, kept_err = io.BytesIO(), io.BytesIO()
    env = WatchedEnv({"SLACK_WEBHOOK": CRED_URL})
    full = [*argv, *([] if config is None else ["--config", config])]
    streams = Streams(
        kept_out if out is None else out, kept_err if err is None else err, lambda: False
    )
    try:
        code = main(full, env, gateway, streams)
    except FakeProcessExit as end:  # a real send ends through the gateway's exit
        code = end.code
    return Result(code, kept_out.getvalue(), kept_err.getvalue(), env)


def assert_untouched(
    result: Result,
    gateway: FakeGateway,
    tmp_path: Path,
    *,
    also_read: tuple[str, ...] = (),
) -> None:
    """Nothing but the input and the config files was touched, and no clock or environment."""
    assert result.env.accessed == []
    assert gateway.connections == []
    assert set(gateway.events) <= ALLOWED_EVENTS, gateway.events
    config = str(tmp_path / "cfg" / "config.yaml")
    allowed_paths = {config, str(tmp_path / "cfg" / "config.d"), *also_read}
    assert set(gateway.read_paths) <= allowed_paths, gateway.read_paths
    assert not {"environ", "wall_time"} & set(gateway.calls), gateway.calls
    assert not (Path(gateway._home) / ".local").exists()
    assert CRED_URL not in result.stdout + result.stderr


# --- golden output: every input source, human and --json --------------------------------------


@pytest.mark.parametrize("flag", [["--stdin-json"], []])
def test_stdin_json_prints_the_body_on_stderr_and_nothing_on_stdout(
    flag: list[str], fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    body = json.dumps(
        {"title": "Build", "message": "done", "level": "warn", "link": "https://a.b/c"}
    )
    result = dry(
        ["send", "--dry-run", *flag],
        fake_gateway,
        stdin=body.encode(),
        config=write_config(tmp_path),
    )
    assert result.code == 0 and result.stdout == ""
    assert result.stderr == "\U0001f7e0 WARN Build\ndone\nhttps://a.b/c\n"
    assert_untouched(result, fake_gateway, tmp_path)


def test_file_input_golden_json(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    source = tmp_path / "n.json"
    source.write_text(json.dumps({"message": "hello"}), encoding="utf-8")
    result = dry(
        ["send", "--dry-run", "--json", "--file", str(source)],
        fake_gateway,
        config=write_config(tmp_path),
    )
    assert result.code == 0 and result.stderr == ""
    document = json.loads(result.stdout)
    assert result.stdout == (
        '{"outcome":"dry_run","tool":"slack-notice","level":"info","truncated":false,'
        f'"bytes":{document["bytes"]},"duration_ms":{document["duration_ms"]},'
        '"http_status":null,"dedupe_key":null,"rendered":"\U0001f535 INFO\\nhello"}\n'
    )
    document = assert_valid("cli/send", result.stdout)
    assert document["rendered"] == "\U0001f535 INFO\nhello"
    assert document["bytes"] == len(
        json.dumps(
            {"body": document["rendered"]}, ensure_ascii=False, separators=(",", ":")
        ).encode()
    )
    assert list(document) == [
        "outcome", "tool", "level", "truncated", "bytes", "duration_ms",
        "http_status", "dedupe_key", "rendered",
    ]  # fmt: skip
    assert_untouched(result, fake_gateway, tmp_path, also_read=(str(source),))


def test_file_dash_reads_stdin(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    result = dry(
        ["send", "--dry-run", "--json", "--file", "-"],
        fake_gateway,
        stdin=b'{"message":"m","level":"error"}',
        config=write_config(tmp_path),
    )
    document = assert_valid("cli/send", result.stdout)
    assert (document["level"], document["rendered"]) == ("error", "\U0001f534 ERROR\nm")


def test_flag_input_reads_no_stream_and_echoes_the_dedupe_key(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    result = dry(
        ["send", "--dry-run", "--json", "--title", "T", "--message", "M", "--dedupe-key=k-1"],
        fake_gateway,
        config=write_config(tmp_path),
    )
    document = assert_valid("cli/send", result.stdout)
    assert document["dedupe_key"] == "k-1" and document["rendered"] == "\U0001f535 INFO T\nM"
    assert fake_gateway.source_reads == 0
    assert_untouched(result, fake_gateway, tmp_path)


def test_sanitizer_and_cuts_are_applied(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    config = write_config(tmp_path, "max_chars: 2000\nbody_variable: text\n")
    message = "a\r\n‮b" + "x" * 5000
    result = dry(
        ["send", "--dry-run", "--json", "--title", "t\nu", "--message", message],
        fake_gateway,
        config=config,
    )
    document = assert_valid("cli/send", result.stdout)
    rendered = document["rendered"]
    assert rendered.startswith("\U0001f535 INFO t u\na\nb") and "‮" not in rendered
    assert rendered.endswith("…[truncated]") and len(rendered) <= 2000
    assert document["truncated"] is True
    assert document["bytes"] == len(
        json.dumps({"text": rendered}, ensure_ascii=False, separators=(",", ":")).encode()
    )


def test_config_over_defaults_for_the_prefix(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    config = write_config(tmp_path, 'level_prefix:\n  warn: "W!"\n')
    result = dry(
        ["send", "--dry-run", "--message", "m", "--level", "warn"], fake_gateway, config=config
    )
    assert result.stderr == "W!\nm\n"


def test_default_config_location_is_used_without_the_config_flag(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    directory = Path(fake_gateway._home) / ".config" / "slack-notice"
    directory.mkdir(parents=True)
    (directory / "config.yaml").write_text('level_prefix:\n  info: "HOME"\n', encoding="utf-8")
    result = dry(["send", "--dry-run", "--message", "m"], fake_gateway)
    assert result.stderr == "HOME\nm\n"
    assert set(fake_gateway.events) <= ALLOWED_EVENTS and fake_gateway.connections == []


def test_the_result_uses_the_deadline_clock(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    read_source = fake_gateway.read_source

    def slow_read(*args: Any) -> SourceRead:
        result = read_source(*args)
        fake_gateway._advance(1.5)  # the fake clock moves while the input is read
        return result

    fake_gateway.read_source = slow_read  # type: ignore[method-assign]
    result = dry(
        ["send", "--dry-run", "--json", "--verbose", "--stdin-json"],
        fake_gateway,
        stdin=b'{"message":"m"}',
        config=write_config(tmp_path),
    )
    assert json.loads(result.stdout)["duration_ms"] >= 1500
    input_line = result.stderr.splitlines()[0]
    assert input_line.startswith("input: ") and int(input_line.split()[1]) >= 1500


# --- --quiet and --verbose --------------------------------------------------------------------


def test_quiet_suppresses_the_human_text(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    result = dry(
        ["send", "--dry-run", "--quiet", "--message", "m"],
        fake_gateway,
        config=write_config(tmp_path),
    )
    assert (result.code, result.stdout, result.stderr) == (0, "", "")


def test_quiet_with_json_still_prints_the_document(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    result = dry(
        ["send", "--dry-run", "--quiet", "--json", "--message", "m"],
        fake_gateway,
        config=write_config(tmp_path),
    )
    assert_valid("cli/send", result.stdout)
    assert result.stderr == ""


def test_verbose_adds_one_line_per_phase_and_no_input_text(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    result = dry(
        ["send", "--dry-run", "--verbose", "--message", CANARY],
        fake_gateway,
        config=write_config(tmp_path),
    )
    lines = result.stderr.splitlines()
    assert [line.split(":")[0] for line in lines[:2]] == ["input", "render"]
    assert all(line.endswith(" ms") for line in lines[:2])
    assert lines[2:] == ["\U0001f535 INFO", CANARY]
    for secret in (CRED_URL, "hooks.slack.com"):
        assert secret not in result.stderr


def test_verbose_with_json_keeps_stdout_a_single_document(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    result = dry(
        ["send", "--dry-run", "--verbose", "--json", "--message", "m"],
        fake_gateway,
        config=write_config(tmp_path),
    )
    assert_valid("cli/send", result.stdout)
    assert [line.split(":")[0] for line in result.stderr.splitlines()] == ["input", "render"]


# --- refusals: fixed text, never a value ------------------------------------------------------

LINK = "https://a.b/" + CANARY + "|x"
REFUSALS: list[tuple[str, bytes, str, str | None]] = [
    ("invalid-json", b"{" + CANARY.encode(), "invalid_payload", ""),
    ("level", json.dumps({"message": "m", "level": CANARY}).encode(), "invalid_payload", "/level"),
    ("empty", b'{"title":"' + CANARY.encode() + b'"}', "empty_message", None),
    ("link", json.dumps({"message": "m", "link": LINK}).encode(), "link_invalid", None),
    ("scheme", json.dumps({"message": "m", "link": "ftp://x"}).encode(), "link_scheme", None),
]  # fmt: skip


@pytest.mark.parametrize(
    ("name", "stdin", "reason", "pointer"), REFUSALS, ids=[r[0] for r in REFUSALS]
)
def test_refusals_exit_20_with_the_fixed_message_only(
    name: str,
    stdin: bytes,
    reason: str,
    pointer: str | None,
    fake_gateway: FakeGateway,
    tmp_path: Path,
) -> None:
    config = write_config(tmp_path)
    human = dry(["send", "--dry-run"], fake_gateway, stdin=stdin, config=config)
    machine = dry(["send", "--dry-run", "--json"], fake_gateway, stdin=stdin, config=config)
    assert human.code == machine.code == 20
    assert human.stdout == "" and human.stderr.startswith(f"refused ({reason}): ")
    assert human.stderr.count("\n") == 1
    error = assert_valid("cli/error", machine.stdout)["error"]
    assert (error["code"], error["reason"]) == ("refused", reason)
    if pointer is not None:
        assert error["details"] == {"pointer": pointer}
    for result in (human, machine):
        assert CANARY not in result.stdout + result.stderr
        assert result.env.accessed == []
    assert set(fake_gateway.events) <= ALLOWED_EVENTS and fake_gateway.connections == []
    assert not (Path(fake_gateway._home) / ".local").exists()


def test_a_flag_refusal_matches_the_json_refusal(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    result = dry(
        ["send", "--dry-run", "--json", "--message", "m", "--level", CANARY],
        fake_gateway,
        config=write_config(tmp_path),
    )
    assert result.code == 20 and CANARY not in result.stdout + result.stderr
    assert json.loads(result.stdout)["error"]["details"] == {"pointer": "/level"}


def test_a_stalled_input_is_exit_12_unavailable_with_no_record(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.source_script.append(SourceRead(b'{"mess', timed_out=True))
    result = dry(["send", "--dry-run", "--json"], fake_gateway, config=write_config(tmp_path))
    assert result.code == 12
    error = assert_valid("cli/error", result.stdout)["error"]
    assert (error["code"], error["details"]) == ("unavailable", {"phase": "input"})
    assert (error["retryable"], error["unknown_outcome"]) == (True, False)
    assert set(fake_gateway.events) <= ALLOWED_EVENTS


def test_the_input_deadline_is_the_config_timeout(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    seen: list[float] = []
    real = fake_gateway.read_source

    def spy(source: Any, max_bytes: int, remaining: float) -> SourceRead:
        seen.append(remaining)
        return real(source, max_bytes, remaining)

    fake_gateway.read_source = spy  # type: ignore[method-assign]
    result = dry(
        ["send", "--dry-run"],
        fake_gateway,
        stdin=b'{"message":"m"}',
        config=write_config(tmp_path, "timeout: 20s\n"),
    )
    assert result.code == 0 and len(seen) == 1 and 19.0 < seen[0] <= 20.0


# --- usage, config and enabled: false ---------------------------------------------------------


def test_a_usage_error_with_json_prints_the_envelope(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    result = dry(
        ["send", "--dry-run", "--json", "--title", CANARY],
        fake_gateway,
        config=write_config(tmp_path),
    )
    assert result.code == 2
    assert assert_valid("cli/error", result.stdout)["error"]["code"] == "usage"
    assert CANARY not in result.stdout + result.stderr and fake_gateway.source_reads == 0


def test_config_errors_exit_2_before_any_input(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    result = dry(
        ["send", "--dry-run", "--json"],
        fake_gateway,
        config=write_config(tmp_path, "max_chars: 5\n"),
    )
    assert result.code == 2 and fake_gateway.source_reads == 0
    assert assert_valid("cli/error", result.stdout)["error"]["details"] == {"key": "max_chars"}


def test_a_missing_config_file_is_exit_2(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    result = dry(
        ["send", "--dry-run", "--json", "--message", "m"],
        fake_gateway,
        config=str(tmp_path / "none.yaml"),
    )
    assert result.code == 2 and json.loads(result.stdout)["error"]["details"] == {"key": "--config"}


DISABLED = "enabled: false\n"


def test_disabled_exits_22_before_input_with_json(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    result = dry(
        ["send", "--dry-run", "--json"],
        fake_gateway,
        stdin=b"{",
        config=write_config(tmp_path, DISABLED),
    )
    assert (result.code, result.stdout, result.stderr) == (22, '{"outcome":"disabled"}\n', "")
    assert assert_valid("cli/send", result.stdout) == {"outcome": "disabled"}
    assert fake_gateway.source_reads == 0 and result.env.accessed == []


def test_disabled_human_line_and_quiet(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    config = write_config(tmp_path, DISABLED)
    loud = dry(["send", "--dry-run", "--message", "m"], fake_gateway, config=config)
    quiet = dry(["send", "--dry-run", "--quiet", "--message", "m"], fake_gateway, config=config)
    assert (loud.code, loud.stdout, loud.stderr) == (22, "", "disabled in config\n")
    assert (quiet.code, quiet.stdout, quiet.stderr) == (22, "", "")


def test_a_combination_error_beats_disabled(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    result = dry(
        ["send", "--dry-run", "--json", "--stdin-json", "--title", "t", "--message", "m"],
        fake_gateway,
        config=write_config(tmp_path, DISABLED),
    )
    assert result.code == 2 and json.loads(result.stdout)["error"]["code"] == "usage"


def test_an_invalid_config_beats_disabled(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    result = dry(
        ["send", "--dry-run", "--message", "m"],
        fake_gateway,
        config=write_config(tmp_path, "enabled: false\nmax_chars: 1\n"),
    )
    assert result.code == 2


# --- the same input without --dry-run is the real send ---------------------------------------


def test_the_same_input_without_dry_run_reads_the_credential_and_the_state(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(Attempt())
    config = write_config(tmp_path)
    result = dry(["send", "--message", "m"], fake_gateway, config=config)  # exits via exit_now
    assert result.code == 0
    assert result.env.accessed == ["SLACK_WEBHOOK"] and len(fake_gateway.connections) == 1
    assert (Path(fake_gateway._home) / ".local").exists()


# --- signals during input and in a dry run ----------------------------------------------------

SIGNALS = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]


@pytest.fixture
def guarded_signals() -> Iterator[None]:
    """A test handler for each signal, so a missing handler fails the test, not the runner."""

    def unexpected(signum: int, _frame: FrameType | None) -> None:
        raise AssertionError(f"signal {signum} was not handled by main")

    saved = {s: signal.signal(s, unexpected) for s in SIGNALS}
    yield
    for s, handler in saved.items():
        signal.signal(s, handler)


def signal_run(gateway: FakeGateway, tmp_path: Path, *, json_mode: bool) -> Result:
    return dry(
        ["send", "--dry-run", *(["--json"] if json_mode else [])],
        gateway,
        config=write_config(tmp_path),
    )


@pytest.mark.usefixtures("guarded_signals")
@pytest.mark.parametrize("sig", SIGNALS)
@pytest.mark.parametrize("json_mode", [False, True])
def test_a_signal_during_input_exits_128_plus_n_with_no_output(
    sig: signal.Signals, json_mode: bool, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    def killed(*_: Any) -> SourceRead:
        os.kill(os.getpid(), sig)
        raise AssertionError("the handler must have raised")

    fake_gateway.read_source = killed  # type: ignore[method-assign]
    result = signal_run(fake_gateway, tmp_path, json_mode=json_mode)
    assert (result.code, result.stdout, result.stderr) == (128 + sig, "", "")
    assert set(fake_gateway.events) <= ALLOWED_EVENTS and fake_gateway.connections == []
    assert not (Path(fake_gateway._home) / ".local").exists()


@pytest.mark.usefixtures("guarded_signals")
@pytest.mark.parametrize("sig", SIGNALS)
def test_a_signal_while_rendering_exits_128_plus_n_with_no_output(
    sig: signal.Signals, fake_gateway: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def killed(*_: Any) -> Any:
        os.kill(os.getpid(), sig)
        raise AssertionError("the handler must have raised")

    monkeypatch.setattr(cli, "render", killed)
    fake_gateway.source_script.append(SourceRead(json.dumps({"message": CANARY}).encode()))
    result = signal_run(fake_gateway, tmp_path, json_mode=True)
    assert (result.code, result.stdout, result.stderr) == (128 + sig, "", "")


@pytest.mark.usefixtures("guarded_signals")
def test_handlers_are_restored_after_main(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    before = {s: signal.getsignal(s) for s in SIGNALS}
    dry(["send", "--dry-run", "--message", "m"], fake_gateway, config=write_config(tmp_path))
    assert {s: signal.getsignal(s) for s in SIGNALS} == before


# --- failing and signalled streams ------------------------------------------------------------


class FailingSink:
    """A stream whose every write and flush fails (a closed or broken pipe)."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def write(self, data: bytes, /) -> int:
        raise self._error

    def flush(self) -> None:
        raise self._error


ERRORS = [BrokenPipeError(32, "pipe"), OSError(9, "bad fd"), ValueError("closed")]
FAILING = [("out",), ("err",), ("out", "err")]


def failing(which: tuple[str, ...], error: Exception) -> dict[str, Any]:
    return {name: FailingSink(error) for name in which}


@pytest.mark.parametrize("error", ERRORS, ids=lambda e: type(e).__name__)
@pytest.mark.parametrize("which", FAILING, ids="+".join)
@pytest.mark.parametrize("extra", [[], ["--json"], ["--verbose"], ["--verbose", "--json"]])
def test_a_dry_run_ignores_write_failures_and_exits_0(
    extra: list[str],
    which: tuple[str, ...],
    error: Exception,
    fake_gateway: FakeGateway,
    tmp_path: Path,
) -> None:
    result = dry(
        ["send", "--dry-run", "--message", "m", *extra],
        fake_gateway,
        config=write_config(tmp_path),
        **failing(which, error),
    )
    assert result.code == 0


@pytest.mark.parametrize("error", ERRORS, ids=lambda e: type(e).__name__)
@pytest.mark.parametrize("which", FAILING, ids="+".join)
@pytest.mark.parametrize("extra", [[], ["--json"], ["--verbose", "--json"]])
def test_a_disabled_result_ignores_write_failures_and_exits_22(
    extra: list[str],
    which: tuple[str, ...],
    error: Exception,
    fake_gateway: FakeGateway,
    tmp_path: Path,
) -> None:
    result = dry(
        ["send", "--dry-run", "--message", "m", *extra],
        fake_gateway,
        config=write_config(tmp_path, DISABLED),
        **failing(which, error),
    )
    assert result.code == 22


def test_a_failing_stderr_does_not_lose_the_json_document(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    result = dry(
        ["send", "--dry-run", "--json", "--verbose", "--message", "m"],
        fake_gateway,
        config=write_config(tmp_path),
        err=FailingSink(BrokenPipeError()),
    )
    assert result.code == 0 and assert_valid("cli/send", result.stdout)["outcome"] == "dry_run"


class SignallingSink(io.BytesIO):
    """Raises ``sig`` at this process from inside the first write, as a real signal would."""

    def __init__(self, sig: signal.Signals) -> None:
        super().__init__()
        self._sig: signal.Signals | None = sig

    def write(self, data: Any, /) -> int:
        if self._sig is not None:
            sig, self._sig = self._sig, None
            os.kill(os.getpid(), sig)  # delivered at the next bytecode of the main thread
        return super().write(data)


@pytest.mark.usefixtures("guarded_signals")
@pytest.mark.parametrize("sig", SIGNALS)
@pytest.mark.parametrize(
    ("argv", "config", "sink", "code"),
    [
        (["--message", "m"], "{}\n", "err", 0),
        (["--json", "--message", "m"], "{}\n", "out", 0),
        ([], DISABLED, "err", 22),
        (["--json"], DISABLED, "out", 22),
        (["--message", "m", "--stdin-json"], "{}\n", "err", 2),
        (["--json", "--message", "m", "--stdin-json"], "{}\n", "out", 2),
        (["--message", "m"], "max_chars: 1\n", "err", 2),
    ],
)
def test_a_signal_during_the_result_print_is_ignored(
    sig: signal.Signals,
    argv: list[str],
    config: str,
    sink: str,
    code: int,
    fake_gateway: FakeGateway,
    tmp_path: Path,
) -> None:
    signalling = SignallingSink(sig)
    sinks: dict[str, Any] = {sink: signalling}
    result = dry(
        ["send", "--dry-run", *argv],
        fake_gateway,
        config=write_config(tmp_path, config),
        **sinks,
    )
    assert result.code == code
    written = signalling.getvalue().decode()
    assert written.endswith("\n") and written.strip()  # the whole result, never a partial write
    if sink == "out" and code != 2:
        assert json.loads(written)["outcome"] in {"dry_run", "disabled"}


# --- the environment is read lazily and never by a dry run --------------------------------------


def test_a_dry_run_without_an_injected_env_never_reads_the_environment(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    out, err = io.BytesIO(), io.BytesIO()
    code = main(
        ["send", "--dry-run", "--message", "m", "--config", write_config(tmp_path)],
        None,
        fake_gateway,
        Streams(out, err, lambda: False),
    )
    assert code == 0 and "environ" not in fake_gateway.calls


# --- assert_untouched itself ------------------------------------------------------------------


@pytest.mark.parametrize(
    "touch",
    [
        lambda gw, tmp: gw.wall_time(),
        lambda gw, tmp: gw.environ(),
        lambda gw, tmp: gw.read_regular_file(str(tmp / "log.jsonl"), 10),
        lambda gw, tmp: gw.list_directory(str(tmp)),
    ],
    ids=["wall_time", "environ", "read-log", "list-dir"],
)
def test_assert_untouched_fails_on_a_forbidden_call(
    touch: Callable[[FakeGateway, Path], object], fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    result = dry(
        ["send", "--dry-run", "--message", "m"], fake_gateway, config=write_config(tmp_path)
    )
    assert_untouched(result, fake_gateway, tmp_path)  # clean first
    with contextlib.suppress(OSError):
        touch(fake_gateway, tmp_path)
    with pytest.raises(AssertionError):
        assert_untouched(result, fake_gateway, tmp_path)

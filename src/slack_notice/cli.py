"""Command-line entry point for slack-notice: parsing, global flags, output and exit codes.

``main(argv, env, gateway, streams)`` is the call shape of the interface. The tests pass a fake
gateway and in-memory streams; the console script passes nothing and gets the system ones.

Rules kept here (interface: Global flags, Output, Exit codes, Error envelope):

- Global flags work before or after the subcommand; a subparser never overwrites a value given
  before it (the subparser copies use ``default=SUPPRESS``).
- Flags are exact: no abbreviations (``allow_abbrev=False``). ``--`` is refused (no command
  takes a positional). A single-value flag given twice is refused rather than last-wins.
- ``--json`` (also spelled ``--json=...``, which argparse then refuses) is looked for in argv
  before parsing, so a usage error prints the envelope.
- A CliError is a result: a write failure on either stream keeps its exit code (each of the
  envelope and the stderr line is tried on its own). Only a failure with no result (``--help``
  or ``--version`` output, an internal error) is exit 1.
- Every message printed here is a fixed string: argparse's own messages quote the input and are
  never shown. The environment is read only for the ``webhook_env`` variable, at step 5 of a real
  send (even the help width is fixed so argparse never reads ``COLUMNS``).
- stdout and stderr are written as UTF-8 with errors replaced, straight to the file descriptors
  (no buffer is left to fail at interpreter shutdown). After the result is printed
  (``Output.result_printed``) a write failure is ignored.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import signal
import sys
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, NoReturn, Protocol

from slack_notice import __version__, webhook
from slack_notice.config import (
    ConfigInvalid,
    HomeUnusable,
    config_file_key,
    load_config,
    resolve_home,
    validate_config,
)
from slack_notice.deadline import Deadline, attempt_work, conclude
from slack_notice.gateway import Gateway, SystemGateway, reserve_std_fds
from slack_notice.log import StateDir, dedupe_key_sha256, log_result, message_sha256
from slack_notice.payload import (
    EmptyMessage,
    FieldRefused,
    InputRefused,
    InputTimedOut,
    LinkRefused,
    Sanitized,
    SourceUnusable,
    decode_notification,
    notification_from_flags,
    read_notification,
    sanitize_notification,
    validate_notification,
)
from slack_notice.render import Rendered, render
from slack_notice.spacing import SendLock, SendLockTimeout, acquire

# Real-time bounds (seconds): the result print is waited for at most PRINT_BOUND before the log
# step and the exit; one advisory stderr write (a phase line, a state warning) at most SIDE_BOUND.
# A stderr that does not take the write is then given up on for the rest of the run.
PRINT_BOUND = 1.0
SIDE_BOUND = 1.0

# Exit codes in use (interface: Exit codes); 0 is a success and never a CliError.
ERROR_EXIT_CODES = frozenset({1, 2, 12, 20})

ACTOR_PATTERN = re.compile(r"(human|auto):[A-Za-z0-9._@/-]{1,64}")
LOGIN_DISALLOWED = re.compile(r"[^A-Za-z0-9._@-]")
CLASS_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")

USAGE_MESSAGE = "invalid command line (see slack-notice --help)"

# Flags that take one value and may be given once. ``--decision-id`` takes one value too, but
# may repeat.
SINGLE_VALUE_FLAGS = (
    "--config",
    "--actor",
    "--file",
    "--title",
    "--message",
    "--level",
    "--link",
    "--dedupe-key",
)
VALUE_FLAGS = frozenset(SINGLE_VALUE_FLAGS) | {"--decision-id"}


# --- errors -----------------------------------------------------------------------------------


class CliError(Exception):
    """A failure with a fixed message that maps to an exit code and the error envelope."""

    def __init__(
        self,
        exit_code: int,
        code: str,
        message: str,
        *,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
        retryable: bool | None = None,
        retry_after_s: float | None = None,
        unknown_outcome: bool | None = None,
        class_name: str | None = None,
    ) -> None:
        if exit_code not in ERROR_EXIT_CODES:
            raise ValueError("not an exit code of the interface")
        super().__init__(code)
        self.exit_code = exit_code
        self.code = code
        self.message = message
        self.reason = reason
        self.details = details
        self.retryable = retryable
        self.retry_after_s = retry_after_s
        self.unknown_outcome = unknown_outcome
        self.class_name = class_name  # exit 1 only: the exception class, shown on stderr

    def envelope(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "reason": self.reason,
                "details": self.details,
                "retryable": self.retryable,
                "retry_after_s": self.retry_after_s,
                "unknown_outcome": self.unknown_outcome,
            }
        }

    def stderr_line(self) -> str:
        if self.code == "refused" and self.reason is not None:
            return f"refused ({self.reason}): {self.message}"
        if self.class_name is not None:
            return f"{self.code}: {self.message} ({self.class_name})"
        return f"{self.code}: {self.message}"


def usage_error(message: str = USAGE_MESSAGE) -> CliError:
    return CliError(2, "usage", message)


def error_from_outcome(outcome: webhook.Outcome) -> CliError:
    """An exit 12 ``Outcome`` (fixed message, flags and details) as a ``CliError``, so the
    messages are defined once, in ``slack_notice.webhook``."""
    assert outcome.exit_code == 12 and outcome.code is not None
    return CliError(
        12,
        outcome.code,
        outcome.message,
        details=None if outcome.details is None else dict(outcome.details),
        retryable=outcome.retryable,
        retry_after_s=outcome.retry_after_s,
        unknown_outcome=outcome.unknown_outcome,
    )


class _EarlyExit(Exception):
    """--help or --version: print the text on stdout and exit 0 (exempt from --json)."""

    def __init__(self, text: str) -> None:
        super().__init__("early exit")
        self.text = text


# --- streams and output -------------------------------------------------------------------------


class ByteSink(Protocol):
    def write(self, data: bytes, /) -> object: ...

    def flush(self) -> object: ...


@dataclass(frozen=True)
class Streams:
    """The process's output streams (bytes) and the terminal test for stdin."""

    out: ByteSink
    err: ByteSink
    stdin_is_tty: Callable[[], bool]


class _FdWriter:
    """Unbuffered writes to a file descriptor: nothing is left to fail when Python shuts down."""

    def __init__(self, fd: int) -> None:
        self._fd = fd

    def write(self, data: bytes, /) -> int:
        view = memoryview(data)
        while view:
            view = view[os.write(self._fd, view) :]
        return len(data)

    def flush(self) -> None:
        return None


def _stdin_is_tty() -> bool:
    try:
        return os.isatty(0)
    except OSError:
        return False


def system_streams() -> Streams:
    return Streams(out=_FdWriter(1), err=_FdWriter(2), stdin_is_tty=_stdin_is_tty)


class Output:
    """Writes the result and the human lines; one place for the encoding and failure rules."""

    def __init__(
        self,
        streams: Streams,
        *,
        verbose: bool,
        quiet: bool,
        gate: _SignalGate | None = None,
    ) -> None:
        self._streams = streams
        self._verbose = verbose
        self._quiet = quiet
        self._gate = _SignalGate() if gate is None else gate
        self._lenient = False
        self._stderr_abandoned = False

    def result_printed(self) -> None:
        """Called immediately BEFORE the result is written, once step 6 is over (a dry run has
        no step 6, so the print is its last step): from here on a write failure is ignored and a
        signal no longer ends the run, so the result is never cut short."""
        self._lenient = True
        self.commit()

    def commit(self) -> None:
        """The result print begins: a signal from here on is ignored."""
        self._gate.commit()

    def arm(self, hook: Callable[[], None]) -> None:
        """Step 5 begins: a signal is the deadline passing (``hook``), not an exit."""
        self._gate.arm(hook)

    def _write(self, sink: ByteSink, text: str) -> None:
        data = text.encode("utf-8", errors="replace")
        try:
            sink.write(data)
            sink.flush()
        except (OSError, ValueError):
            if not self._lenient:
                raise

    def out(self, text: str) -> None:
        self._write(self._streams.out, text)

    def err(self, text: str) -> None:
        self._write(self._streams.err, text)

    def json_document(self, document: object) -> None:
        self.out(json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n")

    def _advisory(self, text: str) -> None:
        """stderr text is advisory: a failure to write it never changes the outcome."""
        try:
            self.err(text)
        except (OSError, ValueError):
            pass

    def info(self, line: str) -> None:
        """A human line that --quiet suppresses; best effort."""
        if not self._quiet:
            self._advisory(line + "\n")

    def abandon_stderr(self) -> None:
        """Every later advisory stderr line (``side_line``) is skipped."""
        self._stderr_abandoned = True

    def side_line(self, text: str) -> None:
        """An advisory stderr write that can never hold the process: it runs in a daemon thread
        that is waited for at most ``SIDE_BOUND`` seconds of real time. A write that does not
        finish marks stderr abandoned, so no later advisory line is tried. Failures are ignored."""
        if self._stderr_abandoned:
            return
        done = threading.Event()

        def write() -> None:
            try:
                self.err(text)
            except Exception:
                pass
            finally:
                done.set()

        threading.Thread(target=write, name="slack-notice-stderr", daemon=True).start()
        if not done.wait(SIDE_BOUND):
            self._stderr_abandoned = True

    def warning(self, line: str) -> None:
        self.side_line(line + "\n")

    def error_line(self, line: str) -> None:
        self.err(line + "\n")

    def phase(self, name: str, elapsed_ms: int) -> None:
        """A --verbose line: the phase and its elapsed milliseconds, nothing else."""
        if self._verbose:
            self.side_line(f"{name}: {elapsed_ms} ms\n")

    def finish(self) -> None:
        """One flush attempt of each stream; failures are ignored."""
        for sink in (self._streams.out, self._streams.err):
            try:
                sink.flush()
            except (OSError, ValueError):
                pass


# --- context and actor -------------------------------------------------------------------------


@dataclass
class Context:
    args: argparse.Namespace
    env: Mapping[str, str] = field(repr=False)  # holds the credential
    gateway: Gateway
    output: Output
    json: bool
    dry_run: bool
    config: str | None
    home: str | None  # None only for `send --dry-run --config`, which needs no home
    actor: str
    actor_source: str
    # Set from ``Verdict.gate_writing`` (``slack_notice.deadline``) by the send; an exit 1 then
    # reports unknown_outcome true and is logged.
    gate_writing: bool = field(default=False)
    # The send's Deadline once it exists: an exception that escapes after a possible write is
    # still told apart from one before it (``writing``).
    deadline: Deadline | None = field(default=None, repr=False)
    _state: StateDir | None = field(default=None, repr=False)
    _deferred_warnings: list[str] = field(default_factory=list, repr=False)

    @property
    def writing(self) -> bool:
        """A request may have been written (the verdict said so, or the gate is writing now)."""
        return self.gate_writing or (self.deadline is not None and self.deadline.writing)

    def state_dir(self) -> StateDir:
        """The run's state directory handle (lazy: nothing is opened until a file is needed).

        Never called for a dry run (it uses no state): the real send asks for it at the send
        lock and the log step, and closes it at the end (``close_state``).
        """
        assert self.home is not None, "state directory requested without a home"
        if self._state is None:
            self._state = StateDir(self.gateway, self.home, self._state_warning)
        return self._state

    def _state_warning(self, line: str) -> None:
        """The one state warning. The worker thread runs the send lock's stamp under the gate's
        lock, and a stderr nobody reads must never hold that lock past the deadline: from any
        thread but the main one the line is kept and written by ``flush_warnings`` (the log
        step, after the result)."""
        if threading.current_thread() is threading.main_thread():
            self.output.warning(line)
        else:
            self._deferred_warnings.append(line)

    def flush_warnings(self) -> None:
        """Write the warnings a worker thread deferred (main thread, after the result)."""
        lines, self._deferred_warnings = self._deferred_warnings, []
        for line in lines:
            self.output.warning(line)  # bounded and never raises

    def close_state(self) -> None:
        """Release the state directory descriptor (safe to call again, or when never opened)."""
        if self._state is not None:
            self._state.close()


def sanitize_login(name: str | None) -> str:
    """Characters outside [A-Za-z0-9._@-] become `_`; cut to 64; `unknown` when empty."""
    if not name:
        return "unknown"
    return LOGIN_DISALLOWED.sub("_", name)[:64]


def resolve_actor(flag: str | None, *, tty: bool, gateway: Gateway) -> tuple[str, str]:
    if flag is not None:
        return flag, "flag"
    if tty:
        return f"human:{sanitize_login(gateway.login_name())}", "tty"
    return "auto:unknown", "default"


# --- parser ---------------------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise usage_error()  # argparse's text quotes the input; never shown

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise usage_error()

    def print_help(self, file: Any = None) -> None:
        raise _EarlyExit(self.format_help())


class _VersionAction(argparse.Action):
    def __init__(self, option_strings: Sequence[str], dest: str = argparse.SUPPRESS, **_: Any):
        super().__init__(option_strings, dest=dest, default=argparse.SUPPRESS, nargs=0)

    def __call__(self, parser: Any, namespace: Any, values: Any, option_string: Any = None) -> None:
        raise _EarlyExit(f"slack-notice {__version__}\n")


def _add_global_flags(parser: argparse.ArgumentParser, *, top: bool) -> None:
    """Global flags on the top parser (real defaults) and on each subparser (SUPPRESS)."""

    def default(value: object) -> object:
        return value if top else argparse.SUPPRESS

    parser.add_argument(
        "--json", action="store_true", default=default(False), help="machine output"
    )
    parser.add_argument("--config", metavar="PATH", default=default(None), help="config file")
    parser.add_argument(
        "--dry-run", action="store_true", default=default(False), help="render only (send)"
    )
    parser.add_argument("--actor", metavar="ACTOR", default=default(None), help="human:X or auto:X")
    parser.add_argument(
        "--verbose", action="store_true", default=default(False), help="more output"
    )
    parser.add_argument("--quiet", action="store_true", default=default(False), help="less output")
    parser.add_argument("--version", action=_VersionAction, help="print the version")


def build_parser() -> argparse.ArgumentParser:
    common: dict[str, Any] = {
        "allow_abbrev": False,
        # A fixed width: the default reads COLUMNS from the environment.
        "formatter_class": functools.partial(argparse.HelpFormatter, width=80),
    }
    if sys.version_info >= (3, 14):
        # Python 3.14 colours help from NO_COLOR, FORCE_COLOR and TERM; no variable is read.
        common["color"] = False
    parser = _Parser(
        prog="slack-notice",
        description="Send one plain-text notification to Slack through a workflow webhook trigger.",
        **common,
    )
    _add_global_flags(parser, top=True)
    commands = parser.add_subparsers(dest="command", metavar="<command>", parser_class=_Parser)

    send = commands.add_parser("send", help="send one notification", **common)
    _add_global_flags(send, top=False)
    send.add_argument("--stdin-json", action="store_true", help="read JSON from stdin")
    send.add_argument("--file", metavar="PATH", help="read JSON from a file ('-' is stdin)")
    send.add_argument("--title", metavar="TEXT")
    send.add_argument("--message", metavar="TEXT")
    # The level and link are checked like the JSON fields (exit 20, with a pointer).
    send.add_argument("--level", metavar="LEVEL")
    send.add_argument("--link", metavar="URL")
    send.add_argument("--dedupe-key", metavar="KEY")
    send.add_argument("--decision-id", metavar="ID", action="append", help="accepted, ignored")

    validate = commands.add_parser("validate", help="check the config and the credential", **common)
    _add_global_flags(validate, top=False)
    validate.add_argument("--test-message", action="store_true", help="send one test message")
    return parser


def _prescan(argv: Sequence[str]) -> None:
    """Refusals that need no parsing: a `--` separator, a repeated single-value flag and a
    separate value that starts with `-` (such a value uses the `=` form; `-` alone is a value).

    A walk over the tokens: a value flag given without `=` consumes the next token as its value,
    so a value is never counted as a flag.
    """
    seen: set[str] = set()
    i = 0
    while i < len(argv):
        token = argv[i]
        i += 1
        if token == "--":
            raise usage_error()
        name, equals, _ = token.partition("=")
        if name not in VALUE_FLAGS:
            continue
        if name in SINGLE_VALUE_FLAGS:
            if name in seen:
                raise usage_error()
            seen.add(name)
        if equals or i >= len(argv):
            continue  # a missing value is argparse's to report
        if argv[i].startswith("-") and argv[i] != "-":
            raise usage_error()
        i += 1


def json_requested(argv: Sequence[str]) -> bool:
    """`--json` or a `--json=...` spelling (argparse refuses it, now with the envelope)."""
    return any(a == "--json" or a.startswith("--json=") for a in argv)


def parse(argv: Sequence[str]) -> argparse.Namespace:
    _prescan(argv)
    args = build_parser().parse_args(list(argv))
    if args.command is None:
        raise usage_error("a command is required (send or validate)")
    if args.verbose and args.quiet:
        raise usage_error("--verbose and --quiet cannot be combined")
    if args.actor is not None and ACTOR_PATTERN.fullmatch(args.actor) is None:
        raise usage_error("--actor must be human:<name> or auto:<name>")
    # An empty --config path is a missing file (config_invalid, details.key --config): config
    # loading decides it (load_settings), not the parser.
    if args.command == "send":
        check_send_combinations(args)
    return args


TEXT_FLAGS = ("title", "message", "level", "link")
MAX_DEDUPE_KEY_CHARS = 1024


def check_send_combinations(args: argparse.Namespace) -> None:
    """Step 1: the flag combinations of `send` that need no stream (exit 2 usage, fixed text).

    Exactly one source is used: JSON on stdin, JSON from --file, or the flags (which need
    --message). The value flags are not judged here: they are checked like the same JSON field
    when the notification is read (``load_notification``, exit 20 with a pointer).
    """
    text_flags = any(vars(args)[name] is not None for name in TEXT_FLAGS)
    if (args.stdin_json or args.file is not None) and text_flags:
        raise usage_error(
            "a JSON source cannot be combined with --title, --message, --level or --link"
        )
    if args.stdin_json and args.file is not None and args.file != "-":
        raise usage_error("--stdin-json cannot be combined with --file <path>")
    if text_flags and args.message is None:
        raise usage_error("--title, --level and --link need --message")
    key: str | None = args.dedupe_key
    if key is not None and not _dedupe_key_ok(key):
        raise usage_error("--dedupe-key must be 1 to 1024 characters of valid UTF-8")


def _dedupe_key_ok(key: str) -> bool:
    if not 1 <= len(key) <= MAX_DEDUPE_KEY_CHARS:
        return False
    try:
        key.encode("utf-8")  # bytes that were not UTF-8 arrive as lone surrogates
    except UnicodeEncodeError:
        return False
    return True


def check_stdin_source(args: argparse.Namespace, streams: Streams) -> None:
    """Step 1: stdin that is a terminal is no source.

    Refused: a JSON source on stdin (--stdin-json, --file -), and no source at all (no JSON
    option and no --message, so the default would read the terminal).
    """
    if args.command != "send":
        return
    if (args.stdin_json or args.file == "-") and streams.stdin_is_tty():
        raise usage_error("--stdin-json and --file - need stdin to be a pipe or a file")
    if (
        not args.stdin_json
        and args.file is None
        and args.message is None
        and streams.stdin_is_tty()
    ):
        raise usage_error("stdin is a terminal: give --message, --stdin-json or --file")


# --- signals ------------------------------------------------------------------------------------

SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


class _Signalled(BaseException):  # noqa: N818  (not an Exception: no handler may swallow it)
    """A signal ended the run: exit 128+N with no envelope and no output."""

    def __init__(self, number: int) -> None:
        super().__init__(number)
        self.number = number


class _SignalGate:
    """What a signal does now (interface: Signals).

    Three phases, in order: before step 5 the handler raises ``_Signalled`` (exit 128+N); from
    step 5 (``arm``) it only calls the hook, which is ``Deadline.note_signal`` (lock-free, never
    raises) and the main thread decides within 100 ms; once the result print has begun
    (``committed``) it does nothing, so the result is written whole.
    """

    def __init__(self) -> None:
        self.committed = False
        self.on_signal: Callable[[], None] | None = None
        self.fired: int | None = None  # the signal that is ending the run before step 5

    def arm(self, hook: Callable[[], None]) -> None:
        """Step 5 begins: a signal is now the deadline passing, not an exit. The send calls this
        with ``Deadline.note_signal`` before it reads the credential and takes the lock."""
        self.on_signal = hook

    def commit(self) -> None:
        """The result print begins: from here on a signal is ignored."""
        self.committed = True


def _set_disposition(number: int, disposition: Any) -> None:
    """``signal.signal`` that never raises ``OSError`` and never prints.

    CPython can report an unraisable error on stderr when the same signal is pending; swapping
    the unraisable hook narrows that window, it does not close it. Nothing may reach stderr after
    a signal."""
    previous_hook = sys.unraisablehook
    sys.unraisablehook = lambda _unraisable: None
    try:
        signal.signal(number, disposition)
    except (OSError, ValueError):
        pass
    finally:
        sys.unraisablehook = previous_hook


@contextmanager
def _exit_on_signal(gate: _SignalGate, restore: bool = True) -> Iterator[None]:
    """SIGTERM, SIGINT and SIGHUP are handled once; the old handlers come back after.

    ``restore=False`` (the process entry) installs a non-raising handler after the block instead:
    once the gate is committed a signal changes nothing (no traceback, no death by the default
    disposition); before that it only records ``gate.fired``, which ``main`` turns into 128+N.

    Before step 5 the first signal raises ``_Signalled`` (a ``BaseException``: no ``except
    Exception`` swallows it) and sets ``gate.fired``; every later one returns, so the first wins.
    From step 5 on (``gate.arm``) the handler never raises. Once ``gate.committed`` it returns at
    once. Handlers can only be installed from the main thread; elsewhere nothing is installed.
    SIGPIPE is left as the interpreter set it (ignored): a closed pipe is a write error.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(number: int, _frame: object) -> None:
        if gate.committed:
            return
        hook = gate.on_signal
        if hook is not None:
            hook()  # lock-free (``Deadline.note_signal``); later signals repeat it harmlessly
            return
        if gate.fired is not None:
            return
        gate.fired = number
        # Handled once: from now on this handler returns at the ``gate.fired`` check above, so a
        # second signal while unwinding is ignored. The dispositions are NOT changed here:
        # CPython reports a race (an unraisable error on stderr) when a pending signal's
        # disposition is changed.
        raise _Signalled(number)

    def record_late(number: int, _frame: object) -> None:
        # The handler left by ``restore=False``: it never raises, but a signal that comes after
        # the block and before the result is committed is recorded; ``main`` turns it into
        # 128+N once the restore loop has finished.
        if not gate.committed and gate.fired is None:
            gate.fired = number

    saved: dict[int, Any] = {}
    try:
        for number in SIGNALS:
            saved[number] = signal.getsignal(number)  # before the install: a signal mid-install
            signal.signal(number, handler)  # still finds it in ``saved``
        yield
    finally:
        # Every signal is restored even when a pending signal raises from a call: the loop
        # finishes, then the first exception is re-raised.
        pending: BaseException | None = None
        for number, previous in saved.items():
            target = (
                record_late if not restore else signal.SIG_DFL if previous is None else previous
            )
            try:
                _set_disposition(number, target)
            except BaseException as error:
                pending = pending or error
        if pending is not None:
            raise pending


# --- dispatch ------------------------------------------------------------------------------------


def load_settings(ctx: Context) -> dict[str, Any]:
    """The effective settings: the config file and drop-ins over the defaults.

    No flag names a setting.

    A file that cannot be used is exit 2 config_invalid with the file path (or `--config` for a
    missing --config file) in details.key and a fixed message. A value that breaks a rule is the
    same error with the config key name (or `?`) in details.key and a message that names the key
    and the rule (never the value).
    """
    # `validate` (#31, #32) reuses this.
    key: str | None = None
    message = ""
    settings: dict[str, Any] = {}
    try:
        values = load_config(ctx.gateway, home=ctx.home, config_path=ctx.config)
        settings = validate_config(
            values, fallback_key=config_file_key(ctx.gateway, home=ctx.home, config_path=ctx.config)
        )
    except ConfigInvalid as error:
        key = error.key
        message = error.message
    if key is not None:  # raised here, not in the handler: no context is kept
        raise CliError(
            2, "config_invalid", message or "configuration is invalid", details={"key": key}
        )
    # No flag of the interface names a setting (the flags are the notification, the global flags
    # and --config), so the flag layer of resolve_settings is empty: the result is the validated
    # config over the defaults, with timeout in seconds. Callers use this, never DEFAULTS.
    return settings


INPUT_FILE_MESSAGE = "--file cannot be read or is not a regular file"


def read_input(ctx: Context, remaining: float) -> dict[str, Any]:
    """Step 3, the reading half: one JSON source to a decoded object, or a CliError.

    The source is the file named by ``--file`` or, otherwise, stdin (``--file -`` included).
    ``remaining`` is the seconds left of the deadline, which starts at step 3. The caller
    never sees input text in an error.

    The send calls this after it started the deadline; the real send logs ``failed`` for the
    timeout error (exit 12 ``unavailable``, phase ``input``).
    A signal during this call raises ``_Signalled`` from the handler of ``_exit_on_signal``.
    """
    file_arg: str | None = ctx.args.file
    source: int | str = 0 if file_arg is None or file_arg == "-" else file_arg
    error: CliError | None = None
    try:
        # A None sys.stdin means stdin was closed at start; interface.md treats that as empty
        # input (fd 0 may have been reused by an import-time open).
        if source == 0 and sys.stdin is None:
            # stdin was closed at start (`<&-`): descriptor 0 may now be something else, so it
            # is not read; a closed stdin is empty input.
            return decode_notification(b"")
        return read_notification(ctx.gateway, source, remaining)
    except InputRefused as refused:
        error = CliError(
            20,
            "refused",
            refused.message,
            reason="invalid_payload",
            details={"pointer": refused.pointer},
        )
    except InputTimedOut:
        error = error_from_outcome(webhook.unavailable("input"))
    except SourceUnusable:
        error = usage_error(INPUT_FILE_MESSAGE)
    raise error  # raised outside the handlers: no __context__ (it would hold input text)


def load_notification(ctx: Context, remaining: float) -> dict[str, Any]:
    """Step 3: the validated notification from the one source in use, or a CliError.

    With --message the flags are the source and nothing is read (stdin included); otherwise one
    JSON source is read (``read_input``). Both go through ``validate_notification``, so a flag
    and a JSON field have the same rule and the same pointer (exit 20 ``invalid_payload``).
    The error holds a fixed message and the pointer, never an input value.

    ``sanitize_loaded`` (the sanitizer, ``empty_message`` and the link rule) comes after this.
    The send handler calls this after starting the deadline.
    """
    args = ctx.args
    refused: FieldRefused | None = None
    notification: dict[str, Any] | None = None
    try:
        if args.message is not None:
            notification = notification_from_flags(
                title=args.title, message=args.message, level=args.level, link=args.link
            )
        else:
            notification = validate_notification(read_input(ctx, remaining))
    except FieldRefused as error:
        refused = error
    if refused is not None:  # raised here, not in the handler: no context is kept
        raise CliError(
            20,
            "refused",
            refused.message,
            reason="invalid_payload",
            details={"pointer": refused.pointer},
        )
    assert notification is not None
    return notification


def sanitize_loaded(notification: dict[str, Any]) -> Sanitized:
    """Step 3, after validation: the sanitized notification, or exit 20 ``refused`` with reason
    ``empty_message``, ``link_invalid`` or ``link_scheme`` (no details; the text is fixed)."""
    emptied: EmptyMessage | None = None
    bad_link: LinkRefused | None = None
    result: Sanitized | None = None
    try:
        result = sanitize_notification(notification)
    except EmptyMessage as error:
        emptied = error
    except LinkRefused as error:
        bad_link = error
    if bad_link is not None:  # raised here, not in the handler: no context is kept
        raise CliError(20, "refused", bad_link.message, reason=bad_link.reason)
    if emptied is not None:  # raised here, not in the handler: no context is kept
        raise CliError(20, "refused", emptied.message, reason="empty_message")
    assert result is not None
    return result


def _not_implemented(_ctx: Context) -> int:
    raise NotImplementedError


def _elapsed_ms(ctx: Context, since: float) -> int:
    return max(0, int((ctx.gateway.monotonic() - since) * 1000))


def _disabled(ctx: Context) -> int:
    """Step 2, `enabled: false`: not an error, nothing sent, exit 22."""
    ctx.output.result_printed()  # before the print: the print is the last step
    if ctx.json:
        ctx.output.json_document({"outcome": "disabled"})
    else:
        ctx.output.info("disabled in config")
    return 22


@dataclass
class _Progress:
    """What steps 3 and 4 have produced so far: the facts the log record is built from."""

    level: str | None = None  # a level that passed validation, before the sanitizer
    notification: Sanitized | None = None
    rendered: Rendered | None = None


def _prepare(
    ctx: Context, settings: dict[str, Any], started: float, progress: _Progress
) -> tuple[Sanitized, Rendered]:
    """Steps 3 and 4, shared by the dry run and the real send: input, sanitizer, render.

    The deadline started at ``started``; ``settings["timeout"]`` seconds remain for the input.
    Raises ``CliError`` (exit 2, 12 ``unavailable``/``input`` or 20).
    """
    loaded = load_notification(ctx, settings["timeout"])
    level = loaded.get("level")
    progress.level = level if isinstance(level, str) else None
    notification = sanitize_loaded(loaded)
    progress.level, progress.notification = notification.level, notification
    ctx.output.phase("input", _elapsed_ms(ctx, started))
    phase_start = ctx.gateway.monotonic()
    rendered = render(notification, settings)  # step 4
    progress.rendered = rendered
    ctx.output.phase("render", _elapsed_ms(ctx, phase_start))
    return notification, rendered


def send(ctx: Context) -> int:
    """The `send` command (interface: Send, steps 1 to 7).

    Step 1 ran in ``parse`` and ``check_stdin_source``, and the home lookup of step 2 in ``_run``.
    Config and ``enabled`` come first (exit 2 and 22 are results of their own), then the dry run
    (steps 3 and 4 only: no credential, no state directory, no lock, no log, no network), then
    the real send.
    """
    settings = load_settings(ctx)  # step 2: config over defaults (exit 2 config_invalid)
    if not settings["enabled"]:
        return _disabled(ctx)
    if ctx.dry_run:
        return _dry_run(ctx, settings)
    return _real_send(ctx, settings)


def _dry_run(ctx: Context, settings: dict[str, Any]) -> int:
    started = ctx.gateway.monotonic()  # step 3: the deadline starts here
    notification, rendered = _prepare(ctx, settings, started, _Progress())
    ctx.output.result_printed()  # before the print: a dry run has no step 6
    if ctx.json:
        ctx.output.json_document(
            {
                "outcome": "dry_run",
                "tool": "slack-notice",
                "level": notification.level,
                "truncated": rendered.truncated,
                "bytes": rendered.bytes,
                "duration_ms": _elapsed_ms(ctx, started),
                "http_status": None,
                "dedupe_key": ctx.args.dedupe_key,
                "rendered": rendered.text,
            }
        )
    else:
        ctx.output.info(rendered.text)
    return 0


# --- the real send: steps 3 to 7 -----------------------------------------------------------------


@dataclass
class _Result:
    """A finished send: the exit code, the print, and the log fields the result decides."""

    code: int
    emit: Callable[[], None]
    log: dict[str, Any]


def _error_result(ctx: Context, error: CliError, *, http_status: int | None = None) -> _Result:
    """A failure as a result: the envelope and the line are printed, the record is logged."""
    return _Result(
        error.exit_code,
        lambda: _emit(ctx.output, error, json_mode=ctx.json),
        {
            "exit_code": error.exit_code,
            "code": error.code,
            "reason": error.reason,
            "unknown_outcome": bool(error.unknown_outcome),
            "http_status": http_status,
        },
    )


def _sent_result(
    ctx: Context, notification: Sanitized, rendered: Rendered, started: float
) -> _Result:
    duration_ms = _elapsed_ms(ctx, started)

    def emit() -> None:
        ctx.output.result_printed()  # the print begins: a signal no longer ends the run
        if ctx.json:
            ctx.output.json_document(
                {
                    "outcome": "sent",
                    "tool": "slack-notice",
                    "level": notification.level,
                    "truncated": rendered.truncated,
                    "bytes": rendered.bytes,
                    "duration_ms": duration_ms,
                    "http_status": 200,
                    "dedupe_key": ctx.args.dedupe_key,
                }
            )
        else:
            ctx.output.info(f"sent ({notification.level}, {duration_ms} ms)")

    return _Result(
        0,
        emit,
        {
            "exit_code": 0,
            "code": None,
            "reason": None,
            "unknown_outcome": False,
            "http_status": 200,
        },
    )


def _verdict_result(
    ctx: Context,
    verdict_outcome: webhook.Outcome | None,
    error_class: str | None,
    progress: _Progress,
    started: float,
) -> _Result:
    """The result of the network phase (``Verdict``): sent, an exit 12 envelope or exit 1."""
    if verdict_outcome is None:
        assert error_class is not None
        return _error_result(ctx, _internal_error_named(error_class, gate_writing=ctx.gate_writing))
    if verdict_outcome.exit_code == 0:
        assert progress.notification is not None and progress.rendered is not None
        return _sent_result(ctx, progress.notification, progress.rendered, started)
    return _error_result(
        ctx, error_from_outcome(verdict_outcome), http_status=verdict_outcome.http_status
    )


def _stamp_hook(ctx: Context, locks: list[SendLock]) -> Callable[[], None]:
    """The gate's ``on_writing``: the send lock's stamp before EACH attempt's write.

    It runs once per attempt that reaches writing (up to four per send), under the gate's lock.
    A failure of the stamp is a state problem, and a state problem never fails a send: the hook
    swallows every ``Exception`` (one warning). If it raised, the gate would go back to idle and
    the send would end exit 1 with ``unknown_outcome`` false, so a known 429 or connection
    failure would be replaced by an internal error. Nothing is swallowed that is not an
    ``Exception``.
    """

    def stamp() -> None:
        try:
            for lock in locks:
                lock.stamp()
        except Exception:
            ctx.state_dir().warn()

    return stamp


def _send_and_report(
    ctx: Context, settings: dict[str, Any], started: float, progress: _Progress
) -> _Result:
    """Steps 3 to 6; a ``CliError`` here is a failure that is printed and logged (exit 12, 20)."""
    at = started + settings["timeout"]
    locks: list[SendLock] = []
    deadline = Deadline(ctx.gateway, at=at, on_writing=_stamp_hook(ctx, locks))
    ctx.deadline = deadline
    notification, rendered = _prepare(ctx, settings, started, progress)
    phase_start = ctx.gateway.monotonic()
    # Step 5. From here a signal is the deadline passing (outcome by phase), never an exit.
    ctx.output.arm(deadline.note_signal)
    name: str = settings["webhook_env"]
    target: webhook.Webhook | None = None
    try:
        target = webhook.read_webhook(ctx.env, name)
    except webhook.CredentialInvalid:
        pass
    if target is None:  # raised here, not in the handler: no context is kept
        raise error_from_outcome(webhook.credential_invalid(name))
    # Step 6. The lock is asked for only now (a real send), and a signal while waiting for it is
    # the deadline (``unavailable``, phase ``lock``).
    timed_out = False
    lock: SendLock | None = None
    try:
        lock = acquire(ctx.state_dir(), ctx.gateway, at, stop=lambda: deadline.signalled)
    except SendLockTimeout:
        timed_out = True
    if timed_out:
        raise error_from_outcome(webhook.unavailable("lock"))
    if lock is not None:
        locks.append(lock)
    try:
        verdict = deadline.run(
            attempt_work(ctx.gateway, target, rendered.body, timeout=settings["timeout"])
        )
    finally:
        if lock is not None:
            try:
                lock.release()  # before the log step: send.lock and log.lock are never both held
            except Exception:  # a state problem never replaces the verdict
                ctx.state_dir().warn()
    ctx.gate_writing = verdict.gate_writing
    ctx.output.phase("send", _elapsed_ms(ctx, phase_start))
    return _verdict_result(ctx, verdict.outcome, verdict.error_class, progress, started)


def _real_send(ctx: Context, settings: dict[str, Any]) -> int:
    """Steps 3 to 7 of a send that is not a dry run. Never returns: the result is printed, then
    logged, then the process ends through ``gateway.exit_now`` (``conclude``), the one place
    that may end it while a worker can still be blocked. An exit 1 from the worker with the gate
    idle is such a result too (``conclude`` and ``exit_now``). Only an exit 2 (a ``--file``
    problem at step 3) and an exception on the main thread before any possible write are raised
    to ``_main`` instead: they are not logged and the run ends by returning."""
    started = ctx.gateway.monotonic()  # step 3: the deadline starts here
    progress = _Progress()
    try:
        try:
            result = _send_and_report(ctx, settings, started, progress)
        except CliError as error:
            if error.exit_code not in (12, 20):
                raise
            result = _error_result(ctx, error)
        except Exception as exc:
            if not ctx.writing:
                raise  # before any possible write: exit 1, unknown_outcome false, not logged
            ctx.gate_writing = True
            result = _error_result(ctx, _internal_error(exc, gate_writing=True))
        _conclude(ctx, settings, started, progress, result)
    finally:
        ctx.close_state()
    raise RuntimeError("exit_now returned")  # unreachable: the gateway's exit does not return


def _conclude(
    ctx: Context, settings: dict[str, Any], started: float, progress: _Progress, result: _Result
) -> None:
    """Step 7: print and flush, then the log record, then the exit (``deadline.conclude``)."""
    # A signal from here on never cuts the result short (before it, an unarmed result is 128+N).
    ctx.output.commit()
    notification, rendered = progress.notification, progress.rendered
    facts: dict[str, Any] = {
        "level": progress.level,
        "bytes_": None if rendered is None else rendered.bytes,
        "truncated": None if rendered is None else rendered.truncated,
        "message_hash": None
        if notification is None
        else message_sha256(notification.title_text, notification.message),
        "dedupe_hash": None
        if notification is None or ctx.args.dedupe_key is None
        else dedupe_key_sha256(ctx.args.dedupe_key),
    }

    printed = threading.Event()  # set by the print thread once the print and flush are over

    def flush() -> None:
        ctx.output.finish()
        printed.set()

    def record() -> None:
        try:
            if not printed.is_set():  # the print may still hold stderr: never write to it
                ctx.output.abandon_stderr()
            ctx.flush_warnings()
            log_start = ctx.gateway.monotonic()
            log_result(
                ctx.state_dir(),
                ctx.gateway,
                enabled=settings["log"],
                version=__version__,
                duration_ms=_elapsed_ms(ctx, started),
                gate_writing=ctx.gate_writing,
                actor=ctx.actor,
                actor_source=ctx.actor_source,
                **facts,
                **result.log,
            )
            ctx.output.phase("log", _elapsed_ms(ctx, log_start))
        finally:
            ctx.close_state()

    conclude(
        ctx.gateway, result.code, emit=result.emit, flush=flush, record=record, bound=PRINT_BOUND
    )


# TODO(#31), TODO(#32): validate.
HANDLERS: dict[str, Callable[[Context], int]] = {
    "send": send,
    "validate": _not_implemented,
}


def _internal_error(exc: Exception, *, gate_writing: bool) -> CliError:
    return _internal_error_named(type(exc).__name__, gate_writing=gate_writing)


def _internal_error_named(name: str, *, gate_writing: bool) -> CliError:
    if CLASS_NAME_PATTERN.fullmatch(name) is None:
        name = "Exception"
    return CliError(
        1,
        "internal",
        "internal error",
        retryable=False,
        unknown_outcome=gate_writing,
        class_name=name,
    )


def _lookup_home(args: argparse.Namespace, gateway: Gateway) -> str | None:
    """Step 2: the home from the password database, once, before any input is read.

    Skipped (None) only for `send --dry-run` with `--config` (even an empty one: whether that
    file exists is config loading's question). Anything else that cannot get a usable home is
    exit 2 config_invalid with details.key `home`.
    """
    if args.command == "send" and args.dry_run and args.config is not None:
        return None
    try:
        return resolve_home(gateway)
    except HomeUnusable:
        raise CliError(
            2, "config_invalid", "configuration is invalid", details={"key": "home"}
        ) from None


def _run(
    argv: list[str],
    env: Mapping[str, str],
    gateway: Gateway,
    streams: Streams,
    holder: list[Context],
    gate: _SignalGate,
) -> int:
    args = parse(argv)
    check_stdin_source(args, streams)
    home = _lookup_home(args, gateway)
    actor, actor_source = resolve_actor(args.actor, tty=streams.stdin_is_tty(), gateway=gateway)
    ctx = Context(
        args=args,
        env=env,
        gateway=gateway,
        output=Output(streams, verbose=args.verbose, quiet=args.quiet, gate=gate),
        json=json_requested(argv),
        dry_run=args.dry_run,
        config=args.config,
        home=home,
        actor=actor,
        actor_source=actor_source,
    )
    holder.append(ctx)
    return HANDLERS[args.command](ctx)


def _emit(output: Output, outcome: _EarlyExit | CliError, *, json_mode: bool) -> None:
    if isinstance(outcome, _EarlyExit):
        output.commit()
        output.out(outcome.text)
        return
    # A CliError is the result: it counts as printed (before the first write, so a failing
    # stream never replaces its exit code and a signal never cuts it short), and the envelope
    # and the stderr line are each tried on their own.
    output.result_printed()
    if json_mode:
        output.json_document(outcome.envelope())
    output.error_line(outcome.stderr_line())


class _LazyEnv(Mapping[str, str]):
    """The environment, copied from the gateway on first access (it holds the credential)."""

    def __init__(self, gateway: Gateway) -> None:
        self._gateway = gateway
        self._values: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._values is None:
            self._values = self._gateway.environ()
        return self._values

    def __getitem__(self, key: str) -> str:
        return self._load()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._load())

    def __len__(self) -> int:
        return len(self._load())


def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    gateway: Gateway | None = None,
    streams: Streams | None = None,
) -> int:
    gateway = SystemGateway() if gateway is None else gateway
    streams = system_streams() if streams is None else streams
    gate = _SignalGate()
    if argv is None:
        reserve_std_fds()  # the process entry: before anything opens a descriptor
    # The process entry (no argv given: the console script and ``python -m``) leaves a no-op
    # handler installed after the run, so a signal while the process ends changes nothing;
    # in-process callers (tests) get the previous handlers back.
    process_entry = argv is None
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        # The handlers stay installed through the printing of the result: a signal before the
        # result print is 128+N with no output, one during or after it is ignored.
        with _exit_on_signal(gate, restore=not process_entry):
            code = _main(argv, env, gateway, streams, gate)
    except _Signalled as signalled:
        return 128 + signalled.number  # no envelope, no output, no log record
    if gate.fired is not None and not gate.committed:
        return 128 + gate.fired  # a _Signalled that cleanup swallowed must not be lost
    return code


def _main(
    argv: list[str],
    env: Mapping[str, str] | None,
    gateway: Gateway,
    streams: Streams,
    gate: _SignalGate,
) -> int:
    json_mode = json_requested(argv)
    holder: list[Context] = []
    outcome: _EarlyExit | CliError | None = None
    code = 0
    # Only Exception is caught: SystemExit, KeyboardInterrupt and ``_Signalled`` (a signal, see
    # ``_exit_on_signal``) pass straight through.
    try:
        # A real send reads the credential from the environment at step 5; a dry run never
        # does, so the copy is made on first access only.
        lazy_env = _LazyEnv(gateway) if env is None else env
        code = _run(argv, lazy_env, gateway, streams, holder, gate)
    except _EarlyExit as early:
        outcome = early
    except CliError as error:
        outcome, code = error, error.exit_code
    except Exception as exc:
        outcome = _internal_error(exc, gate_writing=bool(holder and holder[0].writing))
        code = 1
    output = holder[0].output if holder else Output(streams, verbose=False, quiet=False, gate=gate)
    try:
        if outcome is not None:
            _emit(output, outcome, json_mode=json_mode)
    except Exception as exc:
        # Printing failed before the result counted as printed: an internal error whose own
        # line is best effort.
        code = 1
        try:
            _emit(output, _internal_error(exc, gate_writing=False), json_mode=False)
        except Exception:
            pass
    output.finish()
    return code

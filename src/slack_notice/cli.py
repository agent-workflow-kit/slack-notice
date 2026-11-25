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
  never shown. No variable is read from the environment (``env`` is only carried for later
  issues; even the help width is fixed so argparse never reads ``COLUMNS``).
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
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, NoReturn, Protocol

from slack_notice import __version__
from slack_notice.config import (
    ConfigInvalid,
    HomeUnusable,
    config_file_key,
    load_config,
    resolve_home,
    validate_config,
)
from slack_notice.gateway import Gateway, SystemGateway
from slack_notice.log import StateDir
from slack_notice.payload import (
    FieldRefused,
    InputRefused,
    InputTimedOut,
    SourceUnusable,
    decode_notification,
    notification_from_flags,
    read_notification,
    validate_notification,
)

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

    def __init__(self, streams: Streams, *, verbose: bool, quiet: bool) -> None:
        self._streams = streams
        self._verbose = verbose
        self._quiet = quiet
        self._lenient = False

    def result_printed(self) -> None:
        """Called once step 6 is over: from here on a write failure is ignored."""
        self._lenient = True

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

    def info(self, line: str) -> None:
        """A human line that --quiet suppresses."""
        if not self._quiet:
            self.err(line + "\n")

    def warning(self, line: str) -> None:
        self.err(line + "\n")

    def error_line(self, line: str) -> None:
        self.err(line + "\n")

    def phase(self, name: str, elapsed_ms: int) -> None:
        """A --verbose line: the phase and its elapsed milliseconds, nothing else."""
        if self._verbose:
            self.err(f"{name}: {elapsed_ms} ms\n")

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
    verbose: bool
    quiet: bool
    config: str | None
    home: str | None  # None only for `send --dry-run --config`, which needs no home
    actor: str
    actor_source: str
    # TODO(#25): the deadline gate sets this when it moves to writing; exit 1 then reports
    # unknown_outcome true.
    gate_writing: bool = field(default=False)
    _state: StateDir | None = field(default=None, repr=False)

    def state_dir(self) -> StateDir:
        """The run's state directory handle (lazy: nothing is opened until a file is needed).

        Never called for ``send --dry-run --config`` (home is None, no state is used).
        """
        assert self.home is not None, "state directory requested without a home"
        # todo(#28): close the StateDir (with-scope or close()) when wiring send; call state_dir()
        # only after the dry-run exemption
        if self._state is None:
            self._state = StateDir(self.gateway, self.home, self.output.warning)
        return self._state


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
    text_flags = any(getattr(args, name) is not None for name in TEXT_FLAGS)
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


# --- dispatch ------------------------------------------------------------------------------------


def load_settings(ctx: Context) -> dict[str, Any]:
    """The effective settings: the config file and drop-ins over the defaults.

    No flag names a setting.

    A file that cannot be used is exit 2 config_invalid with the file path (or `--config` for a
    missing --config file) in details.key and a fixed message. A value that breaks a rule is the
    same error with the config key name (or `?`) in details.key and a message that names the key
    and the rule (never the value).
    """
    # TODO(#28), TODO(#31), TODO(#32): the send and validate handlers call this; they wire it in.
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
INPUT_TIMEOUT_MESSAGE = "input did not arrive before the deadline; nothing was sent"


def read_input(ctx: Context, remaining: float) -> dict[str, Any]:
    """Step 3, the reading half: one JSON source to a decoded object, or a CliError.

    The source is the file named by ``--file`` or, otherwise, stdin (``--file -`` included).
    ``remaining`` is the seconds left of the deadline, which starts at step 3. The caller
    never sees input text in an error.

    TODO(#28): the send handler calls this, starts the deadline and logs ``failed`` for the
    timeout error (a log record for exit 12 ``unavailable``, phase ``input``).
    TODO(#27): a signal during this call must exit 128+N; the handler has to raise or exit.
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
        error = CliError(
            12,
            "unavailable",
            INPUT_TIMEOUT_MESSAGE,
            details={"phase": "input"},
            retryable=True,
            unknown_outcome=False,
        )
    except SourceUnusable:
        error = usage_error(INPUT_FILE_MESSAGE)
    raise error  # raised outside the handlers: no __context__ (it would hold input text)


def load_notification(ctx: Context, remaining: float) -> dict[str, Any]:
    """Step 3: the validated notification from the one source in use, or a CliError.

    With --message the flags are the source and nothing is read (stdin included); otherwise one
    JSON source is read (``read_input``). Both go through ``validate_notification``, so a flag
    and a JSON field have the same rule and the same pointer (exit 20 ``invalid_payload``).
    The error holds a fixed message and the pointer, never an input value.

    TODO(#17), TODO(#18): the sanitizer, ``empty_message`` and the link rule come after this.
    TODO(#28): the send handler calls this after starting the deadline.
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


def _not_implemented(_ctx: Context) -> int:
    raise NotImplementedError


# TODO(#28): the send command. TODO(#31), TODO(#32): validate.
HANDLERS: dict[str, Callable[[Context], int]] = {
    "send": _not_implemented,
    "validate": _not_implemented,
}


def _internal_error(exc: Exception, *, gate_writing: bool) -> CliError:
    name = type(exc).__name__
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
) -> int:
    args = parse(argv)
    check_stdin_source(args, streams)
    home = _lookup_home(args, gateway)
    actor, actor_source = resolve_actor(args.actor, tty=streams.stdin_is_tty(), gateway=gateway)
    ctx = Context(
        args=args,
        env=env,
        gateway=gateway,
        output=Output(streams, verbose=args.verbose, quiet=args.quiet),
        json=json_requested(argv),
        dry_run=args.dry_run,
        verbose=args.verbose,
        quiet=args.quiet,
        config=args.config,
        home=home,
        actor=actor,
        actor_source=actor_source,
    )
    holder.append(ctx)
    return HANDLERS[args.command](ctx)


def _emit(output: Output, outcome: _EarlyExit | CliError, *, json_mode: bool) -> None:
    if isinstance(outcome, _EarlyExit):
        output.out(outcome.text)
        return
    # A CliError is the result: it counts as printed, so a failing stream never replaces its
    # exit code, and the envelope and the stderr line are each tried on their own.
    output.result_printed()
    if json_mode:
        output.json_document(outcome.envelope())
    output.error_line(outcome.stderr_line())


def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    gateway: Gateway | None = None,
    streams: Streams | None = None,
) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    gateway = SystemGateway() if gateway is None else gateway
    env = gateway.environ() if env is None else env
    streams = system_streams() if streams is None else streams
    json_mode = json_requested(argv)
    holder: list[Context] = []
    outcome: _EarlyExit | CliError | None = None
    code = 0
    # Only Exception is caught: SystemExit and KeyboardInterrupt (a signal) pass straight
    # through. TODO(#27): signal handlers that exit 128+N before step 5.
    try:
        code = _run(argv, env, gateway, streams, holder)
    except _EarlyExit as early:
        outcome = early
    except CliError as error:
        outcome, code = error, error.exit_code
    except Exception as exc:
        outcome = _internal_error(exc, gate_writing=bool(holder and holder[0].gate_writing))
        code = 1
    output = holder[0].output if holder else Output(streams, verbose=False, quiet=False)
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

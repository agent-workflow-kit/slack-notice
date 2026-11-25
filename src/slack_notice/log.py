"""State directory, log records and rotation.

``StateDir`` is the one handle through which the rest of the tool reaches the state directory
(interface, "Files"): lazy, one warning at most, never an exception for an unusable state.

Log records (interface, "Log"): ``build_record`` turns a finished ``send`` into one schema-shaped
dict (or ``None`` when that exit is not logged), allow-listing every field so that no input
text can reach the file; ``append_record`` writes it under the ``log.lock`` flock, rotating at
1 MiB. ``log_result`` is the one call the ``send`` command makes after the result was printed:
it never raises for a filesystem problem and never changes the exit code.

TODO(#28): the send command calls ``log_result`` after step 7's output and closes the StateDir.
TODO(#21): the send lock (spacing) uses ``StateDir.open_file("send.lock")``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Any

from slack_notice.gateway import Gateway, StateUnusable

# Fixed text: no path, no reason from the filesystem, nothing from hostile input.
STATE_WARNING = (
    "slack-notice: the state directory or a state file cannot be used safely; "
    "the log record or send spacing may be skipped"
)


class StateDir:
    """The state directory for one run.

    Nothing is touched until ``open_file`` is first called ("used only when needed"). When the
    directory or a file is unusable, ``open_file`` returns ``None`` and ``warn`` is called once
    for the whole run (never again, whichever file fails next); the caller then writes no log
    record and takes no lock, and its exit code is unchanged. Other errors (bugs) propagate.
    Descriptors returned by ``open_file`` belong to the caller; ``close`` releases the directory.
    """

    def __init__(self, gateway: Gateway, home: str, warn: Callable[[str], None]) -> None:
        self._gateway = gateway
        self._home = home
        self._warn = warn
        self._dir_fd: int | None = None
        self._dir_failed = False
        self._warned = False
        self._closed = False

    def __enter__(self) -> StateDir:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def warn(self) -> None:
        """The one fixed warning of the run (every later call, whatever the cause, is silent)."""
        if not self._warned:
            self._warned = True
            try:
                self._warn(STATE_WARNING)
            except (OSError, ValueError):
                pass  # a broken stderr never changes what open_file returns

    def open_file(self, name: str, *, append: bool = False) -> int | None:
        """A descriptor for ``name`` in the state directory, or ``None`` when unusable."""
        if self._dir_failed or self._closed:
            return None
        if self._dir_fd is None:
            try:
                self._dir_fd = self._gateway.open_state_dir(self._home)
            except StateUnusable:
                self._dir_failed = True
                self.warn()
                return None
        try:
            return self._gateway.open_state_file(self._dir_fd, name, append=append)
        except StateUnusable:
            self.warn()
            return None

    def rename(self, source: str, target: str) -> None:
        """Rename one state file over another inside the state directory (the log rotation).
        ``FileNotFoundError`` for a missing source; the directory must already be open."""
        if self._dir_fd is None or self._closed:
            raise FileNotFoundError(source)
        self._gateway.rename_state_file(self._dir_fd, source, target)

    def close(self) -> None:
        self._closed = True
        fd, self._dir_fd = self._dir_fd, None
        if fd is not None:
            self._gateway.close_fd(fd)


# --- log records ------------------------------------------------------------------------------

LOG_NAME = "log.jsonl"
LOCK_NAME = "log.lock"
ROTATE_AT = 1024 * 1024  # a log file of this size or more is rotated before the next record
KEEP = 3  # log.jsonl.1 to log.jsonl.3
LOCK_TIMEOUT_S = 1.0
LOCK_POLL_S = 0.02
MAX_WRITE = 1023  # one write of less than 1 KiB: record, LF and an optional repair LF

_SHA16 = re.compile(r"[0-9a-f]{16}\Z")
_ACTOR = re.compile(r"(human|auto):[A-Za-z0-9._@/-]{1,64}\Z")
_VERSION = re.compile(r"[0-9A-Za-z.+_-]{1,64}\Z")
_LEVELS = ("info", "warn", "action", "error")
_REFUSAL_REASONS = ("invalid_payload", "empty_message", "link_invalid", "link_scheme")
_FAILED_CODES = (
    "host_rejected",
    "auth_required",
    "credential_invalid",
    "rate_limited",
    "network_error",
    "unavailable",
    "wrong_host_response",
)
_UNKNOWN_CODES = ("outcome_unknown", "upstream_error", "wrong_host_response")
_NO_RESPONSE_CODES = ("credential_invalid", "unavailable", "network_error")
_MAX_WALL = 253402300799.0  # 9999-12-31T23:59:59Z (float precision ends there)


def hash16(data: bytes) -> str:
    """The first 16 hex characters of the SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()[:16]


def message_sha256(title: str | None, message: str) -> str:
    """Hash of the sanitized title (empty when absent), a LF and the sanitized message."""
    return hash16(f"{title or ''}\n{message}".encode())


def dedupe_key_sha256(key: str) -> str:
    return hash16(key.encode())


def format_ts(wall_time: float) -> str:
    """UTC ``YYYY-MM-DDTHH:MM:SS.mmmZ``. A clock that is NaN, negative or beyond year 9999 is
    clamped, so a broken clock still yields a well-formed timestamp."""
    if wall_time != wall_time:  # NaN
        wall_time = 0.0
    wall_time = min(max(wall_time, 0.0), _MAX_WALL)
    moment = datetime.fromtimestamp(wall_time, tz=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


_MAX_COUNT = 2**53 - 1  # the largest integer every JSON reader keeps exactly


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return min(max(value, 0), _MAX_COUNT)


def build_record(
    *,
    wall_time: float,
    version: str,
    exit_code: int,
    code: str | None,
    reason: str | None,
    unknown_outcome: bool,
    gate_writing: bool,
    level: str | None,
    bytes_: int | None,
    truncated: bool | None,
    duration_ms: int,
    http_status: int | None,
    message_hash: str | None,
    dedupe_hash: str | None,
    actor: str,
    actor_source: str,
) -> dict[str, Any] | None:
    """The log record for a finished ``send``, or ``None`` when that exit is not logged.

    Logged: exit 0 (``sent``), 20 (``refused``), 12 (``outcome_unknown`` when the envelope's
    ``unknown_outcome`` is true, else ``failed``) and exit 1 only when the gate had moved to
    writing (``outcome_unknown``, code ``internal``). Not logged: exit 1 before that, exit 2,
    exit 22, 128+N and anything else. Every value is allow-listed here (enums, fixed-shape
    hashes, integers), so text from the caller's input cannot reach the file.
    """
    if type(exit_code) is not int:
        raise ValueError("exit_code must be an integer")
    if type(duration_ms) is not int:
        raise ValueError("duration_ms must be an integer")
    if exit_code == 0:
        outcome, code, reason = "sent", None, None
    elif exit_code == 20:
        outcome, code = "refused", "refused"
        if reason not in _REFUSAL_REASONS:
            raise ValueError("a refusal needs one of the refusal reasons")
    elif exit_code == 12:
        if unknown_outcome:
            outcome, allowed = "outcome_unknown", _UNKNOWN_CODES
        else:
            outcome, allowed = "failed", _FAILED_CODES
        if code not in allowed:
            raise ValueError(f"code is not valid for outcome {outcome}")
        reason = None
    elif exit_code == 1 and gate_writing:
        outcome, code, reason = "outcome_unknown", "internal", None
    else:
        return None
    if code in _NO_RESPONSE_CODES + ("outcome_unknown",) or outcome == "refused":
        http_status = None
    status = _count(http_status)
    if status is not None and not 100 <= status <= 599:
        status = None
    if code == "upstream_error" and (status is None or status < 500):
        raise ValueError("upstream_error needs a status of 500 to 599")
    if code == "wrong_host_response":
        is_2xx = status is not None and 200 <= status <= 299
        if outcome == "failed" and (status is None or is_2xx):
            raise ValueError("a failed wrong_host_response needs a non-2xx status")
        if outcome == "outcome_unknown" and status is not None and not is_2xx:
            raise ValueError("an unknown wrong_host_response has no status or a 2xx one")
    if level not in _LEVELS:
        level = None
    if not isinstance(message_hash, str) or not _SHA16.match(message_hash):
        message_hash = None
    if not isinstance(dedupe_hash, str) or not _SHA16.match(dedupe_hash):
        dedupe_hash = None
    if not _ACTOR.match(actor) or actor_source not in ("flag", "tty", "default"):
        actor, actor_source = "auto:unknown", "default"
    if not _VERSION.match(version):
        version = "0.0.0+unknown"
    record: dict[str, Any] = {
        "ts": format_ts(wall_time),
        "tool": "slack-notice",
        "version": version,
        "outcome": outcome,
        "exit": exit_code,
        "code": code,
        "reason": reason,
        "level": level,
        "bytes": _count(bytes_),
        "truncated": truncated if isinstance(truncated, bool) else None,
        "duration_ms": _count(duration_ms),
        "http_status": status,
        "message_sha256": message_hash,
        "dedupe_key_sha256": dedupe_hash,
        "actor": actor,
        "actor_source": actor_source,
    }
    if outcome == "sent" and (
        None in (level, record["bytes"], record["truncated"], message_hash) or status != 200
    ):
        raise ValueError("a sent record needs level, bytes, truncated, message_sha256 and 200")
    return record


def encode_record(record: dict[str, Any]) -> bytes:
    """One line: compact JSON in field order, UTF-8, exactly one LF at the end."""
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    if len(line) > MAX_WRITE - 1:
        raise ValueError("log record too long")
    return line


def _acquire(gateway: Gateway, lock_fd: int) -> bool:
    """Poll the flock without blocking every 20 ms for at most 1 s."""
    deadline = gateway.monotonic() + LOCK_TIMEOUT_S
    while True:
        if gateway.try_lock(lock_fd):
            return True
        remaining = deadline - gateway.monotonic()
        if remaining <= 0:
            return False
        gateway.sleep(min(LOCK_POLL_S, remaining))


def _rotate(state: StateDir) -> None:
    """log.jsonl.2 to .3, .1 to .2, log.jsonl to .1; a missing source is skipped."""
    names = [LOG_NAME] + [f"{LOG_NAME}.{n}" for n in range(1, KEEP + 1)]
    for source, target in reversed(list(zip(names[:-1], names[1:], strict=True))):
        try:
            state.rename(source, target)
        except FileNotFoundError:
            continue


def append_record(state: StateDir, gateway: Gateway, record: dict[str, Any]) -> bool:
    """Append one record under the log lock; ``True`` when it was written.

    A state problem, a lock that is not obtained within 1 s and any ``OSError`` skip the record
    with the one fixed warning of the run. Nothing here raises for a filesystem problem.
    """
    try:
        line = encode_record(record)
        lock_fd = state.open_file(LOCK_NAME)
        if lock_fd is None:
            return False
        try:
            if not _acquire(gateway, lock_fd):
                state.warn()
                return False
            try:
                return _append_locked(state, gateway, line)
            finally:
                try:
                    gateway.unlock(lock_fd)
                except OSError:
                    pass  # closing the descriptor below releases the flock anyway
        finally:
            gateway.close_fd(lock_fd)
    except (OSError, ValueError):
        state.warn()
        return False


def _append_locked(state: StateDir, gateway: Gateway, line: bytes) -> bool:
    fd = state.open_file(LOG_NAME, append=True)
    if fd is None:
        return False
    try:
        size = gateway.file_size(fd)
        if size >= ROTATE_AT:
            gateway.close_fd(fd)
            fd = None
            _rotate(state)
            fd = state.open_file(LOG_NAME, append=True)  # a new file: never the rotated one
            if fd is None:
                return False
            size = gateway.file_size(fd)
        data = line
        if size > 0 and gateway.read_at(fd, 1, size - 1) != b"\n":
            data = b"\n" + line  # a torn last line: keep it apart from this record
        written = gateway.write_fd(fd, data)
        if written != len(data):
            try:
                gateway.truncate_fd(fd, size)  # drop the partial line (best effort)
            except OSError:
                pass
            state.warn()
            return False
        return True
    finally:
        if fd is not None:
            gateway.close_fd(fd)


def log_result(state: StateDir | None, gateway: Gateway, *, enabled: bool, **fields: Any) -> bool:
    """Build and append the record for a finished ``send``; ``True`` when one was written.

    ``enabled`` is the config ``log`` key: false writes nothing and never touches the state
    directory. ``fields`` are the keyword arguments of ``build_record`` except ``wall_time``,
    which is read from the gateway here. Never raises for a filesystem problem; a malformed
    call (a bug) is reported through the one warning and the record is skipped, because the
    log can never change the exit code.
    """
    if not enabled or state is None:
        return False
    try:
        record = build_record(wall_time=gateway.wall_time(), **fields)
    except Exception:  # a caller bug: warn, skip, never change the exit code
        state.warn()
        return False
    if record is None:
        return False
    try:
        return append_record(state, gateway, record)
    except Exception:
        state.warn()
        return False

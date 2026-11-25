"""URL allowlist, request, response mapping, retries and deadline.

This stage (#22) is the credential edge: the webhook URL is read from the one environment
variable the config names, through the injected environment mapping only, and validated whole by
a strict anchored pattern before anything is built from it. No URL parser is used. The value that
comes back holds only what the HTTP client needs (the fixed host and port and the path); the path
is the secret, so it is left out of every representation.

One send attempt (#23, ``post_once``): the TLS context comes from the gateway, the request is
written exactly once through the injected gateway connection, the response status and at most
4 KiB of body are read, the connection is closed on every path, and the facts come back as an
``AttemptResult`` (no exception object, no header, no host, no path). Mapping them to exit codes
is ``map_attempt`` (#24, below). The gate, the daemon worker and the hard exit are
``slack_notice.deadline`` (#25); retries are #26.

TODO(#26): implement retries.
TODO(#28): call ``read_webhook`` at send step 5 and map ``CredentialInvalid`` to exit 12
``credential_invalid`` with ``details.env``.
"""

from __future__ import annotations

import enum
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, NoReturn

from slack_notice import __version__
from slack_notice.gateway import (
    Connection,
    Gateway,
    NoUsableCA,
    is_cert_verification_error,
    is_malformed_response,
    is_timeout,
    is_tls_error,
)

HOST = "hooks.slack.com"
PORT = 443
INVALID_MESSAGE = "the webhook credential is unset or not a workflow trigger URL"

# A whole-string allowlist, ASCII only. Used with ``fullmatch`` (never ``$``, which accepts a
# trailing newline). The alphabet is spelled out, so ``\d`` and ``\w`` never come into play.
_PATH = re.compile(r"/triggers/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+){0,3}", re.ASCII)
_URL = re.compile(r"https://hooks\.slack\.com(?P<path>" + _PATH.pattern + ")", re.ASCII)
# Real trigger URLs are about 70 characters; the grammar alone would accept any length.
MAX_LENGTH = 1024
# Only ASCII whitespace is trimmed: any other character at an edge fails the match.
_TRIM = " \t\n\r\x0b\x0c"


class CredentialInvalid(Exception):  # noqa: N818
    """The credential is unset, empty or not a workflow-trigger URL. Exit 12
    ``credential_invalid`` with ``details.env``. Holds the variable name (from the config, never
    the value); ``str()`` is a fixed message. ``read_webhook`` raises it outside any ``except``
    block, so it has no ``__cause__`` and no ``__context__`` (unless a caller raises it from
    inside its own handler)."""

    def __init__(self, env: str) -> None:
        super().__init__(INVALID_MESSAGE)
        self.env = env


class Webhook:
    """A validated destination. ``path`` is the secret. It is kept in a slot (no ``__dict__``),
    left out of ``repr`` (so of ``str``, ``format`` and pytest's failure output), and the object
    cannot be pickled or copied (``__reduce__``, ``__reduce_ex__`` and ``__getstate__`` raise),
    cannot be re-initialised (calling ``__init__`` again raises ``AttributeError``) and is not a
    dataclass (no ``asdict``).
    ``host`` and ``port`` are fixed class constants, not constructor arguments. The constructor
    re-validates the path against the path part of the grammar."""

    __slots__ = ("_path",)
    host = HOST
    port = PORT

    def __init__(self, path: str) -> None:
        # The check runs without an except block, so the error holds no context and no value.
        if type(path) is not str or _PATH.fullmatch(path) is None:
            raise ValueError("not a workflow trigger path")
        try:
            object.__getattribute__(self, "_path")
        except AttributeError:
            object.__setattr__(self, "_path", path)
        else:
            raise AttributeError("Webhook is immutable")

    @property
    def path(self) -> str:
        return self._path

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Webhook is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Webhook is immutable")

    def __repr__(self) -> str:
        return f"Webhook(host={self.host!r}, port={self.port!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Webhook):
            return NotImplemented
        return self._path == other._path

    def __hash__(self) -> int:
        return hash(self._path)

    def __getstate__(self) -> NoReturn:
        raise TypeError("Webhook cannot be pickled or copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Webhook cannot be pickled or copied")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise TypeError("Webhook cannot be pickled or copied")


def read_webhook(env: Mapping[str, str], name: str) -> Webhook:
    """Read the variable ``name`` from ``env`` and validate it whole; raise ``CredentialInvalid``.

    Only the one key is read. The value is never put in an exception, a message or a log. Every
    failure is raised outside an ``except`` block, so no ``__context__`` keeps a hostile
    mapping's exception (which may hold the text).
    """
    value: object = None
    lookup_failed = False
    try:
        value = env[name]
    except Exception:
        lookup_failed = True
    if lookup_failed or type(value) is not str:
        raise CredentialInvalid(name)
    trimmed = value.strip(_TRIM)
    if not trimmed or len(trimmed) > MAX_LENGTH:
        raise CredentialInvalid(name)
    match = _URL.fullmatch(trimmed)
    if match is None:
        raise CredentialInvalid(name)
    return Webhook(path=match.group("path"))


# --- one attempt (issue #23) ------------------------------

CHUNK = 1024  # interface, "Webhook edge": response chunks of at most 1 KiB
BODY_CAP = 4096  # ... up to a cap of 4 KiB
MIN_OP_TIMEOUT = 0.001  # the floor of a derived per-operation timeout (0 would be non-blocking)
_CLASS_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}", re.ASCII)


class Phase(enum.Enum):
    """The last stage an attempt entered. ``CONNECT``: name resolution, TCP and TLS (nothing was
    written). ``WRITE``: the request was being written. ``READ``: the response was awaited or
    read. The deadline gate of #25 moves to writing at the start of ``WRITE``."""

    CONNECT = "connect"
    WRITE = "write"
    READ = "read"


@dataclass(frozen=True)
class Failure:
    """What the attempt knows about a failure, by exception class only: the exception itself is
    dropped because the text of ``http.client``, ``ssl`` and ``socket`` errors can quote the
    request target. ``error_class`` is the class name (``Exception`` when it is not a plain
    identifier)."""

    error_class: str
    timeout: bool
    tls: bool
    cert_verification: bool
    malformed: bool
    no_usable_ca: bool


@dataclass(frozen=True)
class AttemptResult:
    """Raw facts of one attempt. ``status`` is None until a status line was read; ``body`` is at
    most ``BODY_CAP`` bytes; ``body_too_long``: more than the cap was available (``body`` is cut).
    ``failure`` is None for a complete response. ``abandoned``: ``before_write`` refused, so
    nothing was written. Not UTF-8 decoded or parsed here (#24)."""

    phase: Phase
    status: int | None = None
    body: bytes = field(default=b"", repr=False)
    body_too_long: bool = False
    failure: Failure | None = None
    abandoned: bool = False


def class_name(exc: BaseException) -> str:
    """The class name of ``exc`` when it is a plain identifier, else ``Exception``; always an exact
    ``str``. ``__name__`` can be a ``str`` subclass instance: unbound ``str``/``bytes`` methods
    are used so that nothing of the subclass runs or is stored."""
    try:
        name = bytes.decode(str.encode(type(exc).__name__, "ascii"), "ascii")
    except Exception:
        return "Exception"
    return name if _CLASS_NAME.fullmatch(name) else "Exception"


def _failure(exc: Exception) -> Failure:
    return Failure(
        error_class=class_name(exc),
        timeout=is_timeout(exc),
        tls=is_tls_error(exc),
        cert_verification=is_cert_verification_error(exc),
        malformed=is_malformed_response(exc),
        no_usable_ca=isinstance(exc, NoUsableCA),
    )


def post_once(
    gateway: Gateway,
    target: Webhook,
    body: bytes,
    *,
    timeout: float,
    before_write: Callable[[], bool] | None = None,
    remaining: Callable[[], float] | None = None,
) -> AttemptResult:
    """Make exactly one POST attempt and report what happened; never retry, never follow.

    ``timeout`` is the per-operation socket timeout. ``remaining`` (seconds left to the deadline)
    derives each operation's timeout as the smaller of ``timeout`` and the time left (never zero:
    a tiny positive value, so that an expired deadline fails the operation at once instead of
    making the socket non-blocking); without it ``timeout`` is fixed. A per-operation timeout
    cannot bound the whole attempt (a peer that trickles resets it, and a will-close response owns
    its socket), so the caller's deadline never depends on this function returning.
    ``before_write`` is the seam for the
    deadline gate: called after connect and before the first call that can put bytes on the
    socket; ``False`` abandons the attempt (nothing written, ``abandoned`` true). An exception
    raised by ``before_write`` is a bug in the gate, not a connect failure: it propagates after
    the connection is closed and nothing is written (exit 1, internal error; the worker of #25
    catches ``BaseException``).
    A failure is returned, not raised, whatever its class (the phase decides its meaning); only
    ``BaseException`` that is not an ``Exception`` (an interrupt) propagates, after the close.

    The path is the secret: it is passed to the gateway as the request target and nowhere else.
    """

    # The worker running this may spin until the deadline (an endless 1xx or chunk trailer stream
    # is not capped here): ``slack_notice.deadline`` bounds it by the deadline and the hard exit
    # and never depends on this function's cooperation.
    def op_timeout() -> float:
        if remaining is None:
            return timeout
        left = remaining()
        if not left > 0:  # zero, negative, NaN
            return MIN_OP_TIMEOUT
        return max(min(timeout, left), MIN_OP_TIMEOUT)

    phase = Phase.CONNECT
    connection: Connection | None = None
    status: int | None = None
    chunks: list[bytes] = []
    too_long = False
    failure: Failure | None = None
    abandoned = False
    try:
        try:
            context = gateway.tls_context()
            connection = gateway.https_connection(
                target.host,
                target.port,
                timeout=op_timeout(),
                context=context,
                user_agent=f"slack-notice/{__version__}",
            )
            connection.connect()
        except Exception as exc:
            failure = _failure(exc)
        # Outside the ``except``: a bug in the gate is not a connect failure and propagates.
        if failure is None and connection is not None:
            if before_write is not None and not before_write():
                abandoned = True
            else:
                try:
                    phase = Phase.WRITE
                    if remaining is not None:
                        connection.settimeout(op_timeout())
                    connection.post(target.path, body)
                    phase = Phase.READ
                    if remaining is not None:
                        connection.settimeout(op_timeout())
                    response = connection.getresponse()
                    status = response.status
                    total = 0
                    while True:
                        if remaining is not None:
                            connection.settimeout(op_timeout())
                        chunk = response.read(min(CHUNK, BODY_CAP + 1 - total))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > BODY_CAP:
                            too_long = True
                            break
                except Exception as exc:
                    failure = _failure(exc)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    data = b"".join(chunks)[:BODY_CAP]
    return AttemptResult(phase, status, data, too_long, failure, abandoned)


# --- response mapping and the exception phase rule (issue #24) ------------------------------

_HOST_ERROR = re.compile(r"[a-z_]{1,64}", re.ASCII)
_UNAVAILABLE_PHASES = ("input", "lock")
_MAX_STATUS = 599


class Retry(enum.Enum):
    """What a retry loop (#26) may do with an outcome. The counters and waits are not here:
    ``RATE_LIMIT`` is a 429 (nothing was accepted); ``CONNECTION`` is a failure while the gate was
    idle that is not a certificate failure (``details.tls`` may still be true: a handshake failure
    is retried once, and the envelope that ends the send then says ``retryable`` false)."""

    NONE = "none"
    RATE_LIMIT = "rate_limit"
    CONNECTION = "connection"


@dataclass(frozen=True)
class Outcome:
    """The result of one attempt, with exactly the fields the envelope and the log record need.

    ``exit_code`` is 0 (``sent``, ``code`` None) or 12. ``message`` is a fixed string. Nothing
    network-derived is stored except ``details["host_error"]`` (a 400 key that matched
    ``[a-z_]{1,64}``) and the integer status. ``retry_after_s`` is set by the retry loop (#26)
    on ``rate_limited`` with ``with_retry_after``; the server's Retry-After is never read.
    """

    exit_code: int
    code: str | None
    message: str
    http_status: int | None
    retryable: bool | None
    unknown_outcome: bool
    details: dict[str, Any] | None = None
    retry_after_s: float | None = None
    retry: Retry = Retry.NONE

    def with_retry_after(self, seconds: float) -> Outcome:
        if self.code != "rate_limited":
            raise ValueError("retry_after_s belongs to rate_limited only")
        ok = type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0
        if not ok:
            raise ValueError("retry_after_s must be a finite number of seconds, not negative")
        return replace(self, retry_after_s=float(seconds))

    def _require_wait(self) -> None:
        # Both schemas hold a number for rate_limited, never null: the loop (#26) must set it.
        if self.code == "rate_limited" and self.retry_after_s is None:
            raise ValueError("rate_limited needs retry_after_s (with_retry_after)")

    def envelope(self) -> dict[str, Any]:
        """The error envelope (every key present); for exit 12 only."""
        if self.exit_code != 12 or self.code is None:
            raise ValueError("only a failure has an error envelope")
        self._require_wait()
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "reason": None,
                "details": None if self.details is None else dict(self.details),
                "retryable": self.retryable,
                "retry_after_s": self.retry_after_s,
                "unknown_outcome": self.unknown_outcome,
            }
        }

    def log_fields(self) -> dict[str, Any]:
        """The keyword arguments of ``log.build_record`` that this outcome decides."""
        self._require_wait()
        return {
            "exit_code": self.exit_code,
            "code": self.code,
            "reason": None,
            "unknown_outcome": self.unknown_outcome,
            "http_status": self.http_status,
        }


def _failed(
    code: str,
    message: str,
    *,
    retryable: bool,
    unknown: bool,
    details: dict[str, Any] | None = None,
    http_status: int | None = None,
    retry: Retry = Retry.NONE,
) -> Outcome:
    return Outcome(12, code, message, http_status, retryable, unknown, details, None, retry)


def credential_invalid(env: str) -> Outcome:
    """Exit 12 ``credential_invalid`` (no response: ``http_status`` null in the log)."""
    return _failed(
        "credential_invalid", INVALID_MESSAGE, retryable=False, unknown=False, details={"env": env}
    )


def unavailable(phase: str) -> Outcome:
    """Exit 12 ``unavailable``: the input read (``input``) or the lock wait (``lock``) outlasted
    the deadline; nothing was sent."""
    if type(phase) is not str or phase not in _UNAVAILABLE_PHASES:
        raise ValueError("unavailable has the phase input or lock")
    return _failed(
        "unavailable",
        "the deadline passed before anything was sent",
        retryable=True,
        unknown=False,
        details={"phase": phase},
    )


def outcome_unknown() -> Outcome:
    """Exit 12 ``outcome_unknown``: the gate was writing and no complete answer arrived."""
    return _failed(
        "outcome_unknown",
        "the request was sent but no complete answer arrived; it may have been delivered",
        retryable=False,
        unknown=True,
    )


def network_error(*, tls: bool, timeout: bool, no_usable_ca: bool = False) -> Outcome:
    """Exit 12 ``network_error``: the gate was idle, nothing was written. ``tls`` true is not
    retryable (the envelope rule); ``retry`` is for the caller's own loop and is NONE here."""
    if no_usable_ca:
        message = "no usable CA certificates were found"
    elif tls:
        message = "the TLS connection to the host failed"
    elif timeout:
        message = "the connection to the host timed out"
    else:
        message = "the connection to the host failed"
    return _failed(
        "network_error",
        message,
        retryable=not tls,
        unknown=False,
        details={"tls": tls, "timeout": timeout},
    )


def _parse_body(body: bytes, too_long: bool) -> dict[str, Any] | None:
    """The body as a JSON object, or None for a bad body: longer than the cap, not strict UTF-8
    (a byte order mark is a character JSON refuses), a duplicate key at any depth, NaN or
    Infinity, nesting that exhausts the parser, a number it refuses, trailing text, or a value
    that is not an object. Iterative limits are the parser's own; the body is at most 4 KiB."""
    if too_long or len(body) > BODY_CAP:
        return None
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None

    def no_constant(_: str) -> NoReturn:
        raise ValueError("constant")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(text, parse_constant=no_constant, object_pairs_hook=no_duplicates)
    except (ValueError, RecursionError, OverflowError):
        return None
    return value if isinstance(value, dict) else None


def _host_error(attempt: AttemptResult) -> str | None:
    parsed = _parse_body(attempt.body, attempt.body_too_long)
    if parsed is None:
        return None
    value = parsed.get("error")
    if type(value) is str and _HOST_ERROR.fullmatch(value) is not None:
        return value
    return None


def _from_failure(failure: Failure, *, writing: bool) -> Outcome:
    if not writing:
        # Gate idle: nothing was written, whatever the exception was.
        tls = failure.tls or failure.cert_verification or failure.no_usable_ca
        base = network_error(tls=tls, timeout=failure.timeout, no_usable_ca=failure.no_usable_ca)
        no_retry = failure.cert_verification or failure.no_usable_ca
        return replace(base, retry=Retry.NONE if no_retry else Retry.CONNECTION)
    if failure.malformed:
        return _wrong_host_response(None, "the host answer was not valid HTTP", unknown=True)
    return outcome_unknown()


def _wrong_host_response(status: int | None, message: str, *, unknown: bool) -> Outcome:
    return _failed(
        "wrong_host_response",
        message,
        retryable=False,
        unknown=unknown,
        details=None if status is None else {"http_status": status},
        http_status=status,
    )


def map_attempt(attempt: AttemptResult, *, gate_writing: bool) -> Outcome:
    """Map one attempt to an ``Outcome``: the Webhook edge table of the interface.

    ``gate_writing`` is the state of the deadline gate (#25). The phase of a failure is that
    state alone; a contradiction with ``attempt.phase`` (the attempt wrote, or the gate moved to
    writing and the attempt says it never wrote) is resolved as writing, the reading that never
    claims ``unknown_outcome`` false after a write. A failure is judged before any status: when
    ``failure`` is set the status is ignored. After the gate is writing, anything that is not a
    complete answer of a defined class (a status below 200 or above 599 included)
    has ``unknown_outcome`` true. Only integers, fixed messages and the one ``host_error``
    pattern leave this function; the exception, its text and the body are never kept.
    """
    if attempt.abandoned:
        if gate_writing or attempt.phase is not Phase.CONNECT or attempt.failure is not None:
            raise ValueError("an abandoned attempt wrote nothing")
        return network_error(tls=False, timeout=True)
    writing = gate_writing or attempt.phase is not Phase.CONNECT
    if attempt.failure is not None:
        return _from_failure(attempt.failure, writing=writing)
    status = attempt.status
    if type(status) is not int:
        raise ValueError("an attempt with no failure has a status")
    if not writing:
        raise ValueError("a response cannot arrive before the gate is writing")
    if not 200 <= status <= _MAX_STATUS:
        return _wrong_host_response(None, "the host answered with an unusable status", unknown=True)
    if 200 <= status <= 299:
        parsed = _parse_body(attempt.body, attempt.body_too_long) if status == 200 else None
        if parsed is not None and parsed.get("ok") is True:
            return Outcome(0, None, "sent", 200, None, False)
        return _wrong_host_response(
            status, "the host accepted the request but did not confirm it", unknown=True
        )
    if status == 400:
        return _failed(
            "host_rejected",
            "the host rejected the request",
            retryable=False,
            unknown=False,
            details={"host_error": _host_error(attempt), "http_status": 400},
            http_status=400,
        )
    if status in (401, 403, 404, 410):
        return _failed(
            "auth_required",
            "the host refused the credential; regenerate the workflow trigger URL",
            retryable=False,
            unknown=False,
            details={"http_status": status},
            http_status=status,
        )
    if status == 429:
        return _failed(
            "rate_limited",
            "the host is rate limiting requests",
            retryable=True,
            unknown=False,
            details={"http_status": 429},
            http_status=429,
            retry=Retry.RATE_LIMIT,
        )
    if status >= 500:
        return _failed(
            "upstream_error",
            "the host reported a server error; the notification may have been delivered",
            retryable=False,
            unknown=True,
            details={"http_status": status},
            http_status=status,
        )
    return _wrong_host_response(
        status, "the host answered with an unexpected status", unknown=False
    )

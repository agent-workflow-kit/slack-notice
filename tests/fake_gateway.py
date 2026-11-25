"""A fake ``Gateway`` for in-process process tests (issue #5).

``cli.main(argv, env, gateway)`` runs against a ``FakeGateway``: no socket, no name resolution,
no password-database lookup and no wall-clock wait. There is no test-only environment seam.

What it models, and how it stays faithful to ``slack_notice.gateway``:

- Time is the real monotonic clock plus a skew. ``sleep`` and every scripted delay advance the
  skew instead of waiting, so a retry wait or a 30 s stall costs no real time while deadline
  arithmetic, ``read_source`` slices and worker threads still see consistent, monotonic time.
- Socket timeouts are per operation, as in ``http.client``: an operation (connect, TLS
  handshake, first byte, each byte of a trickle) that takes longer than the connection's current
  timeout spends exactly that timeout and raises ``TimeoutError``. A trickle of many short
  intervals is *not* a timeout however long the total is (design D-11). Name resolution is not
  covered by a socket timeout: a stalled resolution blocks until ``release_stalls()``.
- The connection enforces the call order of the interface (``connect`` before ``post``), the
  ``http.client`` state errors (``CannotSendRequest``, ``ResponseNotReady``) and the real
  ``post`` path check (a path ``http.client`` would refuse is ``InvalidURL("invalid request")``
  with no cause and no path in the message).
- The response exposes only ``status`` and ``read``; a body shorter than its declared length
  raises ``IncompleteRead`` exactly where the real wrapper does (checked against the real
  ``http.client`` in the contract tests).
- State files, locks, ``read_regular_file``, ``list_directory`` and ``read_source`` are the real
  implementations (inherited) running on the files a test creates under its private home, so
  hostile paths (symlink, FIFO, wrong owner) behave as in production. Hooks can inject failures.
- ``home_dir``, ``uid`` and ``login_name`` are supplied here; ``pwd`` is never consulted.
  ``is_directory`` is the real check unless ``home_is_directory`` scripts its answer.
- Name resolution inside ``connect()`` is driven by ``Attempt.resolve_stall``,
  ``Attempt.resolve_error`` and ``Attempt.stall_then_proceed`` only. ``Gateway.resolve`` is a
  scripted protocol hook (``resolve_addresses``, ``resolve_error``) that the real connection
  never calls, so those two attributes have no effect on ``connect()``. Multi-address
  resolution (trying the next address) is not modelled.
- ``sleep`` returns at once in real time: a real thread that holds a lock while another
  thread "sleeps" sees the poll loop spin through the whole wait in microseconds. A stalled
  resolution costs up to ``stall_cap_seconds`` (30 s) of real time unless released, and
  advances no skew.
- Contract violations by the code under test (a ``post`` before ``connect``, another host or
  port, a context that does not verify, an exhausted script, ...) are recorded in
  ``violations`` before the ``AssertionError`` is raised, because that error is swallowed by
  a worker thread's catch-all and would otherwise only show up as an exit 1. The
  ``fake_gateway`` fixture asserts at teardown that ``violations`` is empty and that the
  script was consumed (``allow_unconsumed_script`` opts out of the second).

Unverified against a real Slack host (see the issue report): everything about what Slack sends
(real status line and header shapes, how a real 429 or 5xx body looks, connection reuse), and the
exact ``http.client`` and ``ssl`` exception classes and messages for a given network event beyond
the ones the contract tests compare with the standard library.
"""

from __future__ import annotations

import http.client
import math
import os
import re
import ssl
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from slack_notice.gateway import (
    CA_FALLBACK_FILES,
    CaCandidates,
    HomeLookupError,
    NoUsableCA,
    SourceRead,
    SystemGateway,
    _is_dir,  # pyright: ignore[reportPrivateUsage]
    _is_usable_bundle,  # pyright: ignore[reportPrivateUsage]
)

WEBHOOK_HOST = "hooks.slack.com"
WEBHOOK_PORT = 443

# http.client refuses these in a request target (``_contains_disallowed_url_pchar_re``).
_DISALLOWED_PATH_CHARS = re.compile(r"[\x00-\x20\x7f]")
# http.client refuses these in a header value (``_is_illegal_header_value``).
_ILLEGAL_HEADER_VALUE = re.compile(r"\n(?![ \t])|\r(?![ \t\n])")

HANDSHAKE_TIMEOUT_MESSAGE = "_ssl.c:1011: The handshake operation timed out"


def _ssl_error(
    cls: type[ssl.SSLError], code: int, reason: str, text: str, *, library: str = "SSL"
) -> ssl.SSLError:
    error = cls(code, f"[{library}: {reason}] {text} (_ssl.c:1028)")
    error.library = library
    error.reason = reason
    return error


def cert_verify_error() -> ssl.SSLCertVerificationError:
    """What a failed certificate or host name check raises (shape of a real one)."""
    error = _ssl_error(
        ssl.SSLCertVerificationError,
        1,
        "CERTIFICATE_VERIFY_FAILED",
        "certificate verify failed: unable to get local issuer certificate",
    )
    assert isinstance(error, ssl.SSLCertVerificationError)
    error.verify_code = 20
    error.verify_message = "unable to get local issuer certificate"
    return error


def handshake_error() -> ssl.SSLError:
    """A TLS failure that is not a certificate verification failure."""
    return _ssl_error(
        ssl.SSLError, 1, "SSLV3_ALERT_HANDSHAKE_FAILURE", "sslv3 alert handshake failure"
    )


def ssl_eof_error() -> ssl.SSLEOFError:
    """The peer closed the connection without a TLS close_notify."""
    error = _ssl_error(
        ssl.SSLEOFError, 8, "UNEXPECTED_EOF_WHILE_READING", "EOF occurred in violation of protocol"
    )
    assert isinstance(error, ssl.SSLEOFError)
    return error


def ssl_wrong_version() -> ssl.SSLError:
    """The peer answered the ClientHello with something that is not TLS (plain HTTP, say).

    Python 3.12 reports reason ``WRONG_VERSION_NUMBER``; 3.13 reports a "record layer failure"
    with no reason. Only the class and the library are the same in both.
    """
    return _ssl_error(ssl.SSLError, 1, "WRONG_VERSION_NUMBER", "wrong version number")


def tls_broken_pipe() -> BrokenPipeError:
    """The peer was already gone when the ClientHello was written."""
    return BrokenPipeError(32, "Broken pipe")


def handshake_timeout() -> TimeoutError:
    """The handshake did not finish within the socket timeout (not an ``SSLError``)."""
    return TimeoutError(HANDSHAKE_TIMEOUT_MESSAGE)


def _validate_socket_timeout(seconds: object) -> None:
    """The checks ``socket.settimeout`` makes."""
    if seconds is None:
        return
    if not isinstance(seconds, int | float):
        raise TypeError("Timeout value must be a float or None")
    if isinstance(seconds, float) and math.isnan(seconds):
        raise ValueError("Invalid value NaN (not a number)")
    if isinstance(seconds, float) and math.isinf(seconds):
        raise OverflowError("timestamp too large to convert to C _PyTime_t")
    if seconds < 0:
        raise ValueError("Timeout value out of range")


_FRAMINGS = ("length", "chunked", "eof")


@dataclass(frozen=True)
class Reply:
    """A complete or partial HTTP answer.

    ``truncated_by``: the declared length exceeds the bytes that arrive by this many.
    ``first_byte_delay``: seconds before any byte arrives. ``head_trickle`` / ``body_trickle``:
    seconds between bytes of the status line and headers / of the body. ``head_stall_after`` /
    ``body_stall_after``: bytes delivered before the host goes silent (1 is "a stall after the
    first byte"); a body stall point is below the declared total (``len(body) + truncated_by``)
    and at most ``len(body)`` (bytes beyond it never arrive, so the end event comes first).
    ``body_error`` is raised from the read that needs a body byte past ``body_error_after``
    (a reset or TLS failure in mid-body; at most ``len(body)``); later reads end as an
    ``IncompleteRead``.

    ``framing``: ``length`` (Content-Length, a short body is an ``IncompleteRead``), ``chunked``
    (a short body is an ``IncompleteRead`` with no partial data on the read that needs the
    missing byte, as in ``http.client``) or ``eof`` (the body ends where the connection does: a
    truncation cannot be detected and reads simply end).

    Statuses below 200 and above 999 are refused (``http.client`` skips 100 and returns an empty
    body for the other 1xx); 204 and 304 carry no body (``http.client`` forces length 0).
    """

    status: int = 200
    body: bytes = b'{"ok":true}'
    truncated_by: int = 0
    first_byte_delay: float = 0.0
    head_trickle: float | None = None
    head_stall_after: int | None = None
    body_trickle: float | None = None
    body_stall_after: int | None = None
    framing: str = "length"
    body_error: BaseException | None = None
    body_error_after: int = 0

    def __post_init__(self) -> None:
        total = len(self.body) + self.truncated_by
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            raise ValueError("status must be an int")
        if not 200 <= self.status <= 999:
            raise ValueError(f"status {self.status} is outside 200..999")
        if self.status in (204, 304) and total:
            raise ValueError(f"status {self.status} has no body")
        if self.truncated_by < 0:
            raise ValueError("truncated_by must not be negative")
        if self.framing not in _FRAMINGS:
            raise ValueError(f"framing must be one of {_FRAMINGS}")
        if self.body_stall_after is not None and not 0 <= self.body_stall_after < total:
            raise ValueError("body_stall_after must be within 0 .. declared total - 1")
        if self.body_stall_after is not None and self.body_stall_after > len(self.body):
            raise ValueError("body_stall_after must not exceed len(body): later bytes never arrive")
        if self.head_stall_after is not None and self.head_stall_after < 0:
            raise ValueError("head_stall_after must not be negative")
        if self.body_error is not None and not 0 <= self.body_error_after < total:
            raise ValueError("body_error_after must be within 0 .. declared total - 1")
        if self.body_error is not None and self.body_error_after > len(self.body):
            raise ValueError("body_error_after must not exceed len(body): later bytes never arrive")


@dataclass(frozen=True)
class Attempt:
    """What one connection (one send attempt) does, in protocol order.

    Phases: ``resolve_*`` and ``connect_*`` and ``tls_*`` happen in ``connect()`` (gate idle);
    ``write_delay`` and ``write_error`` in ``post()``; ``reply`` in ``getresponse()``/``read()``.
    A ``reply`` that is an exception is raised by ``getresponse()`` after the request was
    written (the post-write failure). Exceptions are raised as given, so a test can carry a
    fake secret in one.

    ``resolve_stall``: name resolution blocks until ``release_stalls()`` and then fails with
    ``OSError``; with ``stall_then_proceed`` it continues into the connect instead.
    ``write_delay``: seconds the write takes under the socket timeout (``TimeoutError`` when
    longer), spent before ``write_error`` is raised.
    """

    resolve_stall: bool = False
    stall_then_proceed: bool = False
    resolve_error: BaseException | None = None
    connect_delay: float = 0.0
    connect_error: BaseException | None = None
    tls_delay: float = 0.0
    tls_error: BaseException | None = None
    write_delay: float = 0.0
    write_error: BaseException | None = None
    request_delivered_on_write_error: bool = False
    reply: Reply | BaseException = field(default_factory=Reply)


class FakeResponse:
    """Only ``status`` and ``read`` are public, as in the ``Response`` protocol.

    The socket timeout is the one in force when ``getresponse()`` returned: with
    ``Connection: close`` ``http.client`` hands the socket to the response, so a later
    ``Connection.settimeout`` does not reach it.
    """

    def __init__(self, gateway: FakeGateway, timeout: float | None, reply: Reply) -> None:
        self._gateway = gateway
        self._timeout = timeout
        self._reply = reply
        self._pos = 0
        self._timed_out = False
        self._broken = False

    @property
    def status(self) -> int:
        return self._reply.status

    def _event(self) -> tuple[int, str]:
        """Where the wire stops delivering body bytes, and why (error, stall, then end)."""
        reply = self._reply
        candidates = [(len(reply.body), 2, "eof")]
        if reply.body_stall_after is not None:
            candidates.append((reply.body_stall_after, 1, "stall"))
        if reply.body_error is not None:
            candidates.append((reply.body_error_after, 0, "error"))
        position, _, kind = min(candidates)
        return position, kind

    def read(self, amount: int) -> bytes:
        reply = self._reply
        self._gateway._record("read")
        if self._timed_out:
            raise OSError("cannot read from timed out object")
        declared_left = len(reply.body) + reply.truncated_by - self._pos
        if self._broken:
            if reply.framing == "eof":
                return b""
            raise http.client.IncompleteRead(
                b"", *(() if reply.framing == "chunked" else (declared_left,))
            )
        # http.client caps the request at the declared length, and the buffered reader then
        # blocks until that many bytes arrive or the stream ends.
        want = max(0, min(amount, declared_left))
        if want == 0:
            return b""
        stop, kind = self._event()
        reach = max(0, stop - self._pos)
        try:
            for _ in range(min(want, reach)):
                if reply.body_trickle:
                    self._gateway._spend(self._timeout, reply.body_trickle)
        except TimeoutError:
            self._timed_out = True
            raise
        if want <= reach:
            data = reply.body[self._pos : self._pos + want]
            self._pos += want
            return data
        if kind == "error":
            assert reply.body_error is not None
            self._broken = True
            raise reply.body_error
        if kind == "stall":
            self._timed_out = True
            self._gateway._stall_silently(self._timeout)
        # the connection ended before the declared length
        if reply.framing == "chunked":
            self._broken = True
            raise http.client.IncompleteRead(b"")
        data = reply.body[self._pos : self._pos + reach]
        self._pos += len(data)
        if reply.framing == "length" and not data:
            raise http.client.IncompleteRead(b"", declared_left)
        return data


class FakeConnection:
    """One scripted send attempt; implements the ``Connection`` protocol.

    ``state`` follows ``http.client``: ``Idle``, ``Request-started`` (a request began but its
    path or headers were refused, or it is being written) and ``Request-sent``.
    """

    def __init__(
        self,
        gateway: FakeGateway,
        attempt: Attempt,
        host: str,
        port: int,
        timeout: float,
        user_agent: str,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.user_agent = user_agent
        self.requests: list[tuple[str, bytes]] = []
        self.closed = False
        self.delivered = False
        self.state = "Idle"
        self._gateway = gateway
        self._attempt = attempt
        self._connected = False
        self._responded = False

    # -- time --

    def _spend(self, seconds: float, message: str = "timed out") -> None:
        self._gateway._spend(self.timeout, seconds, message)

    # -- Connection protocol ----------------------------------------------------------------

    def connect(self) -> None:
        self._gateway._record("connect")
        attempt = self._attempt
        if attempt.resolve_stall:
            self._gateway._block_until_released(proceed=attempt.stall_then_proceed)
        if attempt.resolve_error is not None:
            raise attempt.resolve_error
        self._spend(attempt.connect_delay)
        if attempt.connect_error is not None:
            raise attempt.connect_error
        self._spend(attempt.tls_delay, HANDSHAKE_TIMEOUT_MESSAGE)
        if attempt.tls_error is not None:
            raise attempt.tls_error
        self._connected = True

    def _write_failed(self, path: str, body: bytes) -> None:
        if self._attempt.request_delivered_on_write_error:
            self.delivered = True
            self.requests.append((path, body))

    def post(self, path: str, body: bytes) -> None:
        gateway = self._gateway
        gateway._record("post")
        if self.closed:
            gateway._violation("post() on a closed connection")
        if not self._connected:
            gateway._violation("post() before connect(): the interface connects first")
        if self._responded:
            gateway._violation("post() after getresponse(): one connection, one request")
        if not isinstance(body, bytes):
            raise TypeError("body must be bytes")
        if self.state != "Idle":
            raise http.client.CannotSendRequest(self.state)
        self.state = "Request-started"  # http.client stays here when the request is refused
        path = path or "/"
        if _DISALLOWED_PATH_CHARS.search(path) or not path.isascii():
            raise http.client.InvalidURL("invalid request") from None
        try:
            header = self.user_agent.encode("latin-1")
        except UnicodeEncodeError:
            raise http.client.InvalidURL("invalid request") from None
        if _ILLEGAL_HEADER_VALUE.search(self.user_agent):
            raise ValueError(f"Invalid header value {header!r}")
        self.state = "Request-sent"
        attempt = self._attempt
        try:
            self._spend(attempt.write_delay)
        except TimeoutError:
            self._write_failed(path, body)
            raise
        if attempt.write_error is not None:
            self._write_failed(path, body)
            raise attempt.write_error
        self.delivered = True
        self.requests.append((path, body))

    def getresponse(self) -> FakeResponse:
        self._gateway._record("getresponse")
        if self.state != "Request-sent":
            raise http.client.ResponseNotReady(self.state)
        reply = self._attempt.reply
        if isinstance(reply, BaseException):
            raise reply
        self._spend(reply.first_byte_delay)
        framing_header = (
            "Transfer-Encoding: chunked\r\n"
            if reply.framing == "chunked"
            else f"Content-Length: {len(reply.body)}\r\n"
        )
        head_length = len(f"HTTP/1.1 {reply.status} X\r\n{framing_header}Connection: close\r\n\r\n")
        head_bytes = head_length if reply.head_stall_after is None else reply.head_stall_after
        if reply.head_trickle:
            for _ in range(head_bytes):
                self._spend(reply.head_trickle)
        if reply.head_stall_after is not None:
            self._gateway._stall_silently(self.timeout)
        self.state = "Idle"
        self._responded = True
        return FakeResponse(self._gateway, self.timeout, reply)

    def settimeout(self, seconds: float) -> None:
        """As the real connection: it updates ``timeout``, and the live socket only before the
        response exists (afterwards the response owns the socket and keeps its timeout)."""
        self.timeout = seconds
        if self._connected and not self.closed and not self._responded:
            _validate_socket_timeout(seconds)

    def close(self) -> None:
        self._gateway._record("close")
        self.closed = True
        self.state = "Idle"


def _has_usable_ca(candidates: CaCandidates) -> bool:
    """``build_tls_context``'s rule for "something to trust", without loading anything."""
    if candidates.cafile and _is_usable_bundle(candidates.cafile):
        return True
    if _is_dir(candidates.capath):
        return True
    return any(_is_usable_bundle(fallback) for fallback in candidates.fallback_files)


class FakeGateway(SystemGateway):
    """Scriptable ``Gateway``. Filesystem operations are the real ones under a test's home."""

    def __init__(
        self,
        home: str,
        *,
        uid: int | None = None,
        login_name: str | None = "tester",
        home_error: bool = False,
        home_is_directory: bool | None = None,
        wall_start: float = 1_700_000_000.0,
        environment: dict[str, str] | None = None,
    ) -> None:
        self._home = home
        self._environment = {} if environment is None else dict(environment)
        self._uid = os.getuid() if uid is None else uid
        self._login_name = login_name
        self._home_error = home_error
        # None: is_directory is the real check; True or False scripts the answer
        self._home_is_directory = home_is_directory
        self.source_reads = 0  # calls to read_source(), for "stdin was not read" tests
        self.home_lookups = 0  # calls to home_dir(), for "looked up once / not at all" tests
        self._wall_start = wall_start
        self._skew = 0.0
        self._t0 = time.monotonic()
        self._lock = threading.Lock()
        self._attempts: deque[Attempt] = deque()
        self._waiters: list[threading.Event] = []
        self.stalled = threading.Event()  # set while a stall is blocking, cleared on release
        self.violations: list[str] = []
        self.allow_unconsumed_script = False
        self.state_delay = 0.0  # seconds per state-file operation (open, lock, read)
        self.stall_cap_seconds = 30.0
        self.events: list[str] = []
        self.connections: list[FakeConnection] = []
        # Gateway.resolve hook only: connect() never calls it (see the module docstring)
        self.resolve_addresses = ["192.0.2.1"]
        self.resolve_error: BaseException | None = None
        # trust: None means the default candidates and a context that always builds
        self.ca: CaCandidates | None = None
        self.no_usable_ca = False
        # input and state hooks
        self.source_script: list[SourceRead | BaseException] = []
        self.state_dir_error: BaseException | None = None
        self.state_file_errors: dict[str, BaseException] = {}
        self.lock_held = False
        self.lock_error: BaseException | None = None
        # config files: an error raised for a path (as given to the gateway) instead of reading
        self.file_errors: dict[str, BaseException] = {}
        self.directory_errors: dict[str, BaseException] = {}

    # -- scripting --

    def script(self, *attempts: Attempt) -> None:
        """Queue one ``Attempt`` per expected ``https_connection`` call, in order."""
        with self._lock:
            self._attempts.extend(attempts)

    def assert_script_consumed(self) -> None:
        with self._lock:
            assert not self._attempts, f"{len(self._attempts)} unconsumed scripted attempt(s)"

    def assert_clean(self) -> None:
        """Fixture teardown: no contract violation, and every scripted attempt was used."""
        assert not self.violations, f"contract violations: {self.violations}"
        if not self.allow_unconsumed_script:
            self.assert_script_consumed()

    def release_stalls(self) -> None:
        """Release the stalls that are blocked right now (each then fails with ``OSError``, or
        proceeds with ``Attempt.stall_then_proceed``). A stall that begins later blocks again."""
        with self._lock:
            waiters = list(self._waiters)
            self._waiters.clear()
            self.stalled.clear()
        for waiter in waiters:
            waiter.set()

    # -- internals --

    def _record(self, event: str) -> None:
        with self._lock:
            self.events.append(event)

    def _advance(self, seconds: float) -> None:
        if seconds > 0:
            with self._lock:
                self._skew += seconds

    def _violation(self, message: str) -> None:
        """Record a contract violation by the code under test, then raise it."""
        with self._lock:
            self.violations.append(message)
        raise AssertionError(message)

    def _block_until_released(self, *, proceed: bool = False) -> None:
        """Block one stall until ``release_stalls()`` (or the safety cap)."""
        waiter = threading.Event()
        with self._lock:
            self._waiters.append(waiter)
            self.stalled.set()
        released = waiter.wait(self.stall_cap_seconds)
        with self._lock:
            if waiter in self._waiters:
                self._waiters.remove(waiter)
            if not self._waiters:
                self.stalled.clear()
        if proceed and released:
            return
        raise OSError("fake gateway: stall released" if released else "fake gateway: stall cap")

    def _spend(self, timeout: float | None, seconds: float, message: str = "timed out") -> None:
        """Take ``seconds`` for one operation under a per-operation socket timeout."""
        if timeout is not None and seconds > timeout:
            self._advance(timeout)
            raise TimeoutError(message)
        self._advance(seconds)

    def _stall_silently(self, timeout: float | None) -> None:
        """The peer stops sending: the operation ends by timeout (or blocks without one)."""
        if timeout is None:
            self._block_until_released()
        assert timeout is not None
        self._advance(timeout)
        raise TimeoutError("timed out")

    # -- clock --

    def monotonic(self) -> float:
        with self._lock:
            return time.monotonic() + self._skew

    def wall_time(self) -> float:
        return self._wall_start + (self.monotonic() - self._t0)

    def sleep(self, seconds: float) -> None:
        """As ``SystemGateway.sleep``: zero, negative and NaN do nothing; infinity is an
        ``OverflowError`` (``time.sleep``)."""
        if seconds > 0:
            if math.isinf(seconds):
                raise OverflowError("timestamp too large to convert to C _PyTime_t")
            self._record(f"sleep:{seconds}")
            self._advance(seconds)

    # -- name resolution, password database --

    def resolve(self, host: str, port: int) -> list[str]:
        """Scripted protocol hook. The real ``connect()`` never calls it, so neither does this
        fake's: ``Attempt.resolve_error`` / ``resolve_stall`` drive resolution inside
        ``connect()``, and ``resolve_error`` / ``resolve_addresses`` here only answer a direct
        call. Only one address family and no address fallback is modelled."""
        self._record("resolve")
        if self.resolve_error is not None:
            raise self.resolve_error
        return list(self.resolve_addresses)

    def home_dir(self) -> str:
        self.home_lookups += 1
        if self._home_error:
            raise HomeLookupError
        return self._home

    def is_directory(self, path: str) -> bool:
        if self._home_is_directory is not None:
            return self._home_is_directory
        return super().is_directory(path)

    def uid(self) -> int:
        return self._uid

    def environ(self) -> dict[str, str]:
        return dict(self._environment)

    def login_name(self) -> str | None:
        return self._login_name

    # -- input and files --

    def read_source(
        self, fd_or_path: int | str | os.PathLike[str], max_bytes: int, remaining: float
    ) -> SourceRead:
        self._record("read_source")
        self.source_reads += 1
        if self.source_script:
            result = self.source_script.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return super().read_source(fd_or_path, max_bytes, remaining)

    def open_state_dir(self, home: str) -> int:
        self._record("open_state_dir")
        self._advance(self.state_delay)
        if self.state_dir_error is not None:
            raise self.state_dir_error
        return super().open_state_dir(home)

    def open_state_file(self, dir_fd: int, name: str, *, append: bool = False) -> int:
        self._record(f"open_state_file:{name}")
        self._advance(self.state_delay)
        error = self.state_file_errors.get(name)
        if error is not None:
            raise error
        return super().open_state_file(dir_fd, name, append=append)

    def close_fd(self, fd: int) -> None:
        self._record("close_fd")
        super().close_fd(fd)

    def try_lock(self, fd: int) -> bool:
        self._record("try_lock")
        self._advance(self.state_delay)
        if self.lock_error is not None:
            raise self.lock_error
        if self.lock_held:
            return False
        return super().try_lock(fd)

    def unlock(self, fd: int) -> None:
        self._record("unlock")
        super().unlock(fd)

    def read_regular_file(self, path: str | os.PathLike[str], max_bytes: int) -> bytes:
        self._record("read_regular_file")
        self._advance(self.state_delay)
        error = self.file_errors.get(os.fspath(path))
        if error is not None:
            raise error
        return super().read_regular_file(path, max_bytes)

    def absolute_path(self, path: str) -> str:
        # Deliberate: test_every_gateway_method_is_overridden_by_the_fake requires each method to be
        # faked on purpose. The real (pure) implementation is what the tests want.
        return super().absolute_path(path)

    def list_directory(self, path: str) -> list[str]:
        self._record("list_directory")
        error = self.directory_errors.get(path)
        if error is not None:
            raise error
        return super().list_directory(path)

    # -- trust and network --

    def ca_candidates(self) -> CaCandidates:
        return self.ca if self.ca is not None else CaCandidates(None, None, CA_FALLBACK_FILES)

    def tls_context(self) -> ssl.SSLContext:
        self._record("tls_context")
        if self.no_usable_ca or (self.ca is not None and not _has_usable_ca(self.ca)):
            raise NoUsableCA
        # Verification on, TLS 1.2 minimum, no roots loaded: never used for a real handshake.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def https_connection(
        self, host: str, port: int, *, timeout: float, context: ssl.SSLContext, user_agent: str
    ) -> FakeConnection:
        if (host, port) != (WEBHOOK_HOST, WEBHOOK_PORT):
            self._violation(f"the request goes to {WEBHOOK_HOST}:{WEBHOOK_PORT} only")
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            self._violation("TLS verification must stay on")
        if context.minimum_version < ssl.TLSVersion.TLSv1_2:
            self._violation("the TLS minimum version must be 1.2 or higher")
        self._record("https_connection")
        with self._lock:
            attempt = self._attempts.popleft() if self._attempts else None
        if attempt is None:
            self._violation("fake gateway: no scripted attempt for this connection")
        assert attempt is not None
        connection = FakeConnection(self, attempt, host, port, timeout, user_agent)
        with self._lock:
            self.connections.append(connection)
        return connection

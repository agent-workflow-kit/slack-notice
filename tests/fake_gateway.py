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
- State files, locks, ``read_regular_file`` and ``read_source`` are the real implementations
  (inherited) running on the files a test creates under its private home, so hostile paths
  (symlink, FIFO, wrong owner) behave as in production. Hooks can inject failures instead.
- ``home_dir``, ``uid`` and ``login_name`` are supplied here; ``pwd`` is never consulted.

Unverified against a real Slack host (see the issue report): everything about what Slack sends
(real status line and header shapes, how a real 429 or 5xx body looks, connection reuse), and the
exact ``http.client`` and ``ssl`` exception classes and messages for a given network event beyond
the ones the contract tests compare with the standard library.
"""

from __future__ import annotations

import http.client
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
)

WEBHOOK_HOST = "hooks.slack.com"
WEBHOOK_PORT = 443

# http.client refuses these in a request target (``_contains_disallowed_url_pchar_re``).
_DISALLOWED_PATH_CHARS = re.compile(r"[\x00-\x20\x7f]")


def cert_verify_error() -> ssl.SSLCertVerificationError:
    """What a failed certificate or host name check raises."""
    error = ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer"
    )
    error.verify_code = 20
    error.verify_message = "unable to get local issuer certificate"
    return error


def handshake_error() -> ssl.SSLError:
    """A TLS failure that is not a certificate verification failure."""
    return ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure")


@dataclass(frozen=True)
class Reply:
    """A complete or partial HTTP answer.

    ``truncated_by``: the declared Content-Length exceeds the bytes that arrive by this many.
    ``first_byte_delay``: seconds before any byte arrives. ``head_trickle`` / ``body_trickle``:
    seconds between bytes of the status line and headers / of the body. ``head_stall_after`` /
    ``body_stall_after``: bytes delivered before the host goes silent (1 is "a stall after the
    first byte").
    """

    status: int = 200
    body: bytes = b'{"ok":true}'
    truncated_by: int = 0
    first_byte_delay: float = 0.0
    head_trickle: float | None = None
    head_stall_after: int | None = None
    body_trickle: float | None = None
    body_stall_after: int | None = None


@dataclass(frozen=True)
class Attempt:
    """What one connection (one send attempt) does, in protocol order.

    Phases: ``resolve_*`` and ``connect_*`` and ``tls_*`` happen in ``connect()`` (gate idle);
    ``write_error`` in ``post()``; ``reply`` in ``getresponse()``/``read()``. A ``reply`` that is
    an exception is raised by ``getresponse()`` after the request was written (the post-write
    failure). Exceptions are raised as given, so a test can carry a fake secret in one.
    """

    resolve_stall: bool = False
    resolve_error: BaseException | None = None
    connect_delay: float = 0.0
    connect_error: BaseException | None = None
    tls_delay: float = 0.0
    tls_error: BaseException | None = None
    write_error: BaseException | None = None
    request_delivered_on_write_error: bool = False
    reply: Reply | BaseException = field(default_factory=Reply)


class FakeResponse:
    """Only ``status`` and ``read`` are public, as in the ``Response`` protocol."""

    def __init__(self, gateway: FakeGateway, connection: FakeConnection, reply: Reply) -> None:
        self._gateway = gateway
        self._connection = connection
        self._reply = reply
        self._pos = 0

    @property
    def status(self) -> int:
        return self._reply.status

    def read(self, amount: int) -> bytes:
        reply = self._reply
        self._gateway._record("read")
        declared_left = len(reply.body) + reply.truncated_by - self._pos
        # http.client caps the request at the declared length, and the buffered reader then
        # blocks until that many bytes arrive or the stream ends.
        want = max(0, min(amount, declared_left))
        available = max(0, min(want, len(reply.body) - self._pos))
        stall_at = reply.body_stall_after
        deliver = available
        stalls = stall_at is not None and self._pos + available > stall_at
        if stalls:
            assert stall_at is not None
            deliver = max(0, stall_at - self._pos)
        for _ in range(deliver):
            if reply.body_trickle:
                self._connection._spend(reply.body_trickle)
        if stalls:
            self._connection._stall_silently()
        data = reply.body[self._pos : self._pos + deliver]
        self._pos += len(data)
        if not data and amount > 0 and declared_left > 0:
            raise http.client.IncompleteRead(b"", declared_left)
        return data


class FakeConnection:
    """One scripted send attempt; implements the ``Connection`` protocol."""

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
        self._gateway = gateway
        self._attempt = attempt
        self._connected = False
        self._posted = False

    # -- time --

    def _spend(self, seconds: float) -> None:
        """Take ``seconds`` for one operation under the per-operation socket timeout."""
        timeout = self.timeout
        if timeout is not None and seconds > timeout:
            self._gateway._advance(timeout)
            raise TimeoutError("timed out")
        self._gateway._advance(seconds)

    def _stall_silently(self) -> None:
        """The peer stops sending: the operation ends by timeout (or blocks without one)."""
        if self.timeout is None:
            self._gateway._block_until_released()
        self._gateway._advance(self.timeout)
        raise TimeoutError("timed out")

    # -- Connection protocol ----------------------------------------------------------------

    def connect(self) -> None:
        self._gateway._record("connect")
        attempt = self._attempt
        if attempt.resolve_stall:
            self._gateway._block_until_released()
        if attempt.resolve_error is not None:
            raise attempt.resolve_error
        self._spend(attempt.connect_delay)
        if attempt.connect_error is not None:
            raise attempt.connect_error
        self._spend(attempt.tls_delay)
        if attempt.tls_error is not None:
            raise attempt.tls_error
        self._connected = True

    def post(self, path: str, body: bytes) -> None:
        self._gateway._record("post")
        assert not self.closed, "post() on a closed connection"
        assert self._connected, "post() before connect(): the interface connects first"
        if not isinstance(body, bytes):
            raise TypeError("body must be bytes")
        if self._posted:
            raise http.client.CannotSendRequest("Request-sent")
        self._posted = True  # http.client leaves the connection busy even if the path is refused
        if _DISALLOWED_PATH_CHARS.search(path) or not path.isascii():
            raise http.client.InvalidURL("invalid request") from None
        attempt = self._attempt
        if attempt.write_error is not None:
            if attempt.request_delivered_on_write_error:
                self.delivered = True
                self.requests.append((path, body))
            raise attempt.write_error
        self.delivered = True
        self.requests.append((path, body))

    def getresponse(self) -> FakeResponse:
        self._gateway._record("getresponse")
        if not self._posted:
            raise http.client.ResponseNotReady("Idle")
        reply = self._attempt.reply
        if isinstance(reply, BaseException):
            raise reply
        self._spend(reply.first_byte_delay)
        head_length = len(
            f"HTTP/1.1 {reply.status} X\r\nContent-Length: {len(reply.body)}\r\n"
            "Connection: close\r\n\r\n"
        )
        head_bytes = head_length if reply.head_stall_after is None else reply.head_stall_after
        if reply.head_trickle:
            for _ in range(head_bytes):
                self._spend(reply.head_trickle)
        if reply.head_stall_after is not None:
            self._stall_silently()
        return FakeResponse(self._gateway, self, reply)

    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds

    def close(self) -> None:
        self._gateway._record("close")
        self.closed = True


class FakeGateway(SystemGateway):
    """Scriptable ``Gateway``. Filesystem operations are the real ones under a test's home."""

    def __init__(
        self,
        home: str,
        *,
        uid: int | None = None,
        login_name: str | None = "tester",
        home_error: bool = False,
        wall_start: float = 1_700_000_000.0,
    ) -> None:
        self._home = home
        self._uid = os.getuid() if uid is None else uid
        self._login_name = login_name
        self._home_error = home_error
        self._wall_start = wall_start
        self._skew = 0.0
        self._t0 = time.monotonic()
        self._lock = threading.Lock()
        self._attempts: deque[Attempt] = deque()
        self._release = threading.Event()
        self.stalled = threading.Event()
        self.stall_cap_seconds = 30.0
        self.events: list[str] = []
        self.connections: list[FakeConnection] = []
        # name resolution hook (Gateway.resolve is only a hook; connect() does the real work)
        self.resolve_addresses = ["192.0.2.1"]
        self.resolve_error: BaseException | None = None
        # trust
        self.ca = CaCandidates(None, None, CA_FALLBACK_FILES)
        self.no_usable_ca = False
        # input and state hooks
        self.source_script: list[SourceRead | BaseException] = []
        self.state_dir_error: BaseException | None = None
        self.state_file_errors: dict[str, BaseException] = {}
        self.lock_held = False
        self.lock_error: BaseException | None = None

    # -- scripting --

    def script(self, *attempts: Attempt) -> None:
        """Queue one ``Attempt`` per expected ``https_connection`` call, in order."""
        with self._lock:
            self._attempts.extend(attempts)

    def assert_script_consumed(self) -> None:
        with self._lock:
            assert not self._attempts, f"{len(self._attempts)} unconsumed scripted attempt(s)"

    def release_stalls(self) -> None:
        """Let every stalled name resolution continue (it then fails with ``OSError``)."""
        self._release.set()

    # -- internals --

    def _record(self, event: str) -> None:
        with self._lock:
            self.events.append(event)

    def _advance(self, seconds: float) -> None:
        if seconds > 0:
            with self._lock:
                self._skew += seconds

    def _block_until_released(self) -> None:
        self.stalled.set()
        released = self._release.wait(self.stall_cap_seconds)
        raise OSError("fake gateway: stall released" if released else "fake gateway: stall cap")

    # -- clock --

    def monotonic(self) -> float:
        with self._lock:
            return time.monotonic() + self._skew

    def wall_time(self) -> float:
        return self._wall_start + (self.monotonic() - self._t0)

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self._record(f"sleep:{seconds}")
            self._advance(seconds)

    # -- name resolution, password database --

    def resolve(self, host: str, port: int) -> list[str]:
        self._record("resolve")
        if self.resolve_error is not None:
            raise self.resolve_error
        return list(self.resolve_addresses)

    def home_dir(self) -> str:
        if self._home_error:
            raise HomeLookupError
        return self._home

    def uid(self) -> int:
        return self._uid

    def login_name(self) -> str | None:
        return self._login_name

    # -- input and files --

    def read_source(
        self, fd_or_path: int | str | os.PathLike[str], max_bytes: int, remaining: float
    ) -> SourceRead:
        self._record("read_source")
        if self.source_script:
            result = self.source_script.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return super().read_source(fd_or_path, max_bytes, remaining)

    def open_state_dir(self, home: str) -> int:
        self._record("open_state_dir")
        if self.state_dir_error is not None:
            raise self.state_dir_error
        return super().open_state_dir(home)

    def open_state_file(self, dir_fd: int, name: str, *, append: bool = False) -> int:
        self._record(f"open_state_file:{name}")
        error = self.state_file_errors.get(name)
        if error is not None:
            raise error
        return super().open_state_file(dir_fd, name, append=append)

    def try_lock(self, fd: int) -> bool:
        self._record("try_lock")
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
        return super().read_regular_file(path, max_bytes)

    # -- trust and network --

    def ca_candidates(self) -> CaCandidates:
        return self.ca

    def tls_context(self) -> ssl.SSLContext:
        self._record("tls_context")
        if self.no_usable_ca:
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
        assert (host, port) == (WEBHOOK_HOST, WEBHOOK_PORT), (
            f"the request goes to {WEBHOOK_HOST}:{WEBHOOK_PORT} only"
        )
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, (
            "TLS verification must stay on"
        )
        self._record("https_connection")
        with self._lock:
            if not self._attempts:
                raise AssertionError("fake gateway: no scripted attempt for this connection")
            attempt = self._attempts.popleft()
        connection = FakeConnection(self, attempt, host, port, timeout, user_agent)
        with self._lock:
            self.connections.append(connection)
        return connection

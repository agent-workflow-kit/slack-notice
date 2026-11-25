"""Gateway: the single boundary between slack-notice and the outside world.

Every other module reaches the network, the clock (``monotonic``, ``wall_time``, ``sleep``),
name resolution, the password database (``home_dir``, ``uid``, ``login_name``), the home
directory check (``is_directory``), input sources
(``read_source``), CA files, config-style files (``read_regular_file``) and state files
(``open_state_dir``, ``open_state_file``, ``try_lock``, ``unlock``), config directory listings
(``list_directory``), display paths (``absolute_path``) through the ``Gateway``
protocol defined here, so tests can pass a fake (issue #5). A test (``tests/test_gateway.py``)
fails if any other module imports ``urllib``, ``http``, ``time``, ``fcntl`` or ``subprocess``
or reaches them dynamically. Failures that callers must tell apart are ``NoUsableCA``,
``HomeLookupError``, ``NotRegularFile`` and ``StateUnusable`` (each with a fixed message).

Hard rules, enforced by tests:

- No code here consults the environment. The one exception is ``environ()``, which only hands
  a copy of the process environment to the CLI (the only reader of one variable, the one that
  config names for the credential). Proxy variables, ``SSL_CERT_FILE``, ``SSL_CERT_DIR``,
  ``HOME`` and ``XDG_*`` are never consulted; the home directory comes from the password
  database and trust comes from the compiled OpenSSL defaults (or fixed fallback files).
- ``urllib`` is not used: it reads proxy and CA variables and follows redirects.
- Failures raised here carry fixed messages and never chain a cause that holds a path. Text of
  ``http.client`` exceptions that can quote the request target (``InvalidURL``,
  ``UnicodeEncodeError``) is replaced by a fixed message; other ``http.client``, ``ssl`` and
  ``socket`` exceptions pass through with their own class, and no URL, header or body is
  formatted into a message here.
- ``Retry-After``, ``Location`` and every other response header are unreachable.
"""

from __future__ import annotations

import errno
import fcntl
import http.client
import os
import pwd
import select
import socket
import ssl
import stat
import time
from dataclasses import dataclass, field
from typing import Protocol

# Interface, "Input": at most 100 ms per slice so the main thread notices a deadline or signal;
# a regular file is read in chunks of 64 KiB.
SLICE_SECONDS = 0.1
CHUNK_BYTES = 64 * 1024

# Interface, "Webhook edge": used only when the compiled default trust is unusable.
CA_FALLBACK_FILES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
)


# --- errors ---------------------------------------------------------------------------------


class NoUsableCA(Exception):
    """No CA certificates could be loaded; the caller reports network_error with tls true."""

    def __init__(self) -> None:
        super().__init__("no usable CA certificates were found")


class HomeLookupError(Exception):
    """The password database has no usable entry for the current user."""

    def __init__(self) -> None:
        super().__init__("home directory lookup failed")


class NotRegularFile(Exception):
    """A path that must name a regular file does not (FIFO, device, directory, ...)."""

    def __init__(self) -> None:
        super().__init__("not a regular file")


class StateUnusable(Exception):
    """The state directory or a state file cannot be used safely; ``reason`` is a fixed token."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"state unusable: {reason}")
        self.reason = reason


# --- results --------------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceRead:
    """Outcome of ``read_source``.

    ``timed_out``: the source did not reach end of input within the time that remained; ``data``
    holds what arrived but was not judged. ``too_large``: more than ``max_bytes`` were
    available; ``data`` is cut to ``max_bytes``.
    """

    data: bytes = field(repr=False)
    timed_out: bool = False
    too_large: bool = False


@dataclass(frozen=True)
class CaCandidates:
    """Where trust may come from: the compiled defaults, then fixed fallback bundle files."""

    cafile: str | None
    capath: str | None
    fallback_files: tuple[str, ...]


class Response(Protocol):
    """A complete-or-failing HTTP response. Only the status and the body are exposed: no header
    is reachable by design (a redirect is never followed, ``Retry-After`` is never read)."""

    @property
    def status(self) -> int: ...

    def read(self, amount: int) -> bytes:
        """Read at most ``amount`` bytes; ``b""`` at the end of the body. A body shorter than
        its ``Content-Length`` raises ``http.client.IncompleteRead``."""
        ...


class Connection(Protocol):
    """One HTTPS connection to the webhook host, used for one send attempt."""

    def connect(self) -> None:
        """Resolve, connect and complete the TLS handshake (nothing is written)."""
        ...

    def post(self, path: str, body: bytes) -> None:
        """Write one POST request. The first call that can put bytes on the socket."""
        ...

    def getresponse(self) -> Response: ...

    def settimeout(self, seconds: float) -> None:
        """Set the per-operation socket timeout for the rest of the attempt."""
        ...

    def close(self) -> None: ...


class Gateway(Protocol):
    """Everything slack-notice does outside its own process memory."""

    def monotonic(self) -> float: ...

    def wall_time(self) -> float:
        """Seconds since the epoch, for log timestamps."""
        ...

    def sleep(self, seconds: float) -> None: ...

    def resolve(self, host: str, port: int) -> list[str]:
        """Addresses of ``host`` (TCP). Raises ``OSError`` on failure."""
        ...

    def home_dir(self) -> str:
        """``pw_dir`` of the current uid from the password database (never ``HOME``).

        Returned as found; the config module rejects empty or relative paths and asks
        ``is_directory`` about the rest.
        """
        ...

    def is_directory(self, path: str) -> bool:
        """True when ``path`` is an existing directory (a link to one counts).

        Any ``OSError`` or ``ValueError`` (a NUL, a path that is too long) is ``False``.
        """
        ...

    def uid(self) -> int: ...

    def environ(self) -> dict[str, str]:
        """A copy of the process environment: the CLI default for ``env`` (not consulted here)."""
        ...

    def login_name(self) -> str | None:
        """``pw_name`` of the current uid, or ``None`` when there is no entry."""
        ...

    def read_source(
        self, fd_or_path: int | str | os.PathLike[str], max_bytes: int, remaining: float
    ) -> SourceRead: ...

    def ca_candidates(self) -> CaCandidates: ...

    def tls_context(self) -> ssl.SSLContext: ...

    def https_connection(
        self, host: str, port: int, *, timeout: float, context: ssl.SSLContext, user_agent: str
    ) -> Connection: ...

    def open_state_dir(self, home: str) -> int: ...

    def open_state_file(self, dir_fd: int, name: str, *, append: bool = False) -> int: ...

    def close_fd(self, fd: int) -> None:
        """Close a descriptor returned by ``open_state_dir`` or ``open_state_file``; an
        ``OSError`` (already closed) is ignored."""
        ...

    def try_lock(self, fd: int) -> bool: ...

    def unlock(self, fd: int) -> None: ...

    def read_regular_file(self, path: str | os.PathLike[str], max_bytes: int) -> bytes: ...

    def list_directory(self, path: str) -> list[str]:
        """Entry names of the directory ``path`` (a link to one is followed), in no order.

        Raises ``OSError`` (``FileNotFoundError`` for a missing one, ``NotADirectoryError`` for a
        file) and ``ValueError`` (a NUL). Only names are returned: nothing is opened or read.
        """
        ...

    def absolute_path(self, path: str) -> str:
        """``path`` made absolute for display: unchanged when it is, else joined to the working
        directory (or prefixed ``./`` when that is unavailable). Not normalised, not resolved."""
        ...


# --- failure classification (by exception class; pure) ---------------------------------------


def is_timeout(exc: BaseException) -> bool:
    return isinstance(exc, TimeoutError)


def is_tls_error(exc: BaseException) -> bool:
    """A certificate, host name, handshake or missing-CA failure."""
    return isinstance(exc, ssl.SSLError | NoUsableCA)


def is_cert_verification_error(exc: BaseException) -> bool:
    """A certificate failed verification (a subset of ``is_tls_error``)."""
    return isinstance(exc, ssl.SSLCertVerificationError)


def is_malformed_response(exc: BaseException) -> bool:
    """An answer arrived but is not HTTP (wrong_host_response), as opposed to a lost one.

    ``RemoteDisconnected`` and ``IncompleteRead`` mean the connection or answer was lost.
    """
    if isinstance(exc, http.client.RemoteDisconnected | http.client.IncompleteRead):
        return False
    return isinstance(exc, http.client.HTTPException)


# --- TLS ------------------------------------------------------------------------------------


def _is_usable_bundle(path: str) -> bool:
    """A regular file that loads at least one CA certificate."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return False
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe.load_verify_locations(cafile=path)
        return probe.cert_store_stats()["x509_ca"] > 0
    except (OSError, ssl.SSLError, ValueError):
        return False


def _is_dir(path: str | None) -> bool:
    return bool(path) and os.path.isdir(path)  # type: ignore[arg-type]


def build_tls_context(candidates: CaCandidates) -> ssl.SSLContext:
    """TLS client context: verification on, TLS 1.2 minimum, trust only from ``candidates``.

    ``load_default_certs`` and ``set_default_verify_paths`` are never called: OpenSSL would
    read ``SSL_CERT_FILE`` and ``SSL_CERT_DIR`` from the environment.
    """
    cafile = (
        candidates.cafile if candidates.cafile and _is_usable_bundle(candidates.cafile) else None
    )
    capath = candidates.capath if _is_dir(candidates.capath) else None
    if cafile is None and capath is None:
        for fallback in candidates.fallback_files:
            if _is_usable_bundle(fallback):
                cafile = fallback
                break
    if cafile is None and capath is None:
        raise NoUsableCA

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=cafile, capath=capath)
    return context


# --- HTTPS ----------------------------------------------------------------------------------


class _HttpsResponse:
    def __init__(self, response: http.client.HTTPResponse) -> None:
        self._response = response

    @property
    def status(self) -> int:
        return self._response.status

    def read(self, amount: int) -> bytes:
        data = self._response.read(amount)
        # http.client returns b"" for a body cut short; ``length`` is the declared bytes left.
        if not data and amount > 0 and self._response.length:
            raise http.client.IncompleteRead(b"", self._response.length)
        return data


class _HttpsConnection:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
        user_agent: str,
    ) -> None:
        # No proxy tunnel is ever set and no environment is read. Constructing does not connect.
        self._conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        self._user_agent = user_agent

    def connect(self) -> None:
        self._conn.connect()

    def post(self, path: str, body: bytes) -> None:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "User-Agent": self._user_agent,
        }
        try:
            self._conn.request("POST", path, body=body, headers=headers)
        except (http.client.InvalidURL, UnicodeEncodeError):
            # The original message (or the encode error's ``object``) quotes the request
            # target, which holds the webhook secret.
            raise http.client.InvalidURL("invalid request") from None

    def getresponse(self) -> Response:
        return _HttpsResponse(self._conn.getresponse())

    def settimeout(self, seconds: float) -> None:
        self._conn.timeout = seconds
        if self._conn.sock is not None:
            self._conn.sock.settimeout(seconds)

    def close(self) -> None:
        self._conn.close()


# --- input ----------------------------------------------------------------------------------


def _open_regular_for_reading(path: str | os.PathLike[str]) -> int:
    """Open without blocking (a FIFO must not hang the tool) and require a regular file."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile
    except BaseException:
        os.close(fd)
        raise
    return fd


# --- the real gateway -----------------------------------------------------------------------


class SystemGateway:
    """The production ``Gateway``."""

    def monotonic(self) -> float:
        return time.monotonic()

    def wall_time(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def resolve(self, host: str, port: int) -> list[str]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return [str(info[4][0]) for info in infos]

    def home_dir(self) -> str:
        try:
            return pwd.getpwuid(self.uid()).pw_dir
        except Exception:
            # Any failure, not only a missing entry: the cause may quote the uid or a path.
            raise HomeLookupError from None

    def is_directory(self, path: str) -> bool:
        try:
            return os.path.isdir(path)
        except (OSError, ValueError):
            return False

    def uid(self) -> int:
        return os.getuid()

    def environ(self) -> dict[str, str]:
        return dict(os.environ)

    def login_name(self) -> str | None:
        try:
            return pwd.getpwuid(self.uid()).pw_name
        except (KeyError, OSError):
            return None

    def read_source(
        self, fd_or_path: int | str | os.PathLike[str], max_bytes: int, remaining: float
    ) -> SourceRead:
        """Read a source to end of input in slices of at most 100 ms.

        ``remaining`` is the seconds left of the deadline when the call starts. A source that is
        not at end of input when it runs out is ``timed_out`` (even if some bytes arrived: they
        are returned but were not judged). A path must be a regular file, else ``NotRegularFile``
        (and ``OSError`` for open failures); a descriptor is read as given and not closed, and a
        descriptor that is closed, write-only or a directory is an empty or ended input (the
        bytes read so far), never an error.

        Python signal handlers run between slices, in the main thread. A handler that only sets
        a flag does not stop this call: the handler must raise or exit.
        """
        # todo(#27): signal handler before step 5 must exit/raise; read_source has no stop callback
        if isinstance(fd_or_path, int):
            return self._read_fd(fd_or_path, max_bytes, remaining, lenient=True)
        fd = _open_regular_for_reading(fd_or_path)
        try:
            return self._read_fd(fd, max_bytes, remaining, lenient=False)
        finally:
            os.close(fd)

    def _read_fd(self, fd: int, max_bytes: int, remaining: float, *, lenient: bool) -> SourceRead:
        deadline = self.monotonic() + remaining
        chunks: list[bytes] = []
        total = 0
        try:
            if lenient and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY:
                return SourceRead(b"")  # poll never reports a write-only descriptor readable
            poller = select.poll()
            poller.register(fd, select.POLLIN)
        except (OSError, ValueError, OverflowError):
            if not lenient:
                raise
            return SourceRead(b"")
        while True:
            left = deadline - self.monotonic()
            # ``not left > 0`` also ends a NaN deadline at once.
            if not left > 0:
                return SourceRead(b"".join(chunks), timed_out=True)
            # A regular file is always ready, so it is read in chunks with the same checks.
            try:
                if not poller.poll(min(SLICE_SECONDS, left) * 1000):
                    continue
                chunk = os.read(fd, min(CHUNK_BYTES, max_bytes + 1 - total))
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                if not lenient:
                    raise
                return SourceRead(b"".join(chunks))
            if not chunk:
                return SourceRead(b"".join(chunks))
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                return SourceRead(b"".join(chunks)[:max_bytes], too_large=True)

    def ca_candidates(self) -> CaCandidates:
        # ``openssl_cafile`` and ``openssl_capath`` are the compiled defaults; ``cafile`` and
        # ``capath`` on the same object would honour SSL_CERT_FILE and SSL_CERT_DIR.
        paths = ssl.get_default_verify_paths()
        return CaCandidates(
            paths.openssl_cafile or None, paths.openssl_capath or None, CA_FALLBACK_FILES
        )

    def tls_context(self) -> ssl.SSLContext:
        return build_tls_context(self.ca_candidates())

    def https_connection(
        self, host: str, port: int, *, timeout: float, context: ssl.SSLContext, user_agent: str
    ) -> Connection:
        return _HttpsConnection(host, port, timeout=timeout, context=context, user_agent=user_agent)

    def open_state_dir(self, home: str) -> int:
        """Create (mode 0700) and open ``<home>/.local/state/slack-notice``; return its fd.

        Opened with ``O_DIRECTORY | O_NOFOLLOW`` and checked on the descriptor: owned by the
        user, no permission bits outside 0700 (no group or other access, no setuid, setgid or
        sticky bit). A directory this call just created is set to 0700 whatever the umask; an
        existing one is never changed. Anything else is ``StateUnusable``.
        """
        if not home or not os.path.isabs(home):
            raise StateUnusable("open")
        parent = os.path.join(home, ".local", "state")
        leaf = os.path.join(parent, "slack-notice")
        fd = -1
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            try:
                os.mkdir(leaf, 0o700)
                os.chmod(leaf, 0o700)  # our own new dir: a restrictive umask must not lock us out
            except FileExistsError:
                pass
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except (OSError, ValueError):
            fd = -1
        if fd < 0:
            raise StateUnusable("open")
        reason = None
        try:
            try:
                info = os.fstat(fd)
                if info.st_uid != self.uid():
                    reason = "owner"
                elif stat.S_IMODE(info.st_mode) & 0o7077:
                    reason = "mode"
            except OSError:
                reason = "open"
        except BaseException:
            self.close_fd(fd)
            raise
        if reason is not None:
            self.close_fd(fd)
            raise StateUnusable(reason)
        return fd

    def open_state_file(self, dir_fd: int, name: str, *, append: bool = False) -> int:
        """Open ``name`` (a single path component) relative to ``dir_fd``; mode 0600 on create.

        ``O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`` (plus ``O_APPEND`` for the log) and an ``fstat``
        check on the descriptor: a regular file owned by the user, one link, no permission bits
        outside 0600 (no group or other access, no execute, setuid, setgid or sticky bit). A
        FIFO, symlink, device, hardlinked or foreign file is ``StateUnusable``, never a hang.
        A file this call just created (``O_CREAT | O_EXCL``) is set to 0600 whatever the umask;
        an existing one is never changed. Residual (same-user boundary): ``.local`` and
        ``.local/state`` are followed if they are links; only the leaf is ``O_NOFOLLOW``. The
        leaf can be swapped between ``mkdir`` and ``open`` by the same user (accepted); after
        the open every file is relative to the descriptor.
        """
        if not name or "/" in name or name in (".", "..") or "\0" in name:
            raise ValueError("state file name must be one plain path component")
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
        if append:
            flags |= os.O_APPEND
        fd = -1
        created = False
        for _ in range(3):  # bounded: a file that keeps vanishing is unusable
            try:
                fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd)
                created = True
                break
            except FileExistsError:
                pass
            except OSError:
                break
            try:
                fd = os.open(name, flags, dir_fd=dir_fd)
                break
            except FileNotFoundError:
                continue
            except OSError:
                break
        if fd < 0:
            raise StateUnusable("open")
        reason = None
        try:
            try:
                if created:
                    os.fchmod(fd, 0o600)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    reason = "not_regular"
                elif info.st_uid != self.uid():
                    reason = "owner"
                elif info.st_nlink != 1:
                    reason = "linked"
                elif stat.S_IMODE(info.st_mode) & 0o7177:
                    reason = "mode"
            except OSError:
                reason = "open"
        except BaseException:
            self.close_fd(fd)
            raise
        if reason is not None:
            self.close_fd(fd)
            raise StateUnusable(reason)
        return fd

    def close_fd(self, fd: int) -> None:
        try:
            os.close(fd)
        except OSError:
            pass

    def try_lock(self, fd: int) -> bool:
        """Take an exclusive flock without blocking; ``False`` when another holder has it."""
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                return False
            raise
        return True

    def unlock(self, fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    def read_regular_file(self, path: str | os.PathLike[str], max_bytes: int) -> bytes:
        """Read a config-style file: opened ``O_NONBLOCK``, symlinks followed, the descriptor
        must be a regular file, at most ``max_bytes`` (``ValueError`` when larger)."""
        fd = _open_regular_for_reading(path)
        try:
            data = b""
            while len(data) <= max_bytes:
                chunk = os.read(fd, min(CHUNK_BYTES, max_bytes + 1 - len(data)))
                if not chunk:
                    return data
                data += chunk
            raise ValueError("file too large")
        finally:
            os.close(fd)

    def list_directory(self, path: str) -> list[str]:
        return os.listdir(path)

    def absolute_path(self, path: str) -> str:
        if os.path.isabs(path):
            return path
        try:
            return os.path.join(os.getcwd(), path)
        except OSError:
            return os.path.join(".", path)

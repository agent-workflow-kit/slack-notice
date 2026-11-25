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
is #24; the gate, the deadline and retries are #25 and #26.

TODO(#24): implement response mapping and the exception phase rule.
TODO(#25): implement the deadline (daemon worker, three-state gate, os._exit).
TODO(#26): implement retries.
TODO(#28): call ``read_webhook`` at send step 5 and map ``CredentialInvalid`` to exit 12
``credential_invalid`` with ``details.env``.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import NoReturn

from slack_notice import __version__
from slack_notice.gateway import (
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


# --- one attempt (issue #23) -------------------------------------------------------------------

CHUNK = 1024  # interface, "Webhook edge": response chunks of at most 1 KiB
BODY_CAP = 4096  # ... up to a cap of 4 KiB
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


def _failure(exc: Exception) -> Failure:
    name = type(exc).__name__
    return Failure(
        error_class=name if _CLASS_NAME.fullmatch(name) else "Exception",
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
) -> AttemptResult:
    """Make exactly one POST attempt and report what happened; never retry, never follow.

    ``timeout`` is the per-operation socket timeout. ``before_write`` is the seam for the
    deadline gate: called after connect and before the first call that can put bytes on the
    socket; ``False`` abandons the attempt (nothing written, ``abandoned`` true).
    A failure is returned, not raised, whatever its class (the phase decides its meaning); only
    ``BaseException`` that is not an ``Exception`` (an interrupt) propagates, after the close.

    The path is the secret: it is passed to the gateway as the request target and nowhere else.
    """
    # TODO(#25): derive the per-operation timeout of each phase from the deadline
    # (``connection.settimeout`` between phases) and run this in the daemon worker.
    phase = Phase.CONNECT
    connection = None
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
                timeout=timeout,
                context=context,
                user_agent=f"slack-notice/{__version__}",
            )
            connection.connect()
            if before_write is not None and not before_write():
                abandoned = True
            else:
                phase = Phase.WRITE
                connection.post(target.path, body)
                phase = Phase.READ
                response = connection.getresponse()
                status = response.status
                total = 0
                while True:
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

"""URL allowlist, request, response mapping, retries and deadline.

This stage (#22) is the credential edge: the webhook URL is read from the one environment
variable the config names, through the injected environment mapping only, and validated whole by
a strict anchored pattern before anything is built from it. No URL parser is used. The value that
comes back holds only what the HTTP client needs (the fixed host and port and the path); the path
is the secret, so it is left out of every representation.

TODO(#23): implement the HTTP client and TLS context.
TODO(#24): implement response mapping and the exception phase rule.
TODO(#25): implement the deadline (daemon worker, three-state gate, os._exit).
TODO(#26): implement retries.
TODO(#28): call ``read_webhook`` at send step 5 and map ``CredentialInvalid`` to exit 12
``credential_invalid`` with ``details.env``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import NoReturn

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
    cannot be pickled or copied (``__reduce__`` raises) and is not a dataclass (no ``asdict``).
    ``host`` and ``port`` are fixed class constants, not constructor arguments. The constructor
    re-validates the path against the path part of the grammar."""

    __slots__ = ("_path",)
    host = HOST
    port = PORT

    def __init__(self, path: str) -> None:
        # The check runs without an except block, so the error holds no context and no value.
        if type(path) is not str or _PATH.fullmatch(path) is None:
            raise ValueError("not a workflow trigger path")
        object.__setattr__(self, "_path", path)

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

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
from dataclasses import dataclass, field

HOST = "hooks.slack.com"
PORT = 443
INVALID_MESSAGE = "the webhook credential is unset or not a workflow trigger URL"

# A whole-string allowlist, ASCII only. Used with ``fullmatch`` (never ``$``, which accepts a
# trailing newline). The alphabet is spelled out, so ``\d`` and ``\w`` never come into play.
_URL = re.compile(
    r"https://hooks\.slack\.com(?P<path>/triggers/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+){0,3})",
    re.ASCII,
)
# Real trigger URLs are about 70 characters; the grammar alone would accept any length.
MAX_LENGTH = 1024
# Only ASCII whitespace is trimmed: any other character at an edge fails the match.
_TRIM = " \t\n\r\x0b\x0c"


class CredentialInvalid(Exception):  # noqa: N818
    """The credential is unset, empty or not a workflow-trigger URL. Exit 12
    ``credential_invalid`` with ``details.env``. Holds the variable name (from the config, never
    the value); ``str()`` is a fixed message and no cause or context is kept."""

    def __init__(self, env: str) -> None:
        super().__init__(INVALID_MESSAGE)
        self.env = env


@dataclass(frozen=True, slots=True)
class Webhook:
    """A validated destination. ``path`` is the secret: it is left out of ``repr`` (and so of
    ``str``, ``format`` and pytest's failure output). ``host`` and ``port`` are the fixed
    values the connection is built from."""

    path: str = field(repr=False)
    host: str = HOST
    port: int = PORT


def read_webhook(env: Mapping[str, str], name: str) -> Webhook:
    """Read the variable ``name`` from ``env`` and validate it whole; raise ``CredentialInvalid``.

    Only the one key is read. The value is never put in an exception, a message or a log.
    """
    try:
        value = env[name]
    except KeyError:
        raise CredentialInvalid(name) from None
    if not isinstance(value, str):
        raise CredentialInvalid(name) from None
    trimmed = value.strip(_TRIM)
    if not trimmed or len(trimmed) > MAX_LENGTH:
        raise CredentialInvalid(name) from None
    match = _URL.fullmatch(trimmed)
    if match is None:
        raise CredentialInvalid(name) from None
    return Webhook(path=match.group("path"))

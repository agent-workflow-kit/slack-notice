"""Body layout and cuts (interface.md, Rendering and Output).

``render`` is a pure function from a ``Sanitized`` notification and the validated settings to the
request body. Nothing is escaped: the trigger variable is plain text. The link is counted and
written exactly as given and never cut.

The dry run (``cli.send``) prints ``Rendered.text`` and reports ``bytes`` and ``truncated``.
TODO(#28): the send path posts ``Rendered.body``.
"""

from __future__ import annotations

import builtins
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from slack_notice.payload import Sanitized

# U+2026 HORIZONTAL ELLIPSIS, the cut marker's first character and the title's last.
ELLIPSIS = "…"
MARKER = ELLIPSIS + "[truncated]"
TITLE_LIMIT = 256
MAX_BODY_BYTES = 12000


@dataclass(frozen=True)
class Rendered:
    """``text`` is the body string; ``body`` the serialized request body (UTF-8); ``bytes`` its
    length; ``truncated`` whether the title or the message was cut."""

    text: str
    body: builtins.bytes
    truncated: bool

    @property
    def bytes(self) -> int:
        return len(self.body)


def serialize(variable: str, text: str) -> bytes:
    """``{"<variable>":"<text>"}``: compact, ``ensure_ascii=False``, UTF-8."""
    return json.dumps({variable: text}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def render(notification: Sanitized, settings: Mapping[str, Any]) -> Rendered:
    """Build the body for ``notification`` under ``settings`` (``max_chars``, ``body_variable``,
    ``level_prefix``, as ``config.validate_config`` returns them)."""
    max_chars: int = settings["max_chars"]
    variable: str = settings["body_variable"]
    truncated = False

    prefix_line: str = settings["level_prefix"][notification.level]
    title = notification.title
    if title is not None:
        if len(title) > TITLE_LIMIT:
            title = title[: TITLE_LIMIT - 1] + ELLIPSIS
            truncated = True
        prefix_line = f"{prefix_line} {title}"
    tail = "" if notification.link is None else "\n" + notification.link
    head = prefix_line + "\n"

    def build(message: str) -> tuple[str, bytes]:
        text = head + message + tail
        return text, serialize(variable, text)

    def fits(text: str, body: bytes) -> bool:
        return len(text) <= max_chars and len(body) <= MAX_BODY_BYTES

    message = notification.message
    text, body = build(message)
    if not fits(text, body):
        truncated = True
        # The kept length is non-decreasing in k, as are the character and byte counts, so the
        # largest k that fits is found by bisection. k = 0 (the marker alone) always fits: the
        # head and link are at most 16 + 1 + 256 + 1 + 1025 characters, far below the minimum.
        low, high = 0, len(message)  # invariant: low fits; high + 1.. does not
        while low < high:
            mid = (low + high + 1) // 2
            candidate = build(message[:mid].rstrip() + MARKER)
            if fits(*candidate):
                low = mid
            else:
                high = mid - 1
        text, body = build(message[:low].rstrip() + MARKER)
    return Rendered(text=text, body=body, truncated=truncated)

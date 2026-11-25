"""A leak scanner for the secrets regression tests (#29).

``Secret`` builds a fake webhook URL from parts at runtime (no secret-looking literal on disk)
and every needle a leak could take: the URL, the host plus path, the path, each segment and each
run of segments, and for each of those the percent-encoded, base64 (standard and URL-safe,
padded or not, at all three byte alignments), hex and reversed forms. ``scan`` looks for every
needle in named byte blobs; ``Corpus.collect`` gathers the blobs a run could leave anywhere: the
streams, every file name and file content under a directory tree, and extra text.

The scanner is only worth anything if it can fail: the tests plant each needle form and assert
the scan reports it.
"""

from __future__ import annotations

import base64
import binascii
import os
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

HOST = "hooks.slack.com"


@dataclass(frozen=True)
class Secret:
    """A fake workflow-trigger URL: three secret segments after ``/triggers/``."""

    segments: tuple[str, ...] = ("CAN" + "ARY_29a", "CAN" + "ARY-29b", "Cseg" + "29xQ")

    @property
    def path(self) -> str:
        return "/triggers/" + "/".join(self.segments)

    @property
    def url(self) -> str:
        return "https://" + HOST + self.path

    @property
    def env(self) -> dict[str, str]:
        return {"SLACK_WEBHOOK": self.url}

    def pieces(self) -> list[str]:
        """The strings whose every encoding is a needle."""
        found = [
            self.url,
            self.url.removeprefix("https://"),  # host plus path
            self.path,
            self.path.removeprefix("/"),
            "triggers/" + self.segments[0],
        ]
        for start in range(len(self.segments)):
            for end in range(start + 1, len(self.segments) + 1):
                found.append("/".join(self.segments[start:end]))
        found.extend(self.segments)
        return list(dict.fromkeys(found))

    def needles(self) -> dict[str, str]:
        """needle text -> a label naming its form (for the failure message)."""
        found: dict[str, str] = {}
        for piece in self.pieces():
            for label, text in encodings(piece).items():
                if len(text) >= 6:
                    found.setdefault(text, f"{label}({piece[:12]}...)")
        # The host and the fixed path prefix are not secret on their own, but the spec keeps
        # every output free of them: a URL, even a partial one, is never printed.
        found.setdefault(HOST, "host")
        found.setdefault("/triggers/", "path prefix")
        return found


def _b64_slice(data: bytes, shift: int, *, urlsafe: bool) -> str:
    """The base64 characters that depend only on ``data``, when ``shift`` unknown bytes (0 to 2)
    come before it and more follow (the characters at the edges mix in neighbouring bytes)."""
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    text = encode(b"\x00" * shift + data + b"\x00\x00\x00").decode("ascii")
    first = -(-shift * 8 // 6)  # ceil(8 * shift / 6): the first character free of the shift
    last = (shift + len(data)) * 8 // 6  # floor: the last character free of what follows
    return text[first:last]


def encodings(piece: str) -> dict[str, str]:
    raw = piece.encode("utf-8")
    forms: dict[str, str] = {
        "raw": piece,
        "percent": quote(piece, safe=""),
        "percent-lower": quote(piece, safe="").lower(),
        "percent-all": "".join(f"%{byte:02X}" for byte in raw),
        "percent-all-lower": "".join(f"%{byte:02x}" for byte in raw),
        "hex": raw.hex(),
        "hex-upper": raw.hex().upper(),
        "reversed": piece[::-1],
        "json-escaped": piece.replace("/", "\\/"),
        "unicode-escaped": "".join(f"\\u{ord(c):04x}" for c in piece),
    }
    for shift in range(3):
        forms[f"base64+{shift}"] = _b64_slice(raw, shift, urlsafe=False)
        forms[f"base64url+{shift}"] = _b64_slice(raw, shift, urlsafe=True)
    # A padded or unpadded whole encoding is the shift 0 form plus its tail.
    forms["base64-padded"] = base64.b64encode(raw).decode("ascii")
    forms["base64url-padded"] = base64.urlsafe_b64encode(raw).decode("ascii")
    forms["base64-unpadded"] = forms["base64-padded"].rstrip("=")
    return {label: text for label, text in forms.items() if text}


def scan(blobs: Mapping[str, bytes], secret: Secret) -> list[str]:
    """Every ``blob name: needle form`` found. Text and bytes are searched as UTF-8, and as the
    blob with its escapes undone for the JSON and percent forms a log or document could use."""
    hits: list[str] = []
    needles = secret.needles()
    for name, data in blobs.items():
        views = [data]
        try:
            views.append(data.decode("utf-8", "replace").encode("utf-8", "replace"))
        except (UnicodeError, binascii.Error):  # pragma: no cover - scanning must not crash
            pass
        for text, label in needles.items():
            if any(text.encode("utf-8") in view for view in views):
                hits.append(f"{name}: {label}")
    return hits


@dataclass
class Corpus:
    """Named byte blobs: what a run left anywhere a caller could look."""

    blobs: dict[str, bytes] = field(default_factory=dict)

    def add(self, name: str, data: bytes | str) -> None:
        self.blobs[name] = data if isinstance(data, bytes) else data.encode("utf-8", "replace")

    def add_tree(self, root: Path) -> None:
        """Every name and every readable regular file under ``root`` (links are not followed)."""
        for current, dirs, files in os.walk(root, followlinks=False):
            for entry in [*dirs, *files]:
                path = Path(current, entry)
                relative = str(path.relative_to(root))
                self.add("name:" + relative, relative)
                try:
                    mode = path.lstat().st_mode
                    if stat.S_ISLNK(mode):
                        self.add("link:" + relative, os.readlink(path))
                    elif stat.S_ISREG(mode):
                        self.add("file:" + relative, path.read_bytes())
                except OSError:
                    continue

    def extend(self, items: Iterable[tuple[str, bytes | str]]) -> None:
        for name, data in items:
            self.add(name, data)

    def hits(self, secret: Secret) -> list[str]:
        return scan(self.blobs, secret)

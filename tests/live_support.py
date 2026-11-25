"""Helpers for the live suite (#33). Everything here is exercised offline by
``tests/test_live_support.py``; nothing in this module opens a connection by itself.

Safety model, in one place:

- ``decide`` is the only gate: the live tests run only when an explicit opt-in names the variable
  that holds the trigger URL, and never when ``CI`` (or a known CI marker) is set.
- The URL travels in a ``TriggerUrl`` whose ``repr`` and ``str`` are fixed text, so a failing
  assertion or a traceback cannot print it. Reports record counts and character classes only.
- ``LiveGateway`` refuses to post any request body that lacks one of the fixed marker texts, so a
  live test can only ever post marked test messages.
- This file holds no URL literal: the scheme separator and the host are assembled from parts.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import re
import secrets
import ssl
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, NoReturn

from slack_notice import __version__, webhook
from slack_notice.cli import Streams, main
from slack_notice.gateway import (
    CaCandidates,
    Connection,
    NoUsableCA,
    Response,
    SystemGateway,
    build_tls_context,
)
from slack_notice.render import serialize

# --- the opt-in and the CI refusal ----------------------------------------------------------

OPT_IN_VAR = "SLACK_NOTICE_LIVE_URL_ENV"
REPORT_VAR = "SLACK_NOTICE_LIVE_REPORT"
CI_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "BUILDKITE",
    "JENKINS_URL",
    "TF_BUILD",
    "GITLAB_CI",
    "TRAVIS",
    "TEAMCITY_VERSION",
    "CODEBUILD_BUILD_ID",
    "DRONE",
    "BITBUCKET_BUILD_NUMBER",
)
_VARIABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}", re.ASCII)
# The tool's own credential variable name; the live suite hands the URL to the tool under it.
TOOL_ENV = "SLACK_WEBHOOK"

MARKER = "slack-notice live test"
TEST_MESSAGE_MARKER = "validate: test message"
SCHEME = "https" + "://"
LF = "\n"


@dataclass(frozen=True)
class Decision:
    action: Literal["run", "skip", "refuse"]
    reason: str
    url_env: str | None = None


def decide(env: Mapping[str, str]) -> Decision:
    """Whether the live tests may run. The reason never holds a value from ``env``."""
    for name in CI_VARS:
        if env.get(name):
            return Decision("refuse", f"refusing to run live tests: {name} is set (CI detected)")
    opt_in = env.get(OPT_IN_VAR)
    if opt_in is None or opt_in == "":
        return Decision("skip", f"live tests are opt-in: set {OPT_IN_VAR} to a variable name")
    if _VARIABLE_NAME.fullmatch(opt_in) is None or opt_in == OPT_IN_VAR:
        return Decision(
            "refuse", f"{OPT_IN_VAR} must be the NAME of the variable that holds the trigger URL"
        )
    if not env.get(opt_in, "").strip():
        return Decision("refuse", f"{OPT_IN_VAR} names a variable that is unset or empty")
    return Decision("run", "opt-in present", opt_in)


# --- the secret URL ------------------------------------------------------------------------

_TRIM = " \t\n\r\x0b\x0c"
_REDACTED = "<trigger url redacted>"
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


class TriggerUrl:
    """The maintainer's trigger URL. Printing it, formatting it or putting it in a failure
    message shows fixed text; only ``reveal`` returns the value."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_value", value.strip(_TRIM))

    def reveal(self) -> str:
        return self._value

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("TriggerUrl is immutable")

    def __repr__(self) -> str:
        return _REDACTED

    def __str__(self) -> str:
        return _REDACTED

    def __reduce__(self) -> NoReturn:
        raise TypeError("TriggerUrl cannot be pickled")


def char_classes(text: str) -> list[str]:
    """The character classes present in ``text``: names only, never characters."""
    found: set[str] = set()
    for char in text:
        if "A" <= char <= "Z":
            found.add("upper")
        elif "a" <= char <= "z":
            found.add("lower")
        elif "0" <= char <= "9":
            found.add("digit")
        elif char == "_":
            found.add("underscore")
        elif char == "-":
            found.add("hyphen")
        elif ord(char) > 127:
            found.add("non_ascii")
        elif char in " \t\n\r\x0b\x0c":
            found.add("whitespace")
        else:
            found.add("other_ascii")
    return sorted(found)


@dataclass(frozen=True)
class Shape:
    """What the V4 record keeps of a trigger URL: counts and classes, no value."""

    matches_allowlist: bool
    prefix_ok: bool
    total_length: int
    segment_count: int | None
    segment_lengths: tuple[int, ...]
    segment_classes: tuple[tuple[str, ...], ...]
    charset: tuple[str, ...]
    extras: tuple[str, ...]

    def summary(self) -> dict[str, Any]:
        return {
            "matches_allowlist": self.matches_allowlist,
            "prefix_ok": self.prefix_ok,
            "total_length": self.total_length,
            "segment_count": self.segment_count,
            "segment_lengths": list(self.segment_lengths),
            "segment_classes": [list(item) for item in self.segment_classes],
            "charset_classes": list(self.charset),
            "extras": list(self.extras),
        }


def describe_shape(url: TriggerUrl) -> Shape:
    """Allowlist verdict (the tool's own ``read_webhook``) plus counts and character classes."""
    value = url.reveal()
    matches = True
    try:
        webhook.read_webhook({"V": value}, "V")
    except webhook.CredentialInvalid:
        matches = False
    prefix = SCHEME + webhook.HOST + "/triggers/"
    extras: list[str] = []
    if not value.startswith(prefix):
        return Shape(matches, False, len(value), None, (), (), tuple(char_classes(value)), ())
    rest = value[len(prefix) :]
    for marker, name in (("?", "query"), ("#", "fragment")):
        if marker in rest:
            extras.append(name)
    path = re.split(r"[?#]", rest, maxsplit=1)[0]
    if "@" in path:
        extras.append("userinfo_like")
    if ":" in path:
        extras.append("colon_or_port_like")
    if path.endswith("/"):
        extras.append("trailing_slash")
    segments = path.split("/")
    if any(not item for item in segments):
        extras.append("empty_segment")
    return Shape(
        matches,
        True,
        len(value),
        len(segments),
        tuple(len(item) for item in segments),
        tuple(tuple(char_classes(item)) for item in segments),
        tuple(char_classes(path.replace("/", ""))),
        tuple(extras),
    )


def alter_last_segment(
    url: TriggerUrl, choose: Callable[[str], str] = secrets.choice
) -> TriggerUrl:
    """A syntactically valid URL whose last segment is random (at least 24 characters, 128+
    bits): it cannot reach another workflow in practice. Raises ``ValueError`` (no value in the
    message) for a URL that does not match the allowlist."""
    shape = describe_shape(url)
    if not shape.matches_allowlist:
        raise ValueError("not a trigger URL")
    head, _, last = url.reveal().rpartition("/")
    length = max(len(last), 24)
    return TriggerUrl(head + "/" + "".join(choose(_ALPHABET) for _ in range(length)))


# --- the recorded request ------------------------------------------------------------------


@dataclass
class Exchange:
    """One request through the gateway: sizes, times and the status, never a URL or header."""

    started: float
    request_bytes: int
    request_body: bytes
    status: int | None = None
    response_body: bytes = b""
    elapsed_ms: int | None = None
    error: str | None = None


class LiveExit(BaseException):  # noqa: N818  (nothing may swallow the end of the process)
    """Raised by ``LiveGateway.exit_now`` instead of ending the pytest process."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class MarkerRefused(AssertionError):
    """A request body without a marker text was about to be posted."""


def body_is_marked(body: bytes, markers: Sequence[str]) -> bool:
    text = body.decode("utf-8", errors="replace")
    return any(marker in text for marker in markers)


class _RecordingResponse:
    def __init__(self, inner: Response, exchange: Exchange, clock: Callable[[], float]) -> None:
        self._inner = inner
        self._exchange = exchange
        self.status = inner.status
        exchange.status = inner.status
        exchange.elapsed_ms = round((clock() - exchange.started) * 1000)

    def read(self, amount: int) -> bytes:
        data = self._inner.read(amount)
        if len(self._exchange.response_body) < 4096:
            self._exchange.response_body += data
        return data


class _RecordingConnection:
    def __init__(
        self,
        inner: Connection,
        sink: Callable[[Exchange], None],
        markers: Sequence[str],
        clock: Callable[[], float],
    ) -> None:
        self._inner = inner
        self._sink = sink
        self._markers = markers
        self._clock = clock
        self._exchange: Exchange | None = None

    def connect(self) -> None:
        self._inner.connect()

    def post(self, path: str, body: bytes) -> None:
        if not body_is_marked(body, self._markers):
            raise MarkerRefused("a live request body must carry a marker text")
        self._exchange = Exchange(self._clock(), len(body), body)
        self._sink(self._exchange)
        try:
            self._inner.post(path, body)
        except BaseException as exc:
            self._exchange.error = type(exc).__name__
            raise

    def getresponse(self) -> Response:
        exchange = self._exchange
        try:
            response = self._inner.getresponse()
        except BaseException as exc:
            if exchange is not None:
                exchange.error = type(exc).__name__
            raise
        if exchange is None:
            return response
        return _RecordingResponse(response, exchange, self._clock)

    def settimeout(self, seconds: float) -> None:
        self._inner.settimeout(seconds)

    def close(self) -> None:
        self._inner.close()


class LiveGateway(SystemGateway):
    """The production gateway with three differences: ``exit_now`` raises ``LiveExit`` (the tool
    ends its process with ``os._exit``, which would end pytest), every request is recorded, and
    a body without a marker text is refused. ``connect`` replaces the connection factory (the
    offline tests pass a fake gateway's); ``tls`` replaces the TLS context."""

    def __init__(
        self,
        *,
        sink: Callable[[Exchange], None] | None = None,
        markers: Sequence[str] = (MARKER,),
        connect: Callable[..., Connection] | None = None,
        tls: Callable[[], ssl.SSLContext] | None = None,
    ) -> None:
        self.exchanges: list[Exchange] = []
        self._sink = sink
        self._markers = tuple(markers)
        self._connect = connect
        self._tls = tls

    def _record(self, exchange: Exchange) -> None:
        self.exchanges.append(exchange)
        if self._sink is not None:
            self._sink(exchange)

    def exit_now(self, code: int) -> NoReturn:
        if type(code) is not int or not 0 <= code <= 255:
            raise ValueError("an exit code is an integer from 0 to 255")
        raise LiveExit(code)

    def tls_context(self) -> ssl.SSLContext:
        return super().tls_context() if self._tls is None else self._tls()

    def https_connection(
        self, host: str, port: int, *, timeout: float, context: ssl.SSLContext, user_agent: str
    ) -> Connection:
        opener = super().https_connection if self._connect is None else self._connect
        inner = opener(host, port, timeout=timeout, context=context, user_agent=user_agent)
        return _RecordingConnection(inner, self._record, self._markers, self.monotonic)


INTERRUPT_CODES = (130, 143)


# --- running the real CLI in-process -------------------------------------------------------


@dataclass
class CliResult:
    code: int
    out: bytes
    err: bytes
    exchanges: list[Exchange]
    elapsed_s: float

    @property
    def document(self) -> dict[str, Any] | None:
        try:
            value = json.loads(self.out.decode("utf-8"))
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    @property
    def error(self) -> dict[str, Any]:
        document = self.document or {}
        error = document.get("error")
        return error if isinstance(error, dict) else {}


def run_cli(
    argv: Sequence[str],
    *,
    url: TriggerUrl,
    gateway: LiveGateway,
    work: Path,
    notification: Mapping[str, Any] | None = None,
    config: str = "max_chars: 12000\ntimeout: 30s\n",
) -> CliResult:
    """``cli.main`` in-process with ``gateway``. The notification goes through ``--file``, the
    config through ``--config`` in ``work``; the home directory is the isolated one that the
    conftest guard installs. The URL reaches the tool only through the environment mapping
    handed to ``main``, under the tool's own credential variable."""
    work.mkdir(parents=True, exist_ok=True)
    config_path = work / "config.yaml"
    config_path.write_text(config, encoding="utf-8")
    full = list(argv)
    if notification is not None:
        notice = work / f"notice-{len(list(work.glob('notice-*.json')))}.json"
        notice.write_text(json.dumps(notification), encoding="utf-8")
        full += ["--file", str(notice)]
    full += ["--config", str(config_path)]
    out, err = io.BytesIO(), io.BytesIO()
    streams = Streams(out, err, lambda: False)
    before = len(gateway.exchanges)
    started = time.monotonic()
    try:
        code = main(full, {TOOL_ENV: url.reveal()}, gateway, streams)
    except LiveExit as end:
        if end.code in INTERRUPT_CODES:
            # The tool ends with 130 or 143 on SIGINT or SIGTERM: stop the whole run instead of
            # carrying on with the next live test.
            raise KeyboardInterrupt from None
        code = end.code
    return CliResult(
        code, out.getvalue(), err.getvalue(), gateway.exchanges[before:], time.monotonic() - started
    )


# --- message building ----------------------------------------------------------------------

DEFAULT_PREFIX = {
    "info": "\U0001f535 INFO",
    "warn": "\U0001f7e0 WARN",
    "action": "\U0001f7e1 ACTION",
    "error": "\U0001f534 ERROR",
}


def request_body_bytes(prefix_line: str, message: str, variable: str = "body") -> int:
    """The serialized request body length for a no-link notification."""
    return len(serialize(variable, prefix_line + LF + message))


def message_for_body_size(
    label: str, target: int, *, level: str = "info", title: str | None = None
) -> str:
    """An ASCII message whose notification serializes to exactly ``target`` bytes (no link),
    starting with the label and ending with ``END-<label>`` so a delivered message shows that it
    arrived whole."""
    prefix_line = DEFAULT_PREFIX[level] + ("" if title is None else " " + title)
    head, tail = f"{label} start ", f" END-{label}"
    size = request_body_bytes(prefix_line, head + tail)
    if target < size:
        raise ValueError("target is smaller than the fixed part")
    return head + "x" * (target - size) + tail


def unit_message(label: str, unit: str, width: int, title: str) -> tuple[str, int]:
    """A message of ``count`` copies of ``unit`` (``width`` UTF-8 bytes each) that brings the
    request body of a no-link ``info`` notification just under 12000 bytes. Returns the message
    and the count."""
    head, tail = f"{label} start ", f" END-{label}"
    base = request_body_bytes(DEFAULT_PREFIX["info"] + " " + title, head + tail)
    count = (11990 - base) // width
    return head + unit * count + tail, count


def raw_limit_text(label: str, unit: str, size: int) -> str:
    """The text of a raw limit post: ``size`` is the request body length in bytes for the ASCII
    unit ``x`` and the number of characters of the text for any other unit."""
    if unit == "x":
        base = len(serialize("body", repeated_text(label, "", 0)))
        return repeated_text(label, "x", size - base)
    return repeated_text(label, unit, size)


def repeated_text(label: str, unit: str, count: int) -> str:
    """``<label> start`` + ``count`` copies of ``unit`` + ``END-<label>``: a raw-post text."""
    return f"{MARKER} {label} start {unit * count} END-{label}"


# --- raw requests (the cases the CLI cannot or must not produce) ---------------------------

_HEADER_WHITELIST = (
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
    "retry-after",
    "content-encoding",
    "server",
)


@dataclass
class RawResult:
    status: int
    reason: str
    http_version: int
    headers: dict[str, str]
    location_present: bool
    will_close: bool
    body: str
    elapsed_ms: int
    header_count: int = 0
    header_bytes: int = 0

    def summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "http_version": self.http_version,
            "headers": self.headers,
            "location_present": self.location_present,
            "will_close": self.will_close,
            "header_count": self.header_count,
            "header_bytes": self.header_bytes,
            "body": self.body,
            "elapsed_ms": self.elapsed_ms,
        }


def raw_exchange(
    conn: Any,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    markers: Sequence[str] = (MARKER,),
    clock: Callable[[], float] = time.monotonic,
) -> RawResult:
    """One request on ``conn`` (an ``http.client`` connection). A GET carries no body. A POST
    body must carry a marker text. Bounded read of at most 4096 bytes of the answer."""
    if method == "GET":
        if body is not None:
            raise ValueError("a GET carries no body")
    elif method == "POST":
        if body is None or not body_is_marked(body, markers):
            raise MarkerRefused("a live request body must carry a marker text")
    else:
        raise ValueError("only GET and POST are used")
    sent = {"Connection": "close", "Accept": "application/json"}
    sent.update(headers or {})
    started = clock()
    conn.request(method, path, body=body, headers=sent)
    response = conn.getresponse()
    elapsed = round((clock() - started) * 1000)
    data = response.read(4096)
    kept: dict[str, str] = {}
    for name in _HEADER_WHITELIST:
        value = response.getheader(name)
        if value is not None:
            kept[name] = value[:120]
    every = getattr(response, "headers", None)
    pairs = list(every.items()) if every is not None else []
    return RawResult(
        status=response.status,
        reason=str(response.reason)[:60],
        http_version=response.version,
        headers=kept,
        location_present=response.getheader("location") is not None,
        will_close=bool(response.will_close),
        body=data.decode("utf-8", errors="replace")[:200],
        elapsed_ms=elapsed,
        header_count=len(pairs),
        header_bytes=sum(len(str(k)) + len(str(v)) + 4 for k, v in pairs),
    )


def open_raw_connection(
    gateway: SystemGateway, timeout: float = 15.0
) -> http.client.HTTPSConnection:
    """A verified HTTPS connection object to the webhook host (nothing is connected yet): the
    tool's own TLS context, no proxy, HTTP/1.1."""
    return http.client.HTTPSConnection(
        webhook.HOST, webhook.PORT, timeout=timeout, context=gateway.tls_context()
    )


# --- pacing --------------------------------------------------------------------------------


class Pacer:
    """At least ``gap`` seconds between the starts of two network actions of the suite (the
    tool's own lock spaces its sends only inside one test's private home)."""

    def __init__(
        self,
        gap: float = 1.5,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._gap = gap
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._last is not None and now - self._last < self._gap:
            self._sleep(self._gap - (now - self._last))
        self._last = self._clock()

    def mark(self) -> None:
        """Note that a network action just ended: the next ``wait`` counts from here, so a
        series of several sends is followed by the full gap too."""
        self._last = self._clock()


def gaps(exchanges: Sequence[Exchange]) -> list[float]:
    """Seconds between the starts of consecutive requests."""
    return [round(b.started - a.started, 3) for a, b in zip(exchanges, exchanges[1:], strict=False)]


# --- the report ----------------------------------------------------------------------------

ITEMS: dict[str, str] = {
    "V1": "sustained rate Slack accepts (1 s spacing)",
    "V2": "403/404/410 for a wrong URL; GET on a trigger URL",
    "V3": "length limit counts characters or bytes",
    "V4": "segment count and character set of the real trigger URL",
    "V5": "a 5xx after processing (not reproducible; any 5xx seen is listed)",
    "V18": "compiled default CA paths of this Python",
    "V21": "HTTP/1.1 with Connection: close through http.client",
    "O1": "request header for idempotency (Idempotency-Key tried)",
    "O2": "two machines sharing a workflow (manual)",
    "R": "rendering and wire assumptions (#37 lists)",
    "T": "TLS, DNS and timing details (#37 lists)",
    "N": "not reproducible in a live run (listed so they are not forgotten)",
}


@dataclass
class ManualCheck:
    item: str
    label: str
    expect: str


class Recorder:
    """What a live run learned, as plain data. The report text has the trigger URL and its path
    segments (``add_secret``) replaced by fixed text before it is returned or written."""

    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id or secrets.token_hex(3)
        self.observations: dict[str, dict[str, Any]] = {}
        self.manual_checks: list[ManualCheck] = []
        self.outcomes: dict[str, str] = {}
        self.statuses: dict[int, int] = {}
        self.latencies_ms: list[int] = []
        self._secrets: list[str] = []
        self.redactions = 0
        self.raw_failures = 0

    def add_secret(self, value: str) -> None:
        self._register(value)
        _, found, rest = value.partition("/triggers/")
        if found:  # only the path segments after the fixed prefix are secret
            for part in re.split(r"[/?#]", rest):
                if len(part) >= 8:
                    self._register(part)

    def _register(self, value: str) -> None:
        if value and value not in self._secrets:
            self._secrets.append(value)

    def observe(self, item: str, key: str, value: Any) -> None:
        if item not in ITEMS:
            raise KeyError(item)
        self.observations.setdefault(item, {})[key] = value

    def manual(self, item: str, label: str, expect: str) -> None:
        if item not in ITEMS:
            raise KeyError(item)
        self.manual_checks.append(ManualCheck(item, label, expect))

    def tally(self, exchanges: Sequence[Exchange]) -> None:
        for item in exchanges:
            if item.status is not None:
                self.statuses[item.status] = self.statuses.get(item.status, 0) + 1
            if item.elapsed_ms is not None:
                self.latencies_ms.append(item.elapsed_ms)

    def tally_raw(self, result: RawResult) -> None:
        self.statuses[result.status] = self.statuses.get(result.status, 0) + 1
        self.latencies_ms.append(result.elapsed_ms)

    def _finish(self) -> dict[str, Any]:
        fives = sum(count for status, count in self.statuses.items() if 500 <= status <= 599)
        self.observe("V5", "5xx_seen_in_this_run", fives)
        if self.latencies_ms:
            ordered = sorted(self.latencies_ms)
            self.observe(
                "T",
                "time_to_response_ms",
                {
                    "count": len(ordered),
                    "min": ordered[0],
                    "median": ordered[len(ordered) // 2],
                    "max": ordered[-1],
                },
            )
        if self.raw_failures:
            self.observe("T", "raw_requests_failed", self.raw_failures)
        self.observe("V5", "statuses_seen", {str(k): v for k, v in sorted(self.statuses.items())})
        items: dict[str, Any] = {}
        for item, title in ITEMS.items():
            observed = self.observations.get(item)
            manual = [m for m in self.manual_checks if m.item == item]
            if observed and manual:
                state = "observed; also observe manually"
            elif observed:
                state = "observed"
            elif manual:
                state = "observe manually"
            else:
                state = "not run"
            items[item] = {
                "title": title,
                "state": state,
                "observed": observed or {},
                "look_at_the_destination": [{"label": m.label, "expect": m.expect} for m in manual],
            }
        return {
            "report": "slack-notice live run",
            "run_id": self.run_id,
            "tool_version": __version__,
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "items": items,
            "tests": dict(sorted(self.outcomes.items())),
        }

    def to_json(self) -> str:
        text = json.dumps(self._finish(), indent=2, ensure_ascii=True, sort_keys=False)
        return self._scrub(text) + "\n"

    def to_text(self) -> str:
        data = self._finish()
        lines = [
            f"slack-notice live run {data['run_id']} (tool {data['tool_version']}, "
            f"python {data['python']}, {data['platform']})",
            "",
        ]
        for item, entry in data["items"].items():
            lines.append(f"{item}: {entry['title']} -> {entry['state']}")
            for key, value in entry["observed"].items():
                lines.append(f"    {key} = {json.dumps(value, ensure_ascii=True)}")
            for check in entry["look_at_the_destination"]:
                lines.append(f"    LOOK AT THE DESTINATION: {check['label']}")
                lines.append(f"        expect: {check['expect']}")
                lines.append("        result: [ ] as expected   [ ] missing or different")
            lines.append("")
        if self.raw_failures:
            lines.append(f"raw requests failed: {self.raw_failures} (the run is incomplete)")
            lines.append("")
        lines.append("tests:")
        lines += [f"    {name}: {state}" for name, state in data["tests"].items()]
        return self._scrub("\n".join(lines) + "\n")

    def _scrub(self, text: str) -> str:
        """Replace any trigger URL material by fixed text: the report is always written, because
        losing it after a full run would cost every post that produced it."""
        for secret in sorted(self._secrets, key=len, reverse=True):
            hits = text.count(secret)
            if hits:
                self.redactions += hits
                text = text.replace(secret, _REDACTED)
        return text

    def write(self, directory: Path) -> tuple[Path, Path]:
        """Write ``report.json`` and ``report.txt`` (mode 0600) into ``directory``."""
        directory.mkdir(parents=True, exist_ok=True)
        pairs = (("report.json", self.to_json()), ("report.txt", self.to_text()))
        paths = []
        for name, text in pairs:
            path = directory / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
            paths.append(path)
        return paths[0], paths[1]


def ca_sources(candidates: CaCandidates) -> dict[str, Any]:
    """Which of the tool's CA sources load certificates on this machine, using the tool's own
    ``build_tls_context`` on one source at a time (local file reads only, no network). ``used``
    names what the tool itself would use: the compiled file and directory when usable, else the
    first usable fallback bundle. A directory counts certificates only once they are loaded, so
    its count may be 0 while it is usable."""
    probes = {
        "cafile": CaCandidates(candidates.cafile, None, ()),
        "capath": CaCandidates(None, candidates.capath, ()),
        "fallback": CaCandidates(None, None, candidates.fallback_files),
    }
    counts: dict[str, int | None] = {}
    for name, probe in probes.items():
        try:
            counts[name] = build_tls_context(probe).cert_store_stats().get("x509_ca", 0)
        except NoUsableCA:
            counts[name] = None
    used = [name for name in ("cafile", "capath") if counts[name] is not None]
    if not used and counts["fallback"] is not None:
        used = ["fallback"]
    return {"loaded_ca_certs": counts, "used": used or ["none"]}


def report_directory(env: Mapping[str, str]) -> Path:
    """The directory named by the report variable, else a new private temp directory."""
    named = env.get(REPORT_VAR)
    if named:
        return Path(named)
    return Path(tempfile.mkdtemp(prefix="slack-notice-live-"))

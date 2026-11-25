"""The credential never leaves the process: the whole send path against the fake gateway (#29).

Every scenario runs ``cli.main`` in-process, in each output mode, with the fake credential in
the environment, the cwd and the temp dir inside the private tree. Each states the exact exit
code and the envelope code (or outcome) it must end with, and the shape of stdout the Output
section gives for the mode. Afterwards the scanner looks for the URL, its path, every segment
and their encodings in both streams, the real file descriptors, warnings, logging, the argv and
env of anything spawned (a spawn is refused), every file name and file under the whole private
tree (home, state directory, config, locks, log, cwd, temp) and the fake gateway's own record.
Every injected exception must really have been raised, and the matrix is itself mutation-tested:
production patched to leak into each place makes it fail.
"""

from __future__ import annotations

import http.client
import logging
import os
import signal
import ssl
import subprocess
import tempfile
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, webhook
from slack_notice.gateway import SourceRead
from slack_notice.log import STATE_WARNING
from tests.fake_gateway import (
    Attempt,
    FakeGateway,
    Reply,
)
from tests.harness import assert_valid
from tests.secret_scan import Corpus, Secret, encodings
from tests.send_harness import ENV_NAME, Sent, go, state_path, stdin_json, write_config
from tests.test_send import HELLO, OK, ROWS, reply
from tests.test_send_runtime import (
    free_the_lock_before_the_log,
    hold_the_response,
    worker_raising,
)

SECRET = Secret()
URL = SECRET.url
MODES = [[], ["--json"], ["--verbose"], ["--quiet"], ["--json", "--verbose"], ["--json", "--quiet"]]


def corpus_of(sent: Sent, gateway: FakeGateway, tmp_path: Path) -> Corpus:
    corpus = Corpus()
    corpus.add("stdout", sent.out)
    corpus.add("stderr", sent.err)
    corpus.add_tree(tmp_path)
    corpus.add("gateway.events", "\n".join(gateway.events))
    corpus.add("gateway.calls", "\n".join(gateway.calls))
    corpus.add("gateway.read_paths", "\n".join(gateway.read_paths))
    corpus.add("gateway.violations", "\n".join(gateway.violations))
    corpus.add("document", repr(sent.out))
    corpus.add("repr(state files)", repr(sent.state_files))
    return corpus


# --- the scanner can fail -----------------------------------------------------------------------


def test_the_scanner_has_every_form_of_every_piece() -> None:
    needles = SECRET.needles()
    labels = " ".join(needles.values())
    for form in ("raw", "percent", "percent-all", "hex", "reversed", "base64"):
        assert form in labels
    assert URL in needles and SECRET.path in needles and URL.removeprefix("https://") in needles
    for segment in SECRET.segments:
        assert segment in needles
    # an independent computation of two encodings, so the needles are not tautological
    import base64

    assert base64.b64encode(URL.encode()).decode().rstrip("=") in needles
    assert "".join(f"%{b:02X}" for b in SECRET.segments[0].encode()) in needles


@pytest.mark.parametrize("needle", sorted(SECRET.needles()))
def test_the_scan_fails_on_every_needle_in_a_stream(needle: str) -> None:
    corpus = Corpus()
    corpus.add("stdout", b'{"a":"' + needle.encode() + b'"}')
    assert corpus.hits(SECRET)
    clean = Corpus()
    clean.add("stdout", b'{"outcome":"sent"}')
    assert clean.hits(SECRET) == []


def planted() -> dict[str, bytes]:
    """Forms a leak could take that are not a plain encoding of the text, built from the parts."""
    segment = SECRET.segments[0]
    return {
        "utf-16le url": URL.encode("utf-16-le"),
        "utf-16be url": URL.encode("utf-16-be"),
        "utf-32le segment": segment.encode("utf-32-le"),
        "utf-32be segment": segment.encode("utf-32-be"),
        "utf-16 with a byte order mark": segment.encode("utf-16"),
        "upper-case url": URL.upper().encode(),
        "lower-case url": URL.lower().encode(),
        "upper-case host": SECRET.url.split("/")[2].upper().encode(),
        "upper-case segment": SECRET.segments[1].upper().encode(),
        "lower-case segment": SECRET.segments[2].lower().encode(),
        "window of a segment": segment[2:10].encode(),
        "window of the short segment": SECRET.segments[2].encode(),
    }


@pytest.mark.parametrize("form", sorted(planted()))
def test_the_scan_sees_the_wide_cased_and_windowed_forms(form: str) -> None:
    assert Corpus(blobs={"out": b"before " + planted()[form] + b" after"}).hits(SECRET), form


def test_the_scan_sees_a_value_wrapped_over_lines() -> None:
    wrapped = "\n".join(URL[i : i + 9] for i in range(0, len(URL), 9))
    assert Corpus(blobs={"out": wrapped.encode()}).hits(SECRET)
    spaced = " ".join(SECRET.segments[0])
    assert Corpus(blobs={"out": spaced.encode()}).hits(SECRET)


@pytest.mark.parametrize("cut", [8, 20, 31])
def test_the_scan_sees_a_value_split_between_two_streams(cut: int) -> None:
    corpus = Corpus()
    corpus.add("stdout", b"ok " + URL.encode()[:cut])
    corpus.add("stderr", URL.encode()[cut:] + b" end")
    assert corpus.hits(SECRET)
    reversed_order = Corpus()
    reversed_order.add("stderr", URL.encode()[cut:] + b" end")
    reversed_order.add("stdout", b"ok " + URL.encode()[:cut])
    assert reversed_order.hits(SECRET)


def test_the_scan_stays_quiet_on_a_short_run_and_on_clean_text() -> None:
    short = SECRET.segments[0][:7]  # below the 8-character window
    clean = b'{"outcome":"sent","level":"info"} sent (info, 12 ms)\n' + short.encode()
    assert Corpus(blobs={"out": clean, "err": b"", "big": b"x" * 5000}).hits(SECRET) == []


@pytest.mark.parametrize("where", ["content", "name", "nested", "link"])
def test_the_scan_fails_on_a_planted_file_name_content_or_link(where: str, tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "a" / "b").mkdir(parents=True)
    needle = encodings(SECRET.segments[1])["base64+1"]
    if where == "content":
        (root / "x").write_text("pre " + needle + " post")
    elif where == "name":
        (root / needle).write_text("")
    elif where == "nested":
        (root / "a" / "b" / "log.jsonl").write_bytes(b"\n" + needle.encode())
    else:
        os.symlink(needle, root / "l")
    corpus = Corpus()
    corpus.add_tree(root)
    assert corpus.hits(SECRET)


def test_a_real_run_scanned_with_a_planted_leak_fails_and_without_passes(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(OK)
    sent = go(["send", "--json", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env)
    assert sent.code == 0
    assert corpus_of(sent, fake_gateway, tmp_path).hits(SECRET) == []
    (state_path(fake_gateway) / "stray").write_text(SECRET.path)
    assert corpus_of(sent, fake_gateway, tmp_path).hits(SECRET)


def test_a_leaking_stream_is_caught_end_to_end(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    class Leaky:
        def __init__(self) -> None:
            self.data = b""

        def write(self, data: bytes) -> int:
            self.data += data
            return len(data)

        def flush(self) -> None:
            self.data += URL.encode()  # a bug that echoed the credential

    fake_gateway.script(OK)
    leaky = Leaky()
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env, err=leaky)
    assert corpus_of(sent, fake_gateway, tmp_path).hits(SECRET) == []  # the harness copy is clean
    assert Corpus(blobs={"err": leaky.data}).hits(SECRET)


# --- scenarios ----------------------------------------------------------------------------------


@dataclass
class Run:
    """What a scenario hands to ``go``."""

    stdin: bytes | SourceRead | None = HELLO
    env: Any = field(default_factory=lambda: dict(SECRET.env))
    config: str | None = None
    before: Callable[[], None] | None = None
    # the exact exit code and the envelope code (or the outcome of a success) every mode ends
    # with; "silent" is a signal before step 5, which ends with no envelope and no output
    code: int = 12
    kind: str = ""
    # every exception the scenario injects: each must really have been raised in the run (a
    # raised exception carries a traceback), so a scenario cannot pass by never reaching its fault
    raises: list[BaseException] = field(default_factory=list)
    checks: list[Callable[[], bool]] = field(default_factory=list)  # extra proofs of reach

    def __post_init__(self) -> None:
        assert self.kind, "a scenario states what it ends with"


Setup = Callable[[FakeGateway, pytest.MonkeyPatch, Path], Run]
SCENARIOS: dict[str, Setup] = {}


def scenario(name: str) -> Callable[[Setup], Setup]:
    def register(setup: Setup) -> Setup:
        assert name not in SCENARIOS
        SCENARIOS[name] = setup
        return setup

    return register


def injected(attempts: list[Attempt]) -> list[BaseException]:
    """The exceptions an attempt list will raise (as a field or as a reply or body error)."""
    found: list[BaseException] = []
    for attempt in attempts:
        for item in vars(attempt).values():
            candidates = [item, getattr(item, "body_error", None)]
            found.extend(c for c in candidates if isinstance(c, BaseException))
    return list(dict.fromkeys(found))


def add_attempts(
    name: str,
    attempts: list[Attempt] | Callable[[], list[Attempt]],
    kind: str,
    code: int = 12,
) -> None:
    """A callable builds fresh attempts (and exceptions) for every run."""

    def setup(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
        made = attempts() if callable(attempts) else attempts
        g.script(*made)
        return Run(code=code, kind=kind, raises=injected(made))

    SCENARIOS[name] = setup


# success, and every row of the Webhook edge table
add_attempts("success", [OK], "sent", 0)
add_attempts("success after a 429", [reply(429), OK], "sent", 0)
add_attempts(
    "success with extra keys",
    [Attempt(reply=Reply(body=b'{"ok":true,"u":"' + URL.encode() + b'"}'))],
    "sent",
    0,
)
for _name, (_attempts, _code, _want) in ROWS.items():
    assert _code == 12
    add_attempts("row: " + _name, _attempts, _want["code"])

# hostile responses: whatever the body says, the status decides
STATUS_KIND = {
    200: "wrong_host_response",
    400: "host_rejected",
    429: "rate_limited",
    500: "upstream_error",
    302: "wrong_host_response",
}
for _status in (200, 400, 429, 500, 302):
    for _label, _body in {
        "url": URL.encode(),
        "json-key": b'{"' + URL.encode() + b'":1}',
        "error-key": b'{"error":"' + URL.encode() + b'"}',
        "ok-value": b'{"ok":"' + URL.encode() + b'"}',
        "padded": b" " * 3000 + URL.encode(),
        "split": b'{"error":"' + SECRET.path.encode()[:12] + b"\\u002f" + b'x"}',
        "bad-utf8": b"\xff\xfe" + URL.encode(),
    }.items():
        add_attempts(
            f"body {_status} {_label}",
            [Attempt(reply=Reply(status=_status, body=_body))] * 3,
            STATUS_KIND[_status],
        )
for _framing in ("chunked", "eof"):
    add_attempts(
        f"body {_framing} url",
        [Attempt(reply=Reply(status=400, body=URL.encode(), framing=_framing))],
        "host_rejected",
    )
add_attempts(
    "headers with the url",
    [
        Attempt(
            reply=Reply(
                status=302,
                headers=(("Location", URL), ("Set-Cookie", "t=" + SECRET.path), ("X", URL)),
            )
        )
    ],
    "wrong_host_response",
)
add_attempts(
    "429 retry-after url",
    [Attempt(reply=Reply(status=429, headers=(("Retry-After", URL),)))] * 3,
    "rate_limited",
)

# exceptions that carry the URL, from every phase of the connection
EXCEPTIONS: dict[str, Callable[[], BaseException]] = {
    "ValueError": lambda: ValueError(URL),
    "InvalidURL": lambda: http.client.InvalidURL(URL),
    "OSError": lambda: OSError(13, URL, SECRET.path),
    "SSLError": lambda: ssl.SSLError(1, URL),
    "RuntimeError": lambda: RuntimeError(SECRET.path),
    "UnicodeEncodeError": lambda: UnicodeEncodeError("ascii", URL, 0, 1, URL),
    "KeyError": lambda: KeyError(URL),
    "chained": lambda: _chained(),
}


def _chained() -> BaseException:
    try:
        try:
            raise ValueError(URL)
        except ValueError as inner:
            raise http.client.InvalidURL(SECRET.path) from inner
    except http.client.InvalidURL as outer:
        return outer


PHASES: dict[str, Callable[[BaseException], Attempt]] = {
    "resolve": lambda e: Attempt(resolve_error=e),
    "connect": lambda e: Attempt(connect_error=e),
    "tls": lambda e: Attempt(tls_error=e),
    "write": lambda e: Attempt(write_error=e),
    "reply": lambda e: Attempt(reply=e),
    "body": lambda e: Attempt(reply=Reply(body_error=e)),
}


def phase_kind(phase: str, exception: str) -> str:
    """Before a request is written the failure is a network error; after it, the outcome is
    unknown, except for an ``http.client`` error (``InvalidURL``), which is a malformed answer."""
    if phase in ("resolve", "connect", "tls"):
        return "network_error"
    return "wrong_host_response" if exception in ("InvalidURL", "chained") else "outcome_unknown"


for _p, _make in PHASES.items():
    for _e, _exc in EXCEPTIONS.items():
        add_attempts(f"{_e} in {_p}", lambda m=_make, x=_exc: [m(x())] * 2, phase_kind(_p, _e))


def seed_state_file(g: FakeGateway, name: str, content: bytes) -> Callable[[], None]:
    """A ``before`` hook: a non-empty state file, so the code that needs one is reached."""

    def seed() -> None:
        directory = state_path(g)
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        target = directory / name
        target.write_bytes(content)
        os.chmod(target, 0o600)

    return seed


# the exception raised inside the gateway or the worker. Each method gets what it needs to be
# reached: an existing log for read_at, a retry wait for sleep.
def raising_gateway(method: str, exc: Callable[[], BaseException], code: int, kind: str) -> Setup:
    def setup(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
        raised = exc()

        def boom(*_a: Any, **_k: Any) -> Any:
            raise raised

        mp.setattr(g, method, boom)
        before = None
        if method == "sleep":
            g.script(reply(429), OK, OK)  # a 429 makes the worker wait before the retry
        else:
            g.script(OK, OK, OK)
        if method == "read_at":
            before = seed_state_file(g, "log.jsonl", b'{"old":1}\n')
        g.allow_unconsumed_script = True
        return Run(code=code, kind=kind, before=before, raises=[raised])

    return setup


# method -> (exit code, envelope code): the clock and the log are best effort or a bug (1)
GATEWAY_FAULTS = {
    "tls_context": (12, "network_error"),
    "https_connection": (12, "network_error"),
    "sleep": (1, "internal"),
    "monotonic": (1, "internal"),
    "wall_time": (0, "sent"),
    "read_at": (0, "sent"),
}
for _method, (_code, _kind) in GATEWAY_FAULTS.items():
    for _e in ("ValueError", "InvalidURL"):
        SCENARIOS[f"gateway.{_method} raises {_e}"] = raising_gateway(
            _method, EXCEPTIONS[_e], _code, _kind
        )


@scenario("tls_context finds no ca")
def _no_ca(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.no_usable_ca = True
    g.script(OK)
    g.allow_unconsumed_script = True
    return Run(kind="network_error")


for _after in (False, True):
    for _e in ("ValueError", "InvalidURL", "OSError"):

        def _worker(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, a=_after, e=_e) -> Run:
            raised = EXCEPTIONS[e]()

            def make(*_a: Any, **_k: Any) -> Any:
                def work(deadline: Any) -> Any:
                    if a:
                        assert deadline.enter_writing()
                    raise raised

                return work

            mp.setattr(cli, "attempt_work", make)
            return Run(code=1, kind="internal", raises=[raised])

        SCENARIOS[f"worker raises {_e} {'after' if _after else 'before'} writing"] = _worker


class UrlRepr(Exception):
    """An exception whose every text form is the credential."""

    def __str__(self) -> str:
        return URL

    def __repr__(self) -> str:
        return URL


@scenario("worker raises an exception whose str and repr are the url")
def _repr_worker(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    raised = UrlRepr(URL)

    def make(*_a: Any, **_k: Any) -> Any:
        def work(deadline: Any) -> Any:
            assert deadline.enter_writing()
            raise raised

        return work

    mp.setattr(cli, "attempt_work", make)
    return Run(code=1, kind="internal", raises=[raised])


@scenario("main thread bug before step 5")
def _main_bug(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    raised = ValueError(URL)

    def boom(*_a: Any, **_k: Any) -> Any:
        raise raised

    mp.setattr(cli, "render", boom)
    return Run(code=1, kind="internal", raises=[raised])


@scenario("worker raises with the helper from the runtime tests")
def _helper_worker(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    reached: list[bool] = []
    made = worker_raising(after_writing=True)

    def spy(*a: Any, **k: Any) -> Any:
        work = made(*a, **k)

        def run(deadline: Any) -> Any:
            reached.append(True)  # the helper raises its own RuntimeError right after this
            return work(deadline)

        return run

    mp.setattr(cli, "attempt_work", spy)
    return Run(code=1, kind="internal", checks=[lambda: bool(reached)])


@scenario("caller bug in the log call")
def _caller_bug(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    impossible = webhook.Outcome(12, "upstream_error", "fixed message", None, False, True)

    def fake_work(*_a: Any, **_k: Any) -> Any:
        return lambda deadline: (deadline.enter_writing(), impossible)[1]

    mp.setattr(cli, "attempt_work", fake_work)
    return Run(kind="upstream_error")


# credential_invalid variants: each keeps pieces of the secret in the rejected value
def credential(value: str | None, name: str) -> None:
    def setup(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
        return Run(kind="credential_invalid", env={} if value is None else {ENV_NAME: value})

    SCENARIOS["credential: " + name] = setup


credential(None, "unset")
credential("", "empty")
credential(" \t\r\n\x0b\x0c ", "whitespace")
for _n, _v in {
    "query": URL + "?x=1",
    "fragment": URL + "#f",
    "http": "http://" + URL.removeprefix("https://"),
    "port": "https://hooks.slack.com:443" + SECRET.path,
    "userinfo": "https://u:p@hooks.slack.com" + SECRET.path,
    "trailing dot": "https://hooks.slack.com." + SECRET.path,
    "upper host": "https://HOOKS.SLACK.COM" + SECRET.path,
    "other host": "https://hooks.example.invalid" + SECRET.path,
    "empty segment": URL.replace(SECRET.segments[1], "/" + SECRET.segments[1]),
    "five segments": URL + "/a/b",
    "trailing slash": URL + "/",
    "space in path": URL.replace("_29a", "_29a x"),
    "newline in path": URL + "\n" + SECRET.segments[0],
    "nul": URL + "\x00",
    "unicode": URL + "é",
    "percent": URL.replace(SECRET.segments[2], "%43" + SECRET.segments[2][1:]),
    "too long": URL + "a" * 1100,
    "doubled": URL + URL,
    "key=value": "SLACK_WEBHOOK=" + URL,
    "quoted": '"' + URL + '"',
    "bare path": SECRET.path,
    "bare segment": SECRET.segments[0],
    "wrong scheme case": "HTTPS://hooks.slack.com" + SECRET.path,
    "backslash": URL.replace("/triggers/", "\\triggers\\"),
}.items():
    credential(_v, _n)


@scenario("credential in the wrong variable")
def _wrong_variable(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(kind="credential_invalid", env={"OTHER": URL, "SLACK_NOTICE_WEBHOOK": URL})


@scenario("credential variable named by the config")
def _named_variable(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.script(reply(500))
    return Run(
        kind="upstream_error",
        env={"HOOK_X": URL},
        config=write_config(tmp, "webhook_env: HOOK_X\n"),
    )


@scenario("hostile environment mapping")
def _hostile_env(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    raised = RuntimeError(URL)

    class Hostile(dict[str, str]):
        def __getitem__(self, key: str) -> str:
            raise raised

    return Run(kind="credential_invalid", env=Hostile(), raises=[raised])


# input, lock and deadline cases
@scenario("input timeout")
def _input_timeout(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(kind="unavailable", stdin=SourceRead(b'{"messag', timed_out=True))


@scenario("input read raises with the url")
def _input_raises(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    raised = OSError(URL)
    return Run(
        stdin=None,
        code=2,
        kind="usage",
        before=lambda: g.source_script.append(raised),
        raises=[raised],
    )


@scenario("lock timeout")
def _lock_timeout(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    free_the_lock_before_the_log(g, mp)
    g.lock_held = True
    return Run(kind="unavailable", config=write_config(tmp, "timeout: 3\n"))


@scenario("lock error carries the url")
def _lock_error(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.lock_error = OSError(URL)
    g.script(OK)
    return Run(code=0, kind="sent", raises=[g.lock_error])


# label -> (attempt, exit code, envelope code or outcome); a trickle that fits is a success
DEADLINES: dict[str, tuple[Attempt, int, str]] = {
    "connect slower than the deadline": (Attempt(connect_delay=60.0), 12, "network_error"),
    "tls slower than the deadline": (Attempt(tls_delay=60.0), 12, "network_error"),
    "write slower than the deadline": (Attempt(write_delay=60.0), 12, "outcome_unknown"),
    "first byte slower than the deadline": (
        Attempt(reply=Reply(first_byte_delay=60.0)),
        12,
        "outcome_unknown",
    ),
    "body stalls": (
        Attempt(reply=Reply(body=b'{"ok":true}', body_stall_after=3)),
        12,
        "outcome_unknown",
    ),
    "head stalls": (Attempt(reply=Reply(head_stall_after=5)), 12, "outcome_unknown"),
    "body trickle": (Attempt(reply=Reply(body_trickle=0.5)), 0, "sent"),
}
for _label, (_attempt, _dcode, _dkind) in DEADLINES.items():

    def _deadline(
        g: FakeGateway,
        mp: pytest.MonkeyPatch,
        tmp: Path,
        a: Attempt = _attempt,
        c: int = _dcode,
        k: str = _dkind,
    ) -> Run:
        g.script(a, a)
        g.allow_unconsumed_script = True
        return Run(code=c, kind=k, config=write_config(tmp, "timeout: 3\n"))

    SCENARIOS["deadline: " + _label] = _deadline


@scenario("deadline: long 429 wait")
def _long_429(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.script(reply(429), reply(429), reply(429))
    return Run(kind="rate_limited", config=write_config(tmp, "timeout: 3\n"))


# signals
for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):

    def _signal_writing(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, s: int = _sig) -> Run:
        g.script(OK)
        g.allow_unconsumed_script = True
        hold_the_response(mp, s)
        return Run(kind="outcome_unknown")

    SCENARIOS[f"signal {_sig.name} while writing"] = _signal_writing

    def _signal_input(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, s: int = _sig) -> Run:
        real = g.read_source

        sent_signal: list[bool] = []

        def kill(source: Any, max_bytes: int, remaining: float) -> SourceRead:
            sent_signal.append(True)
            os.kill(os.getpid(), s)
            return real(source, max_bytes, remaining)

        mp.setattr(g, "read_source", kill)
        return Run(code=128 + int(s), kind="silent", checks=[lambda: bool(sent_signal)])

    SCENARIOS[f"signal {_sig.name} during input"] = _signal_input

    def _signal_credential(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, s: int = _sig) -> Run:
        sent_signal: list[bool] = []

        class Signalling(dict[str, str]):
            def __getitem__(self, key: str) -> str:
                sent_signal.append(True)
                os.kill(os.getpid(), s)
                return super().__getitem__(key)

        g.script(OK)
        g.allow_unconsumed_script = True
        return Run(
            kind="unavailable", env=Signalling(SECRET.env), checks=[lambda: bool(sent_signal)]
        )

    SCENARIOS[f"signal {_sig.name} while the credential is read"] = _signal_credential


# state directory, lock, log writer and send lock failing with the url in the exception
for _e in ("OSError", "ValueError", "InvalidURL"):

    def _state(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, e: str = _e) -> Run:
        raised = EXCEPTIONS[e]()
        g.state_dir_error = raised  # type: ignore[assignment]
        g.script(OK)
        return Run(code=1, kind="internal", raises=[raised])

    SCENARIOS[f"state dir raises {_e}"] = _state

    for _name in ("send.lock", "log.lock", "log.jsonl"):

        def _file(
            g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, e: str = _e, n: str = _name
        ) -> Run:
            raised = EXCEPTIONS[e]()
            g.state_file_errors[n] = raised
            g.script(OK)
            if n == "send.lock":  # the spacing lock is part of the send itself
                return Run(code=1, kind="internal", raises=[raised])
            return Run(code=0, kind="sent", raises=[raised])  # the log is best effort

        SCENARIOS[f"state file {_name} raises {_e}"] = _file

    for _hook in ("write_error", "truncate_error", "mtime_error", "set_mtime_error"):

        def _hooked(
            g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, e: str = _e, h: str = _hook
        ) -> Run:
            raised = EXCEPTIONS[e]()
            setattr(g, h, raised)
            before = None
            if h == "truncate_error":
                g.write_limit = 5  # a short write, so the cut back runs
            if h == "mtime_error":
                # the spacing wait reads the modification time only of a non-empty send.lock
                before = seed_state_file(g, "send.lock", b"x")
            g.script(OK)
            # spacing reads the modification time and only catches OSError and ValueError
            if h == "mtime_error" and e == "InvalidURL":
                return Run(code=1, kind="internal", before=before, raises=[raised])
            return Run(code=0, kind="sent", before=before, raises=[raised])

        SCENARIOS[f"{_hook} raises {_e}"] = _hooked


@scenario("log rotation rename raises with the url")
def _rotation(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    def big_log() -> None:
        directory = state_path(g)
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        log_file = directory / "log.jsonl"
        log_file.write_bytes(b"x" * (1024 * 1024 + 1))
        os.chmod(log_file, 0o600)

    raised = OSError(URL)
    g.rename_errors["log.jsonl"] = raised
    g.script(OK)
    return Run(code=0, kind="sent", before=big_log, raises=[raised])


@scenario("home lookup error")
def _home_error(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    mp.setattr(g, "_home_error", True)
    g.script(OK)
    return Run(code=2, kind="config_invalid", checks=[lambda: g.home_lookups >= 1])


@scenario("dry run with the credential in the environment")
def _dry(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(code=0, kind="dry_run")


@scenario("refusal")
def _refusal(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(stdin=stdin_json(title=SECRET.segments[0]), code=20, kind="refused")


@scenario("disabled")
def _disabled(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(code=22, kind="disabled", config=write_config(tmp, "enabled: false\n"))


@scenario("bad config")
def _bad_config(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(code=2, kind="config_invalid", config=write_config(tmp, "webhook_env: not a name\n"))


@scenario("log disabled")
def _log_off(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.script(reply(500))
    return Run(kind="upstream_error", config=write_config(tmp, "log: false\n"))


SPAWNERS = (
    ("subprocess", "Popen"),
    ("os", "posix_spawn"),
    ("os", "posix_spawnp"),
    ("os", "system"),
    ("os", "popen"),
    ("os", "fork"),
    ("os", "forkpty"),
    ("os", "execl"),
    ("os", "execle"),
    ("os", "execlp"),
    ("os", "execlpe"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "execvpe"),
)


def watch_spawns(mp: pytest.MonkeyPatch) -> list[str]:
    """Replace every way to start a process: a call is recorded (argv and env included, so the
    scan sees what a child would have received) and refused. A run must start nothing."""
    seen: list[str] = []

    def spy(label: str) -> Callable[..., Any]:
        def refused(*args: Any, **kwargs: Any) -> Any:
            seen.append(f"{label}: {args!r} {kwargs!r}")
            raise AssertionError(f"{label}: a process was started")

        return refused

    for module_name, attribute in SPAWNERS:
        module = {"subprocess": subprocess, "os": os}[module_name]
        if hasattr(module, attribute):
            mp.setattr(module, attribute, spy(f"{module_name}.{attribute}"))
    return seen


def check_case(
    name: str,
    mode: list[str],
    gateway: FakeGateway,
    mp: pytest.MonkeyPatch,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    recwarn: pytest.WarningsRecorder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Run one scenario in one output mode and assert what it must end with and that the
    credential is nowhere: not in the streams, the real descriptors, warnings, logging, a
    spawned child, any file under the private tree (the cwd and the temp dir are inside it) or
    the fake gateway's record."""
    gateway.allow_unconsumed_script = True
    cwd, temp = tmp_path / "cwd", tmp_path / "tmp"
    cwd.mkdir()
    temp.mkdir()
    mp.chdir(cwd)
    mp.setattr(tempfile, "tempdir", str(temp))
    spawned = watch_spawns(mp)
    caplog.set_level(0)
    run = SCENARIOS[name](gateway, mp, tmp_path)
    argv = ["send", *mode, "--stdin-json"]
    if name == "dry run with the credential in the environment":
        argv.append("--dry-run")
    capfd.readouterr()  # what the setup itself printed is not the run's
    sent = go(
        argv,
        gateway,
        stdin=run.stdin,
        env=run.env,
        config=run.config,
        before=run.before,
        validate_log=False,
    )
    gateway.release_stalls()
    real = capfd.readouterr()
    where = (name, mode)
    # what the run ends with: the exact code, and the shape of stdout the Output section gives
    assert sent.code == run.code, (*where, sent.code, sent.stderr)
    assert spawned == [], (*where, "a process was started")
    for exc in run.raises:  # the fault was really reached and raised in this run
        assert exc.__traceback__ is not None, (*where, "injected exception never raised")
    for check in run.checks:
        assert check(), (*where, "the injected path was never reached")
    check_shape(sent, run, mode, where)
    # nothing went to the real descriptors, to warnings or to logging
    assert real.out == "" and real.err == "", (*where, "real fd output", real.out, real.err)
    assert len(recwarn) == 0, (*where, [str(w.message) for w in recwarn])
    assert caplog.records == [], (*where, [r.getMessage() for r in caplog.records])
    corpus = corpus_of(sent, gateway, tmp_path)
    corpus.add("real stdout", real.out)
    corpus.add("real stderr", real.err)
    corpus.add("warnings", "\n".join(f"{w.category}: {w.message}" for w in recwarn))
    corpus.add("logging", caplog.text + "\n".join(r.getMessage() for r in caplog.records))
    corpus.add("spawned", "\n".join(spawned))
    hits = corpus.hits(SECRET)
    assert hits == [], (*where, hits)
    # a request, when one was made, went to the one fixed place
    for connection in gateway.connections:
        assert (connection.host, connection.port) == ("hooks.slack.com", 443)
        assert URL not in connection.user_agent and SECRET.path not in connection.user_agent
        for _path, body in connection.requests:
            assert SECRET.segments[0].encode() not in body
    assert gateway.violations == []


def check_shape(sent: Sent, run: Run, mode: list[str], where: tuple[Any, ...]) -> None:
    """Output section: no ``--json`` leaves stdout empty; ``--json`` prints exactly one document
    (the outcome of a success, the error envelope otherwise); a signal before step 5 prints
    nothing at all; ``--quiet`` keeps stderr to errors and warnings."""
    if run.kind == "silent" or "--json" not in mode:
        assert sent.out == b"", (*where, sent.out)
    elif run.code in (0, 22):
        assert sent.document["outcome"] == run.kind, where
        assert_valid("cli/send", sent.out)
    else:
        # not schema-checked: one scenario hands the CLI an impossible outcome on purpose
        assert sent.document["error"]["code"] == run.kind, (*where, sent.document)
    if run.kind == "silent":
        assert sent.err == b"", where
    if "--quiet" in mode and run.code in (0, 22):
        assert sent.stderr in ("", STATE_WARNING + "\n"), (*where, sent.stderr)


@pytest.mark.parametrize("mode", MODES, ids=lambda m: " ".join(m) or "plain")
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_the_credential_reaches_no_stream_no_file_and_no_record(
    name: str,
    mode: list[str],
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    recwarn: pytest.WarningsRecorder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    check_case(name, mode, fake_gateway, monkeypatch, tmp_path, capfd, recwarn, caplog)


# --- the matrix can fail ------------------------------------------------------------------------
# Production is mutated to leak the credential into one place; the matrix check must refuse it.


def leaking_render(mp: pytest.MonkeyPatch, leak: Callable[[], None]) -> None:
    """Make ``cli.render`` (always called by a send) leak first. The leak is wrapped so that a
    refusal raised inside it (a spawn spy, say) is swallowed: the matrix must still notice."""
    real = cli.render

    def render(*args: Any, **kwargs: Any) -> Any:
        try:
            leak()
        except Exception:
            pass
        return real(*args, **kwargs)

    mp.setattr(cli, "render", render)


def run_success(
    gateway: FakeGateway,
    mp: pytest.MonkeyPatch,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    recwarn: pytest.WarningsRecorder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    check_case("success", [], gateway, mp, tmp_path, capfd, recwarn, caplog)


def test_the_matrix_passes_a_clean_run(
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    recwarn: pytest.WarningsRecorder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    run_success(fake_gateway, monkeypatch, tmp_path, capfd, recwarn, caplog)


def leak_to_fd1() -> None:
    os.write(1, URL.encode())


def leak_to_fd2() -> None:
    os.write(2, URL.encode())


def leak_to_warnings() -> None:
    warnings.warn(URL, stacklevel=1)


def leak_to_a_child() -> None:
    subprocess.run(["true", URL], check=False)


def leak_to_the_cwd() -> None:
    Path("stray.txt").write_text(URL)


def leak_to_the_temp_dir() -> None:
    handle, _name = tempfile.mkstemp()
    os.write(handle, URL.encode())
    os.close(handle)


def leak_to_logging() -> None:
    logging.getLogger("slack_notice").warning(URL)


LEAKS = {
    "real stdout": (leak_to_fd1, "real fd output"),
    "real stderr": (leak_to_fd2, "real fd output"),
    "warnings": (leak_to_warnings, "CANARY"),
    "a spawned child": (leak_to_a_child, "a process was started"),
    "a stray file in the cwd": (leak_to_the_cwd, r"file:cwd/stray\.txt"),
    "a file in the temp dir": (leak_to_the_temp_dir, r"file:tmp/"),
    "logging": (leak_to_logging, "CANARY"),
}


@pytest.mark.parametrize("where", sorted(LEAKS))
def test_the_matrix_fails_when_production_leaks_into(
    where: str,
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    recwarn: pytest.WarningsRecorder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    leak, message = LEAKS[where]
    leaking_render(monkeypatch, leak)
    with pytest.raises(AssertionError, match=message):
        run_success(fake_gateway, monkeypatch, tmp_path, capfd, recwarn, caplog)


@pytest.mark.parametrize("target", ["state file", "log"])
def test_the_matrix_fails_when_production_leaks_into_the_state_directory(
    target: str,
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    recwarn: pytest.WarningsRecorder,
    caplog: pytest.LogCaptureFixture,
) -> None:
    real = cli.log_result

    def log_result(*args: Any, **kwargs: Any) -> Any:
        written = real(*args, **kwargs)
        name = "stray" if target == "state file" else "log.jsonl"
        with open(state_path(fake_gateway) / name, "ab") as handle:
            handle.write(URL.encode())  # a record or a file that holds the credential
        return written

    monkeypatch.setattr(cli, "log_result", log_result)
    with pytest.raises(AssertionError, match=r"file:.*slack-notice/(stray|log\.jsonl)"):
        run_success(fake_gateway, monkeypatch, tmp_path, capfd, recwarn, caplog)

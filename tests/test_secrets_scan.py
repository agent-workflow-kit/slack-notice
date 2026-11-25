"""The credential never leaves the process: the whole send path against the fake gateway (#29).

Every scenario runs ``cli.main`` in-process, in each output mode, with the fake credential in
the environment. Afterwards the scanner looks for the URL, its path, every segment and their
encodings in both streams, every file name and file under the whole private temp tree (home,
state directory, config, locks, log) and the fake gateway's own record of the run.
"""

from __future__ import annotations

import http.client
import os
import signal
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli, webhook
from slack_notice.gateway import SourceRead
from tests.fake_gateway import (
    Attempt,
    FakeGateway,
    Reply,
)
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
    corpus.add("repr(sent)", repr(sent.records) + repr(sent.state_files))
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
    codes: tuple[int, ...] = (12,)


Setup = Callable[[FakeGateway, pytest.MonkeyPatch, Path], Run]
SCENARIOS: dict[str, Setup] = {}


def scenario(name: str) -> Callable[[Setup], Setup]:
    def register(setup: Setup) -> Setup:
        assert name not in SCENARIOS
        SCENARIOS[name] = setup
        return setup

    return register


def add_attempts(name: str, attempts: list[Attempt], codes: tuple[int, ...] = (12,)) -> None:
    def setup(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
        g.script(*attempts)
        return Run(codes=codes)

    SCENARIOS[name] = setup


# success, and every row of the Webhook edge table
add_attempts("success", [OK], (0,))
add_attempts("success after a 429", [reply(429), OK], (0,))
add_attempts(
    "success with extra keys",
    [Attempt(reply=Reply(body=b'{"ok":true,"u":"' + URL.encode() + b'"}'))],
    (0,),
)
for _name, (_attempts, _code, _want) in ROWS.items():
    add_attempts("row: " + _name, _attempts, (_code,))

# hostile responses
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
            f"body {_status} {_label}", [Attempt(reply=Reply(status=_status, body=_body))] * 3
        )
for _framing in ("chunked", "eof"):
    add_attempts(
        f"body {_framing} url",
        [Attempt(reply=Reply(status=400, body=URL.encode(), framing=_framing))],
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
)
add_attempts(
    "429 retry-after url",
    [Attempt(reply=Reply(status=429, headers=(("Retry-After", URL),)))] * 3,
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
for _p, _make in PHASES.items():
    for _e, _exc in EXCEPTIONS.items():
        add_attempts(f"{_e} in {_p}", [_make(_exc())] * 2)


# the exception raised inside the gateway or the worker (exit 1)
def raising_gateway(method: str, exc: Callable[[], BaseException], codes: tuple[int, ...]) -> Setup:
    def setup(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
        def boom(*_a: Any, **_k: Any) -> Any:
            raise exc()

        mp.setattr(g, method, boom)
        g.script(OK, OK, OK)
        g.allow_unconsumed_script = True
        return Run(codes=codes)

    return setup


for _method in ("tls_context", "https_connection", "sleep", "monotonic", "wall_time", "read_at"):
    for _e in ("ValueError", "InvalidURL"):
        SCENARIOS[f"gateway.{_method} raises {_e}"] = raising_gateway(
            _method, EXCEPTIONS[_e], (0, 1, 12)
        )


@scenario("tls_context finds no ca")
def _no_ca(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.no_usable_ca = True
    g.script(OK)
    g.allow_unconsumed_script = True
    return Run()


for _after in (False, True):
    for _e in ("ValueError", "InvalidURL", "OSError"):

        def _worker(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, a=_after, e=_e) -> Run:
            def make(*_a: Any, **_k: Any) -> Any:
                def work(deadline: Any) -> Any:
                    if a:
                        assert deadline.enter_writing()
                    raise EXCEPTIONS[e]()

                return work

            mp.setattr(cli, "attempt_work", make)
            return Run(codes=(1,))

        SCENARIOS[f"worker raises {_e} {'after' if _after else 'before'} writing"] = _worker


class UrlRepr(Exception):
    """An exception whose every text form is the credential."""

    def __str__(self) -> str:
        return URL

    def __repr__(self) -> str:
        return URL


@scenario("worker raises an exception whose str and repr are the url")
def _repr_worker(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    def make(*_a: Any, **_k: Any) -> Any:
        def work(deadline: Any) -> Any:
            assert deadline.enter_writing()
            raise UrlRepr(URL)

        return work

    mp.setattr(cli, "attempt_work", make)
    return Run(codes=(1,))


@scenario("main thread bug before step 5")
def _main_bug(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise ValueError(URL)

    mp.setattr(cli, "render", boom)
    return Run(codes=(1,))


@scenario("worker raises with the helper from the runtime tests")
def _helper_worker(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    mp.setattr(cli, "attempt_work", worker_raising(after_writing=True))
    return Run(codes=(1,))


@scenario("caller bug in the log call")
def _caller_bug(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    impossible = webhook.Outcome(12, "upstream_error", "fixed message", None, False, True)

    def fake_work(*_a: Any, **_k: Any) -> Any:
        return lambda deadline: (deadline.enter_writing(), impossible)[1]

    mp.setattr(cli, "attempt_work", fake_work)
    return Run()


# credential_invalid variants: each keeps pieces of the secret in the rejected value
def credential(value: str | None, name: str) -> None:
    def setup(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
        return Run(env={} if value is None else {ENV_NAME: value})

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
    return Run(env={"OTHER": URL, "SLACK_NOTICE_WEBHOOK": URL})


@scenario("credential variable named by the config")
def _named_variable(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.script(reply(500))
    return Run(env={"HOOK_X": URL}, config=write_config(tmp, "webhook_env: HOOK_X\n"))


@scenario("hostile environment mapping")
def _hostile_env(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    class Hostile(dict[str, str]):
        def __getitem__(self, key: str) -> str:
            raise RuntimeError(URL)

    return Run(env=Hostile())


# input, lock and deadline cases
@scenario("input timeout")
def _input_timeout(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(stdin=SourceRead(b'{"messag', timed_out=True))


@scenario("input read raises with the url")
def _input_raises(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(stdin=None, codes=(1, 2, 12), before=lambda: g.source_script.append(OSError(URL)))  # type: ignore[arg-type]


@scenario("lock timeout")
def _lock_timeout(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    free_the_lock_before_the_log(g, mp)
    g.lock_held = True
    return Run(config=write_config(tmp, "timeout: 3\n"))


@scenario("lock error carries the url")
def _lock_error(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.lock_error = OSError(URL)
    g.script(OK)
    return Run(codes=(0, 1, 12))


for _label, _attempt in {
    "connect slower than the deadline": Attempt(connect_delay=60.0),
    "tls slower than the deadline": Attempt(tls_delay=60.0),
    "write slower than the deadline": Attempt(write_delay=60.0),
    "first byte slower than the deadline": Attempt(reply=Reply(first_byte_delay=60.0)),
    "body stalls": Attempt(reply=Reply(body=b'{"ok":true}', body_stall_after=3)),
    "head stalls": Attempt(reply=Reply(head_stall_after=5)),
    "body trickle": Attempt(reply=Reply(body_trickle=0.5)),
}.items():

    def _deadline(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, a: Attempt = _attempt) -> Run:
        g.script(a, a)
        g.allow_unconsumed_script = True
        return Run(config=write_config(tmp, "timeout: 3\n"), codes=(0, 12))

    SCENARIOS["deadline: " + _label] = _deadline


@scenario("deadline: long 429 wait")
def _long_429(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.script(reply(429), reply(429), reply(429))
    return Run(config=write_config(tmp, "timeout: 3\n"))


# signals
for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):

    def _signal_writing(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, s: int = _sig) -> Run:
        g.script(OK)
        g.allow_unconsumed_script = True
        hold_the_response(mp, s)
        return Run()

    SCENARIOS[f"signal {_sig.name} while writing"] = _signal_writing

    def _signal_input(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, s: int = _sig) -> Run:
        real = g.read_source

        def kill(source: Any, max_bytes: int, remaining: float) -> SourceRead:
            os.kill(os.getpid(), s)
            return real(source, max_bytes, remaining)

        mp.setattr(g, "read_source", kill)
        return Run(codes=(128 + int(s),))

    SCENARIOS[f"signal {_sig.name} during input"] = _signal_input

    def _signal_credential(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, s: int = _sig) -> Run:
        class Signalling(dict[str, str]):
            def __getitem__(self, key: str) -> str:
                os.kill(os.getpid(), s)
                return super().__getitem__(key)

        g.script(OK)
        g.allow_unconsumed_script = True
        return Run(env=Signalling(SECRET.env), codes=(0, 12))

    SCENARIOS[f"signal {_sig.name} while the credential is read"] = _signal_credential


# state directory, lock, log writer and send lock failing with the url in the exception
for _e in ("OSError", "ValueError", "InvalidURL"):

    def _state(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, e: str = _e) -> Run:
        g.state_dir_error = EXCEPTIONS[e]()  # type: ignore[assignment]
        g.script(OK)
        return Run(codes=(0, 1))

    SCENARIOS[f"state dir raises {_e}"] = _state

    for _name in ("send.lock", "log.lock", "log.jsonl"):

        def _file(
            g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, e: str = _e, n: str = _name
        ) -> Run:
            g.state_file_errors[n] = EXCEPTIONS[e]()
            g.script(OK)
            return Run(codes=(0, 1))

        SCENARIOS[f"state file {_name} raises {_e}"] = _file

    for _hook in ("write_error", "truncate_error", "mtime_error", "set_mtime_error"):

        def _hooked(
            g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path, e: str = _e, h: str = _hook
        ) -> Run:
            setattr(g, h, EXCEPTIONS[e]())
            if h == "truncate_error":
                g.write_limit = 5  # a short write, so the cut back runs
            g.script(OK)
            return Run(codes=(0, 1))

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

    g.rename_errors["log.jsonl"] = OSError(URL)
    g.script(OK)
    return Run(before=big_log, codes=(0, 1))


@scenario("home lookup error")
def _home_error(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    mp.setattr(g, "_home_error", True)
    g.script(OK)
    return Run(codes=(0, 1, 2, 12))


@scenario("dry run with the credential in the environment")
def _dry(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(codes=(0,))


@scenario("refusal")
def _refusal(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(stdin=stdin_json(title=SECRET.segments[0]), codes=(20,))


@scenario("disabled")
def _disabled(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(config=write_config(tmp, "enabled: false\n"), codes=(22,))


@scenario("bad config")
def _bad_config(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    return Run(config=write_config(tmp, "webhook_env: not a name\n"), codes=(2,))


@scenario("log disabled")
def _log_off(g: FakeGateway, mp: pytest.MonkeyPatch, tmp: Path) -> Run:
    g.script(reply(500))
    return Run(config=write_config(tmp, "log: false\n"))


@pytest.mark.parametrize("mode", MODES, ids=lambda m: " ".join(m) or "plain")
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_the_credential_reaches_no_stream_no_file_and_no_record(
    name: str,
    mode: list[str],
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fake_gateway.allow_unconsumed_script = True
    run = SCENARIOS[name](fake_gateway, monkeypatch, tmp_path)
    argv = ["send", *mode, "--stdin-json"]
    if name == "dry run with the credential in the environment":
        argv.append("--dry-run")
    sent = go(
        argv,
        fake_gateway,
        stdin=run.stdin,
        env=run.env,
        config=run.config,
        before=run.before,
        validate_log=False,
    )
    fake_gateway.release_stalls()
    assert sent.code in run.codes, (name, mode, sent.code, sent.stderr)
    hits = corpus_of(sent, fake_gateway, tmp_path).hits(SECRET)
    assert hits == [], (name, mode, hits)
    # a request, when one was made, went to the one fixed place
    for connection in fake_gateway.connections:
        assert (connection.host, connection.port) == ("hooks.slack.com", 443)
        assert URL not in connection.user_agent and SECRET.path not in connection.user_agent
        for _path, body in connection.requests:
            assert SECRET.segments[0].encode() not in body
    assert fake_gateway.violations == []

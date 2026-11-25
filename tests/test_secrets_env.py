"""Proxy, trust, redirect and environment regression tests (#29).

The environment cannot steer the send: no proxy, no trust variable, no ``SLACK_NOTICE_*``,
``HOME``, ``XDG_*``, locale or ``PYTHON*`` variable changes what is sent, printed, logged or
where state goes, and exactly one variable (the configured credential one) is ever read. Nothing
here opens a network connection: the real gateway is exercised only through pure functions and
constructors that do not connect.
"""

from __future__ import annotations

import http.client
import os
import re
import signal
import ssl
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from slack_notice.gateway import (
    CaCandidates,
    NoUsableCA,
    SystemGateway,
    build_tls_context,
)
from tests.fake_gateway import Attempt, FakeGateway, FakeResponse, Reply
from tests.secret_scan import Corpus, Secret
from tests.send_harness import ENV_NAME, Sent, go, stdin_json, write_config
from tests.test_send import HELLO, OK, reply
from tests.test_send_process import child_env
from tests.test_webhook_client import make_cert, wire

SECRET = Secret()
URL = SECRET.url
_PROXY_NAMES = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY"]
PROXY_VARIABLES = [*_PROXY_NAMES, *(name.lower() for name in _PROXY_NAMES)]
TRUST_VARIABLES = [
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SSLKEYLOGFILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "OPENSSL_CONF",
]


def decoys(root: Path) -> dict[str, str]:
    """Every variable the spec says is not read, with a value that would change behavior."""
    values = {
        "HOME": str(root / "decoy-home"),
        "XDG_CONFIG_HOME": str(root / "decoy-config"),
        "XDG_STATE_HOME": str(root / "decoy-state"),
        "XDG_DATA_HOME": str(root / "decoy-data"),
        "XDG_CACHE_HOME": str(root / "decoy-cache"),
        "XDG_RUNTIME_DIR": str(root / "decoy-run"),
        "TMPDIR": str(root / "decoy-tmp"),
        "TMP": str(root / "decoy-tmp"),
        "TEMP": str(root / "decoy-tmp"),
        "LANG": "tr_TR.ISO-8859-9",
        "LC_ALL": "C",
        "LC_CTYPE": "POSIX",
        "LC_MESSAGES": "de_DE.UTF-8",
        "LC_TIME": "ja_JP.UTF-8",
        "LANGUAGE": "xx",
        "TZ": "Pacific/Kiritimati",
        "COLUMNS": "7",
        "LINES": "3",
        "NO_COLOR": "1",
        "TERM": "dumb",
        "PYTHONIOENCODING": "ascii:strict",
        "PYTHONUTF8": "0",
        "PYTHONHASHSEED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONWARNINGS": "error",
        "PYTHONSTARTUP": str(root / "decoy-startup.py"),
        "PYTHONUSERBASE": str(root / "decoy-user"),
        "PYTHONPYCACHEPREFIX": str(root / "decoy-pyc"),
        "PYTHONBREAKPOINT": "0",
        "PYTHONSAFEPATH": "1",
        "PYTHONCOERCECLOCALE": "0",
        "PYTHONLEGACYWINDOWSSTDIO": "1",
        "SLACK_NOTICE_CONFIG": str(root / "decoy-config.yaml"),
        "SLACK_NOTICE_STATE_DIR": str(root / "decoy-state"),
        "SLACK_NOTICE_LOG": "false",
        "SLACK_NOTICE_ENABLED": "false",
        "SLACK_NOTICE_TIMEOUT": "1",
        "SLACK_NOTICE_WEBHOOK_ENV": "OTHER",
        "SLACK_NOTICE_WEBHOOK": "https://decoy.invalid/",
        "SLACK_NOTICE_URL": SECRET.url + "x",
        "SLACK_NOTICE_DEBUG": "1",
        "SLACK_NOTICE_VERBOSE": "1",
        "SLACK_NOTICE_BODY_VARIABLE": "x",
    }
    for name in PROXY_VARIABLES:
        values[name] = "http://127.0.0.1:9"
    for name in TRUST_VARIABLES:
        values[name] = str(root / "decoy-trust")
    return values


# --- 3. proxy and trust variables have no effect ------------------------------------------------


def normalize(text: str) -> str:
    text = re.sub(r'"duration_ms":\d+', '"duration_ms":0', text)
    text = re.sub(r'"ts":"[^"]*"', '"ts":"T"', text)
    return re.sub(r"\d+ ms", "N ms", text)


def fingerprint(sent: Sent, gateway: FakeGateway) -> dict[str, Any]:
    """Everything a caller or the network could see of a run, with the clock noise removed."""
    return {
        "code": sent.code,
        "exited": sent.exited,
        "stdout": normalize(sent.stdout),
        "stderr": normalize(sent.stderr),
        "records": [{**r, "ts": "T", "duration_ms": 0} for r in sent.records],
        "state": {
            name: normalize(data.decode("utf-8", "replace"))
            for name, data in sent.state_files.items()
        },
        "events": [e for e in gateway.events],
        "calls": list(gateway.calls),
        "read_paths": [Path(p).name for p in gateway.read_paths],
        "connections": [
            (c.host, c.port, round(c.timeout), c.user_agent, c.requests)
            for c in gateway.connections
        ],
        "violations": list(gateway.violations),
    }


def gateway_in(
    tmp_path: Path, label: str, *attempts: Attempt, environment: Any = None
) -> FakeGateway:
    home = tmp_path / label
    home.mkdir(mode=0o700)
    gateway = FakeGateway(home=str(home), environment=environment)
    gateway.allow_unconsumed_script = True
    gateway.script(*attempts)
    return gateway


CASES: dict[str, tuple[list[Attempt], list[str], dict[str, str], bytes]] = {
    "sent": ([OK], [], dict(SECRET.env), HELLO),
    "429 then sent": ([reply(429), OK], [], dict(SECRET.env), HELLO),
    "500": ([reply(500)], [], dict(SECRET.env), HELLO),
    "401": ([reply(401)], ["--json"], dict(SECRET.env), HELLO),
    "network error": (
        [Attempt(connect_error=ConnectionRefusedError()), Attempt(connect_error=OSError())],
        [],
        dict(SECRET.env),
        HELLO,
    ),
    "certificate": (
        [Attempt(tls_error=ssl.SSLCertVerificationError(1, "x"))],
        [],
        dict(SECRET.env),
        HELLO,
    ),
    "unset credential": ([], ["--json"], {}, HELLO),
    "refusal": ([], ["--json"], dict(SECRET.env), stdin_json(level="info")),
    "dry run": ([], ["--dry-run", "--json"], dict(SECRET.env), HELLO),
    "verbose": ([OK], ["--verbose"], dict(SECRET.env), HELLO),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_proxy_trust_and_every_other_variable_change_nothing_a_send_does(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts, flags, env, stdin = CASES[name]
    argv = ["send", *flags, "--stdin-json"]
    plain = gateway_in(tmp_path, "plain", *attempts)
    base = fingerprint(go(argv, plain, stdin=stdin, env=env), plain)

    fakes = decoys(tmp_path)
    for key, value in fakes.items():
        monkeypatch.setenv(key, value)
    # the decoys are in the real environment, in the mapping the caller passes and in the
    # gateway's own copy: every way the code could see them
    other = gateway_in(tmp_path, "other", *attempts, environment={**env, **fakes})
    noisy = go(argv, other, stdin=stdin, env={**env, **fakes})
    assert fingerprint(noisy, other) == base
    defaulted = gateway_in(tmp_path, "third", *attempts, environment={**env, **fakes})
    via_gateway = go(argv, defaulted, stdin=stdin, env=None)
    again = fingerprint(via_gateway, defaulted)
    assert again["connections"] == base["connections"]
    assert (again["code"], again["stdout"], again["stderr"], again["records"]) == (
        base["code"],
        base["stdout"],
        base["stderr"],
        base["records"],
    )
    # nothing was created where the variables point
    for key in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "TMPDIR"):
        assert not Path(fakes[key]).exists(), key
    assert not any(Path(tmp_path).glob("decoy-*"))
    corpus = Corpus()
    corpus.add("stdout", noisy.out)
    corpus.add("stderr", noisy.err)
    corpus.extend((f"state:{key}", data) for key, data in noisy.state_files.items())
    corpus.add_tree(tmp_path)
    assert corpus.hits(SECRET) == []


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    cert, _key = make_cert(tmp_path, "trust.example")
    return cert


def stats(context: ssl.SSLContext) -> tuple[Any, ...]:
    return (
        context.verify_mode,
        context.check_hostname,
        context.minimum_version,
        context.keylog_filename,
        tuple(sorted(context.cert_store_stats().items())),
        context.options,
        context.verify_flags,
    )


def test_the_real_trust_logic_ignores_ssl_variables_and_proxies_without_any_connection(
    tmp_path: Path, bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def forbid(name: str) -> Any:
        def refuse(*_a: Any, **_k: Any) -> Any:
            calls.append(name)
            raise AssertionError(name)

        return refuse

    # the default-store entry points read SSL_CERT_FILE and SSL_CERT_DIR: never called
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", forbid("load_default_certs"))
    monkeypatch.setattr(
        ssl.SSLContext, "set_default_verify_paths", forbid("set_default_verify_paths")
    )
    monkeypatch.setattr(ssl, "create_default_context", forbid("create_default_context"))
    monkeypatch.setattr(ssl, "_create_default_https_context", forbid("https_context"))

    gateway = SystemGateway()
    without = gateway.ca_candidates()
    try:
        baseline: Any = stats(gateway.tls_context())
    except NoUsableCA:
        baseline = NoUsableCA
    keylog = tmp_path / "keys.log"
    certdir = tmp_path / "certs"
    certdir.mkdir()
    for name in TRUST_VARIABLES:
        monkeypatch.setenv(name, str(bundle))
    monkeypatch.setenv("SSL_CERT_DIR", str(certdir))
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    for name in PROXY_VARIABLES:
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    with_vars = gateway.ca_candidates()
    assert with_vars == without
    assert str(bundle) not in (with_vars.cafile, with_vars.capath, *with_vars.fallback_files)
    try:
        noisy: Any = stats(gateway.tls_context())
    except NoUsableCA:
        noisy = NoUsableCA
    assert noisy == baseline
    assert not keylog.exists()
    assert calls == []


def test_build_tls_context_trusts_only_the_candidates_it_is_given(
    tmp_path: Path, bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other, _ = make_cert(tmp_path, "other.example")
    for name in TRUST_VARIABLES:
        monkeypatch.setenv(name, str(other))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    context = build_tls_context(CaCandidates(str(bundle), None, ()))
    assert context.cert_store_stats()["x509_ca"] == 1
    assert context.keylog_filename is None
    assert (context.verify_mode, context.check_hostname) == (ssl.CERT_REQUIRED, True)
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    # a variable that names a good bundle does not rescue a missing one
    with pytest.raises(NoUsableCA):
        build_tls_context(CaCandidates(str(tmp_path / "missing"), None, ()))


def test_the_real_connection_has_no_proxy_tunnel_and_is_built_without_connecting(
    tmp_path: Path, bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse_tunnel(*_a: Any, **_k: Any) -> None:
        raise AssertionError("set_tunnel: a proxy was configured")

    monkeypatch.setattr(http.client.HTTPConnection, "set_tunnel", refuse_tunnel)
    import urllib.request

    def refuse_proxies(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("the proxy environment was read")

    monkeypatch.setattr(urllib.request, "getproxies", refuse_proxies)
    monkeypatch.setattr(urllib.request, "proxy_bypass", refuse_proxies)
    for name in PROXY_VARIABLES:
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    context = build_tls_context(CaCandidates(str(bundle), None, ()))
    connection = SystemGateway().https_connection(
        "hooks.slack.com", 443, timeout=3.0, context=context, user_agent="slack-notice/9.9.9"
    )
    inner = connection._conn  # type: ignore[attr-defined]  # pyright: ignore
    assert (inner.host, inner.port, inner._tunnel_host, inner._tunnel_port) == (
        "hooks.slack.com",
        443,
        None,
        None,
    )
    assert inner.sock is None  # nothing was opened
    assert inner._context is context


# --- 4. a redirect never reaches a second server -----------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_wrong_host_response_with_one_connection_and_no_header_read(
    status: int, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    touched: list[str] = []

    class Strict:
        """The response as the CLI may see it: anything but ``status`` and ``read`` is a read."""

        def __init__(self, inner: FakeResponse) -> None:
            object.__setattr__(self, "_inner", inner)

        @property
        def status(self) -> int:
            return object.__getattribute__(self, "_inner").status

        def read(self, amount: int) -> bytes:
            return object.__getattribute__(self, "_inner").read(amount)

        def __getattr__(self, name: str) -> Any:
            touched.append(name)
            raise AttributeError(name)

    from tests.fake_gateway import FakeConnection

    real = FakeConnection.getresponse
    monkeypatch.setattr(FakeConnection, "getresponse", lambda self: Strict(real(self)))
    elsewhere = "https://elsewhere.invalid/" + SECRET.segments[0]
    redirect = Attempt(
        reply=Reply(
            status=status,
            body=b"",
            headers=(("Location", elsewhere), ("Refresh", "0;" + elsewhere)),
        )
    )
    fake_gateway.script(redirect, OK, OK)  # a second and third server stand ready
    sent = go(["send", "--json", "--stdin-json"], fake_gateway, stdin=HELLO, env=SECRET.env)
    assert sent.code == 12 and sent.error["code"] == "wrong_host_response"
    assert (sent.error["unknown_outcome"], sent.error["retryable"]) == (False, False)
    assert len(fake_gateway.connections) == 1
    assert fake_gateway.events.count("https_connection") == 1
    assert len(fake_gateway._attempts) == 2  # type: ignore[attr-defined]  # pyright: ignore
    assert touched == []
    assert (
        b"elsewhere" not in sent.everything and SECRET.segments[0].encode() not in sent.everything
    )
    fake_gateway.allow_unconsumed_script = True


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_over_the_real_wire_is_one_connection_and_never_followed(status: int) -> None:
    raw = (
        f"HTTP/1.1 {status} Moved\r\nLocation: https://elsewhere.invalid/x\r\n"
        "Set-Cookie: a=b\r\nContent-Length: 0\r\n\r\n"
    ).encode()
    conns: list[object] = []
    result, request = wire(raw, conns=conns)
    assert result.status == status and result.body == b"" and result.failure is None
    assert len(conns) == 1
    assert b"elsewhere" not in repr(result).encode()
    assert request.startswith(b"POST ")


# --- 5. the environment is not read -------------------------------------------------------------


class Recording(Mapping[str, str]):
    """An environment that logs every way it is looked at."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values
        self.log: list[tuple[str, Any]] = []

    def __getitem__(self, key: str) -> str:
        self.log.append(("getitem", key))
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        self.log.append(("iter", None))
        return iter(self._values)

    def __len__(self) -> int:
        self.log.append(("len", None))
        return len(self._values)

    def __contains__(self, key: object) -> bool:
        self.log.append(("contains", key))
        return key in self._values

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        self.log.append(("get", key))
        return self._values.get(key, default)

    def keys(self) -> Any:
        self.log.append(("keys", None))
        return self._values.keys()

    def items(self) -> Any:
        self.log.append(("items", None))
        return self._values.items()

    def values(self) -> Any:
        self.log.append(("values", None))
        return self._values.values()

    @property
    def keys_read(self) -> set[str]:
        return {key for kind, key in self.log if kind in ("getitem", "get", "contains")}


def crowded(root: Path) -> dict[str, str]:
    return {**SECRET.env, **decoys(root), "OTHER_HOOK": URL}


def test_a_real_send_reads_exactly_the_credential_variable_and_nothing_else(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording(crowded(tmp_path))
    fake_gateway.script(OK)
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO, env=env)
    assert sent.code == 0
    assert env.log == [("getitem", ENV_NAME)]  # no iteration, no length, no other key


def test_the_configured_variable_is_the_only_one_read(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording(crowded(tmp_path))
    fake_gateway.script(OK)
    config = write_config(tmp_path, "webhook_env: OTHER_HOOK\n")
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO, env=env, config=config)
    assert sent.code == 0 and env.log == [("getitem", "OTHER_HOOK")]


@pytest.mark.parametrize(
    ("flags", "stdin", "config"),
    [
        (["--dry-run"], HELLO, None),
        (["--dry-run", "--json"], stdin_json(level="info"), None),
        ([], stdin_json(level="info"), None),  # a refusal
        ([], HELLO, "enabled: false\n"),  # disabled
        ([], HELLO, "timeout: 1\n"),  # bad config
        ([], b"not json", None),
    ],
)
def test_a_dry_run_a_refusal_and_a_disabled_or_bad_config_read_no_variable_at_all(
    flags: list[str], stdin: bytes, config: str | None, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording(crowded(tmp_path))
    cfg = None if config is None else write_config(tmp_path, config)
    go(["send", "--stdin-json", *flags], fake_gateway, stdin=stdin, env=env, config=cfg)
    assert env.log == []
    assert "environ" not in fake_gateway.calls


@pytest.mark.parametrize(
    "attempts",
    [
        [reply(500)],
        [Attempt(connect_error=OSError())] * 2,
        [reply(429)] * 3,
        [Attempt(reply=reply(200, b"x").reply)],
    ],
)
def test_every_failure_of_a_real_send_still_reads_only_the_credential_variable(
    attempts: list[Attempt], fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    env = Recording(crowded(tmp_path))
    fake_gateway.script(*attempts)
    go(["send", "--stdin-json"], fake_gateway, stdin=HELLO, env=env)
    assert env.log == [("getitem", ENV_NAME)]


@pytest.mark.parametrize("value", [None, "", "  ", URL + "?x"])
def test_an_unset_or_bad_credential_reads_only_the_credential_variable(
    value: str | None, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    values = crowded(tmp_path)
    values.pop(ENV_NAME)
    if value is not None:
        values[ENV_NAME] = value
    env = Recording(values)
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO, env=env)
    assert sent.code == 12 and env.log == [("getitem", ENV_NAME)]


def test_the_default_environment_comes_from_the_gateway_and_is_read_the_same_way(
    tmp_path: Path,
) -> None:
    env = Recording(crowded(tmp_path))
    for flags, expected in (([], [("getitem", ENV_NAME)]), (["--dry-run"], [])):
        gateway = gateway_in(tmp_path, "gw" + "".join(flags).replace("-", ""), OK)
        gateway.environ = lambda: env  # type: ignore[assignment, method-assign, return-value]
        env.log.clear()
        go(["send", "--stdin-json", *flags], gateway, stdin=HELLO, env=None)
        assert env.log == expected


# --- the environment of a real process ---------------------------------------------------------


GUARD_EXIT = 97
GUARD = f"""\
import os
import sys

_REFUSED = {{
    "socket.connect",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.gethostbyaddr",
    "socket.getnameinfo",
    "socket.sendto",
    "socket.sendmsg",
}}


def _guard(event, args):
    if event in _REFUSED:
        os._exit({GUARD_EXIT})


sys.addaudithook(_guard)
"""


def guarded_env(home: Path, root: Path) -> dict[str, str]:
    """The child environment with a guard first on PYTHONPATH: its ``sitecustomize`` ends the
    process with exit 97 on any connect (also a Unix socket), name lookup or datagram send, so
    a child that could reach the network never does. A real child that exits 97 is a failure."""
    directory = root / "guard"
    directory.mkdir(exist_ok=True)
    (directory / "sitecustomize.py").write_text(GUARD, encoding="utf-8")
    env = child_env(home)
    env["PYTHONPATH"] = os.pathsep.join([str(directory), env["PYTHONPATH"]])
    return env


def test_the_child_guard_ends_a_process_that_connects_even_with_the_decoy_variables(
    tmp_path: Path,
) -> None:
    """Self-test of the guard: a child that connects to a Unix socket path (no network at all)
    exits 97 before the connect, also under the decoys that touch how Python starts."""
    home = tmp_path / "probe"
    home.mkdir()
    env = guarded_env(home, tmp_path)
    program = (
        "import socket, sys\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        "s.connect(sys.argv[1])\n"
        "sys.exit(0)\n"
    )
    target = str(tmp_path / "no-such.sock")
    fakes = {k: v for k, v in decoys(tmp_path / "x").items() if not k.startswith(("HOME", "XDG_"))}
    assert fakes["PYTHONSAFEPATH"] == "1" and "PYTHONSTARTUP" in fakes
    for extra in ({}, fakes):
        done = subprocess.run(
            [sys.executable, "-c", program, target],
            env={**env, **extra},
            capture_output=True,
            timeout=60,
            check=False,
            cwd=str(home),
        )
        assert done.returncode == GUARD_EXIT, (extra.keys(), done.stderr)
    for call in ("socket.getaddrinfo('localhost', 80)", "socket.gethostbyname('localhost')"):
        done = subprocess.run(
            [sys.executable, "-c", f"import socket\n{call}"],
            env=env,
            capture_output=True,
            timeout=60,
            check=False,
            cwd=str(home),
        )
        assert done.returncode == GUARD_EXIT, (call, done.stderr)


def run_child(
    tmp_path: Path, label: str, argv: list[str], extra: dict[str, str], stdin: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    home = tmp_path / label
    home.mkdir()
    env = guarded_env(home, tmp_path)
    env.update(extra)
    config = home / "config.yaml"
    config.write_text("log: false\n", encoding="utf-8")
    done = subprocess.run(
        [sys.executable, "-m", "slack_notice", "send", *argv, "--config", str(config)],
        env=env,
        input=stdin if stdin is not None else b"",
        capture_output=True,
        timeout=60,
        check=False,
        cwd=str(home),
    )
    assert done.returncode != GUARD_EXIT, "the child tried to reach the network"
    return done


@pytest.mark.parametrize(
    "case",
    [
        (["--dry-run", "--json", "--message", "hi"], 0, dict(SECRET.env)),
        (["--dry-run", "--verbose", "--message", "hi"], 0, dict(SECRET.env)),
        (["--json", "--message", "hi"], 12, {ENV_NAME: URL + "?x=1"}),  # wrong shape: no network
        (["--json", "--message", "hi"], 12, {}),
        (["--json", "--stdin-json"], 20, dict(SECRET.env)),  # empty stdin: a refusal
    ],
    ids=["dry-json", "dry-verbose", "bad-shape", "unset", "refusal"],
)
def test_a_real_process_behaves_the_same_with_every_decoy_variable(
    case: tuple[list[str], int, dict[str, str]], tmp_path: Path
) -> None:
    argv, code, extra = case
    plain = run_child(tmp_path, "plain", argv, extra)
    fakes = {k: v for k, v in decoys(tmp_path / "x").items() if not k.startswith(("HOME", "XDG_"))}
    # PYTHONSAFEPATH, PYTHONSTARTUP and the like are interpreter settings: the process must
    # still behave the same; HOME and XDG_* stay with the harness's private values (the child
    # env sets them), and they are covered in-process above
    noisy = run_child(tmp_path, "noisy", argv, {**extra, **fakes})
    assert plain.returncode == code
    assert (noisy.returncode, normalize(noisy.stdout.decode()), noisy.stderr) == (
        plain.returncode,
        normalize(plain.stdout.decode()),
        plain.stderr,
    )
    for done in (plain, noisy):
        corpus = Corpus()
        corpus.add("stdout", done.stdout)
        corpus.add("stderr", done.stderr)
        assert corpus.hits(SECRET) == []
    assert not (tmp_path / "x").exists()


def sample_cmdlines(
    read: Callable[[], bytes],
    running: Callable[[], bool],
    *,
    seconds: float = 2.0,
    interval: float = 0.2,
) -> list[bytes]:
    """Read a child's command line until it ends or ``seconds`` pass; the reader is injected so a
    test can script the samples. An unreadable process ends the sampling."""
    samples: list[bytes] = []
    stop = time.monotonic() + seconds
    while time.monotonic() < stop and running():
        try:
            samples.append(read())
        except OSError:
            break
        time.sleep(interval)
    return samples


def check_argv_samples(samples: list[bytes]) -> None:
    """``/proc/<pid>/cmdline`` reads as empty bytes while the child is still inside exec or once
    it is exiting (a zombie until it is reaped), so an empty sample says nothing and is ignored.
    At least one sample must have a command line, and every such sample must start with the
    interpreter, ``-m`` and the module name. Whether a sample holds the credential is checked by
    the caller's corpus."""
    seen = [sample for sample in samples if sample]
    assert seen, f"no sample of the command line was non-empty ({len(samples)} samples)"
    for sample in seen:
        assert sample.split(b"\0")[:3] == [sys.executable.encode(), b"-m", b"slack_notice"]


def argv_corpus(samples: list[bytes], corpus: Corpus | None = None) -> Corpus:
    """A corpus holding every argv sample, empty ones included, as ``argv<index>``."""
    corpus = Corpus() if corpus is None else corpus
    for index, sample in enumerate(samples):
        corpus.add(f"argv{index}", sample)
    return corpus


def test_empty_argv_samples_are_ignored_but_all_empty_samples_fail() -> None:
    good = b"\0".join([sys.executable.encode(), b"-m", b"slack_notice", b"send"]) + b"\0"
    check_argv_samples([b"", good, good])  # an empty sample may come before or after real ones
    check_argv_samples([good, b""])
    with pytest.raises(AssertionError, match="non-empty"):
        check_argv_samples([b"", b"", b""])
    with pytest.raises(AssertionError, match="non-empty"):
        check_argv_samples([])


def test_a_non_empty_argv_sample_that_is_not_ours_fails() -> None:
    good = b"\0".join([sys.executable.encode(), b"-m", b"slack_notice", b"send"]) + b"\0"
    other = b"\0".join([sys.executable.encode(), b"-c", b"pass"]) + b"\0"
    with pytest.raises(AssertionError):
        check_argv_samples([b"", good, other])
    with pytest.raises(AssertionError):
        check_argv_samples([good, b"sh\0-c\0x\0"])


def test_the_credential_in_any_argv_sample_is_found_even_after_empty_samples() -> None:
    leaked = (
        b"\0".join([sys.executable.encode(), b"-m", b"slack_notice", SECRET.segments[0].encode()])
        + b"\0"
    )
    samples = [b"", leaked]
    check_argv_samples(samples)  # the prefix is right: the corpus is what finds the credential
    corpus = argv_corpus(samples)
    assert set(corpus.blobs) == {"argv0", "argv1"}  # every sample, the empty one too
    assert corpus.blobs["argv0"] == b""
    assert corpus.hits(SECRET) != []


def test_the_sampler_ends_at_an_unreadable_process_and_keeps_what_it_read() -> None:
    replies: list[bytes | None] = [b"", b"x\0", None]

    def read() -> bytes:
        item = replies.pop(0)
        if item is None:
            raise ProcessLookupError("gone")
        return item

    assert sample_cmdlines(read, lambda: True, interval=0.0) == [b"", b"x\0"]


def test_a_real_process_with_the_credential_has_it_in_no_argv_stream_or_file(
    tmp_path: Path,
) -> None:
    """The valid fake credential sits in the child's environment while it waits for input that
    never completes: the deadline ends it before step 5, so nothing is ever contacted (and the
    guard would end the child with exit 97 if anything were)."""
    if not Path("/proc/self").is_dir():  # todo(#37): macOS argv check via ps
        pytest.skip("no /proc: the argv of a running process is read from /proc/<pid>/cmdline")
    home = tmp_path / "child"
    home.mkdir()
    config = home / "config.yaml"
    config.write_text("log: false\ntimeout: 3\n", encoding="utf-8")
    env = guarded_env(home, tmp_path)
    env.update(SECRET.env)
    argv = [
        sys.executable,
        "-m",
        "slack_notice",
        "send",
        "--json",
        "--stdin-json",
        "--config",
        str(config),
    ]
    assert SECRET.segments[0] not in " ".join(argv)
    proc = subprocess.Popen(
        argv,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(home),
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    cmdlines: list[bytes] = []
    try:
        proc.stdin.write(b'{"message"')  # then silence: the read ends at the deadline
        proc.stdin.flush()
        cmdlines = sample_cmdlines(
            lambda: Path(f"/proc/{proc.pid}/cmdline").read_bytes(),
            lambda: proc.poll() is None,
        )
        code = proc.wait(timeout=30)
        out, err = proc.stdout.read(), proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()  # this Popen's own pid
            proc.wait()
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()
    assert code != GUARD_EXIT, "the child tried to reach the network"
    assert code == 12 and b"unavailable" in out
    check_argv_samples(cmdlines)
    corpus = argv_corpus(cmdlines)
    corpus.add("stdout", out)
    corpus.add("stderr", err)
    corpus.add("argv", "\0".join(argv))
    corpus.add_tree(home)
    assert corpus.hits(SECRET) == []


def caught_signals(pid: int) -> int:
    """The ``SigCgt`` mask of a process: the bit of every signal it has a handler for."""
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("SigCgt:"):
            return int(line.split()[1], 16)
    raise AssertionError("no SigCgt line")


def wait_for_handler(pid: int, timeout: float = 20.0) -> None:
    """Poll until the process has a SIGTERM handler (Python itself installs none), at most
    ``timeout`` seconds; no fixed sleep."""
    stop = time.monotonic() + timeout
    while time.monotonic() < stop:
        if caught_signals(pid) & (1 << (signal.SIGTERM - 1)):
            return
        time.sleep(0.02)
    raise AssertionError("the child never installed a SIGTERM handler")


def test_a_signal_before_step_5_leaves_a_real_process_silent_and_leak_free(tmp_path: Path) -> None:
    if not Path("/proc/self").is_dir():  # todo(#37): macOS readiness check via ps
        pytest.skip("no /proc: the signal handlers of a process are read from /proc/<pid>/status")
    home = tmp_path / "sig"
    home.mkdir()
    config = home / "config.yaml"
    config.write_text("log: false\ntimeout: 30\n", encoding="utf-8")
    env = guarded_env(home, tmp_path)
    env.update(SECRET.env)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "slack_notice",
            "send",
            "--json",
            "--stdin-json",
            "--config",
            str(config),
        ],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(home),
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    try:
        proc.stdin.write(b'{"message"')
        proc.stdin.flush()
        wait_for_handler(proc.pid)  # the tool has installed its signal handling
        proc.terminate()  # this Popen's own pid
        code = proc.wait(timeout=30)
        out, err = proc.stdout.read(), proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()
    assert code != GUARD_EXIT, "the child tried to reach the network"
    assert code == 143 and out == b"" and err == b""
    corpus = Corpus()
    corpus.add_tree(home)
    assert corpus.hits(SECRET) == []

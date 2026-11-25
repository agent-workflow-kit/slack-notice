"""The HTTP client: one attempt through the gateway (issue #23).

No real network: behavior runs against the fake gateway, the wire format against the real
connection class on a private socketpair. Fake secrets are built at run time around a CANARY.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from slack_notice import __version__, webhook
from slack_notice.gateway import CaCandidates, SystemGateway, build_tls_context
from slack_notice.webhook import Phase, Webhook, post_once
from tests.fake_gateway import Attempt, FakeGateway, Reply

CANARY = "CAN" + "ARY" + "_23x"
PATH = "/triggers/" + CANARY + "/seg"
BODY = b'{"text":"hi"}'


def hook() -> Webhook:
    return Webhook(PATH)


def run(gw: FakeGateway, *attempts: Attempt, **kw):  # noqa: ANN202
    gw.script(*attempts)
    return post_once(gw, hook(), BODY, timeout=5.0, **kw)


def assert_no_secret(result: object) -> None:
    for text in (repr(result), str(result)):
        assert CANARY not in text and "hooks.slack" not in text and "triggers" not in text


# --- success and request ------------------------------------------------------------------


def test_success_returns_status_and_body(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt())
    assert (result.phase, result.status, result.body) == (Phase.READ, 200, b'{"ok":true}')
    assert result.failure is None and not result.body_too_long and not result.abandoned


def test_request_goes_to_the_fixed_host_with_path_body_and_version_agent(
    fake_gateway: FakeGateway,
) -> None:
    run(fake_gateway, Attempt())
    (conn,) = fake_gateway.connections
    assert (conn.host, conn.port) == ("hooks.slack.com", 443)
    assert conn.requests == [(PATH, BODY)]
    assert conn.user_agent == f"slack-notice/{__version__}"
    assert conn.timeout == 5.0


def test_connection_closed_on_success(fake_gateway: FakeGateway) -> None:
    run(fake_gateway, Attempt())
    assert fake_gateway.connections[0].closed


def test_events_order(fake_gateway: FakeGateway) -> None:
    run(fake_gateway, Attempt())
    ev = fake_gateway.events
    order = [ev.index(e) for e in ("tls_context", "https_connection", "connect", "post")]
    assert order == sorted(order)
    assert ev.index("post") < ev.index("getresponse") < ev.index("read") < ev.index("close")


# --- phases and failures ------------------------------------------------------------------


@pytest.mark.parametrize(
    "attempt",
    [
        Attempt(resolve_error=OSError(CANARY)),
        Attempt(connect_error=ConnectionRefusedError(CANARY)),
        Attempt(connect_delay=99.0),
        Attempt(tls_error=ssl.SSLError(CANARY)),
    ],
)
def test_connect_failures_are_phase_connect_and_close(
    fake_gateway: FakeGateway, attempt: Attempt
) -> None:
    result = run(fake_gateway, attempt)
    assert result.phase is Phase.CONNECT and result.status is None
    assert result.failure is not None
    assert "post" not in fake_gateway.events
    assert fake_gateway.connections[0].closed
    assert_no_secret(result)


def test_timeout_flag(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(connect_delay=99.0))
    assert result.failure is not None
    assert result.failure.timeout and not result.failure.tls
    assert result.failure.error_class == "TimeoutError"


def test_cert_verification_failure_flags(fake_gateway: FakeGateway) -> None:
    from tests.fake_gateway import cert_verify_error

    result = run(fake_gateway, Attempt(tls_error=cert_verify_error()))
    f = result.failure
    assert f is not None and f.tls and f.cert_verification and not f.timeout


def test_handshake_failure_is_tls_but_not_cert(fake_gateway: FakeGateway) -> None:
    from tests.fake_gateway import handshake_error

    f = run(fake_gateway, Attempt(tls_error=handshake_error())).failure
    assert f is not None and f.tls and not f.cert_verification


def test_no_usable_ca_is_a_tls_failure_before_any_connection(fake_gateway: FakeGateway) -> None:
    fake_gateway.no_usable_ca = True
    result = post_once(fake_gateway, hook(), BODY, timeout=5.0)
    f = result.failure
    assert f is not None and f.tls and f.no_usable_ca and not f.cert_verification
    assert result.phase is Phase.CONNECT
    assert fake_gateway.connections == []


def test_write_failure_is_phase_write(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(write_error=BrokenPipeError(CANARY)))
    assert result.phase is Phase.WRITE and result.status is None
    assert result.failure is not None and result.failure.error_class == "BrokenPipeError"
    assert fake_gateway.connections[0].closed
    assert_no_secret(result)


def test_write_timeout(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(write_delay=99.0))
    assert result.phase is Phase.WRITE
    assert result.failure is not None and result.failure.timeout


def test_getresponse_exception_is_phase_read_without_status(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(reply=http.client.RemoteDisconnected(CANARY)))
    assert result.phase is Phase.READ and result.status is None
    f = result.failure
    assert f is not None and not f.malformed and f.error_class == "RemoteDisconnected"
    assert_no_secret(result)


@pytest.mark.parametrize(
    "exc", [http.client.BadStatusLine(CANARY), http.client.LineTooLong("status line")]
)
def test_non_http_answer_is_flagged_malformed(fake_gateway: FakeGateway, exc: Exception) -> None:
    f = run(fake_gateway, Attempt(reply=exc)).failure
    assert f is not None and f.malformed


def test_invalid_request_target_error_is_fixed_class_only(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(write_error=http.client.InvalidURL(CANARY)))
    assert result.phase is Phase.WRITE
    assert_no_secret(result)


def test_unexpected_exception_class_is_a_failure_not_a_raise(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(tls_error=RuntimeError(CANARY)))
    assert result.failure is not None and result.failure.error_class == "RuntimeError"
    assert_no_secret(result)


def test_base_exception_propagates_but_closes(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(Attempt(write_error=KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        post_once(fake_gateway, hook(), BODY, timeout=5.0)
    assert fake_gateway.connections[0].closed


def test_hostile_class_name_is_not_reported(fake_gateway: FakeGateway) -> None:
    hostile = type("Bad\nName " + CANARY, (OSError,), {})
    result = run(fake_gateway, Attempt(connect_error=hostile()))
    assert result.failure is not None and result.failure.error_class == "Exception"


def test_result_holds_no_exception_or_traceback(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(connect_error=OSError(CANARY)))
    assert not any(isinstance(v, BaseException) for v in vars(result).values())
    assert not any(isinstance(v, BaseException) for v in vars(result.failure).values())


# --- before_write hook (seam for the deadline gate, #25) ------------------------------------


def test_before_write_is_called_after_connect_and_before_post(fake_gateway: FakeGateway) -> None:
    seen: list[list[str]] = []

    def gate() -> bool:
        seen.append(list(fake_gateway.events))
        return True

    run(fake_gateway, Attempt(), before_write=gate)
    assert seen and seen[0][-1] == "connect" and "post" not in seen[0]


def test_before_write_false_abandons_without_writing(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(), before_write=lambda: False)
    assert result.abandoned and result.phase is Phase.CONNECT
    assert "post" not in fake_gateway.events
    assert fake_gateway.connections[0].closed


def test_before_write_not_called_when_connect_fails(fake_gateway: FakeGateway) -> None:
    calls: list[int] = []
    run(
        fake_gateway, Attempt(connect_error=OSError()), before_write=lambda: calls.append(1) or True
    )
    assert calls == []


# --- response reading ------------------------------------------------------------------------


def test_body_is_read_in_chunks_of_at_most_1kib(fake_gateway: FakeGateway, monkeypatch) -> None:
    import tests.fake_gateway as fg

    sizes: list[int] = []
    original = fg.FakeResponse.read

    def spy(self, amount):  # noqa: ANN001, ANN202
        sizes.append(amount)
        return original(self, amount)

    monkeypatch.setattr(fg.FakeResponse, "read", spy)
    run(fake_gateway, Attempt(reply=Reply(body=b"a" * 3000)))
    assert sizes and max(sizes) <= 1024


def test_body_at_the_cap_is_complete(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(reply=Reply(body=b"a" * 4096)))
    assert len(result.body) == 4096 and not result.body_too_long


def test_body_over_the_cap_is_flagged_and_cut(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(reply=Reply(body=b"a" * 5_000_000)))
    assert result.body_too_long and len(result.body) == 4096
    assert result.status == 200


def test_over_cap_stops_reading(fake_gateway: FakeGateway, monkeypatch) -> None:
    import tests.fake_gateway as fg

    total: list[int] = []
    original = fg.FakeResponse.read

    def spy(self, amount):  # noqa: ANN001, ANN202
        data = original(self, amount)
        total.append(len(data))
        return data

    monkeypatch.setattr(fg.FakeResponse, "read", spy)
    run(fake_gateway, Attempt(reply=Reply(body=b"a" * 1_000_000)))
    assert sum(total) <= 4097


def test_empty_body(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(reply=Reply(status=429, body=b"")))
    assert (result.status, result.body, result.failure) == (429, b"", None)


@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
def test_framings(fake_gateway: FakeGateway, framing: str) -> None:
    result = run(fake_gateway, Attempt(reply=Reply(framing=framing)))
    assert result.body == b'{"ok":true}' and result.failure is None


def test_truncated_body_keeps_status_and_is_a_read_failure(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(reply=Reply(body=b'{"ok"', truncated_by=5)))
    assert result.phase is Phase.READ and result.status == 200
    f = result.failure
    assert f is not None and f.error_class == "IncompleteRead" and not f.malformed
    assert result.body == b'{"ok"'


def test_body_stall_is_a_timeout_failure_with_status(fake_gateway: FakeGateway) -> None:
    result = run(
        fake_gateway, Attempt(reply=Reply(body=b"abc", body_stall_after=1, truncated_by=2))
    )
    assert result.status == 200
    assert result.failure is not None and result.failure.timeout


def test_body_reset_mid_read(fake_gateway: FakeGateway) -> None:
    reply = Reply(body=b"abcdef", body_error=ConnectionResetError(CANARY), body_error_after=2)
    result = run(fake_gateway, Attempt(reply=reply))
    assert result.status == 200 and result.failure is not None
    assert result.failure.error_class == "ConnectionResetError"
    assert_no_secret(result)


def test_slow_trickle_within_the_per_op_timeout_succeeds(fake_gateway: FakeGateway) -> None:
    result = run(fake_gateway, Attempt(reply=Reply(body_trickle=0.5, head_trickle=0.1)))
    assert result.failure is None and result.body == b'{"ok":true}'


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_is_returned_and_never_followed(fake_gateway: FakeGateway, status: int) -> None:
    result = run(fake_gateway, Attempt(reply=Reply(status=status, body=b"moved")))
    assert result.status == status
    assert len(fake_gateway.connections) == 1
    assert fake_gateway.events.count("https_connection") == 1


def test_no_header_is_exposed_on_the_result() -> None:
    names = {n for n in dir(webhook.AttemptResult) if not n.startswith("_")}
    assert not any("retry" in n or "location" in n or "header" in n for n in names)


# --- connection hygiene ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "attempt",
    [
        Attempt(),
        Attempt(connect_error=OSError()),
        Attempt(write_error=OSError()),
        Attempt(reply=http.client.BadStatusLine("x")),
        Attempt(reply=Reply(body=b"x", truncated_by=3)),
    ],
)
def test_every_path_closes_exactly_once(fake_gateway: FakeGateway, attempt: Attempt) -> None:
    run(fake_gateway, attempt)
    assert fake_gateway.events.count("close") == 1


def test_a_failing_close_does_not_change_the_result(fake_gateway: FakeGateway, monkeypatch) -> None:
    import tests.fake_gateway as fg

    def boom(self) -> None:  # noqa: ANN001
        raise OSError(CANARY)

    monkeypatch.setattr(fg.FakeConnection, "close", boom)
    result = run(fake_gateway, Attempt())
    assert result.status == 200 and result.failure is None


def test_exactly_one_attempt_no_internal_retry(fake_gateway: FakeGateway) -> None:
    run(fake_gateway, Attempt(connect_error=OSError()))
    assert fake_gateway.events.count("https_connection") == 1


def test_no_exception_context_leaks_into_the_result(fake_gateway: FakeGateway) -> None:
    # The classification runs inside an except block; nothing of it may outlive the call.
    import gc

    result = run(fake_gateway, Attempt(connect_error=OSError(CANARY)))
    gc.collect()
    assert CANARY not in repr(vars(result)) and CANARY not in repr(vars(result.failure))


# --- the real connection class on a socketpair ------------------------------------------------


class PairGateway(SystemGateway):
    """The production gateway, except that ``connect`` adopts one end of a socketpair (no
    resolution, no network). Everything else is the real code."""

    def __init__(self, sock: socket.socket, cafile: str | None = None, tls: bool = False) -> None:
        self._tls = tls or cafile is not None
        self._sock = sock
        self._cafile = cafile
        self.conns: list[object] = []

    def tls_context(self) -> ssl.SSLContext:
        if self._cafile is None:
            bare = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies, trusts nothing
            bare.check_hostname = True
            bare.verify_mode = ssl.CERT_REQUIRED
            return bare
        return build_tls_context(CaCandidates(self._cafile, None, ()))

    def https_connection(self, host, port, *, timeout, context, user_agent):  # noqa: ANN001, ANN201
        conn = super().https_connection(
            host, port, timeout=timeout, context=context, user_agent=user_agent
        )
        inner = conn._conn  # type: ignore[attr-defined]
        sock = self._sock
        context_ = context
        plain = not self._tls

        def connect() -> None:
            if plain:
                sock.settimeout(inner.timeout)
                inner.sock = sock
            else:
                inner.sock = context_.wrap_socket(sock, server_hostname=host)

        inner.connect = connect
        self.conns.append(conn)
        return conn


def serve(server: socket.socket, reply: bytes, seen: list[bytes]) -> threading.Thread:
    def work() -> None:
        server.settimeout(5)
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = server.recv(4096)
                if not chunk:
                    break
                data += chunk
            seen.append(data)
            if reply:
                server.sendall(reply)
            server.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    return thread


def wire(reply: bytes, *, body: bytes = BODY):  # noqa: ANN202
    client, server = socket.socketpair()
    seen: list[bytes] = []
    gw = PairGateway(client)
    thread = serve(server, reply, seen)
    try:
        result = post_once(gw, hook(), body, timeout=5.0)
    finally:
        thread.join(6)
        server.close()
        client.close()
    return result, seen[0] if seen else b""


OK = b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{"ok":true}'


def test_wire_request_is_exactly_the_specified_bytes() -> None:
    result, raw = wire(OK)
    assert result.status == 200
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("ascii").split("\r\n")
    assert lines[0] == f"POST {PATH} HTTP/1.1"
    assert sorted(lines[1:]) == sorted(
        [
            "Host: hooks.slack.com",
            "Accept-Encoding: identity",
            "Content-Type: application/json",
            "Accept: application/json",
            "Connection: close",
            f"User-Agent: slack-notice/{__version__}",
            f"Content-Length: {len(BODY)}",
        ]
    )
    assert rest == BODY or rest == b""  # the body may arrive in the same or the next segment


@pytest.mark.parametrize(
    "reply",
    [
        b"",  # early close: no response at all
        b"garbage with no http\r\n\r\n",
        b"HTTP/1.1 20",  # cut inside the status line
        b"\x00\xff\xfe" * 100,
        b"HTTP/9.9 200 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n" + b"X: " + b"a" * 70000 + b"\r\n\r\n",  # huge header line
        b"HTTP/1.1 200 OK\r\n" + b"X: a\r\n" * 200 + b"\r\n",  # too many headers
    ],
)
def test_wire_non_http_or_hostile_head_is_a_read_failure(reply: bytes) -> None:
    result, _ = wire(reply)
    assert result.phase is Phase.READ and result.status is None
    assert result.failure is not None
    assert_no_secret(result)


def test_wire_redirect_location_is_never_read_or_followed() -> None:
    reply = (
        b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/x\r\nContent-Length: 0\r\n\r\n"
    )
    result, _ = wire(reply)
    assert result.status == 302 and result.body == b""
    assert CANARY not in repr(result) and "elsewhere" not in repr(result)


def test_wire_http_10_close_delimited() -> None:
    result, _ = wire(b'HTTP/1.0 200 OK\r\n\r\n{"ok":true}')
    assert result.status == 200 and result.body == b'{"ok":true}'


def test_wire_chunked() -> None:
    result, _ = wire(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b'5\r\n{"ok"\r\n6\r\n:true}\r\n0\r\n\r\n'
    )
    assert result.body == b'{"ok":true}' and result.failure is None


def test_wire_1xx_is_skipped_by_http_client() -> None:
    result, _ = wire(b"HTTP/1.1 100 Continue\r\n\r\n" + OK)
    assert result.status == 200


def test_wire_wrong_content_length_short_is_incomplete() -> None:
    result, _ = wire(b'HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{"ok":true}')
    assert result.status == 200 and result.failure is not None
    assert result.failure.error_class == "IncompleteRead"


def test_wire_huge_body_is_cut_at_the_cap() -> None:
    result, _ = wire(b"HTTP/1.1 200 OK\r\n\r\n" + b"a" * 200_000)
    assert result.body_too_long and len(result.body) == 4096


def test_wire_socket_is_closed_afterwards() -> None:
    client, server = socket.socketpair()
    gw = PairGateway(client)
    thread = serve(server, OK, [])
    before = len(os.listdir("/proc/self/fd"))
    post_once(gw, hook(), BODY, timeout=5.0)
    thread.join(6)
    server.close()
    # post_once closed the connection, which closes the adopted socket
    assert client.fileno() == -1
    assert len(os.listdir("/proc/self/fd")) <= before


# --- real TLS verification failure on a socketpair --------------------------------------------


def make_cert(tmp_path: Path, name: str) -> tuple[Path, Path]:
    cert, key = tmp_path / f"{name}.c.pem", tmp_path / f"{name}.k.pem"
    proc = subprocess.run(  # noqa: S603
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            f"/CN={name}",
            "-addext",
            f"subjectAltName=DNS:{name}",
        ],
        capture_output=True,
        env={"PATH": os.environ["PATH"], "HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path)},
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        pytest.skip("openssl cannot generate a certificate here")
    return cert, key


@pytest.fixture
def selfsigned(tmp_path: Path) -> tuple[Path, Path]:
    return make_cert(tmp_path, "other.invalid")


def test_real_tls_wrong_host_is_a_cert_verification_failure(
    selfsigned: tuple[Path, Path],
) -> None:
    cert, key = selfsigned
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(cert), str(key))
    client, server = socket.socketpair()

    def serve_tls() -> None:
        try:
            server.settimeout(5)
            with server_ctx.wrap_socket(server, server_side=True) as tls:
                tls.recv(10)
        except OSError:
            pass

    thread = threading.Thread(target=serve_tls, daemon=True)
    thread.start()
    gw = PairGateway(client, cafile=str(cert))  # trusted, but the name is not hooks.slack.com
    result = post_once(gw, hook(), BODY, timeout=5.0)
    thread.join(6)
    assert result.phase is Phase.CONNECT
    f = result.failure
    assert f is not None and f.tls and f.cert_verification
    assert_no_secret(result)


def test_real_tls_untrusted_root_is_a_cert_verification_failure(
    selfsigned: tuple[Path, Path],
) -> None:
    cert, key = selfsigned
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(cert), str(key))
    client, server = socket.socketpair()

    def serve_tls() -> None:
        try:
            server.settimeout(5)
            with server_ctx.wrap_socket(server, server_side=True) as tls:
                tls.recv(10)
        except OSError:
            pass

    thread = threading.Thread(target=serve_tls, daemon=True)
    thread.start()
    gw = PairGateway(client, tls=True)  # a context that trusts nothing
    result = post_once(gw, hook(), BODY, timeout=5.0)
    thread.join(6)
    f = result.failure
    assert f is not None and f.tls and f.cert_verification


def test_environment_cannot_add_trust_or_a_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A server whose certificate is valid for the right name but signed by nobody we trust:
    # SSL_CERT_FILE and SSL_CERT_DIR name it, a proxy variable is set, and the attempt must still
    # fail verification (or find no CA at all) and never tunnel.
    cert, key = make_cert(tmp_path, "hooks.slack.com")
    certdir = tmp_path / "certs"
    certdir.mkdir()
    for name, value in (
        ("SSL_CERT_FILE", str(cert)),
        ("SSL_CERT_DIR", str(certdir)),
        ("https_proxy", "http://proxy.invalid:3128"),
        ("HTTPS_PROXY", "http://proxy.invalid:3128"),
        ("ALL_PROXY", "http://proxy.invalid:3128"),
        ("SSLKEYLOGFILE", str(tmp_path / "keys.log")),
    ):
        monkeypatch.setenv(name, value)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(cert), str(key))
    client, server = socket.socketpair()

    def serve_tls() -> None:
        try:
            server.settimeout(5)
            with server_ctx.wrap_socket(server, server_side=True) as tls:
                tls.recv(10)
        except OSError:
            pass

    thread = threading.Thread(target=serve_tls, daemon=True)
    thread.start()

    class RealTrust(PairGateway):
        def tls_context(self) -> ssl.SSLContext:  # the production trust logic, as is
            return SystemGateway.tls_context(self)

    gw = RealTrust(client, tls=True)
    result = post_once(gw, hook(), BODY, timeout=5.0)
    thread.join(6)
    f = result.failure
    assert result.status is None and f is not None and f.tls
    assert f.cert_verification or f.no_usable_ca
    assert gw.conns[0]._conn._tunnel_host is None  # type: ignore[attr-defined]
    assert not (tmp_path / "keys.log").exists()

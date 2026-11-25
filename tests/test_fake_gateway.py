"""Contract tests for the fake gateway (issue #5).

The fake must behave like the real gateway protocol: same inputs, outputs, errors and failure
semantics. Where the real ``http.client`` classes can be driven without a socket, the fake is
compared with them directly; everything else is checked against the protocol's docstrings and
the interface's Webhook edge table.
"""

from __future__ import annotations

import ast
import errno
import http.client
import io
import math
import os
import re
import socket
import ssl
import struct
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from slack_notice import gateway as gw_module
from slack_notice.gateway import (
    CaCandidates,
    Gateway,
    HomeLookupError,
    NotRegularFile,
    NoUsableCA,
    Response,
    SourceRead,
    StateUnusable,
    SystemGateway,
    is_cert_verification_error,
    is_malformed_response,
    is_timeout,
    is_tls_error,
)
from tests.fake_gateway import (
    Attempt,
    FakeConnection,
    FakeGateway,
    Reply,
    cert_verify_error,
    handshake_error,
    handshake_timeout,
    ssl_eof_error,
    ssl_wrong_version,
    tls_broken_pipe,
)
from tests.test_gateway import ROOT_CA_PEM

SRC = Path(__file__).resolve().parent.parent / "src" / "slack_notice"
WEBHOOK = "hooks.slack.com"
PATH = "/triggers/T123/A456/secretpart"
BODY = b'{"text":"hello"}'


@pytest.fixture
def gw(fake_gateway: FakeGateway) -> FakeGateway:
    return fake_gateway


def open_connection(gw: FakeGateway, timeout: float = 5.0) -> FakeConnection:
    return gw.https_connection(
        "hooks.slack.com",
        443,
        timeout=timeout,
        context=gw.tls_context(),
        user_agent="slack-notice/0.1.0",
    )


def full_exchange(gw: FakeGateway, timeout: float = 5.0) -> tuple[int, bytes]:
    """The webhook module's sequence: connect, post, getresponse, read in 1 KiB chunks."""
    conn = gw.https_connection(
        "hooks.slack.com",
        443,
        timeout=timeout,
        context=gw.tls_context(),
        user_agent="slack-notice/0.1.0",
    )
    try:
        conn.connect()
        conn.post(PATH, BODY)
        response = conn.getresponse()
        chunks = []
        while True:
            chunk = response.read(1024)
            if not chunk:
                break
            chunks.append(chunk)
        return response.status, b"".join(chunks)
    finally:
        conn.close()


# --- protocol conformance --------------------------------------------------------------------


def test_fake_satisfies_the_gateway_protocol(gw: FakeGateway) -> None:
    protocol_view: Gateway = gw  # pyright checks the structural match
    for name in dir(Gateway):
        if name.startswith("_"):
            continue
        assert callable(getattr(protocol_view, name)), name


# --- Webhook edge: one scripted response per row ---------------------------------------------

EDGE_ROWS = [
    ("200 success", 200, b'{"ok":true}'),
    ("200 wrong body", 200, b'{"ok":false}'),
    ("200 not JSON", 200, b"<html>hi</html>"),
    ("200 empty", 200, b""),
    ("200 body over the 4 KiB cap", 200, b'{"ok":true,"pad":"' + b"x" * 5000 + b'"}'),
    ("200 not UTF-8", 200, b'{"ok":true,"x":"\xff\xfe"}'),
    ("204", 204, b""),
    ("400 with error key", 400, b'{"ok":false,"error":"invalid_payload"}'),
    ("401", 401, b'{"ok":false,"error":"invalid_auth"}'),
    ("403", 403, b""),
    ("404", 404, b"not found"),
    ("410", 410, b""),
    ("429", 429, b'{"ok":false,"error":"rate_limited"}'),
    ("500", 500, b""),
    ("502", 502, b"bad gateway"),
    ("503", 503, b""),
    ("301", 301, b""),
    ("302", 302, b""),
    ("307", 307, b""),
    ("418 other", 418, b""),
]


@pytest.mark.parametrize(("name", "status", "body"), EDGE_ROWS, ids=[r[0] for r in EDGE_ROWS])
def test_serves_each_webhook_edge_row(gw: FakeGateway, name: str, status: int, body: bytes) -> None:
    gw.script(Attempt(reply=Reply(status=status, body=body)))
    assert full_exchange(gw) == (status, body)
    gw.assert_script_consumed()


def test_default_attempt_is_the_success_form(gw: FakeGateway) -> None:
    gw.script(Attempt())
    assert full_exchange(gw) == (200, b'{"ok":true}')


def test_records_the_request_and_connection_parameters(gw: FakeGateway) -> None:
    gw.script(Attempt())
    full_exchange(gw, timeout=7.0)
    (conn,) = gw.connections
    assert (conn.host, conn.port, conn.user_agent) == ("hooks.slack.com", 443, "slack-notice/0.1.0")
    assert conn.requests == [(PATH, BODY)]
    assert conn.closed


def test_response_exposes_only_status_and_read(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(status=429)))
    conn = open_connection(gw)
    conn.connect()
    conn.post(PATH, BODY)
    response = conn.getresponse()
    public = {n for n in dir(response) if not n.startswith("_")}
    assert public == {"status", "read"}


def test_exhausted_script_is_loud(gw: FakeGateway) -> None:
    with pytest.raises(AssertionError, match="no scripted attempt"):
        open_connection(gw)
    assert gw.violations == ["fake gateway: no scripted attempt for this connection"]
    gw.violations.clear()  # expected here; the fixture teardown would fail the test otherwise


def test_unconsumed_script_is_detected(gw: FakeGateway) -> None:
    gw.script(Attempt(), Attempt())
    full_exchange(gw)
    with pytest.raises(AssertionError, match="unconsumed"):
        gw.assert_script_consumed()
    with pytest.raises(AssertionError, match="unconsumed"):
        gw.assert_clean()  # what the fixture teardown runs
    gw.allow_unconsumed_script = True
    gw.assert_clean()


def test_teardown_check_reports_contract_violations(gw: FakeGateway) -> None:
    gw.script(Attempt())
    conn = open_connection(gw)
    with pytest.raises(AssertionError, match="connect"):
        conn.post(PATH, BODY)
    with pytest.raises(AssertionError, match="contract violations"):
        gw.assert_clean()
    gw.violations.clear()
    gw.assert_clean()


@pytest.mark.parametrize("what", ["host", "port", "verify", "tls10", "closed", "after_response"])
def test_each_contract_violation_is_recorded(gw: FakeGateway, what: str) -> None:
    gw.script(Attempt())
    context = gw.tls_context()
    if what == "host":
        with pytest.raises(AssertionError):
            gw.https_connection("example.com", 443, timeout=1.0, context=context, user_agent="x")
    elif what == "port":
        with pytest.raises(AssertionError):
            gw.https_connection(WEBHOOK, 8443, timeout=1.0, context=context, user_agent="x")
    elif what == "verify":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with pytest.raises(AssertionError):
            gw.https_connection(WEBHOOK, 443, timeout=1.0, context=context, user_agent="x")
    elif what == "tls10":
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        with pytest.raises(AssertionError, match="1.2"):
            gw.https_connection(WEBHOOK, 443, timeout=1.0, context=context, user_agent="x")
    else:
        conn = open_connection(gw)
        conn.connect()
        if what == "closed":
            conn.close()
        else:
            conn.post(PATH, BODY)
            conn.getresponse()
        with pytest.raises(AssertionError):
            conn.post(PATH, BODY)
    assert len(gw.violations) == 1
    gw.violations.clear()
    gw.allow_unconsumed_script = True


# --- failures before the first write (gate idle) ----------------------------------------------


def test_name_resolution_failure_comes_from_connect(gw: FakeGateway) -> None:
    gw.script(
        Attempt(resolve_error=socket.gaierror(socket.EAI_NONAME, "Name or service not known"))
    )
    conn = open_connection(gw)
    with pytest.raises(socket.gaierror):
        conn.connect()
    assert gw.events == ["tls_context", "https_connection", "connect"]


def test_connection_refused(gw: FakeGateway) -> None:
    gw.script(Attempt(connect_error=ConnectionRefusedError(errno.ECONNREFUSED, "refused")))
    with pytest.raises(ConnectionRefusedError):
        full_exchange(gw)


def test_connect_slower_than_the_socket_timeout_times_out(gw: FakeGateway) -> None:
    gw.script(Attempt(connect_delay=30.0))
    start = gw.monotonic()
    with pytest.raises(TimeoutError) as info:
        full_exchange(gw, timeout=2.0)
    assert is_timeout(info.value)
    assert gw.monotonic() - start == pytest.approx(2.0, abs=0.5)


def test_connect_faster_than_the_timeout_advances_the_clock(gw: FakeGateway) -> None:
    gw.script(Attempt(connect_delay=1.5))
    start = gw.monotonic()
    full_exchange(gw, timeout=5.0)
    assert gw.monotonic() - start >= 1.5


def test_tls_handshake_failure_is_an_ssl_error_not_verification(gw: FakeGateway) -> None:
    gw.script(Attempt(tls_error=handshake_error()))
    with pytest.raises(ssl.SSLError) as info:
        full_exchange(gw)
    assert is_tls_error(info.value)
    assert not is_cert_verification_error(info.value)


def test_certificate_verification_failure(gw: FakeGateway) -> None:
    gw.script(Attempt(tls_error=cert_verify_error()))
    with pytest.raises(ssl.SSLCertVerificationError) as info:
        full_exchange(gw)
    assert is_cert_verification_error(info.value)
    assert is_tls_error(info.value)


def test_no_usable_ca_fails_at_context_creation(gw: FakeGateway) -> None:
    gw.no_usable_ca = True
    with pytest.raises(NoUsableCA) as info:
        gw.tls_context()
    assert is_tls_error(info.value)


def test_stalled_name_resolution_blocks_connect_until_released(gw: FakeGateway) -> None:
    gw.script(Attempt(resolve_stall=True))
    conn = open_connection(gw, timeout=1.0)
    outcome: list[BaseException | None] = []

    def worker() -> None:
        try:
            conn.connect()
            outcome.append(None)
        except BaseException as error:
            outcome.append(error)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    assert gw.stalled.wait(5)
    # The socket timeout does not cover name resolution: still blocked well past it.
    thread.join(1.5)
    assert thread.is_alive()
    gw.release_stalls()
    thread.join(5)
    assert not thread.is_alive()
    assert isinstance(outcome[0], OSError)


def test_stall_is_released_by_the_fixture_safety_cap(gw: FakeGateway) -> None:
    gw.stall_cap_seconds = 0.2
    gw.script(Attempt(resolve_stall=True))
    conn = open_connection(gw)
    with pytest.raises(OSError, match="stall"):
        conn.connect()


# --- request writing ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/a b", "/a\nb", "/a\x7fb", "/a\x00b", "/café", "/☃"])
def test_post_rejects_unsendable_paths_like_the_real_connection(gw: FakeGateway, path: str) -> None:
    """Same class and the fixed message as the real ``_HttpsConnection.post``."""
    real = gw_module._HttpsConnection(  # type: ignore[attr-defined]
        "hooks.slack.com",
        443,
        timeout=1.0,
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
        user_agent="x",
    )
    with pytest.raises(http.client.InvalidURL) as real_info:
        real.post(path, BODY)
    gw.script(Attempt())
    conn = open_connection(gw)
    conn.connect()
    with pytest.raises(http.client.InvalidURL) as fake_info:
        conn.post(path, BODY)
    assert str(fake_info.value) == str(real_info.value) == "invalid request"
    assert fake_info.value.__cause__ is None and fake_info.value.__suppress_context__


def test_post_requires_bytes_body(gw: FakeGateway) -> None:
    gw.script(Attempt())
    conn = open_connection(gw)
    conn.connect()
    with pytest.raises(TypeError):
        conn.post(PATH, "text")  # type: ignore[arg-type]


def test_post_before_connect_is_a_spec_violation(gw: FakeGateway) -> None:
    gw.script(Attempt())
    conn = open_connection(gw)
    with pytest.raises(AssertionError, match="connect"):
        conn.post(PATH, BODY)
    assert len(gw.violations) == 1
    gw.violations.clear()


def test_second_post_on_one_connection_is_refused(gw: FakeGateway) -> None:
    gw.script(Attempt())
    conn = open_connection(gw)
    conn.connect()
    conn.post(PATH, BODY)
    with pytest.raises(http.client.CannotSendRequest):
        conn.post(PATH, BODY)


def test_getresponse_before_post_is_not_ready(gw: FakeGateway) -> None:
    gw.script(Attempt())
    conn = open_connection(gw)
    conn.connect()
    with pytest.raises(http.client.ResponseNotReady):
        conn.getresponse()


def test_write_failure(gw: FakeGateway) -> None:
    gw.script(Attempt(write_error=BrokenPipeError(errno.EPIPE, "broken pipe")))
    conn = open_connection(gw)
    conn.connect()
    with pytest.raises(BrokenPipeError):
        conn.post(PATH, BODY)


def test_write_failure_can_say_whether_the_host_got_the_request(gw: FakeGateway) -> None:
    gw.script(
        Attempt(write_error=ConnectionResetError(), request_delivered_on_write_error=True),
        Attempt(write_error=ConnectionResetError()),
    )
    for _ in range(2):
        conn = open_connection(gw)
        conn.connect()
        with pytest.raises(ConnectionResetError):
            conn.post(PATH, BODY)
    assert [c.delivered for c in gw.connections] == [True, False]


# --- failures after the write ------------------------------------------------------------------


def test_failure_after_the_write_is_raised_by_getresponse(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=http.client.RemoteDisconnected("Remote end closed connection")))
    conn = open_connection(gw)
    conn.connect()
    conn.post(PATH, BODY)
    with pytest.raises(http.client.RemoteDisconnected) as info:
        conn.getresponse()
    assert not is_malformed_response(info.value)  # a lost answer, not a malformed one
    assert gw.connections[0].delivered  # the request was written


def test_malformed_answer_is_an_http_exception_not_a_loss(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=http.client.BadStatusLine("garbage")))
    with pytest.raises(http.client.BadStatusLine) as info:
        full_exchange(gw)
    assert is_malformed_response(info.value)


def test_connection_reset_after_the_write(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=ConnectionResetError(errno.ECONNRESET, "reset")))
    with pytest.raises(ConnectionResetError):
        full_exchange(gw)


def test_first_byte_later_than_the_socket_timeout_times_out(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(first_byte_delay=60.0)))
    start = gw.monotonic()
    with pytest.raises(TimeoutError):
        full_exchange(gw, timeout=2.0)
    assert gw.monotonic() - start == pytest.approx(2.0, abs=0.5)


def test_stall_after_the_first_byte_times_out_per_operation(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(head_stall_after=1)))
    start = gw.monotonic()
    with pytest.raises(TimeoutError):
        full_exchange(gw, timeout=3.0)
    assert gw.monotonic() - start == pytest.approx(3.0, abs=0.5)


def test_stall_inside_the_body_times_out_after_the_bytes_before_it(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(body=b'{"ok":true}', body_stall_after=4)))
    conn = open_connection(gw, timeout=1.0)
    conn.connect()
    conn.post(PATH, BODY)
    response = conn.getresponse()
    assert response.read(4) == b'{"ok'
    with pytest.raises(TimeoutError):
        response.read(1024)


def test_trickled_response_beats_a_per_operation_timeout_but_not_a_deadline(
    gw: FakeGateway,
) -> None:
    """One byte per 0.4 s with a 1 s socket timeout completes (spike result in design D-11)."""
    body = b'{"ok":true}'
    gw.script(Attempt(reply=Reply(body=body, head_trickle=0.4, body_trickle=0.4)))
    start = gw.monotonic()
    assert full_exchange(gw, timeout=1.0) == (200, body)
    elapsed = gw.monotonic() - start
    assert elapsed >= 0.4 * len(body)  # the body alone
    assert elapsed > 5.0  # head bytes too: far past a 1 s timeout in total


def test_trickle_slower_than_the_socket_timeout_times_out(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(body_trickle=5.0)))
    with pytest.raises(TimeoutError):
        full_exchange(gw, timeout=1.0)


def test_settimeout_applies_to_operations_before_getresponse(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(first_byte_delay=10.0)))
    conn = open_connection(gw, timeout=60.0)
    conn.connect()
    conn.post(PATH, BODY)
    conn.settimeout(1.0)
    start = gw.monotonic()
    with pytest.raises(TimeoutError):
        conn.getresponse()
    assert gw.monotonic() - start == pytest.approx(1.0, abs=0.5)


def test_settimeout_after_getresponse_does_not_reach_the_response(gw: FakeGateway) -> None:
    """With ``Connection: close`` the response owns the socket and keeps its timeout."""
    gw.script(Attempt(reply=Reply(body_trickle=5.0)))
    conn = open_connection(gw, timeout=1.0)
    conn.connect()
    conn.post(PATH, BODY)
    response = conn.getresponse()
    conn.settimeout(60.0)
    start = gw.monotonic()
    with pytest.raises(TimeoutError):
        response.read(1024)
    assert gw.monotonic() - start == pytest.approx(1.0, abs=0.5)


def test_truncated_content_length_raises_incomplete_read(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(body=b"abcd", truncated_by=6)))
    conn = open_connection(gw)
    conn.connect()
    conn.post(PATH, BODY)
    response = conn.getresponse()
    assert response.read(3) == b"abc"
    assert response.read(3) == b"d"
    with pytest.raises(http.client.IncompleteRead) as info:
        response.read(3)
    assert not is_malformed_response(info.value)


class _BytesSocket:
    """Just enough socket for ``http.client.HTTPResponse``: no real socket is involved."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def makefile(self, *_args: object, **_kwargs: object) -> io.BufferedReader:
        return io.BufferedReader(io.BytesIO(self._data))  # type: ignore[arg-type]


@pytest.mark.parametrize("truncated_by", [0, 6])
@pytest.mark.parametrize("amount", [1, 3, 1024])
def test_read_sequence_matches_real_http_client(
    gw: FakeGateway, truncated_by: int, amount: int
) -> None:
    """Drive the real response wrapper over canned bytes and compare read-by-read."""
    body = b"abcdefgh"
    wire = (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(body) + truncated_by).encode()
        + b"\r\n\r\n"
        + body
    )
    real_http = http.client.HTTPResponse(_BytesSocket(wire))  # type: ignore[arg-type]
    real_http.begin()
    real = gw_module._HttpsResponse(real_http)  # type: ignore[attr-defined]

    gw.script(Attempt(reply=Reply(body=body, truncated_by=truncated_by)))
    conn = open_connection(gw)
    conn.connect()
    conn.post(PATH, BODY)
    fake = conn.getresponse()

    def drive(response: Response) -> list[object]:
        seen: list[object] = []
        for _ in range(20):
            try:
                chunk = response.read(amount)
            except http.client.IncompleteRead:
                seen.append("IncompleteRead")
                break
            seen.append(chunk)
            if not chunk:
                break
        return seen

    assert drive(fake) == drive(real)


def test_read_after_the_end_stays_empty(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(body=b"x")))
    conn = open_connection(gw)
    conn.connect()
    conn.post(PATH, BODY)
    response = conn.getresponse()
    assert [response.read(8), response.read(8), response.read(8)] == [b"x", b"", b""]


# --- injected exceptions ride through unchanged ---------------------------------------------


@pytest.mark.parametrize("phase", ["resolve", "connect", "tls", "write", "reply"])
def test_injected_exception_instance_is_raised_as_given(gw: FakeGateway, phase: str) -> None:
    secret = "https://hooks.slack.com/triggers/T/SECRET"
    error = OSError(secret)
    attempt = {
        "resolve": Attempt(resolve_error=error),
        "connect": Attempt(connect_error=error),
        "tls": Attempt(tls_error=ssl.SSLError(secret)),
        "write": Attempt(write_error=error),
        "reply": Attempt(reply=error),
    }[phase]
    gw.script(attempt)
    with pytest.raises(OSError, match="SECRET"):
        full_exchange(gw)


# --- clock -------------------------------------------------------------------------------------


def test_sleep_advances_the_clock_without_waiting(gw: FakeGateway) -> None:
    real_start = time.monotonic()
    before = gw.monotonic()
    gw.sleep(120.0)
    assert gw.monotonic() - before >= 120.0
    assert time.monotonic() - real_start < 5.0
    assert "sleep:120.0" in gw.events


def test_sleep_of_zero_or_negative_does_nothing(gw: FakeGateway) -> None:
    before = gw.monotonic()
    gw.sleep(0)
    gw.sleep(-5)
    assert gw.monotonic() - before < 1.0


def test_clock_is_monotonic_and_wall_time_follows_it(gw: FakeGateway) -> None:
    first, wall_first = gw.monotonic(), gw.wall_time()
    gw.sleep(10)
    assert gw.monotonic() >= first + 10
    assert gw.wall_time() >= wall_first + 10
    assert gw.monotonic() >= first


def test_wall_time_start_is_configurable(tmp_path: Path) -> None:
    gateway = FakeGateway(home=str(tmp_path), wall_start=1_000_000.0)
    assert 1_000_000.0 <= gateway.wall_time() < 1_000_100.0


def test_clock_advance_is_thread_safe(gw: FakeGateway) -> None:
    before = gw.monotonic()

    def spin() -> None:
        for _ in range(200):
            gw.sleep(1.0)

    threads = [threading.Thread(target=spin) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert gw.monotonic() - before >= 800.0


# --- password database stand-in ----------------------------------------------------------------


def test_home_uid_and_login_come_from_the_fake(tmp_path: Path) -> None:
    gateway = FakeGateway(home=str(tmp_path), login_name="tester")
    assert gateway.home_dir() == str(tmp_path)
    assert gateway.uid() == os.getuid()
    assert gateway.login_name() == "tester"


def test_home_is_returned_as_found_even_when_hostile() -> None:
    for hostile in ("", "relative/dir", "/does/not/exist"):
        assert FakeGateway(home=hostile).home_dir() == hostile


def test_home_lookup_failure_and_missing_login() -> None:
    gateway = FakeGateway(home="/x", home_error=True, login_name=None)
    with pytest.raises(HomeLookupError):
        gateway.home_dir()
    assert gateway.login_name() is None


def test_fake_never_consults_the_password_database(
    gw: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_a: object, **_k: object) -> None:
        raise AssertionError("pwd consulted")

    monkeypatch.setattr("pwd.getpwuid", refuse)
    monkeypatch.setattr("pwd.getpwnam", refuse)
    gw.home_dir()
    gw.login_name()
    gw.uid()
    gw.open_state_dir(gw.home_dir())


def test_uid_can_differ_to_exercise_the_owner_check(tmp_path: Path) -> None:
    gateway = FakeGateway(home=str(tmp_path), uid=os.getuid() + 1)
    assert gateway.uid() == os.getuid() + 1
    with pytest.raises(StateUnusable) as info:
        gateway.open_state_dir(str(tmp_path))
    assert info.value.reason == "owner"


# --- name resolution hook ----------------------------------------------------------------------


def test_resolve_hook_returns_addresses_or_fails(gw: FakeGateway) -> None:
    assert gw.resolve("hooks.slack.com", 443) == ["192.0.2.1"]
    gw.resolve_error = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    with pytest.raises(socket.gaierror):
        gw.resolve("hooks.slack.com", 443)


# --- TLS context and CA candidates -------------------------------------------------------------


def test_tls_context_verifies_and_needs_tls12(gw: FakeGateway) -> None:
    context = gw.tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_connection_refuses_a_context_that_does_not_verify(gw: FakeGateway) -> None:
    gw.script(Attempt())
    weak = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    weak.check_hostname = False
    weak.verify_mode = ssl.CERT_NONE
    with pytest.raises(AssertionError, match="verif"):
        gw.https_connection("hooks.slack.com", 443, timeout=1.0, context=weak, user_agent="x")
    gw.violations.clear()
    gw.allow_unconsumed_script = True


def test_connection_refuses_another_host_or_port(gw: FakeGateway) -> None:
    gw.script(Attempt(), Attempt())
    for host, port in (("example.com", 443), ("hooks.slack.com", 8443)):
        with pytest.raises(AssertionError, match="hooks.slack.com"):
            gw.https_connection(host, port, timeout=1.0, context=gw.tls_context(), user_agent="x")
    gw.violations.clear()
    gw.allow_unconsumed_script = True


def test_tls_context_honors_the_ca_hook(gw: FakeGateway, tmp_path: Path) -> None:
    nothing = CaCandidates(None, None, ("/nonexistent/bundle.pem",))
    gw.ca = nothing
    with pytest.raises(NoUsableCA):
        gw.tls_context()
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    gw.ca = CaCandidates(str(garbage), str(tmp_path / "missing-dir"), ())
    with pytest.raises(NoUsableCA):
        gw.tls_context()
    bundle = tmp_path / "bundle.pem"
    bundle.write_text(ROOT_CA_PEM)
    for usable in (
        CaCandidates(str(bundle), None, ()),
        CaCandidates(None, str(tmp_path), ()),
        CaCandidates(None, None, (str(garbage), str(bundle))),
    ):
        gw.ca = usable
        assert gw.tls_context().verify_mode == ssl.CERT_REQUIRED


def test_ca_candidates_are_scripted(gw: FakeGateway) -> None:
    default = gw.ca_candidates()
    assert isinstance(default, CaCandidates)
    assert default.fallback_files == gw_module.CA_FALLBACK_FILES
    custom = CaCandidates("/c/file", "/c/dir", ("/c/fallback",))
    gw.ca = custom
    assert gw.ca_candidates() == custom


# --- input, state files, config-style files ----------------------------------------------------


def test_read_source_scripted_results(gw: FakeGateway) -> None:
    gw.source_script = [
        SourceRead(b"partial", timed_out=True),
        SourceRead(b"x" * 3, too_large=True),
    ]
    assert gw.read_source(0, 10, 1.0) == SourceRead(b"partial", timed_out=True)
    assert gw.read_source("/any", 10, 1.0) == SourceRead(b"x" * 3, too_large=True)


def test_read_source_scripted_exception(gw: FakeGateway) -> None:
    gw.source_script = [NotRegularFile()]
    with pytest.raises(NotRegularFile):
        gw.read_source("/any", 10, 1.0)


def test_read_source_without_a_script_reads_a_real_descriptor(gw: FakeGateway) -> None:
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, b"hello")
        os.close(write_end)
        write_end = -1
        assert gw.read_source(read_end, 100, 5.0) == SourceRead(b"hello")
    finally:
        os.close(read_end)
        if write_end != -1:
            os.close(write_end)


def test_read_source_deadline_runs_on_the_fake_clock(gw: FakeGateway) -> None:
    """An hour of deadline ends in well under 2 real seconds once the fake clock jumps ahead."""
    read_end, write_end = os.pipe()

    stop = threading.Event()

    def jump() -> None:
        # Advance the fake clock only once read_source has started, then keep advancing until
        # the test ends, so a late start can never leave the read polling for an hour.
        while "read_source" not in gw.events and not stop.wait(0.01):
            pass
        stop.wait(0.1)  # real time: let the read take its deadline from the fake clock
        while not stop.is_set():
            gw.sleep(4000.0)
            stop.wait(0.2)

    helper = threading.Thread(target=jump, daemon=True)
    try:
        real_start = time.monotonic()
        helper.start()
        result = gw.read_source(read_end, 100, 3600.0)  # no writer closes: never ends
        assert result.timed_out
        assert time.monotonic() - real_start < 2.0
    finally:
        stop.set()
        helper.join(5)
        os.close(read_end)
        os.close(write_end)


def test_state_directory_roundtrip_and_hostile_symlink(gw: FakeGateway, tmp_path: Path) -> None:
    home = gw.home_dir()
    dir_fd = gw.open_state_dir(home)
    try:
        file_fd = gw.open_state_file(dir_fd, "send.lock")
        try:
            assert gw.try_lock(file_fd)
            gw.unlock(file_fd)
        finally:
            os.close(file_fd)
    finally:
        os.close(dir_fd)
    leaf = Path(home) / ".local" / "state" / "slack-notice"
    victim = tmp_path / "victim"
    victim.mkdir()
    (leaf / "log.jsonl").symlink_to(victim)
    dir_fd = gw.open_state_dir(home)
    try:
        with pytest.raises(StateUnusable):
            gw.open_state_file(dir_fd, "log.jsonl", append=True)
    finally:
        os.close(dir_fd)


def test_state_hooks_inject_unusable_dir_and_files(gw: FakeGateway) -> None:
    gw.state_dir_error = StateUnusable("mode")
    with pytest.raises(StateUnusable) as info:
        gw.open_state_dir(gw.home_dir())
    assert info.value.reason == "mode"
    gw.state_dir_error = None
    gw.state_file_errors["log.jsonl"] = StateUnusable("not_regular")
    dir_fd = gw.open_state_dir(gw.home_dir())
    try:
        with pytest.raises(StateUnusable):
            gw.open_state_file(dir_fd, "log.jsonl", append=True)
        os.close(gw.open_state_file(dir_fd, "send.lock"))  # other names are unaffected
    finally:
        os.close(dir_fd)


def test_lock_held_by_someone_else_and_lock_failure(gw: FakeGateway) -> None:
    dir_fd = gw.open_state_dir(gw.home_dir())
    fd = gw.open_state_file(dir_fd, "send.lock")
    try:
        gw.lock_held = True
        assert gw.try_lock(fd) is False
        gw.lock_held = False
        gw.lock_error = OSError(errno.ENOLCK, "no locks")
        with pytest.raises(OSError):
            gw.try_lock(fd)
    finally:
        os.close(fd)
        os.close(dir_fd)


def test_real_lock_contention_still_works_through_the_fake(gw: FakeGateway) -> None:
    dir_fd = gw.open_state_dir(gw.home_dir())
    first = gw.open_state_file(dir_fd, "send.lock")
    second = gw.open_state_file(dir_fd, "send.lock")
    try:
        assert gw.try_lock(first)
        assert gw.try_lock(second) is False
        gw.unlock(first)
        assert gw.try_lock(second)
    finally:
        os.close(first)
        os.close(second)
        os.close(dir_fd)


def test_read_regular_file_rejects_a_fifo_without_blocking(gw: FakeGateway, tmp_path: Path) -> None:
    fifo = tmp_path / "config.yaml"
    os.mkfifo(fifo)
    with pytest.raises(NotRegularFile):
        gw.read_regular_file(fifo, 100)


# --- the call trace ------------------------------------------------------------------------------


def test_events_record_the_webhook_call_order(gw: FakeGateway) -> None:
    gw.script(Attempt())
    full_exchange(gw)
    assert gw.events == [
        "tls_context",
        "https_connection",
        "connect",
        "post",
        "getresponse",
        "read",
        "read",
        "close",
    ]


# --- fidelity against the real http.client, on local socketpairs only ---------------------------


class RealWire:
    """The real ``_HttpsConnection`` wired to one end of a local socketpair (no network)."""

    def __init__(self, timeout: float, user_agent: str = "slack-notice/0.1.0") -> None:
        self.client, self.server = socket.socketpair()
        self.client.settimeout(timeout)
        self.connection = gw_module._HttpsConnection(  # type: ignore[attr-defined]
            WEBHOOK,
            443,
            timeout=timeout,
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
            user_agent=user_agent,
        )
        self.connection._conn.sock = self.client  # type: ignore[attr-defined]

    def send(self, wire: bytes, *, end: bool = False) -> None:
        self.server.sendall(wire)
        if end:
            self.server.shutdown(socket.SHUT_WR)

    def reset(self) -> None:
        """Close the server end with a TCP-style reset (``ConnectionResetError`` on the client)."""
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.server.close()


@pytest.fixture
def real_wire() -> Iterator[Callable[..., RealWire]]:
    made: list[RealWire] = []

    def make(timeout: float = 0.3, **kwargs: str) -> RealWire:
        wire = RealWire(timeout, **kwargs)
        made.append(wire)
        return wire

    yield make
    for wire in made:
        wire.connection.close()
        wire.client.close()
        wire.server.close()


def head(framing: str, declared: int = 0, status: int = 200) -> bytes:
    length = "Transfer-Encoding: chunked" if framing == "chunked" else f"Content-Length: {declared}"
    tail = "" if framing == "eof" else f"{length}\r\n"
    return f"HTTP/1.1 {status} OK\r\n{tail}Connection: close\r\n\r\n".encode()


def wire_body(framing: str, body: bytes, declared: int) -> bytes:
    """The bytes a host sends: the declared length (or a chunk size) and what arrives."""
    if framing == "chunked":
        wire = head(framing) + f"{declared:x}\r\n".encode() + body
        return wire + (b"\r\n0\r\n\r\n" if len(body) == declared else b"")
    return head(framing, declared) + body


Outcome = tuple[str, object]


def outcome(call: Callable[[], object]) -> Outcome:
    try:
        return ("ok", call())
    except BaseException as error:
        return (type(error).__name__, error.args if not isinstance(error, TimeoutError) else ())


def fake_exchange(gw: FakeGateway, attempt: Attempt, timeout: float = 0.3) -> FakeConnection:
    gw.script(attempt)
    conn = open_connection(gw, timeout=timeout)
    conn.connect()
    return conn


def test_state_errors_after_a_refused_path_match_http_client(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    real = real_wire().connection
    conn = fake_exchange(gw, Attempt())

    def steps(c: FakeConnection | gw_module._HttpsConnection) -> list[Outcome]:  # type: ignore[name-defined]
        return [
            outcome(lambda: c.post("/a b", BODY)),
            outcome(lambda: c.post(PATH, BODY)),
            outcome(lambda: c.getresponse()),
        ]

    assert steps(conn) == steps(real)
    assert steps(conn)[1] == ("CannotSendRequest", ("Request-started",))
    assert steps(conn)[2] == ("ResponseNotReady", ("Request-started",))


def test_second_getresponse_and_getresponse_after_close_are_not_ready_like_http_client(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    wire = real_wire()
    wire.send(wire_body("length", b"ok", 2))
    real = wire.connection
    conn = fake_exchange(gw, Attempt(reply=Reply(body=b"ok")))

    def steps(c: FakeConnection | gw_module._HttpsConnection) -> list[Outcome]:  # type: ignore[name-defined]
        c.post(PATH, BODY)
        c.getresponse()
        second = outcome(lambda: c.getresponse())
        c.close()
        return [second, outcome(lambda: c.getresponse())]

    assert steps(conn) == steps(real) == [("ResponseNotReady", ("Idle",))] * 2


def test_getresponse_before_any_post_matches_http_client(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    real = real_wire().connection
    conn = fake_exchange(gw, Attempt())
    assert outcome(conn.getresponse) == outcome(real.getresponse)
    assert outcome(conn.getresponse) == ("ResponseNotReady", ("Idle",))


def test_reads_after_a_timeout_fail_like_http_client(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    wire = real_wire()
    wire.send(wire_body("length", b"ab", 9))  # never ends: the host goes silent
    wire.connection.post(PATH, BODY)
    real = wire.connection.getresponse()
    conn = fake_exchange(gw, Attempt(reply=Reply(body=b"abcdefghi", body_stall_after=2)))
    conn.post(PATH, BODY)
    fake = conn.getresponse()
    expected = [
        ("ok", b"a"),
        ("TimeoutError", ()),
        ("OSError", ("cannot read from timed out object",)),
        ("OSError", ("cannot read from timed out object",)),
    ]
    assert [outcome(lambda: real.read(1))] + [
        outcome(lambda: real.read(9)) for _ in range(3)
    ] == expected
    assert [outcome(lambda: fake.read(1))] + [
        outcome(lambda: fake.read(9)) for _ in range(3)
    ] == expected


def test_response_keeps_its_timeout_when_settimeout_follows_getresponse(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    """Real: the response holds the socket (timeout 0.3 s), so a 30 s setting changes nothing."""
    wire = real_wire(0.3)
    wire.send(wire_body("length", b"abc", 9))
    wire.connection.post(PATH, BODY)
    real = wire.connection.getresponse()
    wire.connection.settimeout(30.0)
    started = time.monotonic()
    real_outcome = outcome(lambda: real.read(9))
    assert time.monotonic() - started < 5.0
    conn = fake_exchange(
        gw, Attempt(reply=Reply(body=b"abcdefghi", body_stall_after=3)), timeout=0.3
    )
    conn.post(PATH, BODY)
    fake = conn.getresponse()
    conn.settimeout(30.0)
    start = gw.monotonic()
    assert outcome(lambda: fake.read(9)) == real_outcome == ("TimeoutError", ())
    assert gw.monotonic() - start == pytest.approx(0.3, abs=0.2)


@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
@pytest.mark.parametrize("amount", [1, 3, 1024])
@pytest.mark.parametrize("truncated", [False, True])
def test_framing_read_sequences_match_http_client(
    gw: FakeGateway,
    real_wire: Callable[..., RealWire],
    framing: str,
    amount: int,
    truncated: bool,
) -> None:
    body = b"abcdefgh"
    extra = 6 if truncated else 0
    wire = real_wire(0.3)
    wire.send(wire_body(framing, body, len(body) + extra), end=True)
    wire.connection.post(PATH, BODY)
    real = wire.connection.getresponse()
    conn = fake_exchange(
        gw, Attempt(reply=Reply(body=body, truncated_by=extra, framing=framing)), timeout=0.3
    )
    conn.post(PATH, BODY)
    fake = conn.getresponse()

    def drive(response: Response) -> list[Outcome]:
        seen: list[Outcome] = []
        for _ in range(20):
            step = outcome(lambda: response.read(amount))
            if step[0] == "IncompleteRead":
                step = ("IncompleteRead", step[1][:1])  # type: ignore[index]
            seen.append(step)
            if step[0] != "ok" or step[1] == b"":
                break
        return seen

    assert drive(fake) == drive(real)


def test_eof_framing_hides_a_truncation(gw: FakeGateway) -> None:
    conn = fake_exchange(gw, Attempt(reply=Reply(body=b"abc", truncated_by=4, framing="eof")))
    conn.post(PATH, BODY)
    response = conn.getresponse()
    assert [response.read(10), response.read(10)] == [b"abc", b""]


def test_chunked_truncation_is_an_incomplete_read_without_the_partial_data(
    gw: FakeGateway,
) -> None:
    conn = fake_exchange(gw, Attempt(reply=Reply(body=b"abc", truncated_by=4, framing="chunked")))
    conn.post(PATH, BODY)
    response = conn.getresponse()
    with pytest.raises(http.client.IncompleteRead) as info:
        response.read(10)
    assert info.value.partial == b""  # http.client drops it (verified in the sequence test)
    with pytest.raises(http.client.IncompleteRead):
        response.read(10)


@pytest.mark.parametrize("amount", [2, 1024])
def test_body_error_matches_a_reset_in_the_body(
    gw: FakeGateway, real_wire: Callable[..., RealWire], amount: int
) -> None:
    wire = real_wire(0.5)
    wire.send(wire_body("length", b"abc", 9))
    wire.connection.post(PATH, BODY)
    real = wire.connection.getresponse()
    wire.reset()
    conn = fake_exchange(
        gw,
        Attempt(
            reply=Reply(
                body=b"abcdefghi",
                body_error=ConnectionResetError(errno.ECONNRESET, "reset"),
                body_error_after=3,
            )
        ),
        timeout=0.5,
    )
    conn.post(PATH, BODY)
    fake = conn.getresponse()

    def drive(response: Response) -> list[str]:
        classes = []
        for _ in range(3):
            step = outcome(lambda: response.read(amount))
            classes.append(step[0] if step[0] != "ok" else "ok:" + repr(step[1]))
        return classes

    fake_seen, real_seen = drive(fake), drive(real)
    assert fake_seen == real_seen


def test_body_error_arrives_after_the_bytes_before_it(gw: FakeGateway) -> None:
    secret = ssl.SSLError("secret-in-error")
    conn = fake_exchange(
        gw, Attempt(reply=Reply(body=b"abcdef", body_error=secret, body_error_after=4))
    )
    conn.post(PATH, BODY)
    response = conn.getresponse()
    assert response.read(4) == b"abcd"
    with pytest.raises(ssl.SSLError, match="secret"):
        response.read(2)


def test_body_error_first_read_raises_as_given(gw: FakeGateway) -> None:
    error = ConnectionResetError(errno.ECONNRESET, "reset")
    conn = fake_exchange(gw, Attempt(reply=Reply(body=b"abc", body_error=error)))
    conn.post(PATH, BODY)
    with pytest.raises(ConnectionResetError):
        conn.getresponse().read(10)


def test_write_delay_is_spent_under_the_timeout_before_the_write_error(gw: FakeGateway) -> None:
    conn = fake_exchange(
        gw,
        Attempt(write_delay=0.5, write_error=BrokenPipeError(errno.EPIPE, "pipe")),
        timeout=5.0,
    )
    start = gw.monotonic()
    with pytest.raises(BrokenPipeError):
        conn.post(PATH, BODY)
    assert gw.monotonic() - start >= 0.5


def test_write_delay_longer_than_the_timeout_times_out_like_a_blocked_send(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    wire = real_wire(0.2)  # nobody reads the server end: sendall of a huge body blocks
    real_outcome = outcome(lambda: wire.connection.post(PATH, b"x" * 8_000_000))
    conn = fake_exchange(
        gw,
        Attempt(
            write_delay=30.0,
            write_error=BrokenPipeError(),
            request_delivered_on_write_error=True,
        ),
        timeout=0.2,
    )
    start = gw.monotonic()
    assert outcome(lambda: conn.post(PATH, BODY)) == real_outcome == ("TimeoutError", ())
    assert gw.monotonic() - start == pytest.approx(0.2, abs=0.2)
    assert conn.delivered  # the scripted flag says the host saw the request


# --- reply validation ----------------------------------------------------------------------------


@pytest.mark.parametrize("status", [100, 101, 199, 0, -1, 1000, 99999])
def test_reply_refuses_statuses_outside_200_to_999(status: int) -> None:
    with pytest.raises(ValueError, match="status"):
        Reply(status=status)


@pytest.mark.parametrize("status", [204, 304])
def test_reply_refuses_a_body_where_http_client_forces_none(status: int) -> None:
    with pytest.raises(ValueError, match="no body"):
        Reply(status=status, body=b"x")
    with pytest.raises(ValueError, match="no body"):
        Reply(status=status, body=b"", truncated_by=2)
    assert Reply(status=status, body=b"").status == status


@pytest.mark.parametrize(
    "kwargs",
    [
        {"truncated_by": -1},
        {"framing": "gzip"},
        {"body_stall_after": -1},
        {"body_stall_after": 11},  # the declared total
        {"body_stall_after": 12},
        {"body": b"ab", "truncated_by": 5, "body_stall_after": 3},  # past the EOF event
        {"body": b"ab", "truncated_by": 5, "body_stall_after": 5},
        {"body": b"ab", "truncated_by": 5, "body_error": OSError(), "body_error_after": 3},
        {"head_stall_after": -1},
        {"body_error": OSError(), "body_error_after": 11},
        {"body_error": OSError(), "body_error_after": -1},
    ],
)
def test_reply_refuses_bad_stall_and_error_points(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Reply(**kwargs)  # type: ignore[arg-type]


def test_a_stall_counts_from_the_declared_length_not_the_available_bytes(gw: FakeGateway) -> None:
    """A stall at ``len(body)`` of a truncated body is a stall, not an ``IncompleteRead``."""
    for reply in (
        Reply(body=b"abcde", truncated_by=5, body_stall_after=5),
        Reply(body=b"", truncated_by=5, body_stall_after=0),
    ):
        conn = fake_exchange(gw, Attempt(reply=reply), timeout=1.0)
        conn.post(PATH, BODY)
        response = conn.getresponse()
        start = gw.monotonic()
        with pytest.raises(TimeoutError):
            while response.read(1024):
                pass
        assert gw.monotonic() - start == pytest.approx(1.0, abs=0.5)


# --- stalls release one at a time --------------------------------------------------------------


def run_connect(conn: FakeConnection) -> tuple[threading.Thread, list[BaseException | None]]:
    outcomes: list[BaseException | None] = []

    def worker() -> None:
        try:
            conn.connect()
            outcomes.append(None)
        except BaseException as error:
            outcomes.append(error)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread, outcomes


def test_release_frees_only_the_stalls_blocked_at_that_moment(gw: FakeGateway) -> None:
    gw.script(Attempt(resolve_stall=True), Attempt(resolve_stall=True))
    first, second = open_connection(gw), open_connection(gw)
    thread_one, outcome_one = run_connect(first)
    assert gw.stalled.wait(5)
    gw.release_stalls()
    thread_one.join(5)
    assert isinstance(outcome_one[0], OSError)
    assert not gw.stalled.is_set()  # nothing is blocked now
    thread_two, outcome_two = run_connect(second)
    assert gw.stalled.wait(5)  # a new stall sets it again and blocks again
    thread_two.join(0.3)
    assert thread_two.is_alive()
    gw.release_stalls()
    thread_two.join(5)
    assert isinstance(outcome_two[0], OSError)


def test_a_release_before_the_stall_does_not_make_it_instant(gw: FakeGateway) -> None:
    gw.release_stalls()
    gw.script(Attempt(resolve_stall=True))
    thread, outcomes = run_connect(open_connection(gw))
    assert gw.stalled.wait(5)
    thread.join(0.3)
    assert thread.is_alive() and not outcomes
    gw.release_stalls()
    thread.join(5)


def test_a_released_resolution_can_proceed_to_complete_the_connect(gw: FakeGateway) -> None:
    """The docs/plan.md case: a connect that blocks past the deadline and then proceeds."""
    gw.script(Attempt(resolve_stall=True, stall_then_proceed=True))
    conn = open_connection(gw)
    thread, outcomes = run_connect(conn)
    assert gw.stalled.wait(5)
    gw.release_stalls()
    thread.join(5)
    assert outcomes == [None]
    conn.post(PATH, BODY)  # the connection is usable: the request is written afterwards
    assert conn.delivered


def test_a_proceeding_stall_still_fails_at_the_safety_cap(gw: FakeGateway) -> None:
    gw.stall_cap_seconds = 0.1
    gw.script(Attempt(resolve_stall=True, stall_then_proceed=True))
    with pytest.raises(OSError, match="cap"):
        open_connection(gw).connect()


def test_state_delay_advances_the_fake_clock_for_state_operations(gw: FakeGateway) -> None:
    gw.state_delay = 5.0
    real_start = time.monotonic()
    start = gw.monotonic()
    dir_fd = gw.open_state_dir(gw.home_dir())
    fd = gw.open_state_file(dir_fd, "log.jsonl", append=True)
    try:
        assert gw.try_lock(fd)
        gw.unlock(fd)
    finally:
        os.close(fd)
        os.close(dir_fd)
    assert gw.monotonic() - start >= 15.0
    config = Path(gw.home_dir()) / "config.yaml"
    config.write_text("x")
    before = gw.monotonic()
    gw.read_regular_file(config, 10)
    assert gw.monotonic() - before >= 5.0
    assert time.monotonic() - real_start < 5.0


# --- the resolution hooks ---------------------------------------------------------------------


def test_gateway_resolve_hooks_do_not_affect_connect(gw: FakeGateway) -> None:
    """The real connection never calls ``Gateway.resolve``; only the Attempt fields count."""
    gw.resolve_error = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    gw.resolve_addresses = []
    gw.script(Attempt(), Attempt(resolve_error=socket.gaierror(socket.EAI_NONAME, "x")))
    full_exchange(gw)
    with pytest.raises(socket.gaierror):
        full_exchange(gw)
    assert "resolve" not in gw.events


# --- the public surface is the real gateway's ----------------------------------------------------


def test_every_gateway_method_is_overridden_by_the_fake() -> None:
    """A new ``Gateway`` or ``SystemGateway`` method must be faked deliberately, not inherited.

    ``_read_fd`` is the one real implementation the fake keeps (``read_source`` wraps it).
    """
    allowed_inherited = {"_read_fd"}
    names = {
        name
        for name, value in vars(SystemGateway).items()
        if callable(value) and not name.startswith("__")
    }
    names |= {
        name
        for name in dir(Gateway)
        if not name.startswith("_") and callable(getattr(Gateway, name))
    }
    missing = sorted(n for n in names - allowed_inherited if n not in vars(FakeGateway))
    assert not missing


# --- TLS error helpers match real errors ------------------------------------------------------


def real_handshake_error(
    server_action: Callable[[socket.socket], object], timeout: float = 2.0
) -> BaseException:
    client, server = socket.socketpair()
    client.settimeout(timeout)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    thread = threading.Thread(target=server_action, args=(server,))
    thread.start()
    try:
        with pytest.raises(BaseException) as info:
            context.wrap_socket(client, server_hostname=WEBHOOK)
        return info.value
    finally:
        thread.join(5)
        client.close()
        server.close()


def test_ssl_eof_error_matches_a_real_one() -> None:
    def peer(server: socket.socket) -> None:
        server.recv(65536)
        server.close()

    real = real_handshake_error(peer)
    fake = ssl_eof_error()
    assert type(fake) is type(real) is ssl.SSLEOFError
    assert (fake.reason, fake.library, fake.errno) == (real.reason, real.library, real.errno)  # type: ignore[attr-defined]
    assert is_tls_error(fake) and not is_cert_verification_error(fake)


def test_ssl_wrong_version_matches_a_real_non_tls_answer() -> None:
    def peer(server: socket.socket) -> None:
        server.recv(65536)
        server.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        try:
            server.recv(65536)
        except ConnectionResetError:
            pass  # the client closed with unread data

    real = real_handshake_error(peer)
    fake = ssl_wrong_version()
    # 3.12 says WRONG_VERSION_NUMBER and 3.13 "record layer failure": class and library only
    assert type(fake) is type(real) is ssl.SSLError
    assert fake.library == real.library == "SSL"  # type: ignore[attr-defined]
    assert is_tls_error(fake) and not is_cert_verification_error(fake)


def test_tls_broken_pipe_matches_a_peer_that_is_already_gone() -> None:
    real = real_handshake_error(lambda server: server.close())
    fake = tls_broken_pipe()
    assert isinstance(real, BrokenPipeError) and type(fake) is BrokenPipeError
    assert fake.errno == real.errno == errno.EPIPE
    assert not is_tls_error(fake)


def test_handshake_timeout_matches_a_silent_peer() -> None:
    real = real_handshake_error(lambda server: server.recv(65536), timeout=0.3)
    fake = handshake_timeout()
    assert type(fake) is type(real) is TimeoutError
    assert "The handshake operation timed out" in str(real)
    assert "The handshake operation timed out" in str(fake)
    assert is_timeout(fake) and not is_tls_error(fake)


def test_cert_verify_error_has_the_attributes_of_a_real_one() -> None:
    """Pinned to what a real failed verification carries (observed on 3.13 with a self-signed
    server certificate on a local socketpair): reason, library, errno, verify code and text."""
    error = cert_verify_error()
    assert isinstance(error, ssl.SSLCertVerificationError)
    assert (error.reason, error.library, error.errno) == (  # type: ignore[attr-defined]
        "CERTIFICATE_VERIFY_FAILED",
        "SSL",
        1,
    )
    assert isinstance(error.verify_code, int) and error.verify_message
    assert "CERTIFICATE_VERIFY_FAILED" in str(error)
    handshake = handshake_error()
    assert handshake.library == "SSL" and not isinstance(handshake, ssl.SSLCertVerificationError)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "error",
    [
        ssl_eof_error(),
        ssl_wrong_version(),
        cert_verify_error(),
        tls_broken_pipe(),
        handshake_timeout(),
    ],
    ids=["eof", "wrong_version", "cert", "broken_pipe", "handshake_timeout"],
)
def test_tls_errors_ride_through_connect_as_given(gw: FakeGateway, error: BaseException) -> None:
    gw.script(Attempt(tls_error=error))
    with pytest.raises(type(error)) as info:
        open_connection(gw).connect()
    assert info.value is error


def test_tls_delay_past_the_timeout_is_a_handshake_timeout(gw: FakeGateway) -> None:
    gw.script(Attempt(tls_delay=30.0))
    with pytest.raises(TimeoutError, match="handshake operation timed out"):
        open_connection(gw, timeout=1.0).connect()


# --- request headers and path -----------------------------------------------------------------


def test_header_value_with_a_newline_is_refused_at_post_like_http_client(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    real = real_wire(user_agent="agent\nInjected: yes").connection
    gw.script(Attempt())
    conn = gw.https_connection(
        WEBHOOK, 443, timeout=1.0, context=gw.tls_context(), user_agent="agent\nInjected: yes"
    )
    conn.connect()
    real_outcome, fake_outcome = (
        outcome(lambda: real.post(PATH, BODY)),
        outcome(lambda: conn.post(PATH, BODY)),
    )
    assert real_outcome[0] == fake_outcome[0] == "ValueError"
    assert not conn.requests and not conn.delivered


def test_header_value_that_is_not_latin1_is_an_invalid_request_like_the_real_wrapper(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    real = real_wire(user_agent="agent\u2603").connection
    gw.script(Attempt())
    conn = gw.https_connection(
        WEBHOOK, 443, timeout=1.0, context=gw.tls_context(), user_agent="agent\u2603"
    )
    conn.connect()
    assert outcome(lambda: conn.post(PATH, BODY)) == outcome(lambda: real.post(PATH, BODY))
    assert outcome(lambda: conn.post(PATH, BODY))[0] == "CannotSendRequest"


def test_an_empty_path_is_requested_as_a_slash(
    gw: FakeGateway, real_wire: Callable[..., RealWire]
) -> None:
    wire = real_wire()
    wire.connection.post("", BODY)
    assert wire.server.recv(4096).startswith(b"POST / HTTP/1.1\r\n")
    conn = fake_exchange(gw, Attempt())
    conn.post("", BODY)
    assert conn.requests == [("/", BODY)]


# --- timeouts and sleeping validate like the real ones -----------------------------------------


@pytest.mark.parametrize(
    "seconds", [-1, -0.5, "5", b"1", [1], math.nan, math.inf, 0, 2, 1.5, True, None]
)
def test_settimeout_validates_like_socket_settimeout(
    gw: FakeGateway, real_wire: Callable[..., RealWire], seconds: object
) -> None:
    real = real_wire().connection
    conn = fake_exchange(gw, Attempt())
    # the exception class must match; the message text is the standard library's own
    assert (
        outcome(lambda: conn.settimeout(seconds))[0]  # type: ignore[arg-type]
        == outcome(lambda: real.settimeout(seconds))[0]  # type: ignore[arg-type]
    )


def test_settimeout_before_connect_or_after_the_response_is_not_validated(
    gw: FakeGateway,
) -> None:
    """The real connection only forwards to a live socket: before connect and after the
    response took the socket there is nothing to validate against."""
    gw.script(Attempt())
    conn = open_connection(gw)
    conn.settimeout(-1.0)  # no socket yet
    conn.timeout = 5.0
    conn.connect()
    conn.post(PATH, BODY)
    conn.getresponse()
    conn.settimeout(-1.0)  # the response owns the socket
    assert conn.timeout == -1.0


@pytest.mark.parametrize("seconds", [math.inf, -math.inf, -5.0, 0.0, math.nan])
def test_sleep_matches_the_real_gateway(gw: FakeGateway, seconds: float) -> None:
    def call(target: Gateway) -> str:
        return outcome(lambda: target.sleep(seconds))[0]  # the class; messages are time's own

    assert call(gw) == call(SystemGateway())


# --- hard rules for the whole suite --------------------------------------------------------------


def test_fake_gateway_never_opens_a_socket(gw: FakeGateway) -> None:
    """The conftest guard is installed (``socket.connect`` refuses), and a full exchange,
    a failing one and a direct resolve all pass under it."""
    assert socket.socket.connect.__name__ == "refuse_network"
    assert socket.getaddrinfo.__name__ == "refuse_network"
    gw.script(Attempt(), Attempt(resolve_error=socket.gaierror(1, "x")))
    full_exchange(gw)
    with pytest.raises(socket.gaierror):
        full_exchange(gw)
    gw.resolve("hooks.slack.com", 443)


def test_fake_module_has_no_socket_or_subprocess_imports() -> None:
    source = (Path(__file__).parent / "fake_gateway.py").read_text()
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"subprocess", "urllib", "requests", "pwd", "socket", "select"}


def test_no_environment_variable_exists_only_for_tests() -> None:
    """No source module reads a test-only variable, and none reads the environment at all
    for tool locations (the gateway reads none)."""
    suspicious = re.compile(r"^(SLACK_NOTICE_\w*|\w*(TEST|FAKE|MOCK|PYTEST)\w*)$")
    for path in SRC.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not suspicious.match(node.value), f"{path.name}: {node.value}"
            if isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv", "putenv"}:
                # The gateway's one `environ()` hands the environment to the CLI, once.
                allowed = path.name == "gateway.py" and node.attr == "environ"
                assert path.name != "gateway.py" or allowed, f"gateway.py reads {node.attr}"
    gateway_reads = [
        n
        for n in ast.walk(ast.parse((SRC / "gateway.py").read_text()))
        if isinstance(n, ast.Attribute) and n.attr in {"environ", "getenv", "putenv"}
    ]
    assert len(gateway_reads) == 1

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
import os
import re
import socket
import ssl
import threading
import time
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
)

SRC = Path(__file__).resolve().parent.parent / "src" / "slack_notice"
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


def test_unconsumed_script_is_detected(gw: FakeGateway) -> None:
    gw.script(Attempt(), Attempt())
    full_exchange(gw)
    with pytest.raises(AssertionError, match="unconsumed"):
        gw.assert_script_consumed()


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


def test_settimeout_applies_to_later_operations(gw: FakeGateway) -> None:
    gw.script(Attempt(reply=Reply(first_byte_delay=10.0)))
    conn = open_connection(gw, timeout=60.0)
    conn.connect()
    conn.post(PATH, BODY)
    conn.settimeout(1.0)
    start = gw.monotonic()
    with pytest.raises(TimeoutError):
        conn.getresponse()
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


def test_connection_refuses_another_host_or_port(gw: FakeGateway) -> None:
    gw.script(Attempt(), Attempt())
    for host, port in (("example.com", 443), ("hooks.slack.com", 8443)):
        with pytest.raises(AssertionError, match="hooks.slack.com"):
            gw.https_connection(host, port, timeout=1.0, context=gw.tls_context(), user_agent="x")


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
    read_end, write_end = os.pipe()
    try:
        result = gw.read_source(read_end, 100, 0.3)  # no writer closes: never ends
        assert result.timed_out
    finally:
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


# --- hard rules for the whole suite --------------------------------------------------------------


def test_fake_gateway_never_opens_a_socket(gw: FakeGateway) -> None:
    """The conftest guard raises NetworkRefused on any socket use; a full exchange passes."""
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
    assert not imported & {"subprocess", "urllib", "requests", "pwd"}


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
                assert path.name != "gateway.py", f"gateway.py reads the environment ({node.attr})"

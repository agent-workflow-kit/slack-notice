"""Response mapping and the exception phase rule (issue #24).

``map_attempt(attempt, gate_writing=...)`` turns the raw facts of one attempt into an ``Outcome``:
the exit code, envelope and log fields of the Webhook edge table. Every envelope is validated
against schemas/cli/error.json and every log record against schemas/log.json. Nothing here
touches a network. Fake secrets are built at run time around a CANARY.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
from typing import Any

import pytest

from slack_notice import __version__, webhook
from slack_notice.gateway import NoUsableCA
from slack_notice.log import build_record, encode_record
from slack_notice.webhook import AttemptResult, Failure, Outcome, Phase, Retry, map_attempt
from tests.fake_gateway import Attempt, FakeGateway, Reply
from tests.harness import assert_valid

CANARY = "CAN" + "ARY" + "_24x"
OK = b'{"ok":true}'


def attempt(status: int | None = 200, body: bytes = OK, **kw: Any) -> AttemptResult:
    kw.setdefault("phase", Phase.READ)
    return AttemptResult(status=status, body=body, **kw)


def fail(exc: Exception, phase: Phase = Phase.READ) -> AttemptResult:
    return AttemptResult(phase=phase, failure=webhook._failure(exc))


def check(outcome: Outcome, *, gate_writing: bool = True) -> dict[str, Any]:
    """Validate the envelope and the log record the outcome produces; return the envelope."""
    assert outcome.exit_code in (0, 12)
    if outcome.exit_code == 12:
        text = json.dumps(outcome.envelope())
        assert CANARY not in text
        assert_valid("cli/error", text)
    fields = outcome.log_fields()
    record = build_record(
        wall_time=1_700_000_000.0,
        version=__version__,
        gate_writing=gate_writing,
        level="info",
        bytes_=12,
        truncated=False,
        duration_ms=5,
        message_hash="0" * 16,
        dedupe_hash=None,
        actor="human:tester",
        actor_source="flag",
        **fields,
    )
    assert record is not None
    parsed = assert_valid("log", encode_record(record))
    assert parsed["http_status"] == outcome.http_status
    assert parsed["code"] == outcome.code
    if outcome.exit_code == 12:
        return outcome.envelope()["error"]  # type: ignore[no-any-return]
    return {}


def flags(o: Outcome) -> tuple[Any, ...]:
    return (o.exit_code, o.code, o.retryable, o.unknown_outcome, o.details)


# --- one case per status, 100..599 ------------------------------


def expected_for_status(status: int) -> tuple[Any, ...]:
    if 100 <= status <= 199:
        return (12, "wrong_host_response", False, True, None)
    if status == 200:
        return (0, None, None, False, None)
    if 200 < status <= 299:
        return (12, "wrong_host_response", False, True, {"http_status": status})
    if status == 400:
        return (12, "host_rejected", False, False, {"host_error": None, "http_status": 400})
    if status in (401, 403, 404, 410):
        return (12, "auth_required", False, False, {"http_status": status})
    if status == 429:
        return (12, "rate_limited", True, False, {"http_status": 429})
    if 500 <= status <= 599:
        return (12, "upstream_error", False, True, {"http_status": status})
    return (12, "wrong_host_response", False, False, {"http_status": status})


@pytest.mark.parametrize("status", range(100, 600))
def test_every_status_with_an_empty_body_maps_per_the_table(status: int) -> None:
    body = OK if status == 200 else b""
    outcome = map_attempt(attempt(status, body), gate_writing=True)
    assert flags(outcome) == expected_for_status(status)
    if outcome.code == "rate_limited":
        outcome = outcome.with_retry_after(2.0)
    check(outcome)


def test_the_success_outcome() -> None:
    o = map_attempt(attempt(), gate_writing=True)
    assert (o.exit_code, o.code, o.http_status, o.unknown_outcome) == (0, None, 200, False)
    assert o.retry is Retry.NONE
    check(o)
    with pytest.raises(ValueError):
        o.envelope()


@pytest.mark.parametrize("status", [0, 1, 99, 600, 601, 700, 999, 1000, -1, 2**40])
def test_a_status_outside_100_to_599_is_not_an_http_answer(status: int) -> None:
    # The log schema holds 100..599 only; a status that is not one is no clear answer.
    o = map_attempt(attempt(status, b""), gate_writing=True)
    assert flags(o) == (12, "wrong_host_response", False, True, None)
    check(o)


@pytest.mark.parametrize("status", [True, 200.0, "200", b"200"])
def test_a_status_that_is_not_an_int_is_a_caller_bug(status: Any) -> None:
    with pytest.raises(ValueError):
        map_attempt(attempt(status), gate_writing=True)


def test_no_status_no_failure_and_not_abandoned_is_a_caller_bug() -> None:
    with pytest.raises(ValueError):
        map_attempt(AttemptResult(phase=Phase.READ), gate_writing=True)


def test_4xx_5xx_and_3xx_samples_have_fixed_messages() -> None:
    for status in (302, 400, 401, 404, 418, 429, 500, 503):
        o = map_attempt(attempt(status, b"hello " + CANARY.encode()), gate_writing=True)
        assert CANARY not in o.message and CANARY not in repr(o)
        assert o.message


def test_429_asks_for_a_rate_limit_retry_and_never_reads_retry_after() -> None:
    o = map_attempt(attempt(429, b""), gate_writing=True)
    assert o.retry is Retry.RATE_LIMIT and o.retry_after_s is None
    assert o.with_retry_after(4.0).retry_after_s == 4.0
    env = check(o.with_retry_after(4.0))
    assert env["retry_after_s"] == 4 and env["details"] == {"http_status": 429}
    # a 429 body is irrelevant, even one that claims success
    assert map_attempt(attempt(429, OK), gate_writing=True).code == "rate_limited"


def test_only_a_429_has_a_rate_limit_retry() -> None:
    for status in range(100, 600):
        o = map_attempt(attempt(status, b""), gate_writing=True)
        assert (o.retry is Retry.RATE_LIMIT) == (status == 429)
        assert o.retry is not Retry.CONNECTION


def test_with_retry_after_rejects_a_bad_wait() -> None:
    o = map_attempt(attempt(429, b""), gate_writing=True)
    for bad in (-1.0, float("nan"), float("inf"), True, "2"):
        with pytest.raises(ValueError):
            o.with_retry_after(bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        map_attempt(attempt(500, b""), gate_writing=True).with_retry_after(2.0)


# --- the body of a 200 ------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b'{"ok":true}',
        b'{"ok": true}\n',
        b' \t\r\n{"ok":true}',
        b'{"ok":true,"extra":[1,2,{"a":null}],"n":1.5e300}',
        b'{"other":1,"ok":true}',
        b'{"\\u006fk":true}',
        b'{"ok":true,"s":"\\ud800"}',
        b'{"ok":true,"big":' + b"9" * 4000 + b"}",
    ],
)
def test_200_success_forms(body: bytes) -> None:
    o = map_attempt(attempt(200, body), gate_writing=True)
    assert o.exit_code == 0 and o.http_status == 200
    check(o)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"   ",
        b"not json",
        b"\xef\xbb\xbf" + OK,  # BOM
        b'{"ok":true}x',  # trailing garbage
        b'{"ok":true}{"ok":true}',
        b'{"ok":true} {',
        b'{"ok":true,"ok":true}',  # duplicate keys
        b'{"ok":false,"ok":true}',
        b'{"ok":true,"a":{"b":1,"b":2}}',  # nested duplicates
        b'{"ok":NaN}',
        b'{"ok":true,"x":NaN}',
        b'{"ok":true,"x":Infinity}',
        b'{"ok":true,"x":-Infinity}',
        b'{"ok":false}',
        b'{"ok":1}',
        b'{"ok":1.0}',
        b'{"ok":"true"}',
        b'{"ok":null}',
        b'{"ok":[true]}',
        b'{"OK":true}',
        b"{}",
        b"[]",
        b'[{"ok":true}]',
        b'"ok"',
        b"true",
        b"null",
        b"1",
        b'{"ok":true',  # truncated
        b"{'ok':true}",
        b'\xff{"ok":true}',  # not UTF-8
        b'{"ok":true,"x":"\xff"}',
        b'{"ok":true,"x":"\xc3"}',
        b'{"ok":true,"x":"\xed\xa0\x80"}',  # encoded surrogate
        b'{"ok":true,"x":"\xc0\xaf"}',  # overlong
        b"[" * 3000 + b"]" * 3000,  # deep nesting
        b'{"ok":true,"x":' + b"[" * 3000 + b"]" * 3000 + b"}",
        b'{"a":' * 1000 + b"1" + b"}" * 1000,
        b'{"ok":true,"big":' + b"9" * 4090,  # truncated big int literal
        b"\x00" + OK,
        b'{"ok":true}\x00',
    ],
)
def test_200_with_a_bad_body_is_wrong_host_response_with_unknown_outcome(body: bytes) -> None:
    o = map_attempt(attempt(200, body), gate_writing=True)
    assert flags(o) == (12, "wrong_host_response", False, True, {"http_status": 200})
    check(o)


def test_200_with_a_body_over_the_cap_is_a_bad_body_even_if_the_start_is_valid() -> None:
    body = OK + b" " * 4090
    o = map_attempt(attempt(200, body[:4096], body_too_long=True), gate_writing=True)
    assert flags(o) == (12, "wrong_host_response", False, True, {"http_status": 200})
    check(o)


def test_200_with_a_body_exactly_at_the_cap_is_judged_on_its_content() -> None:
    body = OK + b" " * (4096 - len(OK))
    assert len(body) == 4096
    assert map_attempt(attempt(200, body), gate_writing=True).exit_code == 0


def test_a_huge_int_literal_is_not_an_exception() -> None:
    body = b'{"ok":true,"n":' + b"1" * 4080 + b"}"  # over the int digit limit
    o = map_attempt(attempt(200, body), gate_writing=True)
    assert o.exit_code in (0, 12)
    if o.exit_code == 12:  # the interpreter refuses it: a bad body, still no crash
        assert o.code == "wrong_host_response"


@pytest.mark.parametrize("status", [201, 202, 204, 226, 299])
def test_other_2xx_even_with_the_success_body_is_unknown(status: int) -> None:
    o = map_attempt(attempt(status, OK), gate_writing=True)
    assert flags(o) == (12, "wrong_host_response", False, True, {"http_status": status})
    check(o)


# --- 400 host_error ------------------------------


@pytest.mark.parametrize(
    ("body", "host_error"),
    [
        (b'{"ok":false,"error":"invalid_payload"}', "invalid_payload"),
        (b'{"error":"a"}', "a"),
        (b'{"error":"' + b"a" * 64 + b'"}', "a" * 64),
        (b'{"error":"' + b"a" * 65 + b'"}', None),
        (b'{"error":""}', None),
        (b'{"error":"Invalid"}', None),
        (b'{"error":"has-dash"}', None),
        (b'{"error":"digit1"}', None),
        (b'{"error":"line\\nbreak"}', None),
        (b'{"error":"abc\\n"}', None),  # not a $-style match
        (b'{"error":"\\u0430bc"}', None),  # non-ASCII lookalike
        (b'{"error":"\\u1d00"}', None),
        (b'{"error":1}', None),
        (b'{"error":null}', None),
        (b'{"error":["a"]}', None),
        (b'{"error":{"a":"b"}}', None),
        (b'{"x":"abc"}', None),
        (b'{"error":"abc","error":"def"}', None),
        (b'{"error":"abc"}x', None),
        (b'{"error":"abc"', None),
        (b"", None),
        (b"[]", None),
        (b"\xef\xbb\xbf" + b'{"error":"abc"}', None),
        (b'{"error":"abc","n":NaN}', None),
        (b'{"error":"\xff"}', None),
        (b"<html>bad</html>", None),
        (b'{"error":"abc_def_"}', "abc_def_"),
        (b'{"error":"_"}', "_"),
    ],
)
def test_400_host_error_only_when_it_matches(body: bytes, host_error: str | None) -> None:
    o = map_attempt(attempt(400, body), gate_writing=True)
    assert o.code == "host_rejected"
    assert o.details == {"host_error": host_error, "http_status": 400}
    check(o)


def test_400_with_a_cut_body_has_no_host_error() -> None:
    body = b'{"error":"abc"}' + b" " * 4090
    o = map_attempt(attempt(400, body[:4096], body_too_long=True), gate_writing=True)
    assert o.details == {"host_error": None, "http_status": 400}


def test_400_deep_nesting_and_bad_utf8_are_not_crashes() -> None:
    for body in (b"[" * 4000, b'{"error":"abc","x":' + b"[" * 3000, b"\xff\xfe"):
        o = map_attempt(attempt(400, body), gate_writing=True)
        assert o.details == {"host_error": None, "http_status": 400}


def test_the_response_body_is_never_echoed() -> None:
    secret = CANARY.encode()
    for status in (200, 201, 302, 400, 401, 429, 500):
        o = map_attempt(attempt(status, b'{"error":"x","m":"' + secret + b'"}'), gate_writing=True)
        assert CANARY not in repr(o) and CANARY not in json.dumps(o.details)
        assert CANARY not in o.message


# --- failures: the phase rule ------------------------------

REQ = http.client.RemoteDisconnected
EXC_CLASSES: list[tuple[str, Exception]] = [
    ("ConnectionResetError", ConnectionResetError(CANARY)),
    ("BrokenPipeError", BrokenPipeError(CANARY)),
    ("TimeoutError", TimeoutError(CANARY)),
    ("socket.timeout", TimeoutError(CANARY)),
    ("SSLEOFError", ssl.SSLEOFError(CANARY)),
    ("SSLError", ssl.SSLError(CANARY)),
    ("SSLCertVerificationError", ssl.SSLCertVerificationError(CANARY)),
    ("SSLZeroReturnError", ssl.SSLZeroReturnError(CANARY)),
    ("RemoteDisconnected", http.client.RemoteDisconnected(CANARY)),
    ("BadStatusLine", http.client.BadStatusLine(CANARY)),
    ("LineTooLong", http.client.LineTooLong(CANARY)),
    ("IncompleteRead", http.client.IncompleteRead(CANARY.encode())),
    ("InvalidURL", http.client.InvalidURL(CANARY)),
    ("UnknownProtocol", http.client.UnknownProtocol(CANARY)),
    ("HTTPException", http.client.HTTPException(CANARY)),
    ("CannotSendRequest", http.client.CannotSendRequest(CANARY)),
    ("ResponseNotReady", http.client.ResponseNotReady(CANARY)),
    ("OSError", OSError(CANARY)),
    ("ConnectionRefusedError", ConnectionRefusedError(CANARY)),
    ("gaierror", socket.gaierror(-2, CANARY)),
    ("NoUsableCA", NoUsableCA()),
    ("ValueError", ValueError(CANARY)),
    ("UnicodeError", UnicodeError(CANARY)),
    ("RuntimeError", RuntimeError(CANARY)),
    ("MemoryError", MemoryError(CANARY)),
]
LOST = {
    "ConnectionResetError",
    "BrokenPipeError",
    "TimeoutError",
    "socket.timeout",
    "SSLEOFError",
    "SSLError",
    "SSLCertVerificationError",
    "SSLZeroReturnError",
    "RemoteDisconnected",
    "IncompleteRead",
    "OSError",
    "ConnectionRefusedError",
    "gaierror",
    "NoUsableCA",
    "ValueError",
    "UnicodeError",
    "RuntimeError",
    "MemoryError",
}
NOT_HTTP = {
    "BadStatusLine",
    "LineTooLong",
    "InvalidURL",
    "UnknownProtocol",
    "HTTPException",
    "CannotSendRequest",
    "ResponseNotReady",
}


def test_the_class_table_is_complete() -> None:
    assert LOST | NOT_HTTP == {n for n, _ in EXC_CLASSES} and not LOST & NOT_HTTP


@pytest.mark.parametrize(("name", "exc"), EXC_CLASSES, ids=[n for n, _ in EXC_CLASSES])
def test_gate_idle_any_exception_is_network_error(name: str, exc: Exception) -> None:
    o = map_attempt(fail(exc, Phase.CONNECT), gate_writing=False)
    tls = isinstance(exc, ssl.SSLError | NoUsableCA)
    timeout = isinstance(exc, TimeoutError)
    assert flags(o) == (12, "network_error", not tls, False, {"tls": tls, "timeout": timeout})
    assert o.http_status is None
    env = check(o, gate_writing=False)
    assert env["retry_after_s"] is None
    cert = isinstance(exc, ssl.SSLCertVerificationError) or isinstance(exc, NoUsableCA)
    assert (o.retry is Retry.CONNECTION) == (not cert)


@pytest.mark.parametrize(("name", "exc"), EXC_CLASSES, ids=[n for n, _ in EXC_CLASSES])
def test_gate_writing_any_exception_is_never_a_clear_answer(name: str, exc: Exception) -> None:
    for phase in (Phase.WRITE, Phase.READ):
        o = map_attempt(fail(exc, phase), gate_writing=True)
        assert o.unknown_outcome is True and o.retryable is False
        assert o.retry is Retry.NONE and o.http_status is None
        if name in LOST:
            assert (o.code, o.details) == ("outcome_unknown", None)
        else:
            assert (o.code, o.details) == ("wrong_host_response", None)
        check(o)


@pytest.mark.parametrize(("name", "exc"), EXC_CLASSES, ids=[n for n, _ in EXC_CLASSES])
def test_the_gate_decides_not_the_attempt_phase(name: str, exc: Exception) -> None:
    # Gate idle but the attempt claims it wrote: contradictory input, resolved conservatively.
    o = map_attempt(fail(exc, Phase.WRITE), gate_writing=False)
    assert o.unknown_outcome is True
    # Gate writing with a connect-phase failure: the gate wins (it moves only right before a write).
    o = map_attempt(fail(exc, Phase.CONNECT), gate_writing=True)
    assert o.unknown_outcome is True


def test_a_failure_with_a_status_ignores_the_status() -> None:
    f = webhook._failure(http.client.IncompleteRead(b"x"))
    for status in (200, 400, 401, 429, 500, 302):
        a = AttemptResult(phase=Phase.READ, status=status, body=OK, failure=f)
        o = map_attempt(a, gate_writing=True)
        assert (o.code, o.unknown_outcome, o.http_status, o.details) == (
            "outcome_unknown",
            True,
            None,
            None,
        )
        check(o)


def test_a_body_failure_after_a_status_line_is_malformed_with_no_status() -> None:
    f = Failure("MalformedChunkSize", False, False, False, True, False)
    o = map_attempt(AttemptResult(Phase.READ, 200, OK, failure=f), gate_writing=True)
    assert (o.code, o.details, o.unknown_outcome) == ("wrong_host_response", None, True)
    check(o)


def test_cert_verification_idle_is_tls_true_not_retried_and_not_retryable() -> None:
    o = map_attempt(fail(ssl.SSLCertVerificationError(CANARY), Phase.CONNECT), gate_writing=False)
    assert o.details == {"tls": True, "timeout": False}
    assert o.retryable is False and o.retry is Retry.NONE
    check(o, gate_writing=False)


def test_handshake_failure_is_retried_once_by_the_caller_but_the_envelope_is_not_retryable() -> (
    None
):
    # interface: a handshake failure that is not a verification failure is retried (once); the
    # envelope that ends the send has details.tls true and so retryable false.
    o = map_attempt(fail(ssl.SSLEOFError(CANARY), Phase.CONNECT), gate_writing=False)
    assert o.retry is Retry.CONNECTION and o.retryable is False
    assert o.details == {"tls": True, "timeout": False}


def test_no_usable_ca_is_tls_true_with_its_own_message_and_no_retry() -> None:
    o = map_attempt(fail(NoUsableCA(), Phase.CONNECT), gate_writing=False)
    assert o.details == {"tls": True, "timeout": False}
    assert "no usable CA certificates" in o.message
    assert o.retry is Retry.NONE and o.retryable is False
    check(o, gate_writing=False)


def test_timeout_idle_is_retryable_with_timeout_true() -> None:
    o = map_attempt(fail(TimeoutError(), Phase.CONNECT), gate_writing=False)
    assert o.details == {"tls": False, "timeout": True} and o.retryable is True
    assert o.retry is Retry.CONNECTION


def test_a_broken_pipe_before_the_write_is_retried_tls_false_but_ssl_eof_is_tls_true() -> None:
    # the TLS-event ambiguity: both can be "the peer closed on us", the class decides tls
    pipe = map_attempt(fail(BrokenPipeError(), Phase.CONNECT), gate_writing=False)
    eof = map_attempt(fail(ssl.SSLEOFError(), Phase.CONNECT), gate_writing=False)
    assert pipe.details == {"tls": False, "timeout": False} and pipe.retryable is True
    assert eof.details == {"tls": True, "timeout": False} and eof.retryable is False
    assert pipe.retry is eof.retry is Retry.CONNECTION


def test_no_failure_text_in_any_output() -> None:
    for _, exc in EXC_CLASSES:
        for gate in (False, True):
            o = map_attempt(fail(exc, Phase.READ if gate else Phase.CONNECT), gate_writing=gate)
            assert CANARY not in repr(o) and CANARY not in json.dumps(o.envelope())
            assert CANARY not in json.dumps(o.log_fields())


def test_an_odd_error_class_name_reaches_nothing() -> None:
    f = Failure("Exception", False, False, False, False, False)
    o = map_attempt(AttemptResult(Phase.CONNECT, failure=f), gate_writing=False)
    assert o.code == "network_error"


# --- abandoned ------------------------------


def test_an_abandoned_attempt_wrote_nothing_and_is_a_retryable_timeout() -> None:
    o = map_attempt(AttemptResult(Phase.CONNECT, abandoned=True), gate_writing=False)
    assert flags(o) == (12, "network_error", True, False, {"tls": False, "timeout": True})
    assert o.retry is Retry.NONE
    check(o, gate_writing=False)


def test_an_abandoned_attempt_with_a_writing_gate_is_a_caller_bug() -> None:
    with pytest.raises(ValueError):
        map_attempt(AttemptResult(Phase.CONNECT, abandoned=True), gate_writing=True)


# --- the other cells of the exit-12 table ------------------------------


def test_outcome_unknown_constructor() -> None:
    o = webhook.outcome_unknown()
    assert flags(o) == (12, "outcome_unknown", False, True, None)
    check(o)


def test_network_error_constructor_for_the_deadline() -> None:
    o = webhook.network_error(tls=False, timeout=True)
    assert flags(o) == (12, "network_error", True, False, {"tls": False, "timeout": True})
    check(o, gate_writing=False)
    o = webhook.network_error(tls=True, timeout=False)
    assert o.retryable is False
    check(o, gate_writing=False)


@pytest.mark.parametrize("phase", ["input", "lock"])
def test_unavailable(phase: str) -> None:
    o = webhook.unavailable(phase)
    assert flags(o) == (12, "unavailable", True, False, {"phase": phase})
    env = check(o, gate_writing=False)
    assert env["retry_after_s"] is None and env["reason"] is None


@pytest.mark.parametrize("phase", ["", "net", "INPUT", None, 1])
def test_unavailable_rejects_another_phase(phase: Any) -> None:
    with pytest.raises(ValueError):
        webhook.unavailable(phase)


def test_credential_invalid() -> None:
    o = webhook.credential_invalid("MY_HOOK")
    assert flags(o) == (12, "credential_invalid", False, False, {"env": "MY_HOOK"})
    assert o.http_status is None
    check(o, gate_writing=False)


def test_credential_invalid_from_the_exception_of_the_credential_edge() -> None:
    err = webhook.CredentialInvalid("MY_HOOK")
    o = webhook.credential_invalid(err.env)
    assert o.message == webhook.INVALID_MESSAGE


def test_every_envelope_key_is_present() -> None:
    for o in (
        map_attempt(attempt(500, b""), gate_writing=True),
        webhook.unavailable("lock"),
        webhook.outcome_unknown(),
    ):
        err = o.envelope()["error"]
        assert list(err) == [
            "code",
            "message",
            "reason",
            "details",
            "retryable",
            "retry_after_s",
            "unknown_outcome",
        ]
        assert err["reason"] is None


# --- the log outcome rule ------------------------------


def test_log_outcome_follows_unknown_outcome() -> None:
    cases = [
        (map_attempt(attempt(500, b""), gate_writing=True), "outcome_unknown"),
        (map_attempt(attempt(201, OK), gate_writing=True), "outcome_unknown"),
        (map_attempt(attempt(302, b""), gate_writing=True), "failed"),
        (map_attempt(attempt(400, b""), gate_writing=True), "failed"),
        (webhook.outcome_unknown(), "outcome_unknown"),
        (webhook.unavailable("input"), "failed"),
        (map_attempt(fail(OSError(), Phase.CONNECT), gate_writing=False), "failed"),
        (map_attempt(fail(OSError(), Phase.READ), gate_writing=True), "outcome_unknown"),
    ]
    for o, want in cases:
        f = o.log_fields()
        assert f["exit_code"] == 12 and f["reason"] is None
        record = build_record(
            wall_time=1.0,
            version=__version__,
            gate_writing=True,
            level="info",
            bytes_=1,
            truncated=False,
            duration_ms=1,
            message_hash="0" * 16,
            dedupe_hash=None,
            actor="human:t",
            actor_source="flag",
            **f,
        )
        assert record is not None and record["outcome"] == want


# --- end to end through post_once on the fake gateway ------------------------------


def run(gw: FakeGateway, *attempts: Attempt) -> AttemptResult:
    gw.script(*attempts)
    return webhook.post_once(gw, webhook.Webhook("/triggers/" + CANARY + "/x"), b"{}", timeout=5.0)


def test_end_to_end_success(fake_gateway: FakeGateway) -> None:
    o = map_attempt(run(fake_gateway, Attempt()), gate_writing=True)
    assert o.exit_code == 0


@pytest.mark.parametrize(
    ("reply", "code", "unknown"),
    [
        (Reply(status=500, body=b"{}"), "upstream_error", True),
        (Reply(status=302, body=b""), "wrong_host_response", False),
        (Reply(status=200, body=b"nope"), "wrong_host_response", True),
        (Reply(status=401, body=b'{"error":"invalid_auth"}'), "auth_required", False),
        (Reply(status=200, body=b'{"ok":true}' + b" " * 5000), "wrong_host_response", True),
    ],
)
def test_end_to_end_replies(
    fake_gateway: FakeGateway, reply: Reply, code: str, unknown: bool
) -> None:
    o = map_attempt(run(fake_gateway, Attempt(reply=reply)), gate_writing=True)
    assert (o.code, o.unknown_outcome) == (code, unknown)
    check(o)


def test_end_to_end_connect_and_post_write_failures(fake_gateway: FakeGateway) -> None:
    a = run(fake_gateway, Attempt(connect_error=ConnectionRefusedError(CANARY)))
    o = map_attempt(a, gate_writing=False)
    assert o.code == "network_error" and a.phase is Phase.CONNECT
    check(o, gate_writing=False)
    a = run(fake_gateway, Attempt(reply=http.client.RemoteDisconnected(CANARY)))
    o = map_attempt(a, gate_writing=True)
    assert o.code == "outcome_unknown"
    check(o)
    a = run(fake_gateway, Attempt(write_error=BrokenPipeError(CANARY)))
    o = map_attempt(a, gate_writing=True)
    assert o.code == "outcome_unknown"
    check(o)

"""Retries: 429 and failures before the first byte (issue #26).

The worker body ``attempt_work`` runs the retry loop. Most tests drive it synchronously on a frozen
fake clock (``gateway.sleep`` advances it, nothing really sleeps), so waits and deadlines are
exact; the tests that need a real worker thread (a deadline that passes while a retry is stalled)
use ``Deadline.run`` with a bound of a fraction of a second. Every envelope and log record that a
result produces is validated against the schemas. Fake secrets are built at run time around a
CANARY; nothing here touches a network.
"""

from __future__ import annotations

import itertools
import json
import socket
from collections.abc import Callable
from typing import Any

import pytest

from slack_notice import __version__, deadline, gateway
from slack_notice.deadline import Deadline, GateState, Verdict, attempt_work
from slack_notice.log import build_record, encode_record
from slack_notice.webhook import Outcome, Webhook
from tests.fake_gateway import (
    Attempt,
    FakeGateway,
    Reply,
    cert_verify_error,
    handshake_error,
    ssl_eof_error,
    tls_broken_pipe,
)
from tests.harness import assert_valid

CANARY = "CAN" + "ARY" + "_26r"
PATH = "/triggers/" + CANARY + "/seg"
BODY = b'{"text":"hi"}'
JOIN = 5.0  # a safety bound: a test that reaches it has failed

RATE = Attempt(reply=Reply(status=429, body=b"{}"))
REFUSED = Attempt(connect_error=ConnectionRefusedError(CANARY))
EOF = Attempt(tls_error=ssl_eof_error())
OK = Attempt()


def freeze(gw: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> None:
    """The clock moves only when the fake gateway advances it (a sleep, a scripted delay)."""
    monkeypatch.setattr(gw, "monotonic", lambda: 1000.0 + gw._skew)  # pyright: ignore[reportPrivateUsage]


class Run:
    """One synchronous run of the worker body on a frozen clock."""

    def __init__(self, gw: FakeGateway, monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
        self.gw = gw
        freeze(gw, monkeypatch)
        self.writing_calls = 0
        self.gate_at_sleep: list[GateState] = []
        self.deadline = Deadline(gw, at=gw.monotonic() + seconds, on_writing=self._on_writing)
        original = gw.sleep

        def sleep(seconds: float) -> None:
            self.gate_at_sleep.append(self.deadline.state)
            original(seconds)

        monkeypatch.setattr(gw, "sleep", sleep)

    def _on_writing(self) -> None:
        self.writing_calls += 1

    def work(self, timeout: float = 5.0) -> Outcome:
        return attempt_work(self.gw, Webhook(PATH), BODY, timeout=timeout)(self.deadline)

    @property
    def sleeps(self) -> list[float]:
        return [float(e.split(":")[1]) for e in self.gw.events if e.startswith("sleep:")]

    @property
    def posts(self) -> int:
        return self.gw.events.count("post")

    @property
    def connections(self) -> int:
        return self.gw.events.count("https_connection")


@pytest.fixture
def run(fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Run]:
    def make(*script: Attempt, seconds: float = 1000.0, leftover: bool = False) -> Run:
        fake_gateway.allow_unconsumed_script = leftover
        fake_gateway.script(*script)
        return Run(fake_gateway, monkeypatch, seconds)

    return make


def check(outcome: Outcome) -> dict[str, Any]:
    """Validate the envelope and the log record; nothing secret in either. Returns the error."""
    assert outcome.exit_code in (0, 12)
    error: dict[str, Any] = {}
    if outcome.exit_code == 12:
        text = json.dumps(outcome.envelope())
        assert CANARY not in text and "triggers" not in text
        error = assert_valid("cli/error", text)["error"]
    record = build_record(
        wall_time=1_700_000_000.0,
        version=__version__,
        gate_writing=False,
        level="info",
        bytes_=12,
        truncated=False,
        duration_ms=5,
        message_hash="0" * 16,
        dedupe_hash=None,
        actor="human:tester",
        actor_source="flag",
        **outcome.log_fields(),
    )
    assert record is not None
    text = encode_record(record)
    assert CANARY.encode() not in text
    assert_valid("log", text)
    return error


def flags(error: dict[str, Any]) -> tuple[Any, ...]:
    return (error["code"], error["retryable"], error["unknown_outcome"], error["retry_after_s"])


# --- 429 ---------------------------------------------------------------------------------------


def test_429_three_times_waits_2_then_4_then_rate_limited(run: Callable[..., Run]) -> None:
    r = run(RATE, RATE, RATE)
    outcome = r.work()
    assert r.sleeps == [2.0, 4.0]
    assert (r.connections, r.posts) == (3, 3)
    assert flags(check(outcome)) == ("rate_limited", True, False, 4.0)


def test_the_final_429_leaves_the_gate_idle_and_a_decision_in_the_gap_is_rate_limited(
    run: Callable[..., Run],
) -> None:
    r = run(RATE, RATE, RATE)
    outcome = r.work()
    assert r.deadline.state is GateState.IDLE  # stored and idle in one step
    verdict = r.deadline.decide(expired=True)
    assert verdict is not None
    assert verdict.outcome is not None
    assert flags(check(verdict.outcome)) == ("rate_limited", True, False, 4.0)
    assert not verdict.unknown_outcome
    assert outcome.exit_code == 12


def test_the_gate_is_idle_again_while_waiting_after_each_429(run: Callable[..., Run]) -> None:
    r = run(RATE, RATE, RATE)
    r.work()
    assert r.gate_at_sleep == [GateState.IDLE, GateState.IDLE]


def test_each_attempt_that_writes_takes_the_writing_step_again(run: Callable[..., Run]) -> None:
    r = run(RATE, RATE, OK)
    assert r.work().message == "sent"
    assert r.writing_calls == 3  # the send lock is re-stamped before every POST (#28)


def test_429_then_200_waits_once(run: Callable[..., Run]) -> None:
    r = run(RATE, OK)
    outcome = r.work()
    assert (outcome.exit_code, r.sleeps, r.posts) == (0, [2.0], 2)
    check(outcome)


def test_429_twice_then_200(run: Callable[..., Run]) -> None:
    r = run(RATE, RATE, OK)
    outcome = r.work()
    assert (outcome.exit_code, r.sleeps, r.posts) == (0, [2.0, 4.0], 3)


@pytest.mark.parametrize(
    "body", [b"", b"not json", b"x" * 5000, b'{"retry_after":45}', b"Retry-After: 45"]
)
def test_only_the_status_of_a_429_counts(run: Callable[..., Run], body: bytes) -> None:
    r = run(Attempt(reply=Reply(status=429, body=body)), OK)
    assert r.work().exit_code == 0
    assert r.sleeps == [2.0]


RETRY_AFTER_VALUES = [
    "nan",
    "-5",
    "1e999",
    "Wed, 21 Oct 2026 07:28:00 GMT",
    "5",
    "45",
    "0",
    "\u00b2",
]


@pytest.mark.parametrize("value", RETRY_AFTER_VALUES)
def test_a_retry_after_header_of_any_value_is_ignored(run: Callable[..., Run], value: str) -> None:
    # The gateway Response exposes no headers, so this is a guard by construction: the headers
    # only lengthen the head, and the retry loop cannot read them.
    hinted = Attempt(reply=Reply(status=429, body=b"{}", headers=(("Retry-After", value),)))
    r = run(hinted, hinted, hinted)
    outcome = r.work()
    assert r.sleeps == [2.0, 4.0]
    assert flags(check(outcome)) == ("rate_limited", True, False, 4.0)


def test_a_server_wait_hint_cannot_change_the_waits() -> None:
    # The Response protocol has no header access, so Retry-After (nan, -5, 1e999, an HTTP date,
    # 5, 45, 0, a superscript two) cannot be read: the waits are constants.
    assert not {"getheader", "getheaders", "headers", "msg"} & set(dir(gateway.Response))
    assert deadline.RATE_LIMIT_WAITS == (2.0, 4.0)
    assert deadline.CONNECTION_WAIT == 2.0


def test_a_failure_reading_a_429_body_is_outcome_unknown_and_never_retried(
    run: Callable[..., Run],
) -> None:
    broken = Attempt(
        reply=Reply(status=429, body=b"{}", body_error=ConnectionResetError(), body_error_after=1)
    )
    r = run(broken, OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.posts) == ([], 1)
    assert flags(check(outcome)) == ("outcome_unknown", False, True, None)


# --- failures before the first byte ------------------------------------------------------------


def test_connect_refused_is_retried_once_after_2_s(run: Callable[..., Run]) -> None:
    r = run(REFUSED, REFUSED)
    outcome = r.work()
    assert (r.sleeps, r.connections, r.posts) == ([2.0], 2, 0)
    assert flags(check(outcome)) == ("network_error", True, False, None)
    assert r.gate_at_sleep == [GateState.IDLE]


def test_connect_failure_then_200(run: Callable[..., Run]) -> None:
    r = run(REFUSED, OK)
    assert r.work().exit_code == 0
    assert (r.sleeps, r.posts) == ([2.0], 1)


def test_name_resolution_failure_is_retried_once(run: Callable[..., Run]) -> None:
    failing = Attempt(resolve_error=socket.gaierror(-2, CANARY))
    r = run(failing, failing)
    outcome = r.work()
    assert (r.sleeps, r.connections) == ([2.0], 2)
    assert flags(check(outcome)) == ("network_error", True, False, None)


@pytest.mark.parametrize("phase", ["connect", "tls"])
def test_a_timeout_before_the_first_byte_is_retried_once(
    run: Callable[..., Run], phase: str
) -> None:
    slow = Attempt(connect_delay=100.0) if phase == "connect" else Attempt(tls_delay=100.0)
    r = run(slow, slow)
    error = check(r.work())
    assert (r.sleeps, r.connections, r.posts) == ([2.0], 2, 0)
    assert error["details"] == {"tls": False, "timeout": True}
    assert (error["retryable"], error["unknown_outcome"]) == (True, False)


@pytest.mark.parametrize(
    ("tls_error", "retryable", "tls"),
    [
        (ssl_eof_error, False, True),
        (handshake_error, False, True),
        (tls_broken_pipe, True, False),  # the same event as an EOF, but not a TLS error class
    ],
    ids=["ssl_eof", "alert", "broken_pipe"],
)
def test_a_handshake_failure_is_retried_once_and_the_final_flags_follow_the_class(
    run: Callable[..., Run], tls_error: Callable[[], Exception], retryable: bool, tls: bool
) -> None:
    failing = Attempt(tls_error=tls_error())
    r = run(failing, failing)
    error = check(r.work())
    assert (r.sleeps, r.connections, r.posts) == ([2.0], 2, 0)
    assert (error["retryable"], error["details"]["tls"]) == (retryable, tls)
    assert error["unknown_outcome"] is False


def test_handshake_eof_then_success(run: Callable[..., Run]) -> None:
    r = run(EOF, OK)
    assert r.work().exit_code == 0
    assert (r.sleeps, r.posts) == ([2.0], 1)


def test_a_certificate_failure_is_never_retried(run: Callable[..., Run]) -> None:
    r = run(Attempt(tls_error=cert_verify_error()), OK, leftover=True)
    error = check(r.work())
    assert (r.sleeps, r.connections) == ([], 1)
    assert flags(error) == ("network_error", False, False, None)
    assert error["details"]["tls"] is True


def test_no_usable_ca_is_never_retried(run: Callable[..., Run], fake_gateway: FakeGateway) -> None:
    fake_gateway.no_usable_ca = True
    r = run(OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.connections) == ([], 0)
    assert check(outcome)["details"]["tls"] is True


@pytest.mark.parametrize("status", [500, 502, 503, 599])
def test_5xx_is_not_retried(run: Callable[..., Run], status: int) -> None:
    r = run(Attempt(reply=Reply(status=status, body=b"{}")), OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.posts) == ([], 1)
    assert flags(check(outcome)) == ("upstream_error", False, True, None)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410, 418, 302, 200, 204])
def test_other_statuses_are_not_retried(run: Callable[..., Run], status: int) -> None:
    body = b"" if status == 204 else b"{}"
    r = run(Attempt(reply=Reply(status=status, body=body)), OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.posts) == ([], 1)
    check(outcome)


# --- failures after the first byte are never retried -------------------------------------------

AFTER_WRITE = {
    "write_reset": Attempt(write_error=ConnectionResetError(CANARY)),
    "write_broken_pipe": Attempt(write_error=BrokenPipeError(CANARY)),
    "write_timeout": Attempt(write_delay=100.0),
    "reply_reset": Attempt(reply=ConnectionResetError(CANARY)),
    "reply_timeout": Attempt(reply=Reply(first_byte_delay=100.0)),
    "reply_ssl_eof": Attempt(reply=ssl_eof_error()),
    "body_reset": Attempt(reply=Reply(body_error=ConnectionResetError(CANARY), body_error_after=1)),
    "body_short": Attempt(reply=Reply(truncated_by=5)),
    "body_stall": Attempt(reply=Reply(body_stall_after=1)),
}


@pytest.mark.parametrize("name", sorted(AFTER_WRITE))
def test_a_failure_after_the_first_byte_is_never_retried(
    run: Callable[..., Run], name: str
) -> None:
    r = run(AFTER_WRITE[name], OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.connections, r.posts) == ([], 1, 1)
    assert flags(check(outcome)) == ("outcome_unknown", False, True, None)


def test_a_failure_after_a_429_retry_wrote_is_never_retried(run: Callable[..., Run]) -> None:
    r = run(RATE, AFTER_WRITE["reply_reset"], OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.connections, r.posts) == ([2.0], 2, 2)
    assert flags(check(outcome)) == ("outcome_unknown", False, True, None)


def test_a_connection_retry_that_then_writes_and_fails_is_never_retried(
    run: Callable[..., Run],
) -> None:
    r = run(REFUSED, AFTER_WRITE["write_reset"], OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.connections, r.posts) == ([2.0], 2, 1)
    assert check(outcome)["code"] == "outcome_unknown"


# --- independent counters ----------------------------------------------------------------------


def test_429_twice_then_connection_refused_is_four_requests_at_most(
    run: Callable[..., Run],
) -> None:
    r = run(RATE, RATE, REFUSED, REFUSED, OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.connections) == ([2.0, 4.0, 2.0], 4)
    assert flags(check(outcome)) == ("network_error", True, False, None)


def test_429_then_connection_failure_then_429_uses_the_second_429_wait(
    run: Callable[..., Run],
) -> None:
    r = run(RATE, REFUSED, RATE, OK)
    assert r.work().exit_code == 0
    assert (r.sleeps, r.connections, r.posts) == ([2.0, 2.0, 4.0], 4, 3)


def test_connection_failure_then_three_429s_ends_rate_limited_after_four_attempts(
    run: Callable[..., Run],
) -> None:
    r = run(REFUSED, RATE, RATE, RATE, OK, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.connections) == ([2.0, 2.0, 4.0], 4)
    assert flags(check(outcome)) == ("rate_limited", True, False, 4.0)


# --- the deadline cuts retries -----------------------------------------------------------------


def test_a_429_wait_as_long_as_the_time_left_ends_the_send_at_once(
    run: Callable[..., Run],
) -> None:
    r = run(RATE, OK, seconds=2.0, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.connections) == ([], 1)  # no sleep, no second attempt
    assert flags(check(outcome)) == ("rate_limited", True, False, 2.0)


def test_a_429_wait_shorter_than_the_time_left_is_taken(run: Callable[..., Run]) -> None:
    r = run(RATE, OK, seconds=2.5)
    assert r.work().exit_code == 0
    assert r.sleeps == [2.0]


def test_the_second_429_wait_that_does_not_fit_reports_that_wait(run: Callable[..., Run]) -> None:
    r = run(RATE, RATE, OK, seconds=5.0, leftover=True)  # 2 s fits (3 left), 4 s does not
    outcome = r.work()
    assert (r.sleeps, r.connections) == ([2.0], 2)
    assert flags(check(outcome)) == ("rate_limited", True, False, 4.0)


def test_a_connection_wait_that_does_not_fit_ends_with_network_error(
    run: Callable[..., Run],
) -> None:
    r = run(REFUSED, OK, seconds=2.0, leftover=True)
    outcome = r.work()
    assert (r.sleeps, r.connections) == ([], 1)
    assert flags(check(outcome)) == ("network_error", True, False, None)


def test_a_connection_failure_after_a_429_that_cannot_wait_reports_the_connection_result(
    run: Callable[..., Run],
) -> None:
    r = run(RATE, REFUSED, OK, seconds=3.0, leftover=True)  # 2 s fits (1 left), the next does not
    outcome = r.work()
    assert (r.sleeps, r.connections) == ([2.0], 2)
    assert flags(check(outcome)) == ("network_error", True, False, None)


def test_a_deadline_that_passes_during_the_wait_makes_no_new_attempt(
    run: Callable[..., Run], monkeypatch: pytest.MonkeyPatch
) -> None:
    r = run(RATE, OK, seconds=30.0, leftover=True)
    original = r.gw.sleep

    def long_sleep(seconds: float) -> None:
        original(seconds + 100.0)  # the wait overran the deadline

    monkeypatch.setattr(r.gw, "sleep", long_sleep)
    outcome = r.work()
    assert (r.connections, r.posts) == (1, 1)  # nothing is opened after the deadline
    assert flags(check(outcome)) == ("rate_limited", True, False, 2.0)


def test_a_deadline_during_the_4_s_wait_after_the_second_429_reports_that_wait(
    run: Callable[..., Run], monkeypatch: pytest.MonkeyPatch
) -> None:
    r = run(RATE, RATE, OK, seconds=30.0, leftover=True)
    original = r.gw.sleep

    def sleep(seconds: float) -> None:
        original(seconds + (100.0 if seconds == 4.0 else 0.0))  # the 4 s wait overran

    monkeypatch.setattr(r.gw, "sleep", sleep)
    outcome = r.work()
    assert (r.connections, r.posts) == (2, 2)
    assert flags(check(outcome)) == ("rate_limited", True, False, 4.0)


def test_a_tls_failure_after_the_deadline_with_no_earlier_result_is_the_timeout_network_error(
    run: Callable[..., Run],
) -> None:
    # The handshake ran into the deadline and then failed with a TLS class: with no earlier
    # result the send reports what an idle gate at the deadline reports (Deadline paragraph).
    slow_eof = Attempt(connect_delay=0.9, tls_delay=0.9, tls_error=ssl_eof_error())
    r = run(slow_eof, OK, seconds=1.0, leftover=True)
    error = check(r.work())
    assert (r.sleeps, r.connections) == ([], 1)
    assert error["details"] == {"tls": False, "timeout": True}
    assert (error["code"], error["retryable"], error["unknown_outcome"]) == (
        "network_error",
        True,
        False,
    )


def test_a_signal_during_the_wait_makes_no_new_attempt(
    run: Callable[..., Run], monkeypatch: pytest.MonkeyPatch
) -> None:
    r = run(REFUSED, OK, leftover=True)
    original = r.gw.sleep

    def signalled_sleep(seconds: float) -> None:
        r.deadline.note_signal()
        original(seconds)

    monkeypatch.setattr(r.gw, "sleep", signalled_sleep)
    outcome = r.work()
    assert r.connections == 1
    assert flags(check(outcome)) == ("network_error", True, False, None)


def test_a_retry_cut_by_the_deadline_keeps_the_earlier_result_when_the_attempt_timed_out(
    run: Callable[..., Run],
) -> None:
    # The retry's own timeout is the deadline: the 429 stays the last result.
    r = run(RATE, Attempt(connect_delay=100.0), seconds=2.25)
    outcome = r.work()
    assert (r.sleeps, r.connections, r.posts) == ([2.0], 2, 1)
    assert flags(check(outcome)) == ("rate_limited", True, False, 2.0)


# --- a real worker thread: the deadline passes inside a retry ----------------------------------


def run_thread(gw: FakeGateway, seconds: float) -> tuple[Deadline, Verdict]:
    d = Deadline(gw, at=gw.monotonic() + seconds)
    verdict = d.run(attempt_work(gw, Webhook(PATH), BODY, timeout=5.0))
    return d, verdict


def finish(gw: FakeGateway, d: Deadline) -> None:
    gw.release_stalls()
    assert d.worker is not None
    d.worker.join(JOIN)
    assert not d.worker.is_alive()


@pytest.mark.parametrize(
    "stalled",
    [
        Attempt(resolve_stall=True),
        Attempt(connect_delay=100.0),
        Attempt(tls_delay=100.0),
        Attempt(resolve_stall=True, stall_then_proceed=True),
    ],
    ids=["resolve", "connect", "handshake", "resolve-then-proceed"],
)
def test_a_deadline_in_the_connect_of_a_retry_reports_rate_limited_never_unknown(
    fake_gateway: FakeGateway, stalled: Attempt
) -> None:
    fake_gateway.script(RATE, stalled)
    d, verdict = run_thread(fake_gateway, 2.25)  # the 2 s wait moves the fake clock, 0.25 s remain
    finish(fake_gateway, d)
    assert verdict.outcome is not None
    assert flags(check(verdict.outcome)) == ("rate_limited", True, False, 2.0)
    assert not verdict.unknown_outcome and not verdict.gate_writing
    assert fake_gateway.events.count("post") == 1  # nothing is written after the 429
    assert fake_gateway.events.count("https_connection") == 2  # and no third attempt follows


def test_nothing_is_written_after_the_gate_was_abandoned(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(RATE, Attempt(resolve_stall=True, stall_then_proceed=True))
    d, verdict = run_thread(fake_gateway, 2.25)
    finish(fake_gateway, d)
    assert d.state is GateState.ABANDONED
    assert fake_gateway.events.count("post") == 1
    assert verdict.outcome is not None and verdict.outcome.code == "rate_limited"


def test_a_retry_that_is_writing_when_the_deadline_passes_is_outcome_unknown(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(RATE, Attempt(reply=Reply(first_byte_delay=100.0)))
    d, verdict = run_thread(fake_gateway, 2.25)
    finish(fake_gateway, d)
    assert verdict.outcome is not None
    assert flags(check(verdict.outcome)) == ("outcome_unknown", False, True, None)
    assert verdict.gate_writing


def test_a_connection_retry_that_is_writing_at_the_deadline_is_outcome_unknown(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(REFUSED, Attempt(write_delay=100.0))
    d, verdict = run_thread(fake_gateway, 2.25)
    finish(fake_gateway, d)
    assert verdict.outcome is not None and verdict.outcome.code == "outcome_unknown"
    assert fake_gateway.events.count("post") == 1


def test_a_worker_exception_in_a_retry_before_writing_is_exit_1_not_unknown(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(RATE, Attempt(connect_error=KeyboardInterrupt()))
    d, verdict = run_thread(fake_gateway, 30.0)
    finish(fake_gateway, d)
    assert (verdict.exit_code, verdict.error_class) == (1, "KeyboardInterrupt")
    assert (verdict.gate_writing, verdict.unknown_outcome) == (False, False)


def test_a_worker_exception_in_a_retry_after_writing_is_unknown(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(RATE, Attempt(reply=SystemExit(CANARY)))
    d, verdict = run_thread(fake_gateway, 30.0)
    finish(fake_gateway, d)
    assert (verdict.exit_code, verdict.error_class) == (1, "SystemExit")
    assert (verdict.gate_writing, verdict.unknown_outcome) == (True, True)
    assert CANARY not in repr(verdict)


# --- every scripted sequence -------------------------------------------------------------------

KINDS: dict[str, Attempt] = {
    "429": RATE,
    "refused": REFUSED,
    "eof": EOF,
    "cert": Attempt(tls_error=cert_verify_error()),
    "reset": Attempt(write_error=ConnectionResetError()),
    "200": OK,
}
RETRIED = ("429", "refused", "eof")


def oracle(sequence: tuple[str, ...]) -> tuple[int, list[float], str]:
    """The Retries paragraph as a loop: (attempts used, waits, kind of the last attempt)."""
    rate = connection = 0
    waits: list[float] = []
    used = 0
    for kind in sequence:
        used += 1
        if kind == "429" and rate < 2:
            waits.append((2.0, 4.0)[rate])
            rate += 1
        elif kind in ("refused", "eof") and connection < 1:
            waits.append(2.0)
            connection += 1
        else:
            return used, waits, kind
    raise AssertionError("the sequence is too short for the oracle")


EXPECTED: dict[str, tuple[Any, ...] | None] = {
    "429": ("rate_limited", True, False, 4.0),
    "refused": ("network_error", True, False, None),
    "eof": ("network_error", False, False, None),
    "cert": ("network_error", False, False, None),
    "reset": ("outcome_unknown", False, True, None),
    "200": None,
}


def test_every_sequence_of_four_attempts_follows_the_table_and_the_bounds(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    gw = fake_gateway
    gw.allow_unconsumed_script = True
    freeze(gw, monkeypatch)
    for sequence in itertools.product(KINDS, repeat=4):
        gw._attempts.clear()  # pyright: ignore[reportPrivateUsage]
        gw.events.clear()
        gw.connections.clear()
        gw._skew = 0.0  # pyright: ignore[reportPrivateUsage]
        gw.script(*(KINDS[k] for k in sequence))
        d = Deadline(gw, at=gw.monotonic() + 1000.0)
        outcome = attempt_work(gw, Webhook(PATH), BODY, timeout=5.0)(d)
        used, waits, last = oracle(sequence)
        sleeps = [float(e.split(":")[1]) for e in gw.events if e.startswith("sleep:")]
        label = "/".join(sequence)
        assert (gw.events.count("https_connection"), sleeps) == (used, waits), label
        assert used <= 4 and len(waits) <= 3 and waits.count(4.0) <= 1, label
        assert gw.events.count("post") <= used, label
        # only a 429 or a connection failure is ever followed by another attempt
        assert all(kind in RETRIED for kind in sequence[: used - 1]), label
        expected = EXPECTED[last]
        if expected is None:
            assert outcome.exit_code == 0, label
        else:
            assert flags(check(outcome)) == expected, label
    gw.events.clear()


def test_the_loop_is_bounded_whatever_the_script_says(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    gw = fake_gateway
    gw.allow_unconsumed_script = True
    freeze(gw, monkeypatch)
    gw.script(*([RATE, REFUSED] * 10))
    d = Deadline(gw, at=gw.monotonic() + 1000.0)
    attempt_work(gw, Webhook(PATH), BODY, timeout=5.0)(d)
    assert gw.events.count("https_connection") <= 4

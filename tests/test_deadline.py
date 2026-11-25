"""The deadline: daemon worker, three-state gate, result slot and the hard exit (issue #25).

Most tests run against the fake gateway's clock (real time plus a skew that the worker, or the
test, advances) and use real threads only where the point is a thread: a worker that never
returns, a race, the daemon flag. Real waits are bounded by a fraction of a second. Every worker a
test leaves blocked is released and joined before the test ends. Fake secrets are built at run
time around a CANARY; nothing here touches a network.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import slack_notice
from slack_notice import cli, deadline
from slack_notice.deadline import (
    Deadline,
    GateState,
    Verdict,
    attempt_work,
    conclude,
    end_process,
)
from slack_notice.gateway import SystemGateway
from slack_notice.webhook import (
    AttemptResult,
    Outcome,
    Phase,
    Retry,
    Webhook,
    map_attempt,
    network_error,
    outcome_unknown,
)
from tests.fake_gateway import Attempt, FakeGateway, FakeProcessExit

CANARY = "CAN" + "ARY" + "_25d"
PATH = "/triggers/" + CANARY + "/seg"
BODY = b'{"text":"hi"}'
WAIT = 5.0  # a safety bound for events: a test that reaches it has failed


def make(gw: FakeGateway, *, in_seconds: float = 30.0, **kw: object) -> Deadline:
    return Deadline(gw, at=gw.monotonic() + in_seconds, **kw)  # type: ignore[arg-type]


def advance(gw: FakeGateway, seconds: float) -> None:
    gw._advance(seconds)  # pyright: ignore[reportPrivateUsage]


def rate_limited() -> Outcome:
    return map_attempt(AttemptResult(Phase.READ, 429, b""), gate_writing=True).with_retry_after(2.0)


@pytest.fixture
def silent_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    """``run`` replaces ``threading.excepthook`` for the life of the process: put it back."""
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)


@pytest.fixture(autouse=True)
def _restore_hook(silent_hook: None) -> None:  # pyright: ignore[reportUnusedFunction]
    return None


@pytest.fixture
def release() -> Iterator[threading.Event]:
    """An event a blocked worker waits on; set and the worker joined at teardown."""
    event = threading.Event()
    yield event
    event.set()


def join(d: Deadline) -> None:
    assert d.worker is not None
    d.worker.join(WAIT)
    assert not d.worker.is_alive()


# --- the gate ------------------------------------------------------------------------------


def test_the_gate_starts_idle_and_moves_to_writing_once(fake_gateway: FakeGateway) -> None:
    calls: list[int] = []
    d = make(fake_gateway, on_writing=lambda: calls.append(1))
    assert d.state is GateState.IDLE and not d.writing
    assert d.enter_writing() is True
    assert d.state is GateState.WRITING and d.writing and calls == [1]
    with pytest.raises(ValueError):  # a second write without a fully read 429 is a bug
        d.enter_writing()
    assert calls == [1]


def test_a_decided_deadline_refuses_the_move_to_writing(fake_gateway: FakeGateway) -> None:
    calls: list[int] = []
    d = make(fake_gateway, in_seconds=-1.0, on_writing=lambda: calls.append(1))
    verdict = d.decide(expired=True)
    assert verdict is not None and verdict.deadline_hit
    assert d.state is GateState.ABANDONED
    assert d.enter_writing() is False
    assert calls == [] and not d.writing


def test_a_full_429_moves_the_gate_back_to_idle_and_a_retry_can_write_again(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    assert d.enter_writing()
    assert d.record(rate_limited(), final=False) is True
    assert d.state is GateState.IDLE
    assert d.enter_writing() is True and d.state is GateState.WRITING


def test_a_connection_failure_is_kept_as_the_last_result_with_the_gate_idle(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    failure = network_error(tls=False, timeout=False)
    assert d.record(failure, final=False) is True
    assert d.state is GateState.IDLE
    verdict = d.decide(expired=True)
    assert verdict is not None and verdict.outcome == failure and verdict.deadline_hit


def test_a_retry_result_that_is_not_a_429_cannot_move_a_writing_gate_back(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    assert d.enter_writing()
    with pytest.raises(ValueError):
        d.record(outcome_unknown(), final=False)
    assert d.state is GateState.WRITING


def test_a_result_after_the_decision_is_dropped(fake_gateway: FakeGateway) -> None:
    d = make(fake_gateway)
    first = d.decide(expired=True)
    assert first is not None
    assert d.record(network_error(tls=False, timeout=False), final=True) is False
    assert d.decide(expired=True) == first  # decided once: the same answer again


def test_not_expired_and_nothing_stored_is_no_decision(fake_gateway: FakeGateway) -> None:
    d = make(fake_gateway)
    assert d.decide(expired=False) is None
    assert d.state is GateState.IDLE  # looking is not deciding


def test_a_stored_final_result_beats_the_deadline_even_when_expired(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    assert d.enter_writing()
    final = map_attempt(AttemptResult(Phase.READ, 200, b'{"ok":true}'), gate_writing=True)
    assert d.record(final, final=True)
    verdict = d.decide(expired=True)
    assert verdict is not None and verdict.outcome == final and not verdict.deadline_hit


# --- the deadline outcome by gate state ---------------------------------------------------------


def test_idle_at_the_deadline_is_network_error_with_timeout_and_no_unknown_outcome(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    verdict = d.decide(expired=True)
    assert verdict is not None and verdict.outcome is not None
    out = verdict.outcome
    assert (out.exit_code, out.code, out.unknown_outcome, out.retryable) == (
        12,
        "network_error",
        False,
        True,
    )
    assert out.details == {"tls": False, "timeout": True}
    assert (verdict.exit_code, verdict.unknown_outcome, verdict.gate_writing) == (12, False, False)


def test_idle_at_the_deadline_with_a_last_429_reports_that_429(fake_gateway: FakeGateway) -> None:
    d = make(fake_gateway)
    assert d.enter_writing()
    last = rate_limited()
    assert d.record(last, final=False)
    verdict = d.decide(expired=True)
    assert verdict is not None and verdict.outcome == last
    assert last.retry_after_s == 2.0 and not verdict.unknown_outcome


def test_writing_at_the_deadline_is_outcome_unknown_and_the_gate_stays_writing(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    assert d.enter_writing()
    verdict = d.decide(expired=True)
    assert verdict is not None and verdict.outcome == outcome_unknown()
    assert (verdict.exit_code, verdict.unknown_outcome, verdict.gate_writing) == (12, True, True)
    assert d.state is GateState.WRITING
    assert d.record(rate_limited(), final=False) is False  # too late: nothing moves it back
    assert d.state is GateState.WRITING


def test_a_writing_gate_with_an_earlier_429_is_still_unknown(fake_gateway: FakeGateway) -> None:
    d = make(fake_gateway)
    assert d.enter_writing()
    assert d.record(rate_limited(), final=False)
    assert d.enter_writing()  # the retry writes
    verdict = d.decide(expired=True)
    assert verdict is not None and verdict.outcome == outcome_unknown()


# --- run: the worker and the wait ---------------------------------------------------------------


def test_run_returns_the_workers_result_and_marks_the_worker_a_daemon(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    seen: list[bool] = []
    sent = map_attempt(AttemptResult(Phase.READ, 200, b'{"ok":true}'), gate_writing=True)

    def work(dl: Deadline) -> Outcome:
        assert dl.worker is not None
        seen.append(dl.worker.daemon)
        return sent

    verdict = d.run(work)
    assert verdict.outcome == sent and verdict.exit_code == 0 and not verdict.deadline_hit
    assert seen == [True]  # process exit does not wait for the worker
    join(d)


def test_the_worker_is_started_once(fake_gateway: FakeGateway) -> None:
    d = make(fake_gateway)
    d.run(lambda _d: outcome_unknown())
    with pytest.raises(RuntimeError):
        d.run(lambda _d: outcome_unknown())
    join(d)


def test_a_worker_that_never_returns_ends_at_the_deadline_with_the_gate_idle(
    fake_gateway: FakeGateway, release: threading.Event
) -> None:
    d = make(fake_gateway, in_seconds=0.15)
    began = time.monotonic()

    def work(_d: Deadline) -> Outcome:
        release.wait(WAIT)
        return outcome_unknown()

    verdict = d.run(work)
    assert time.monotonic() - began < 1.0  # within slices of the deadline, not the worker
    assert verdict.deadline_hit and verdict.outcome is not None
    assert verdict.outcome.code == "network_error" and verdict.exit_code == 12
    assert d.state is GateState.ABANDONED
    assert d.worker is not None and d.worker.is_alive()  # never joined by run
    release.set()
    join(d)


def test_a_worker_blocked_after_the_gate_moved_to_writing_is_outcome_unknown(
    fake_gateway: FakeGateway, release: threading.Event
) -> None:
    d = make(fake_gateway)

    def work(dl: Deadline) -> Outcome:
        assert dl.enter_writing()
        advance(fake_gateway, 100.0)  # the deadline passes while the worker is writing
        release.wait(WAIT)
        return map_attempt(AttemptResult(Phase.READ, 200, b'{"ok":true}'), gate_writing=True)

    verdict = d.run(work)
    assert verdict.outcome == outcome_unknown() and verdict.unknown_outcome
    release.set()
    join(d)
    assert d.decide(expired=True) == verdict  # a late final result changed nothing


@pytest.mark.parametrize(
    "status, code",
    [(200, None), (400, "host_rejected"), (429, "rate_limited"), (500, "upstream_error")],
)
def test_a_response_complete_at_the_deadline_is_reported_as_it_is(
    fake_gateway: FakeGateway, status: int, code: str | None
) -> None:
    d = make(fake_gateway)

    def work(dl: Deadline) -> Outcome:
        assert dl.enter_writing()
        advance(fake_gateway, 100.0)  # the response arrives after the deadline instant
        body = b'{"ok":true}' if status == 200 else b"{}"
        out = map_attempt(AttemptResult(Phase.READ, status, body), gate_writing=True)
        return out.with_retry_after(4.0) if status == 429 else out

    verdict = d.run(work)
    assert verdict.outcome is not None and verdict.outcome.code == code
    assert verdict.outcome.code != "outcome_unknown" and not verdict.deadline_hit
    join(d)


def test_a_worker_that_finishes_just_before_the_check_wins(fake_gateway: FakeGateway) -> None:
    d = make(fake_gateway, in_seconds=-5.0)  # already past when run starts
    done = threading.Event()
    final = map_attempt(AttemptResult(Phase.READ, 200, b'{"ok":true}'), gate_writing=True)

    def work(dl: Deadline) -> Outcome:
        assert dl.enter_writing()
        return final

    # The worker needs a moment: hold the main thread's first check until the result is stored.
    real_decide = d.decide

    def decide(*, expired: bool) -> Verdict | None:
        assert d.worker is not None
        d.worker.join(WAIT)
        done.set()
        return real_decide(expired=expired)

    d.decide = decide  # type: ignore[method-assign]
    verdict = d.run(work)
    assert done.is_set() and verdict.outcome == final and not verdict.deadline_hit


def test_a_worker_that_finishes_after_the_decision_changes_nothing(
    fake_gateway: FakeGateway, release: threading.Event
) -> None:
    d = make(fake_gateway, in_seconds=-1.0)
    entered_after: list[bool] = []

    def work(dl: Deadline) -> Outcome:
        release.wait(WAIT)
        entered_after.append(dl.enter_writing())
        return outcome_unknown()

    verdict = d.run(work)
    assert verdict.deadline_hit and verdict.outcome is not None
    assert verdict.outcome.code == "network_error"
    release.set()
    join(d)
    assert entered_after == [False]  # no write follows an abandoned gate
    assert d.decide(expired=True) == verdict


def test_a_signal_is_the_deadline_within_a_slice(
    fake_gateway: FakeGateway, release: threading.Event
) -> None:
    d = make(fake_gateway, in_seconds=60.0)
    began = time.monotonic()
    started = threading.Event()

    def work(_d: Deadline) -> Outcome:
        started.set()
        release.wait(WAIT)
        return outcome_unknown()

    timer = threading.Timer(0.05, d.note_signal)  # stands in for the signal handler
    timer.start()
    verdict = d.run(work)
    timer.join()
    assert time.monotonic() - began < 1.0
    assert verdict.deadline_hit and verdict.outcome is not None
    assert verdict.outcome.code == "network_error"
    release.set()
    join(d)


def test_a_signal_while_writing_is_outcome_unknown(
    fake_gateway: FakeGateway, release: threading.Event
) -> None:
    d = make(fake_gateway, in_seconds=60.0)

    def work(dl: Deadline) -> Outcome:
        assert dl.enter_writing()
        d.note_signal()
        release.wait(WAIT)
        return outcome_unknown()

    verdict = d.run(work)
    assert verdict.outcome == outcome_unknown()
    release.set()
    join(d)


def test_note_signal_takes_no_lock(fake_gateway: FakeGateway) -> None:
    """A signal handler runs in the main thread between bytecodes, possibly while the main thread
    holds the gate lock: ``note_signal`` must not wait for it."""
    d = make(fake_gateway)
    with d._lock:  # pyright: ignore[reportPrivateUsage]
        d.note_signal()  # a lock-taking implementation would deadlock here
    assert d.signalled


# --- exceptions in the worker -------------------------------------------------------------------


class HostileError(Exception):
    def __init__(self) -> None:
        super().__init__("body " + CANARY + " " + PATH)


class Interrupt(BaseException):  # noqa: N818
    pass


@pytest.mark.parametrize(
    "factory, name",
    [
        (HostileError, "HostileError"),
        (Interrupt, "Interrupt"),
        (KeyboardInterrupt, "KeyboardInterrupt"),
        (lambda: SystemExit(3), "SystemExit"),
        (lambda: ValueError(CANARY), "ValueError"),
    ],
)
@pytest.mark.parametrize("writing", [False, True])
def test_a_worker_exception_is_exit_1_with_the_class_name_only(
    fake_gateway: FakeGateway,
    factory: Callable[[], BaseException],
    name: str,
    writing: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    d = make(fake_gateway)

    def work(dl: Deadline) -> Outcome:
        if writing:
            assert dl.enter_writing()
        raise factory()

    verdict = d.run(work)
    assert verdict.outcome is None and verdict.error_class == name
    assert (verdict.exit_code, verdict.unknown_outcome, verdict.gate_writing) == (
        1,
        writing,
        writing,
    )
    assert not verdict.deadline_hit
    for text in (repr(verdict), str(verdict)):
        assert CANARY not in text and "triggers" not in text
    join(d)
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""  # threading.excepthook prints nothing


def test_a_worker_exception_keeps_no_traceback(fake_gateway: FakeGateway) -> None:
    d = make(fake_gateway)

    def work(_d: Deadline) -> Outcome:
        raise HostileError

    verdict = d.run(work)
    assert not any(isinstance(v, BaseException) for v in vars(verdict).values())
    join(d)


def test_an_exception_whose_class_name_is_not_an_identifier_is_called_exception(
    fake_gateway: FakeGateway,
) -> None:
    odd = type("odd name ‮" + CANARY, (Exception,), {})
    d = make(fake_gateway)

    def work(_d: Deadline) -> Outcome:
        raise odd

    verdict = d.run(work)
    assert verdict.error_class == "Exception"
    join(d)


def test_a_worker_that_returns_something_else_is_an_internal_error(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    verdict = d.run(lambda _d: CANARY)  # type: ignore[arg-type,return-value]
    assert verdict.outcome is None and verdict.error_class == "TypeError"
    join(d)


def test_the_silent_excepthook_prints_nothing(
    fake_gateway: FakeGateway, capsys: pytest.CaptureFixture[str]
) -> None:
    d = make(fake_gateway)
    d.run(lambda _d: outcome_unknown())
    join(d)
    args = threading.ExceptHookArgs((HostileError, HostileError(), None, None))
    threading.excepthook(args)
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


# --- the race: writing against the deadline -----------------------------------------------------


def test_the_move_to_writing_and_the_deadline_have_exactly_one_winner(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway)
    barrier = threading.Barrier(2)
    moved: list[bool] = []
    decided: list[Verdict | None] = []

    def worker() -> None:
        barrier.wait(WAIT)
        moved.append(d.enter_writing())

    thread = threading.Thread(target=worker)
    thread.start()
    barrier.wait(WAIT)
    decided.append(d.decide(expired=True))
    thread.join(WAIT)
    (verdict,) = decided
    assert verdict is not None
    assert len(moved) == 1
    assert verdict.unknown_outcome is moved[0]  # unknown iff the gate reached writing
    assert (d.state is GateState.WRITING) is moved[0]
    assert (d.state is GateState.ABANDONED) is (not moved[0])


# --- the attempt as the worker's body -----------------------------------------------------------


def hook() -> Webhook:
    return Webhook(PATH)


def attempt(gw: FakeGateway, *, in_seconds: float = 0.2) -> tuple[Deadline, Verdict]:
    d = make(gw, in_seconds=in_seconds)
    verdict = d.run(attempt_work(gw, hook(), BODY, timeout=5.0))
    return d, verdict


def test_a_complete_attempt_is_sent(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(Attempt())
    d, verdict = attempt(fake_gateway, in_seconds=30.0)
    assert verdict.exit_code == 0 and verdict.outcome is not None
    assert verdict.outcome.message == "sent"
    join(d)


def test_stalled_name_resolution_is_network_error_with_nothing_written(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(Attempt(resolve_stall=True))
    d, verdict = attempt(fake_gateway)
    assert verdict.deadline_hit and verdict.outcome is not None
    assert (verdict.exit_code, verdict.outcome.code) == (12, "network_error")
    assert not verdict.unknown_outcome
    fake_gateway.release_stalls()
    join(d)
    assert [c.requests for c in fake_gateway.connections] == [[]]  # zero request bytes
    assert "post" not in fake_gateway.events


def test_a_connect_that_proceeds_after_the_deadline_writes_nothing(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(Attempt(resolve_stall=True, stall_then_proceed=True))
    d, verdict = attempt(fake_gateway)
    assert verdict.outcome is not None and verdict.outcome.code == "network_error"
    fake_gateway.release_stalls()  # the connect now proceeds, finds the gate abandoned
    join(d)
    assert "post" not in fake_gateway.events
    assert fake_gateway.connections[0].requests == [] and fake_gateway.connections[0].closed
    assert d.state is GateState.ABANDONED


class BlockingConnection:
    """A connection that connects, accepts the request, then does what the test says."""

    def __init__(self, release: threading.Event, *, trickle: bool) -> None:
        self.release = release
        self.trickle = trickle
        self.requests: list[tuple[str, bytes]] = []
        self.closed = False
        self.timeouts: list[float] = []
        self.ticks = 0

    def connect(self) -> None:
        return None

    def post(self, path: str, body: bytes) -> None:
        self.requests.append((path, body))

    def settimeout(self, seconds: float) -> None:
        self.timeouts.append(seconds)

    def getresponse(self) -> object:
        if self.trickle:
            # a peer that sends one byte of the head every 10 ms: no per-operation timeout fires
            while not self.release.wait(0.01):
                self.ticks += 1
        else:
            self.release.wait(WAIT)
        raise OSError("released")

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("trickle", [False, True])
def test_a_stall_or_trickle_after_the_first_byte_is_outcome_unknown_at_the_deadline(
    fake_gateway: FakeGateway,
    monkeypatch: pytest.MonkeyPatch,
    release: threading.Event,
    trickle: bool,
) -> None:
    conn = BlockingConnection(release, trickle=trickle)
    monkeypatch.setattr(fake_gateway, "https_connection", lambda *a, **k: conn)
    began = time.monotonic()
    d, verdict = attempt(fake_gateway, in_seconds=0.2)
    assert time.monotonic() - began < 1.2  # deadline plus a slice, never the worker's pace
    assert verdict.outcome == outcome_unknown() and verdict.exit_code == 12
    assert conn.requests == [(PATH, BODY)]
    assert d.worker is not None and d.worker.is_alive()  # a trickling worker is not waited for
    release.set()
    join(d)
    assert conn.closed


def test_a_result_that_arrives_after_the_deadline_with_the_gate_writing_is_dropped(
    fake_gateway: FakeGateway,
) -> None:
    d = make(fake_gateway, in_seconds=30.0)
    # The deadline is decided before the worker reports: nothing it says changes the verdict.
    first = d.decide(expired=True)
    assert first is not None and first.outcome is not None
    assert first.outcome.code == "network_error"
    assert d.record(rate_limited(), final=True) is False


# --- post_once per-operation timeouts derived from the deadline -------------------------------


def test_each_operation_timeout_is_the_smaller_of_the_option_and_the_time_left(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    from slack_notice.webhook import post_once

    fake_gateway.script(Attempt())
    left = iter([3.0, 2.5, 2.0, 1.5, 1.0, 0.5, 0.25])
    seen: list[float] = []
    real = fake_gateway.https_connection

    def tracking(*args: object, **kw: object):  # noqa: ANN202
        seen.append(float(kw["timeout"]))  # type: ignore[arg-type]
        conn = real(*args, **kw)  # type: ignore[arg-type]
        original = conn.settimeout

        def settimeout(seconds: float) -> None:
            seen.append(seconds)
            original(seconds)

        monkeypatch.setattr(conn, "settimeout", settimeout)
        return conn

    monkeypatch.setattr(fake_gateway, "https_connection", tracking)
    post_once(fake_gateway, hook(), BODY, timeout=2.2, remaining=lambda: next(left))
    # connect, before the write, before the response, before each of the two body reads
    assert seen == [2.2, 2.2, 2.0, 1.5, 1.0]


@pytest.mark.parametrize("left", [0.0, -3.0, float("nan"), float("-inf")])
def test_no_time_left_gives_a_tiny_positive_timeout_never_zero(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, left: float
) -> None:
    from slack_notice.webhook import post_once

    fake_gateway.script(Attempt(connect_delay=1.0))  # longer than the tiny timeout
    seen: list[float] = []
    real = fake_gateway.https_connection

    def tracking(*args: object, **kw: object):  # noqa: ANN202
        seen.append(float(kw["timeout"]))  # type: ignore[arg-type]
        return real(*args, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(fake_gateway, "https_connection", tracking)
    result = post_once(fake_gateway, hook(), BODY, timeout=5.0, remaining=lambda: left)
    assert 0 < seen[0] <= 0.01  # never 0 (non-blocking) or negative
    assert result.failure is not None and result.failure.timeout and result.phase is Phase.CONNECT


def test_without_a_remaining_callable_the_timeout_is_fixed(fake_gateway: FakeGateway) -> None:
    from slack_notice.webhook import post_once

    fake_gateway.script(Attempt())
    post_once(fake_gateway, hook(), BODY, timeout=4.0)
    assert fake_gateway.connections[0].timeout == 4.0


# --- the exit ------------------------------------------------------------------------------------


def test_exit_now_goes_through_the_gateway_only(monkeypatch: pytest.MonkeyPatch) -> None:
    codes: list[int] = []

    def fake_exit(code: int) -> None:
        codes.append(code)
        raise FakeProcessExit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)
    with pytest.raises(FakeProcessExit):
        SystemGateway().exit_now(12)
    assert codes == [12]
    for bad in (-1, 256, True, 1.0, "1", None):
        with pytest.raises(ValueError):
            SystemGateway().exit_now(bad)  # type: ignore[arg-type]
    assert codes == [12]


def test_the_fake_gateway_exit_records_and_raises_the_code(fake_gateway: FakeGateway) -> None:
    with pytest.raises(FakeProcessExit) as info:
        fake_gateway.exit_now(12)
    assert info.value.code == 12 and fake_gateway.exit_codes == [12]
    with pytest.raises(ValueError):
        fake_gateway.exit_now(300)
    assert fake_gateway.exit_codes == [12]


def test_end_process_flushes_then_exits_even_when_a_flush_fails(fake_gateway: FakeGateway) -> None:
    order: list[str] = []

    def bad() -> None:
        order.append("bad")
        raise OSError("closed")

    with pytest.raises(FakeProcessExit):
        end_process(
            fake_gateway, 12, [lambda: order.append("out"), bad, lambda: order.append("err")]
        )
    assert order == ["out", "bad", "err"] and fake_gateway.exit_codes == [12]


def test_conclude_prints_flushes_logs_then_exits_in_that_order(fake_gateway: FakeGateway) -> None:
    order: list[str] = []
    with pytest.raises(FakeProcessExit):
        conclude(
            fake_gateway,
            12,
            emit=lambda: order.append("emit"),
            flush=lambda: order.append("flush"),
            record=lambda: order.append("record"),
        )
    assert order == ["emit", "flush", "record"] and fake_gateway.exit_codes == [12]


def test_a_slow_log_step_comes_after_the_flushed_result(fake_gateway: FakeGateway) -> None:
    printed: list[str] = []
    flushed_before_log: list[bool] = []

    def record() -> None:
        flushed_before_log.append("flushed" in printed)
        advance(fake_gateway, 5.0)  # a log step that takes 5 s

    def flush() -> None:
        printed.append("flushed")

    with pytest.raises(FakeProcessExit):
        conclude(fake_gateway, 0, emit=lambda: printed.append("result"), flush=flush, record=record)
    assert printed == ["result", "flushed"] and flushed_before_log == [True]


def test_a_failing_log_step_never_changes_the_exit_code(fake_gateway: FakeGateway) -> None:
    def record() -> None:
        raise OSError("disk full " + CANARY)

    with pytest.raises(FakeProcessExit):
        conclude(fake_gateway, 12, emit=lambda: None, flush=lambda: None, record=record)
    assert fake_gateway.exit_codes == [12]


def test_a_failing_print_is_exit_1_and_still_ends_the_process(fake_gateway: FakeGateway) -> None:
    order: list[str] = []

    def emit() -> None:
        raise BrokenPipeError

    with pytest.raises(FakeProcessExit):
        conclude(
            fake_gateway,
            12,
            emit=emit,
            flush=lambda: order.append("flush"),
            record=lambda: order.append("record"),
        )
    assert fake_gateway.exit_codes == [1] and order == ["flush", "record"]


def test_an_exception_in_flush_or_exit_path_still_reaches_the_exit(
    fake_gateway: FakeGateway,
) -> None:
    def flush() -> None:
        raise ValueError("I/O operation on closed file")

    with pytest.raises(FakeProcessExit):
        conclude(fake_gateway, 0, emit=lambda: None, flush=flush, record=lambda: None)
    assert fake_gateway.exit_codes == [0]


def test_os_exit_appears_in_no_module_but_the_gateway() -> None:
    src = Path(slack_notice.__file__).parent
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
            n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
        }
        names |= {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
        if path.name == "gateway.py":
            assert "_exit" in names
        else:
            assert "_exit" not in names, path.name


# --- a real process: the worker cannot keep it alive -----------------------------------------


CHILD = textwrap.dedent(
    """
    import os, sys, threading
    from slack_notice.deadline import Deadline, conclude
    from slack_notice.gateway import SystemGateway

    gateway = SystemGateway()
    read_end, write_end = os.pipe()  # nothing is ever written: the worker blocks in the syscall
    d = Deadline(gateway, at=gateway.monotonic() + 0.3)

    def work(dl):
        dl.enter_writing() if sys.argv[1] == "writing" else None
        os.read(read_end, 1)

    verdict = d.run(work)
    out = sys.stdout

    def emit():
        out.write("RESULT " + str(verdict.outcome.code) + "\\n")

    conclude(gateway, verdict.exit_code, emit=emit, flush=out.flush, record=lambda: None)
    """
)


@pytest.mark.parametrize("state, code", [("idle", "network_error"), ("writing", "outcome_unknown")])
def test_a_worker_blocked_in_a_syscall_cannot_keep_the_process_alive(
    tmp_path: Path, state: str, code: str
) -> None:
    src = str(Path(slack_notice.__file__).resolve().parent.parent)
    env = {
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path),
        "PYTHONPATH": src,
        "PATH": "/usr/bin:/bin",
    }
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", CHILD, state],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=tmp_path,
    )  # the pid Popen captured is the only one this test signals
    try:
        out, err = proc.communicate(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert (proc.returncode, out, err) == (12, f"RESULT {code}\n".encode(), b"")


# --- the signal handler and the output of the CLI -----------------------------------------------


def test_the_output_ignores_write_failures_from_the_move_to_writing_without_committing() -> None:
    gate = cli._SignalGate()  # pyright: ignore[reportPrivateUsage]

    class Broken:
        def write(self, data: bytes, /) -> object:
            raise BrokenPipeError

        def flush(self) -> object:
            return None

    streams = cli.Streams(out=Broken(), err=Broken(), stdin_is_tty=lambda: False)
    output = cli.Output(streams, verbose=False, quiet=False, gate=gate)
    with pytest.raises(BrokenPipeError):
        output.out("x")
    output.writing_began()
    output.out("x")  # ignored from here on
    assert gate.committed is False  # a signal still counts as the deadline
    output.result_printed()
    assert gate.committed is True


def test_the_gate_hook_makes_a_signal_the_deadline_instead_of_an_exit(
    fake_gateway: FakeGateway,
) -> None:
    import signal

    d = make(fake_gateway)
    gate = cli._SignalGate()  # pyright: ignore[reportPrivateUsage]
    with cli._exit_on_signal(gate):  # pyright: ignore[reportPrivateUsage]
        gate.on_signal = d.note_signal
        signal.raise_signal(signal.SIGTERM)
        signal.raise_signal(signal.SIGHUP)  # handled once is the hook's business: idempotent
    assert d.signalled


def test_without_the_hook_a_signal_still_raises(fake_gateway: FakeGateway) -> None:
    import signal

    gate = cli._SignalGate()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(cli._Signalled):  # pyright: ignore[reportPrivateUsage]
        with cli._exit_on_signal(gate):  # pyright: ignore[reportPrivateUsage]
            signal.raise_signal(signal.SIGTERM)


def test_no_thread_is_left_running(fake_gateway: FakeGateway) -> None:
    before = {t for t in threading.enumerate() if t.name == deadline.WORKER_NAME}
    d = make(fake_gateway)
    d.run(lambda _d: outcome_unknown())
    join(d)
    after = {t for t in threading.enumerate() if t.name == deadline.WORKER_NAME}
    assert after == before


def test_retry_enum_is_the_one_the_gate_checks() -> None:
    assert Retry.RATE_LIMIT.value == "rate_limit"

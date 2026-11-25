"""Signals at every phase of the send (issue #27).

The real ``send`` is wired by #28, so ``mimic_send`` runs the pieces it will wire, in the order
of interface steps 5 to 7: ``_exit_on_signal`` with a ``_SignalGate``,
``gate.arm(deadline.note_signal)``, ``spacing.acquire(stop=...)``, ``Deadline.run`` on a real
daemon worker, ``deadline.conclude`` (print and flush, then the log record, then the exit) and
the fake gateway's ``exit_now``. Signals are real (``os.kill`` at this process) and go through
the real handler. Phases before the worker are deterministic (the fake clock moves only in a
sleep); phases inside the worker use real time with a generous bound and are triggered by
events, never by sleeps. Nothing touches a network; the fake secret is built from parts.
"""

# ruff: noqa: F811  (the fixtures are imported from test_spacing and used by name)
from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from slack_notice import __version__, cli
from slack_notice.cli import (  # pyright: ignore[reportPrivateUsage]
    SIGNALS,
    _exit_on_signal,
    _set_disposition,
    _SignalGate,
    _Signalled,
)
from slack_notice.deadline import Deadline, GateState, attempt_work, conclude
from slack_notice.log import build_record, encode_record
from slack_notice.spacing import SendLockTimeout, acquire
from slack_notice.webhook import Outcome, Webhook, unavailable
from tests.fake_gateway import Attempt, FakeGateway, FakeProcessExit, Reply
from tests.harness import assert_valid
from tests.test_spacing import (  # noqa: F401  (fixtures and helpers)
    WALL,
    Lines,
    can_flock,
    gw,
    home,
    lock_path,
    make_lock_file,
    open_fds,
    state,
    warned,
)

CANARY = "CAN" + "ARY" + "_27s"
PATH = "/triggers/" + CANARY + "/seg"
BODY = b'{"text":"hi"}'
ALL = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]
REAL_BOUND = 1.0  # generous: the design is 0.1 s; a loaded CI machine must not make this flaky
SAFETY = 10.0  # a test that waits this long has failed


@dataclass
class Sent:
    """What one mimicked send left behind."""

    code: int | None = None  # the exit code, None when the run never reached the exit
    printed: list[str] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)
    outcome: Outcome | None = None
    signalled_before_5: int | None = None
    verdict_at: float = 0.0
    handlers_after: dict[int, Any] = field(default_factory=dict)


Hook = Callable[[], None]


def mimic_send(
    gateway: FakeGateway,
    state_dir: Any,
    *,
    seconds: float = 30.0,
    before5: Hook | None = None,
    after_arm: Hook | None = None,
    after_acquire: Hook | None = None,
    after_commit: Hook | None = None,
    attempts: tuple[Attempt, ...] = (),
    in_emit: Hook | None = None,
    in_record: Hook | None = None,
    work: Callable[[Deadline], Outcome] | None = None,
) -> Sent:
    """Steps 5 to 7 of a send, as #28 wires them. Returns what was printed and logged."""
    sent = Sent()
    gate = _SignalGate()
    gateway.script(*attempts)
    gateway.allow_unconsumed_script = True
    before_handlers = {s: signal.getsignal(s) for s in SIGNALS}
    try:
        with _exit_on_signal(gate):
            try:
                if before5 is not None:
                    before5()
                # TODO(#28): the real send creates the Deadline at step 3 (it covers the input
                # read); the harness creates it here, later, only for convenience. Arm before
                # acquire (a signal during the lock wait is the deadline, not an exit), and
                # commit when the result print starts (``emit`` below).
                at = gateway.monotonic() + seconds
                deadline = Deadline(gateway, at=at)
                gate.arm(deadline.note_signal)  # step 5 begins
                if after_arm is not None:
                    after_arm()
                gate_writing = False
                try:
                    lock = acquire(state_dir, gateway, at, stop=lambda: deadline.signalled)
                except SendLockTimeout:
                    outcome = unavailable("lock")
                    code = outcome.exit_code
                else:
                    if after_acquire is not None:
                        after_acquire()
                    body_work = work or attempt_work(gateway, Webhook(PATH), BODY, timeout=5.0)
                    verdict = deadline.run(body_work)
                    if lock is not None:
                        lock.release()
                    assert verdict.outcome is not None
                    outcome, code = verdict.outcome, verdict.exit_code
                    gate_writing = verdict.gate_writing
                sent.outcome = outcome
                sent.verdict_at = time.monotonic()

                def emit() -> None:
                    if in_emit is not None:
                        in_emit()
                    gate.commit()
                    if after_commit is not None:
                        after_commit()
                    text = json.dumps(outcome.envelope() if code == 12 else {"outcome": "sent"})
                    sent.printed.append(text)

                def record() -> None:
                    if in_record is not None:
                        in_record()
                    rec = build_record(
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
                        **outcome.log_fields(),
                    )
                    assert rec is not None
                    assert_valid("log", encode_record(rec))
                    sent.records.append(rec)

                conclude(gateway, code, emit=emit, flush=lambda: None, record=record)
            except _Signalled as signalled:
                sent.signalled_before_5 = signalled.number
                sent.code = 128 + signalled.number
    except FakeProcessExit as end:
        sent.code = end.args[0] if end.args else None
    sent.handlers_after = {s: signal.getsignal(s) for s in SIGNALS}
    assert sent.handlers_after == before_handlers  # installed and restored, never leaked
    return sent


def kill(sig: int) -> None:
    os.kill(os.getpid(), sig)


@dataclass
class Killer:
    """Signals this process once ``when`` is set (from a helper thread), records the time."""

    when: threading.Event
    sig: int
    at: float = 0.0
    thread: threading.Thread | None = None

    def start(self) -> Killer:
        def body() -> None:
            if self.when.wait(SAFETY):
                self.at = time.monotonic()
                kill(self.sig)

        self.thread = threading.Thread(target=body, daemon=True)
        self.thread.start()
        return self

    def join(self) -> None:
        assert self.thread is not None
        self.thread.join(SAFETY)
        assert not self.thread.is_alive()


def fds_and_lock(home: Path) -> Callable[[], None]:
    def check() -> None:
        path = lock_path(home)
        assert not path.exists() or can_flock(path)  # the send lock was released

    return check


def assert_one_result(sent: Sent, *, code: str, unknown: bool, outcome: str) -> dict[str, Any]:
    assert sent.code == 12
    assert len(sent.printed) == 1  # printed exactly once
    error = assert_valid("cli/error", sent.printed[0])["error"]
    assert (error["code"], error["unknown_outcome"]) == (code, unknown)
    assert CANARY not in sent.printed[0]
    assert len(sent.records) == 1
    assert sent.records[0]["outcome"] == outcome  # outcome_unknown exactly when unknown_outcome
    assert sent.records[0]["exit"] == 12 and sent.records[0]["code"] == code
    return error


# --- before step 5 ---------------------------------------------------------------------------


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_before_step_5_exits_128_plus_n_with_no_output_and_no_record(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path
) -> None:
    sent = mimic_send(gw, state, before5=lambda: kill(sig))
    assert sent.code == 128 + sig and sent.signalled_before_5 == sig
    assert (sent.printed, sent.records, sent.outcome) == ([], [], None)
    assert gw.exit_codes == []  # no hard exit: main returns the code


def test_two_signals_pending_before_step_5_end_the_run_once_with_the_first_handled(
    gw: FakeGateway, state: Any
) -> None:
    def both() -> None:
        old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGHUP, signal.SIGTERM})
        kill(signal.SIGTERM)
        kill(signal.SIGHUP)
        signal.pthread_sigmask(signal.SIG_SETMASK, old)  # both are delivered now
        time.sleep(0.05)  # reaching a bytecode boundary: the first handler raises

    sent = mimic_send(gw, state, before5=both)
    assert sent.code in (128 + signal.SIGTERM, 128 + signal.SIGHUP)
    assert sent.printed == [] and sent.records == []


def test_the_gate_handler_does_not_raise_a_second_time(gw: FakeGateway) -> None:
    gate = _SignalGate()
    with _exit_on_signal(gate):
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        with pytest.raises(_Signalled):
            handler(signal.SIGTERM, None)
        handler(signal.SIGINT, None)  # already pending when the dispositions changed: ignored
        assert gate.fired == signal.SIGTERM


def test_an_armed_handler_never_raises(gw: FakeGateway) -> None:
    gate = _SignalGate()
    noted: list[int] = []
    gate.arm(lambda: noted.append(1))
    with _exit_on_signal(gate):
        for sig in ALL * 2:
            handler = signal.getsignal(sig)
            assert callable(handler)
            handler(sig, None)  # does not raise, however often it comes
    assert len(noted) == 6


def test_handlers_are_restored_even_when_a_previous_one_was_not_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = signal.signal
    seen: list[tuple[int, Any]] = []

    def fake_signal(number: int, handler: Any) -> Any:
        seen.append((number, handler))
        return real(number, handler)

    monkeypatch.setattr(signal, "signal", fake_signal)
    monkeypatch.setattr(signal, "getsignal", lambda number: None)  # as for a handler from C
    with _exit_on_signal(_SignalGate()):
        pass
    monkeypatch.undo()
    assert [h for _, h in seen[3:]] == [signal.SIG_DFL] * 3


def test_nothing_is_installed_off_the_main_thread() -> None:
    result: list[Any] = []

    def body() -> None:
        before = signal.getsignal(signal.SIGTERM)
        with _exit_on_signal(_SignalGate()):
            result.append(signal.getsignal(signal.SIGTERM) == before)

    t = threading.Thread(target=body)
    t.start()
    t.join(SAFETY)
    assert result == [True]


def test_sigpipe_is_left_as_the_interpreter_set_it() -> None:
    before = signal.getsignal(signal.SIGPIPE)
    with _exit_on_signal(_SignalGate()):
        assert signal.getsignal(signal.SIGPIPE) == before
    assert signal.getsignal(signal.SIGPIPE) == before


# --- step 5: the lock wait and the spacing wait -----------------------------------------------


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_right_after_step_5_begins_is_unavailable_and_sends_nothing(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path
) -> None:
    sent = mimic_send(gw, state, after_arm=lambda: kill(sig))
    error = assert_one_result(sent, code="unavailable", unknown=False, outcome="failed")
    assert error["details"] == {"phase": "lock"}
    assert gw.events.count("https_connection") == 0
    fds_and_lock(home)()


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_during_the_lock_wait_is_unavailable_within_100_ms(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gw.lock_held = True
    original = gw.sleep
    sleeps = 0
    marks: list[float] = []

    def sleep(seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        original(seconds)
        if sleeps == 4:
            marks.append(gw.monotonic())
            kill(sig)

    monkeypatch.setattr(gw, "sleep", sleep)
    before = open_fds(state)
    sent = mimic_send(gw, state)
    error = assert_one_result(sent, code="unavailable", unknown=False, outcome="failed")
    assert error["details"] == {"phase": "lock"}
    assert gw.monotonic() - marks[0] <= 0.1  # fake clock: noticed at the very next poll
    assert sleeps == 4  # nothing slept after the signal
    assert open_fds() == before
    assert gw.events.count("https_connection") == 0


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_during_the_spacing_wait_is_unavailable_within_100_ms(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = make_lock_file(home, size=1, mtime=WALL - 0.05)  # 0.95 s to wait
    original = gw.sleep
    sleeps = 0
    marks: list[float] = []

    def sleep(seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        assert seconds <= 0.1 + 1e-9
        original(seconds)
        if sleeps == 2:
            marks.append(gw.monotonic())
            kill(sig)

    monkeypatch.setattr(gw, "sleep", sleep)
    before = open_fds(state)
    sent = mimic_send(gw, state)
    assert_one_result(sent, code="unavailable", unknown=False, outcome="failed")
    assert gw.monotonic() - marks[0] <= 0.1
    assert sleeps == 2
    assert can_flock(path)
    assert path.stat().st_mtime == pytest.approx(WALL - 0.05, abs=1e-3)  # never stamped
    assert open_fds() == before


# --- the worker phases (real time, event driven) ----------------------------------------------


@pytest.fixture
def release() -> Iterator[threading.Event]:
    event = threading.Event()
    yield event
    event.set()


def worker_phase(
    gw: FakeGateway,
    state: Any,
    sig: int,
    *,
    attempts: tuple[Attempt, ...] = (),
    work: Callable[[Deadline], Outcome] | None = None,
    reached: threading.Event,
) -> tuple[Sent, Killer]:
    killer = Killer(reached, sig).start()
    sent = mimic_send(gw, state, attempts=attempts, work=work)
    killer.join()
    assert sent.verdict_at - killer.at < REAL_BOUND  # noticed within a slice, far below the cap
    return sent, killer


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_during_name_resolution_is_network_error_with_nothing_sent(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path
) -> None:
    reached = gw.stalled  # set while the resolution is blocked
    try:
        sent, _ = worker_phase(
            gw, state, sig, attempts=(Attempt(resolve_stall=True),), reached=reached
        )
    finally:
        gw.release_stalls()
    error = assert_one_result(sent, code="network_error", unknown=False, outcome="failed")
    assert error["details"]["timeout"] is True  # as at the deadline
    assert "post" not in gw.events
    fds_and_lock(home)()


class Blocking:
    """A connection that takes the request, then blocks in the response until released."""

    def __init__(self, release: threading.Event, reached: threading.Event, *, body: bool) -> None:
        self.release, self.reached, self.body = release, reached, body
        self.requests: list[tuple[str, bytes]] = []
        self.closed = False

    def connect(self) -> None: ...

    def settimeout(self, seconds: float) -> None: ...

    def post(self, path: str, body: bytes) -> None:
        self.requests.append((path, body))
        if not self.body:
            return

    def getresponse(self) -> object:
        self.reached.set()
        self.release.wait(SAFETY)
        raise OSError("released")

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_while_the_gate_is_writing_is_outcome_unknown(
    sig: signal.Signals,
    gw: FakeGateway,
    state: Any,
    home: Path,
    release: threading.Event,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached = threading.Event()
    conn = Blocking(release, reached, body=False)
    monkeypatch.setattr(gw, "https_connection", lambda *a, **k: conn)
    sent, _ = worker_phase(gw, state, sig, reached=reached)
    assert_one_result(sent, code="outcome_unknown", unknown=True, outcome="outcome_unknown")
    assert conn.requests == [(PATH, BODY)]  # sent once, never again
    release.set()
    fds_and_lock(home)()


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_during_the_response_read_is_outcome_unknown(
    sig: signal.Signals,
    gw: FakeGateway,
    state: Any,
    home: Path,
    release: threading.Event,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached = threading.Event()

    class Trickle:
        status = 200

        def read(self, amount: int) -> bytes:
            reached.set()
            return b"" if release.wait(0.01) else b"x"

    class Conn(Blocking):
        def getresponse(self) -> object:
            return Trickle()

    conn = Conn(release, reached, body=True)
    monkeypatch.setattr(gw, "https_connection", lambda *a, **k: conn)
    sent, _ = worker_phase(gw, state, sig, reached=reached)
    assert_one_result(sent, code="outcome_unknown", unknown=True, outcome="outcome_unknown")
    release.set()


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_during_a_retry_wait_returns_the_last_result_and_opens_no_connection(
    sig: signal.Signals,
    gw: FakeGateway,
    state: Any,
    home: Path,
    release: threading.Event,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached = threading.Event()

    def long_sleep(seconds: float) -> None:  # the retry wait: one unsliced sleep in the worker
        reached.set()
        release.wait(SAFETY)

    monkeypatch.setattr(gw, "sleep", long_sleep)
    rate = Attempt(reply=Reply(status=429, body=b"{}"))
    sent, _ = worker_phase(gw, state, sig, attempts=(rate, rate), reached=reached)
    error = assert_one_result(sent, code="rate_limited", unknown=False, outcome="failed")
    assert error["retry_after_s"] == 2.0
    release.set()
    deadline_worker = [t for t in threading.enumerate() if t.name == "slack-notice-worker"]
    for t in deadline_worker:
        t.join(SAFETY)
    assert gw.events.count("https_connection") == 1  # the woken worker opened nothing more


# --- the result print and after it ------------------------------------------------------------


@pytest.mark.parametrize("sig", ALL)
def test_signals_while_armed_before_commit_at_the_result_print_leave_one_whole_result(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path
) -> None:
    def two() -> None:
        kill(sig)
        kill(signal.SIGTERM)
        time.sleep(0.02)

    sent = mimic_send(gw, state, attempts=(Attempt(),), in_emit=two)
    assert sent.code == 0
    assert sent.printed == ['{"outcome": "sent"}']  # whole, once
    assert len(sent.records) == 1 and sent.records[0]["outcome"] == "sent"


@pytest.mark.parametrize("sig", ALL)
def test_signals_after_commit_before_the_write_are_ignored(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path
) -> None:
    def two() -> None:
        kill(sig)
        kill(signal.SIGTERM)
        time.sleep(0.02)

    sent = mimic_send(gw, state, attempts=(Attempt(),), after_commit=two)
    assert sent.code == 0
    assert sent.printed == ['{"outcome": "sent"}']  # committed and armed: exit and result unchanged
    assert len(sent.records) == 1 and sent.records[0]["outcome"] == "sent"


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_after_the_result_during_the_log_step_changes_nothing(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path
) -> None:
    def late() -> None:
        kill(sig)
        time.sleep(0.02)

    sent = mimic_send(gw, state, attempts=(Attempt(),), in_record=late)
    assert sent.code == 0 and len(sent.printed) == 1 and len(sent.records) == 1


def test_a_signal_noted_before_a_complete_response_does_not_discard_it(
    gw: FakeGateway, state: Any
) -> None:
    """The slot is looked at first: a final result that is already there wins over the signal."""
    sig = signal.SIGTERM

    def work(deadline: Deadline) -> Outcome:
        out = attempt_work(gw, Webhook(PATH), BODY, timeout=5.0)(deadline)
        kill(sig)  # lands after the worker has its final result, before it is recorded
        time.sleep(0.02)
        return out

    sent = mimic_send(gw, state, attempts=(Attempt(),), work=work)
    assert sent.code == 0 and sent.printed == ['{"outcome": "sent"}']


def test_the_gate_states_are_those_of_the_spec() -> None:
    assert {s.value for s in GateState} == {"idle", "writing", "abandoned"}


# --- round 1 review: restore window, per-signal restore, unraisable hook, remaining phases ------


def test_without_restore_a_noop_handler_stays_so_a_later_signal_changes_nothing() -> None:
    before = {s: signal.getsignal(s) for s in SIGNALS}
    gate = _SignalGate()
    try:
        with _exit_on_signal(gate, restore=False):
            pass
        for sig in SIGNALS:
            handler = signal.getsignal(sig)
            assert callable(handler) and handler != before[sig]
        for sig in ALL:
            kill(sig)  # no KeyboardInterrupt, no death, no raise
        time.sleep(0.02)
        assert gate.fired is None  # the no-op does not touch the gate
    finally:
        for sig, handler in before.items():
            signal.signal(sig, handler)


@pytest.mark.parametrize("argv", [None, ["send"]])
def test_only_the_process_entry_keeps_a_handler_installed(
    argv: list[str] | None, monkeypatch: pytest.MonkeyPatch, gw: FakeGateway
) -> None:
    seen: list[bool] = []
    real = cli._exit_on_signal  # pyright: ignore[reportPrivateUsage]

    def spy(gate: _SignalGate, restore: bool = True) -> Any:
        seen.append(restore)
        return real(gate, restore=True)  # never leave a handler behind in the test run

    monkeypatch.setattr(cli, "_exit_on_signal", spy)
    monkeypatch.setattr(cli, "_main", lambda *a, **k: 0)
    monkeypatch.setattr("sys.argv", ["slack-notice"])
    cli.main(argv, {}, gw)
    assert seen == [argv is not None]


def test_a_signal_mid_install_restores_the_handlers_already_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {s: signal.getsignal(s) for s in SIGNALS}
    real = signal.signal
    calls = 0

    def flaky(number: int, handler: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:  # the second install: a signal arrives, its handler raises
            real(number, handler)
            raise _Signalled(number)
        return real(number, handler)

    monkeypatch.setattr(signal, "signal", flaky)
    with pytest.raises(_Signalled):
        with _exit_on_signal(_SignalGate()):
            pytest.fail("the body must not run")
    monkeypatch.undo()
    assert {s: signal.getsignal(s) for s in SIGNALS} == before


@pytest.mark.parametrize("failing", [0, 1, 2])
def test_every_signal_is_restored_even_when_one_restore_raises(
    failing: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = {s: signal.getsignal(s) for s in SIGNALS}
    real = signal.signal
    restores = 0

    def flaky(number: int, handler: Any) -> Any:
        nonlocal restores
        old = real(number, handler)
        if handler is before[signal.Signals(number)]:  # a restore, not the install
            restores += 1
            if restores - 1 == failing:
                raise _Signalled(number)  # a pending signal's handler raising from the call
        return old

    monkeypatch.setattr(signal, "signal", flaky)
    with pytest.raises(_Signalled):
        with _exit_on_signal(_SignalGate()):
            pass
    monkeypatch.undo()
    assert restores == 3
    assert {s: signal.getsignal(s) for s in SIGNALS} == before


def test_a_signalled_swallowed_by_cleanup_is_not_lost(
    monkeypatch: pytest.MonkeyPatch, gw: FakeGateway
) -> None:
    def swallowing(argv: Any, env: Any, gateway: Any, streams: Any, gate: _SignalGate) -> int:
        try:
            gate.fired = signal.SIGTERM  # the handler ran and raised ...
            raise _Signalled(signal.SIGTERM)
        except BaseException:  # ... and a cleanup converted it
            return 0

    monkeypatch.setattr(cli, "_main", swallowing)
    assert cli.main(["send"], {}, gw) == 128 + signal.SIGTERM


@pytest.mark.parametrize("raises", [False, True])
def test_the_unraisable_hook_is_restored_by_set_disposition(
    raises: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook = sys.unraisablehook
    seen: list[Any] = []

    def fake_signal(number: int, handler: Any) -> Any:
        seen.append(sys.unraisablehook)
        if raises:
            raise OSError("ignored")

    monkeypatch.setattr(signal, "signal", fake_signal)
    _set_disposition(signal.SIGTERM, signal.SIG_DFL)
    monkeypatch.undo()
    assert seen and seen[0] is not hook  # silenced during the call
    assert sys.unraisablehook is hook  # and back after, raise or not


# --- remaining phases of the spec table ------------------------------------------------------


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_after_acquire_before_the_worker_connects_is_network_error_timeout(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path
) -> None:
    sent = mimic_send(gw, state, attempts=(Attempt(),), after_acquire=lambda: kill(sig))
    error = assert_one_result(sent, code="network_error", unknown=False, outcome="failed")
    assert error["details"]["timeout"] is True
    assert "post" not in gw.events
    fds_and_lock(home)()


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_during_a_429_response_body_read_is_outcome_unknown(
    sig: signal.Signals,
    gw: FakeGateway,
    state: Any,
    home: Path,
    release: threading.Event,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached = threading.Event()

    class Trickle:
        status = 429

        def read(self, amount: int) -> bytes:
            reached.set()
            return b"" if release.wait(0.01) else b"x"

    class Conn(Blocking):
        def getresponse(self) -> object:
            return Trickle()

    conn = Conn(release, reached, body=True)
    monkeypatch.setattr(gw, "https_connection", lambda *a, **k: conn)
    sent, _ = worker_phase(gw, state, sig, reached=reached)
    assert_one_result(sent, code="outcome_unknown", unknown=True, outcome="outcome_unknown")
    release.set()


@pytest.mark.parametrize("sig", ALL)
def test_a_signal_during_a_retry_wait_after_a_connection_failure_is_a_retryable_network_error(
    sig: signal.Signals,
    gw: FakeGateway,
    state: Any,
    home: Path,
    release: threading.Event,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached = threading.Event()

    def long_sleep(seconds: float) -> None:
        reached.set()
        release.wait(SAFETY)

    monkeypatch.setattr(gw, "sleep", long_sleep)
    failing = Attempt(connect_error=OSError("refused"))
    sent, _ = worker_phase(gw, state, sig, attempts=(failing, Attempt()), reached=reached)
    error = assert_one_result(sent, code="network_error", unknown=False, outcome="failed")
    assert error["retryable"] is True
    release.set()
    for t in [t for t in threading.enumerate() if t.name == "slack-notice-worker"]:
        t.join(SAFETY)
    assert gw.events.count("https_connection") == 1  # the woken worker opened nothing more

"""Bounded stderr writes, commit before conclude and write state kept on errors (#28, round 1).

Same in-process harness, fake gateway and fake clock as ``test_send.py``. The bounds are real
time (a pipe nobody reads does not care about the fake clock); the tests shrink them.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from typing import Any

import pytest

from slack_notice import cli
from slack_notice.deadline import Deadline, GateState
from slack_notice.gateway import reserve_std_fds
from slack_notice.spacing import SendLock
from tests.fake_gateway import FakeGateway
from tests.send_harness import CANARY, SEND, Sent, go, stdin_json
from tests.test_send import HELLO, OK

STALL = 3.0  # how long a "blocked" write stays blocked (a failing test finishes by itself)
LIMIT = 1.5  # the run must reach exit_now well inside this


class BlockedSink:
    """A stream whose write blocks (a full pipe nobody reads) once ``armed`` is set."""

    def __init__(self, armed: threading.Event | None = None) -> None:
        self.armed = armed
        self.attempts: list[bytes] = []
        self.release = threading.Event()

    def write(self, data: bytes) -> int:
        self.attempts.append(data)
        if self.armed is None or self.armed.is_set():
            self.release.wait(STALL)
        return len(data)

    def flush(self) -> None:
        pass


class ResultSink:
    """stdout: records the result and arms the blocked stderr."""

    def __init__(self, armed: threading.Event) -> None:
        self.armed = armed
        self.data = b""

    def write(self, data: bytes) -> int:
        self.data += data
        self.armed.set()
        return len(data)

    def flush(self) -> None:
        pass


@pytest.fixture(autouse=True)
def short_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "PRINT_BOUND", 0.05)
    monkeypatch.setattr(cli, "SIDE_BOUND", 0.05)


def failing_stamp(fake_gateway: FakeGateway) -> None:
    """The send lock's stamp fails in the worker thread: a deferred state warning."""

    def always(_fd: int, _seconds: float) -> None:
        raise RuntimeError("x")

    fake_gateway.set_mtime = always  # type: ignore[method-assign]


def timed(
    argv: list[str], fake_gateway: FakeGateway, **kwargs: Any
) -> tuple[Sent, float, BlockedSink]:
    sink: BlockedSink = kwargs["err"]
    begin = time.monotonic()
    sent = go(argv, fake_gateway, stdin=HELLO, **kwargs)
    elapsed = time.monotonic() - begin
    sink.release.set()
    return sent, elapsed, sink


# --- R1: a blocked stderr never holds the exit ------------------------------------------------


def test_a_deferred_worker_warning_on_a_blocked_stderr_reaches_exit_now(
    fake_gateway: FakeGateway,
) -> None:
    failing_stamp(fake_gateway)
    fake_gateway.script(OK)
    sent, elapsed, sink = timed(["send", "--json", "--stdin-json"], fake_gateway, err=BlockedSink())
    assert (sent.code, sent.exited) == (0, True)
    assert elapsed < LIMIT
    assert len(sink.attempts) == 1  # the warning, once: the stream is then given up on


def test_verbose_after_the_result_on_a_blocked_stderr_reaches_exit_now(
    fake_gateway: FakeGateway,
) -> None:
    failing_stamp(fake_gateway)
    fake_gateway.script(OK)
    armed = threading.Event()  # blocks only once the result is out: the phase lines get through
    out = ResultSink(armed)
    sent, elapsed, sink = timed(
        ["send", "--json", "--verbose", "--stdin-json"],
        fake_gateway,
        out=out,
        err=BlockedSink(armed),
    )
    assert (sent.code, sent.exited) == (0, True)
    assert elapsed < LIMIT
    # input, render and send lines got through; then ONE write blocked (the warning), and the
    # log phase line was skipped
    assert [a.split(b":")[0] for a in sink.attempts[:3]] == [b"input", b"render", b"send"]
    assert len(sink.attempts) == 4


def test_verbose_before_the_result_on_a_blocked_stderr_reaches_exit_now(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK)
    sent, elapsed, sink = timed(
        ["send", "--json", "--verbose", "--stdin-json"], fake_gateway, err=BlockedSink()
    )
    assert (sent.code, sent.exited) == (0, True)
    assert elapsed < LIMIT
    assert len(sink.attempts) == 1  # the first phase line blocked; every later one was skipped
    assert sent.document["outcome"] == "sent"
    assert len(sent.records) == 1


def test_a_result_still_printing_on_a_blocked_stderr_stops_every_later_stderr_write(
    fake_gateway: FakeGateway,
) -> None:
    failing_stamp(fake_gateway)
    fake_gateway.script(OK)
    sent, elapsed, sink = timed(["send", "--stdin-json"], fake_gateway, err=BlockedSink())
    assert (sent.code, sent.exited) == (0, True)
    assert elapsed < LIMIT
    assert len(sink.attempts) == 1  # the result line only: no warning, no log phase line
    assert len(sent.records) == 1  # the record is still written


# --- R2: the result print is committed before conclude -----------------------------------------


def test_a_signal_while_the_print_thread_runs_never_gives_exit_20_with_an_empty_output(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The signal lands once the print thread runs (before its first write) while the main thread
    waits in the join. Only the commit in ``_conclude`` makes the armed gate ignore it; without
    it the handler records the signal and the print is cut short."""
    real = cli.Output.result_printed
    delivered: list[bool] = []

    def printed(self: cli.Output) -> None:
        if threading.current_thread().name == "slack-notice-print" and not delivered:
            delivered.append(True)
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.02)  # inside the 0.05 print bound; the main thread's join runs the handler
        real(self)

    monkeypatch.setattr(cli.Output, "result_printed", printed)
    sent = go([*SEND], fake_gateway, stdin=stdin_json(title=CANARY))
    assert delivered == [True]
    assert sent.code == 20
    assert sent.out != b"", "exit 20 with an empty output"
    assert sent.error == {
        "code": "refused",
        "reason": "empty_message",
        "message": sent.error["message"],
        "retryable": None,
        "unknown_outcome": None,
        "details": None,
        "retry_after_s": None,
    }, sent.out
    assert sent.stdout.endswith("\n") and sent.stdout.count("\n") == 1


# --- R3: a possible write is never lost -------------------------------------------------------


def test_a_release_that_raises_after_a_200_does_not_replace_the_verdict(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: SendLock) -> None:
        raise RuntimeError("x")

    monkeypatch.setattr(SendLock, "release", boom)
    fake_gateway.script(OK)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.exited) == (0, True)
    assert sent.document["outcome"] == "sent"
    assert [r["outcome"] for r in sent.records] == ["sent"]


def test_a_decide_that_raises_while_writing_is_exit_1_unknown_and_logged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = Deadline.decide

    def decide(self: Deadline, **kwargs: Any) -> Any:
        if self._state is GateState.WRITING:  # pyright: ignore[reportPrivateUsage]
            raise RuntimeError("x")
        return real(self, **kwargs)

    monkeypatch.setattr(Deadline, "decide", decide)
    fake_gateway.script(OK)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.exited) == (1, True)
    assert sent.error["code"] == "internal" and sent.error["unknown_outcome"] is True
    (record,) = sent.records
    assert (record["outcome"], record["exit"]) == ("outcome_unknown", 1)


def test_a_result_builder_that_raises_after_a_200_is_exit_1_unknown_and_logged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("x")

    monkeypatch.setattr(cli, "_sent_result", boom)
    fake_gateway.script(OK)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.exited) == (1, True)
    assert sent.error["code"] == "internal" and sent.error["unknown_outcome"] is True
    (record,) = sent.records
    assert (record["outcome"], record["exit"]) == ("outcome_unknown", 1)


def test_an_exception_before_any_write_still_ends_exit_1_unknown_false_and_unlogged(
    fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("x")

    monkeypatch.setattr(cli, "render", boom)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.exited) == (1, False)
    assert sent.error["unknown_outcome"] is False and sent.records == []


# --- R4: descriptors 0, 1 and 2 are never left free for a socket -------------------------------


def test_reserve_std_fds_reopens_a_closed_descriptor_on_dev_null_and_leaves_open_ones() -> None:
    kept = os.dup(0)
    probe = os.dup(0)  # a free number is whatever this was
    os.close(probe)
    try:
        assert kept != probe
        before = os.fstat(kept)
        reserve_std_fds((probe, kept))
        assert os.fstat(probe).st_rdev == os.stat(os.devnull).st_rdev
        assert os.fstat(kept) == before  # an open descriptor is not touched
    finally:
        for fd in {probe, kept}:
            try:
                os.close(fd)
            except OSError:
                pass

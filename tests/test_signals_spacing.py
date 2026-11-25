"""Signals during the send lock and the spacing wait (issue #27).

``acquire(..., stop=...)``: a stop request (the send passes ``Deadline.signalled``) ends the lock
wait and the spacing wait within 100 ms of fake time, the same way the deadline does
(``SendLockTimeout``), with the lock released, the descriptor closed and nothing stamped. The
clock is the fake gateway's: a sleep advances it and nothing really sleeps, so the bounds are
exact. The fake clock only moves in a sleep, so "noticed within 100 ms" is measured as the fake
time that elapsed between the stop request and the raise.
"""

# ruff: noqa: F811  (the fixtures are imported from test_spacing and used by name)
from __future__ import annotations

import os
import signal
from pathlib import Path
from typing import Any

import pytest

from slack_notice.deadline import Deadline
from slack_notice.spacing import SPACING_S, SendLockTimeout, acquire
from tests.fake_gateway import FakeGateway
from tests.test_spacing import (  # noqa: F401  (fixtures)
    FAR,
    WALL,
    Lines,
    can_flock,
    gw,
    home,
    leaf,
    lock_path,
    make_lock_file,
    open_fds,
    sleeps,
    state,
    warned,
)

BOUND = 0.1  # the interface: a signal is noticed within 100 ms


class Flip:
    """A ``stop`` callback that turns true once ``gw`` has slept ``after`` seconds in total."""

    def __init__(self, gw: FakeGateway, after: float) -> None:
        self.gw = gw
        self.after = after
        self.start = gw.monotonic()
        self.flipped_at: float | None = None
        self.calls = 0

    def __call__(self) -> bool:
        self.calls += 1
        now = self.gw.monotonic()
        if self.flipped_at is None and now - self.start >= self.after:
            self.flipped_at = now
        return self.flipped_at is not None


def test_a_stop_already_requested_ends_the_lock_wait_at_once(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    before = open_fds(state)
    with pytest.raises(SendLockTimeout):
        acquire(state, gw, FAR, stop=lambda: True)
    assert sleeps(gw) == []
    assert open_fds() == before
    assert can_flock(lock_path(home))
    assert not any(e in ("set_mtime", "write_fd") for e in gw.events)


def test_a_stop_during_the_lock_wait_is_noticed_within_100_ms(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    gw.lock_held = True
    before = open_fds(state)
    stop = Flip(gw, after=0.12)
    with pytest.raises(SendLockTimeout):
        acquire(state, gw, FAR, stop=stop)
    assert stop.flipped_at is not None
    assert gw.monotonic() - stop.flipped_at <= BOUND
    assert max(sleeps(gw)) <= 0.05
    assert open_fds() == before
    assert lock_path(home).stat().st_size == 0  # nothing stamped


def test_a_stop_during_the_spacing_wait_is_noticed_within_100_ms(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    path = make_lock_file(home, size=1, mtime=WALL - 0.1)  # 0.9 s to wait
    before = open_fds(state)
    stop = Flip(gw, after=0.25)
    with pytest.raises(SendLockTimeout):
        acquire(state, gw, FAR, stop=stop)
    assert stop.flipped_at is not None
    assert gw.monotonic() - stop.flipped_at <= BOUND
    assert sum(sleeps(gw)) < 0.9  # the wait was cut short
    assert max(sleeps(gw)) <= BOUND + 1e-9  # sliced, never one long sleep
    assert can_flock(path)  # released
    assert open_fds() == before
    assert path.stat().st_mtime == pytest.approx(WALL - 0.1, abs=1e-3)  # not stamped


def test_the_spacing_wait_is_sliced_but_still_waits_the_whole_time(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    make_lock_file(home, size=1, mtime=WALL - 0.1)
    lock = acquire(state, gw, FAR, stop=lambda: False)
    assert lock is not None
    with lock:
        waits = sleeps(gw)
    assert sum(waits) == pytest.approx(SPACING_S - 0.1, abs=1e-6)
    assert max(waits) <= BOUND + 1e-9
    assert len(waits) >= 9


def test_without_a_stop_the_behaviour_is_the_old_one(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    make_lock_file(home, size=1, mtime=WALL - 0.5)
    with acquire(state, gw, FAR) as lock:  # type: ignore[union-attr]
        assert lock is not None
    assert sum(sleeps(gw)) == pytest.approx(0.5, abs=1e-6)


# --- a real signal through the real handler and a real Deadline ---------------------------------


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_real_signal_in_the_spacing_wait_stops_it_within_100_ms(
    sig: signal.Signals, gw: FakeGateway, state: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from slack_notice.cli import _exit_on_signal, _SignalGate  # pyright: ignore[reportPrivateUsage]

    path = make_lock_file(home, size=1, mtime=WALL - 0.1)
    deadline = Deadline(gw, at=gw.monotonic() + 30)
    gate = _SignalGate()
    gate.arm(deadline.note_signal)
    original = gw.sleep
    count = 0
    sent_at: list[float] = []

    def sleep(seconds: float) -> None:
        nonlocal count
        count += 1
        original(seconds)
        if count == 3:
            sent_at.append(gw.monotonic())
            os.kill(os.getpid(), sig)

    monkeypatch.setattr(gw, "sleep", sleep)
    before = open_fds(state)
    with _exit_on_signal(gate):
        with pytest.raises(SendLockTimeout):
            acquire(state, gw, FAR, stop=lambda: deadline.signalled)
    assert deadline.signalled
    assert gw.monotonic() - sent_at[0] <= BOUND
    assert can_flock(path)
    assert open_fds() == before
    assert leaf(home).is_dir()

"""Send lock and 1 s spacing (issue #21).

The clock is the fake gateway's: waits are recorded ``sleep`` events that advance the fake
clock, so nothing here really sleeps except the two small real-process tests. Files are real
files under ``tmp_path``; the file's modification time is set with ``os.utime`` against the
fake wall time, which tests pin where they need an exact boundary.
"""

from __future__ import annotations

import errno
import fcntl
import math
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from slack_notice.log import STATE_WARNING, StateDir, log_result
from slack_notice.spacing import LOCK_NAME, POLL_S, SPACING_S, SendLock, SendLockTimeout, acquire
from tests.fake_gateway import FakeGateway
from tests.harness import ROOT

WALL = 1_700_000_100.0
FAR = 1e9  # a deadline that never matters


class Lines:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "statehome"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def gw(home: Path) -> FakeGateway:
    gateway = FakeGateway(home=str(home))
    gateway.wall_time = lambda: WALL  # type: ignore[method-assign]  # pinned: exact boundaries
    return gateway


@pytest.fixture
def warned() -> Lines:
    return Lines()


@pytest.fixture
def state(gw: FakeGateway, home: Path, warned: Lines) -> Any:
    with StateDir(gw, str(home), warned) as state_dir:
        yield state_dir


def leaf(home: Path) -> Path:
    return home / ".local" / "state" / "slack-notice"


def lock_path(home: Path) -> Path:
    return leaf(home) / LOCK_NAME


def make_lock_file(home: Path, *, size: int, mtime: float) -> Path:
    directory = leaf(home)
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    path = lock_path(home)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.ftruncate(fd, size)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    os.utime(path, ns=(int(mtime * 1e9), int(mtime * 1e9)))
    return path


def sleeps(gw: FakeGateway) -> list[float]:
    return [float(e.split(":", 1)[1]) for e in gw.events if e.startswith("sleep:")]


def open_fds(state: Any = None) -> int:
    """Open descriptors of this process; ``state`` is warmed up first so that its lazily
    opened directory descriptor is not counted as a leak."""
    if state is not None:
        fd = state.open_file("log.lock")
        if fd is not None:
            os.close(fd)
    return len(os.listdir("/proc/self/fd"))


def take(state: Any, gw: FakeGateway, deadline: float) -> SendLock:
    lock = acquire(state, gw, deadline)
    assert lock is not None
    return lock


def can_flock(path: Path) -> bool:
    """True when an independent open file description can take the lock at once."""
    fd = os.open(path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True
    finally:
        os.close(fd)


# --- spacing from the modification time ------------------------------------------------------


def test_constants_are_the_specified_ones() -> None:
    assert SPACING_S == 1.0
    assert POLL_S == 0.05


def test_first_send_with_an_empty_state_directory_has_no_wait(
    gw: FakeGateway, state: Any, home: Path, warned: Lines
) -> None:
    lock = acquire(state, gw, FAR)
    assert lock is not None
    with lock:
        assert sleeps(gw) == []
        assert lock_path(home).stat().st_size == 0
        lock.stamp()
        assert lock_path(home).stat().st_size == 1
        assert lock_path(home).stat().st_mtime == pytest.approx(WALL, abs=1e-3)
    assert warned.lines == []
    assert (lock_path(home).stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize(
    ("age", "expected_wait"),
    [(0.999, 0.001), (1.0, None), (1.001, None), (0.0, 1.0), (0.5, 0.5)],
)
def test_the_one_second_boundary(
    gw: FakeGateway, state: Any, home: Path, age: float, expected_wait: float | None
) -> None:
    make_lock_file(home, size=1, mtime=WALL - age)
    with take(state, gw, FAR) as lock:
        assert lock is not None
        waited = sleeps(gw)
    if expected_wait is None:
        assert waited == []
    else:
        assert len(waited) == 1
        assert waited[0] == pytest.approx(expected_wait, abs=1e-5)


@pytest.mark.parametrize("offset", [0.001, 3600.0, 1e9, 1e12])
def test_a_modification_time_in_the_future_is_ignored(
    gw: FakeGateway, state: Any, home: Path, offset: float
) -> None:
    make_lock_file(home, size=1, mtime=WALL + offset)
    with take(state, gw, FAR) as lock:
        assert lock is not None
    assert sleeps(gw) == []  # never an unbounded (or any) sleep


def test_a_modification_time_before_1970_is_ignored(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    make_lock_file(home, size=1, mtime=-5000.0)
    with take(state, gw, FAR) as lock:
        assert lock is not None
    assert sleeps(gw) == []


def test_a_clock_going_backwards_between_two_sends_does_not_wait(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    with take(state, gw, FAR) as lock:
        assert lock is not None
        lock.stamp()  # stamped at WALL
    gw.wall_time = lambda: WALL - 3600.0  # type: ignore[method-assign]
    with take(state, gw, FAR) as again:
        assert again is not None
    assert sleeps(gw) == []


def test_size_zero_means_no_earlier_send_even_with_a_fresh_mtime(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    path = make_lock_file(home, size=0, mtime=WALL)  # a first send that crashed
    with take(state, gw, FAR) as lock:
        assert lock is not None
        assert sleeps(gw) == []
        lock.stamp()
    assert path.stat().st_size == 1


def test_two_senders_creating_the_file_at_once_second_waits_one_second(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    with StateDir(gw, str(home), warned) as first_state, StateDir(gw, str(home), warned) as other:
        first = acquire(first_state, gw, FAR)
        assert first is not None
        with first:
            first.stamp()
        second = acquire(other, gw, FAR)
        assert second is not None
        with second:
            assert sleeps(gw) == [pytest.approx(1.0)]
            second.stamp()
        assert lock_path(home).stat().st_size == 1


@pytest.mark.parametrize("size", [1, 2, 4096, 5 * 1024 * 1024])
def test_the_content_of_the_file_is_never_read(
    gw: FakeGateway, state: Any, home: Path, size: int
) -> None:
    path = make_lock_file(home, size=size, mtime=WALL - 0.25)
    with open(path, "r+b") as handle:  # garbage, NaN-looking text, a newline: all ignored
        handle.write(b"nan\n-1\n\xff\xfe" + b"9" * 64)
    os.utime(path, ns=(int((WALL - 0.25) * 1e9), int((WALL - 0.25) * 1e9)))  # the write moved it
    with take(state, gw, FAR) as lock:
        assert lock is not None
    assert sleeps(gw) == [pytest.approx(0.75, abs=1e-5)]
    assert "read_at" not in gw.events


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_a_nonfinite_modification_time_is_ignored(
    gw: FakeGateway, state: Any, home: Path, bad: float
) -> None:
    make_lock_file(home, size=1, mtime=WALL)
    gw.file_mtime = lambda fd: bad  # type: ignore[method-assign]
    with take(state, gw, FAR) as lock:
        assert lock is not None
    assert sleeps(gw) == []


def test_a_nonfinite_wall_clock_waits_for_nothing_and_never_blocks_the_send(
    gw: FakeGateway, state: Any, home: Path, warned: Lines
) -> None:
    make_lock_file(home, size=1, mtime=WALL)
    gw.wall_time = lambda: math.nan  # type: ignore[method-assign]
    with take(state, gw, FAR) as lock:
        assert lock is not None
        lock.stamp()  # os.utime refuses NaN: one warning, no exception
    assert sleeps(gw) == []
    assert warned.lines == [STATE_WARNING]


def test_the_stamp_marks_an_existing_file_without_growing_it(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    path = make_lock_file(home, size=1, mtime=WALL - 0.4)
    with take(state, gw, FAR) as lock:
        assert lock is not None
        lock.stamp()
        lock.stamp()  # a second call does nothing
    assert path.stat().st_size == 1
    assert path.stat().st_mtime == pytest.approx(WALL, abs=1e-3)
    assert gw.events.count("set_mtime") == 1


# --- the lock and the deadline ---------------------------------------------------------------


def test_a_held_lock_is_polled_every_50_ms_until_it_is_free(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    gw.lock_held = True
    real_sleep = gw.sleep

    def sleep_then_free(seconds: float) -> None:
        real_sleep(seconds)
        if len(sleeps(gw)) == 3:
            gw.lock_held = False

    gw.sleep = sleep_then_free  # type: ignore[method-assign]
    with take(state, gw, gw.monotonic() + 10) as lock:
        assert lock is not None
    assert sleeps(gw) == [0.05, 0.05, 0.05]
    assert gw.events.count("try_lock") == 4


def test_a_wait_that_outlasts_the_deadline_is_a_lock_timeout(
    gw: FakeGateway, state: Any, home: Path, warned: Lines
) -> None:
    gw.lock_held = True
    before = open_fds(state)
    deadline = gw.monotonic() + 0.2
    with pytest.raises(SendLockTimeout):
        acquire(state, gw, deadline)
    assert gw.monotonic() >= deadline  # it waited the whole deadline, then gave up
    assert sum(sleeps(gw)) <= 0.2 + 1e-3
    assert max(sleeps(gw)) <= 0.05
    assert not any(e == "set_mtime" or e == "write_fd" for e in gw.events)  # nothing stamped
    assert lock_path(home).stat().st_size == 0
    assert open_fds() == before  # the descriptor was closed on the way out
    assert warned.lines == []  # a timeout is not a state problem


@pytest.mark.parametrize("deadline", [math.nan, -math.inf, 0.0])
def test_a_deadline_already_past_or_nan_fails_at_once_and_never_loops(
    gw: FakeGateway, state: Any, deadline: float
) -> None:
    gw.lock_held = True
    with pytest.raises(SendLockTimeout):
        acquire(state, gw, deadline)
    assert sleeps(gw) == []
    assert gw.events.count("try_lock") == 1


def test_a_free_lock_is_taken_even_when_the_deadline_is_past_if_no_wait_is_needed(
    gw: FakeGateway, state: Any
) -> None:
    with take(state, gw, 0.0) as lock:
        assert lock is not None


def test_the_spacing_wait_respects_the_deadline(gw: FakeGateway, state: Any, home: Path) -> None:
    make_lock_file(home, size=1, mtime=WALL - 0.2)  # 0.8 s still to wait
    path = lock_path(home)
    deadline = gw.monotonic() + 0.3
    before = open_fds(state)
    with pytest.raises(SendLockTimeout):
        acquire(state, gw, deadline)
    assert sleeps(gw) == []  # a wait longer than the time that remains ends the send at once
    assert gw.monotonic() < deadline
    assert can_flock(path)  # released
    assert open_fds() == before
    assert path.stat().st_mtime == pytest.approx(WALL - 0.2, abs=1e-3)  # not stamped


def test_a_spacing_wait_equal_to_the_time_remaining_also_ends_at_once(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    path = make_lock_file(home, size=1, mtime=WALL - 0.2)
    exact_wait = SPACING_S - (WALL - path.stat().st_mtime_ns / 1e9)  # as the code computes it
    gw.monotonic = lambda: 100.0  # type: ignore[method-assign]
    with pytest.raises(SendLockTimeout):
        acquire(state, gw, 100.0 + exact_wait)
    assert sleeps(gw) == []


def test_the_size_and_time_are_read_after_the_lock_is_taken(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    """Another process stamps the file while this one waits on a busy flock: the wait must come
    from the file as it is once the lock is held. A real two-process 1 s test is not added (slow
    and flaky); this fake holder is deterministic."""
    make_lock_file(home, size=0, mtime=WALL - 5)  # empty before the lock is taken
    calls = {"n": 0}
    real_try_lock = gw.try_lock

    def try_lock(fd: int) -> bool:
        calls["n"] += 1
        if calls["n"] == 1:
            make_lock_file(home, size=1, mtime=WALL - 0.25)  # the "other process" stamps
            return False
        return real_try_lock(fd)

    gw.try_lock = try_lock  # type: ignore[method-assign]
    with take(state, gw, FAR) as lock:
        assert lock is not None
    assert sleeps(gw) == [POLL_S, pytest.approx(0.75, abs=1e-5)]


def test_a_failed_set_mtime_leaves_the_write_time_and_the_next_send_waits_a_second(
    gw: FakeGateway, state: Any, home: Path, warned: Lines
) -> None:
    gw.set_mtime_error = OSError(errno.EPERM, "x")
    with take(state, gw, FAR) as first:
        first.stamp()  # the byte is written, the utime fails: one warning
    assert warned.lines == [STATE_WARNING]
    gw.set_mtime_error = None
    nanos = int((WALL - 0.003) * 1e9)
    os.utime(lock_path(home), ns=(nanos, nanos))  # as the write: ~now
    with take(state, gw, FAR) as second:
        assert second is not None
    assert sleeps(gw) == [pytest.approx(0.997, abs=1e-5)]
    assert warned.lines == [STATE_WARNING]


def test_a_failure_right_after_the_open_closes_the_descriptor(
    gw: FakeGateway, state: Any, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import slack_notice.spacing as spacing

    def broken(*_args: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(spacing, "SendLock", broken)
    before = open_fds(state)
    with pytest.raises(KeyboardInterrupt):
        acquire(state, gw, FAR)
    assert open_fds() == before


def test_the_spacing_wait_that_ends_before_the_deadline_proceeds(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    make_lock_file(home, size=1, mtime=WALL - 0.2)
    with take(state, gw, gw.monotonic() + 5) as lock:
        assert lock is not None
    assert sleeps(gw) == [pytest.approx(0.8, abs=1e-5)]


# --- release on every path and descriptor hygiene -------------------------------------------


@pytest.mark.parametrize("error", [RuntimeError("x"), KeyboardInterrupt(), SystemExit(3)])
def test_the_lock_is_released_when_the_body_raises(
    gw: FakeGateway, state: Any, home: Path, error: BaseException
) -> None:
    before = open_fds(state)
    with pytest.raises(type(error)):
        with take(state, gw, FAR) as lock:
            assert lock is not None
            lock.stamp()
            raise error
    assert can_flock(lock_path(home))
    assert open_fds() == before


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(2), RuntimeError("x")])
def test_a_signal_style_exception_during_the_lock_wait_releases_and_propagates(
    gw: FakeGateway, state: Any, home: Path, error: BaseException
) -> None:
    gw.lock_held = True

    def interrupted(seconds: float) -> None:
        raise error

    gw.sleep = interrupted  # type: ignore[method-assign]
    before = open_fds(state)
    with pytest.raises(type(error)):
        acquire(state, gw, FAR)
    assert open_fds() == before
    assert can_flock(lock_path(home))


def test_an_exception_during_the_spacing_wait_releases_the_lock(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    make_lock_file(home, size=1, mtime=WALL)

    def interrupted(seconds: float) -> None:
        raise KeyboardInterrupt

    gw.sleep = interrupted  # type: ignore[method-assign]
    before = open_fds(state)
    with pytest.raises(KeyboardInterrupt):
        acquire(state, gw, FAR)
    assert open_fds() == before
    assert can_flock(lock_path(home))


def test_release_is_idempotent_and_stamp_after_release_does_nothing(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    lock = acquire(state, gw, FAR)
    assert lock is not None
    lock.release()
    lock.release()
    lock.stamp()
    assert gw.events.count("unlock") == 1
    assert "write_fd" not in gw.events
    assert lock_path(home).stat().st_size == 0


def test_the_lock_is_released_before_the_log_record(
    gw: FakeGateway, state: Any, home: Path
) -> None:
    with take(state, gw, FAR) as lock:
        assert lock is not None
        lock.stamp()
    written = log_result(
        state,
        gw,
        enabled=True,
        version="1.2.3",
        exit_code=0,
        code=None,
        reason=None,
        unknown_outcome=False,
        gate_writing=False,
        level="info",
        bytes_=1,
        truncated=False,
        duration_ms=1,
        http_status=200,
        message_hash="0123456789abcdef",
        dedupe_hash=None,
        actor="auto:unknown",
        actor_source="default",
    )
    assert written
    events = gw.events
    assert events.index("unlock") < events.index("open_state_file:log.lock")
    assert events.count("open_state_dir") == 1  # one StateDir handle for both


# --- state problems never block a send ------------------------------------------------------


def _hostile(kind: str, home: Path, tmp_path: Path) -> None:
    directory = leaf(home)
    directory.mkdir(parents=True, mode=0o700)
    path = directory / LOCK_NAME
    if kind == "symlink":
        target = tmp_path / "elsewhere"
        target.write_bytes(b"")
        path.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "hardlink":
        other = tmp_path / "other"
        other.write_bytes(b"")
        os.chmod(other, 0o600)
        os.link(other, path)
    elif kind == "mode":
        path.write_bytes(b"")
        os.chmod(path, 0o666)
    elif kind == "directory":
        path.mkdir()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink", "mode", "directory"])
def test_a_hostile_lock_file_means_no_spacing_one_warning_no_exception(
    gw: FakeGateway, state: Any, home: Path, tmp_path: Path, warned: Lines, kind: str
) -> None:
    _hostile(kind, home, tmp_path)
    before = open_fds(state)
    assert acquire(state, gw, FAR) is None
    assert acquire(state, gw, FAR) is None  # still one warning for the whole run
    assert warned.lines == [STATE_WARNING]
    assert sleeps(gw) == []
    assert open_fds() == before
    if kind == "symlink":
        assert (tmp_path / "elsewhere").read_bytes() == b""  # nothing written through the link


def test_a_bad_send_lock_does_not_poison_the_log_lock(
    gw: FakeGateway, state: Any, home: Path, tmp_path: Path
) -> None:
    _hostile(tmp_path=tmp_path, home=home, kind="fifo")
    assert acquire(state, gw, FAR) is None
    fd = state.open_file("log.lock")
    assert fd is not None
    gw.close_fd(fd)


def test_an_unusable_state_directory_means_no_spacing(
    gw: FakeGateway, state: Any, warned: Lines
) -> None:
    from slack_notice.gateway import StateUnusable

    gw.state_dir_error = StateUnusable("mode")
    assert acquire(state, gw, FAR) is None
    assert warned.lines == [STATE_WARNING]
    assert sleeps(gw) == []


def test_a_closed_state_dir_means_no_spacing(gw: FakeGateway, state: Any) -> None:
    state.close()
    assert acquire(state, gw, FAR) is None


@pytest.mark.parametrize("number", [errno.ENOLCK, errno.EIO, errno.EBADF])
def test_a_lock_call_that_fails_means_no_spacing_and_no_leak(
    gw: FakeGateway, state: Any, warned: Lines, number: int
) -> None:
    gw.lock_error = OSError(number, "x")
    before = open_fds(state)
    assert acquire(state, gw, FAR) is None
    assert warned.lines == [STATE_WARNING]
    assert open_fds() == before


@pytest.mark.parametrize("number", [errno.ENOSPC, errno.EROFS, errno.EDQUOT, errno.EIO])
def test_a_failed_stamp_write_warns_once_and_never_raises(
    gw: FakeGateway, state: Any, home: Path, warned: Lines, number: int
) -> None:
    gw.write_error = OSError(number, "x")
    with take(state, gw, FAR) as lock:
        assert lock is not None
        lock.stamp()
    assert warned.lines == [STATE_WARNING]
    assert lock_path(home).stat().st_size == 0
    assert can_flock(lock_path(home))


def test_a_short_stamp_write_counts_as_a_failure(
    gw: FakeGateway, state: Any, home: Path, warned: Lines
) -> None:
    gw.write_limit = 0
    with take(state, gw, FAR) as lock:
        assert lock is not None
        lock.stamp()
    assert warned.lines == [STATE_WARNING]


@pytest.mark.parametrize("number", [errno.EROFS, errno.EPERM])
def test_a_failed_utime_warns_once_and_never_raises(
    gw: FakeGateway, state: Any, warned: Lines, number: int
) -> None:
    gw.set_mtime_error = OSError(number, "x")
    with take(state, gw, FAR) as lock:
        assert lock is not None
        lock.stamp()
    assert warned.lines == [STATE_WARNING]


@pytest.mark.parametrize("which", ["file_size", "file_mtime"])
def test_an_unreadable_spacing_state_skips_the_wait_but_keeps_the_lock(
    gw: FakeGateway, state: Any, home: Path, warned: Lines, which: str
) -> None:
    make_lock_file(home, size=1, mtime=WALL)

    def broken(*_args: Any) -> Any:
        raise OSError(errno.EIO, "x")

    setattr(gw, which, broken)
    with take(state, gw, FAR) as lock:
        assert lock is not None
        assert not can_flock(lock_path(home))  # still serialized
    assert sleeps(gw) == []
    assert warned.lines == [STATE_WARNING]


def test_no_input_text_in_the_warning_or_the_exception(
    gw: FakeGateway, state: Any, home: Path, warned: Lines
) -> None:
    canary = "ca" + "nary-" + "5d27"
    gw.write_error = OSError(errno.ENOSPC, canary)
    with take(state, gw, FAR) as lock:
        assert lock is not None
        lock.stamp()
    assert canary not in "".join(warned.lines)
    gw.lock_held = True
    with pytest.raises(SendLockTimeout) as caught:
        acquire(state, gw, gw.monotonic() + 0.1)
    assert canary not in str(caught.value) + repr(caught.value)


# --- real processes ----------------------------------------------------------------------------


def _child_env(tmp_path: Path) -> dict[str, str]:
    private = tmp_path / "private"
    private.mkdir(exist_ok=True)
    return {
        "HOME": str(private),
        "XDG_CONFIG_HOME": str(private / "c"),
        "XDG_STATE_HOME": str(private / "s"),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(ROOT / "src"),
    }


def _spawn(tmp_path: Path, *args: str) -> subprocess.Popen[bytes]:
    child = Path(__file__).resolve().parent / "send_lock_child.py"
    return subprocess.Popen(
        [sys.executable, "-I", str(child), *args],
        env=_child_env(tmp_path),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def test_a_lock_held_by_another_process_times_out_then_is_taken_after_it_exits(
    tmp_path: Path, home: Path, warned: Lines
) -> None:
    ready, release = tmp_path / "ready", tmp_path / "release"
    child = _spawn(tmp_path, "hold", str(home), str(ready), str(release))
    try:
        for _ in range(2000):  # bounded: at most about 10 s
            if ready.exists() or child.poll() is not None:
                break
            time.sleep(0.005)
        assert ready.exists(), "the child never took the lock"
        gateway = FakeGateway(home=str(home))  # fake clock: polling costs no real time
        with StateDir(gateway, str(home), warned) as state:
            with pytest.raises(SendLockTimeout):
                acquire(state, gateway, gateway.monotonic() + 0.5)
            assert len(sleeps(gateway)) >= 9
            release.write_text("go")
            assert child.wait(timeout=30) == 0
            with take(state, gateway, gateway.monotonic() + 5) as lock:
                assert lock is not None
    finally:
        if child.poll() is None:  # only the handle this test started
            child.kill()
            child.wait(timeout=10)
    assert warned.lines == []


def test_two_processes_are_never_inside_the_critical_section_together(
    tmp_path: Path, home: Path
) -> None:
    marker = tmp_path / "inside"
    children = [_spawn(tmp_path, "section", str(home), str(marker), "4") for _ in range(2)]
    try:
        codes = [c.wait(timeout=60) for c in children]
    finally:
        for c in children:  # only the handles this test started
            if c.poll() is None:
                c.kill()
                c.wait(timeout=10)
    assert codes == [0, 0]
    assert not marker.exists()

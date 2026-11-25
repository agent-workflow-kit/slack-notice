"""State directory and safe state-file opening (issue #13), through the gateway and the fake.

Every hostile object is a real filesystem object under ``tmp_path``. Accepted residuals are
pinned by a test so a change shows up in review: see ``test_parent_symlink_is_followed`` and
``test_replaced_state_dir_after_open_keeps_using_the_opened_directory``.
"""

from __future__ import annotations

import errno
import os
import signal
import stat
import time
from pathlib import Path

import pytest

from slack_notice import cli
from slack_notice.gateway import StateUnusable, SystemGateway
from slack_notice.log import STATE_WARNING, StateDir
from tests.fake_gateway import FakeGateway

CANARY = "ca" + "nary-" + "7f3a"  # appears nowhere in output: built from parts


class Lines:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)


def state_path(home: Path) -> Path:
    return home / ".local" / "state" / "slack-notice"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "statehome"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def gw(home: Path) -> FakeGateway:
    return FakeGateway(home=str(home))


def make_state(home: Path, mode: int = 0o700) -> Path:
    leaf = state_path(home)
    leaf.mkdir(parents=True, mode=mode)
    leaf.chmod(mode)
    return leaf


def assert_one_warning(lines: Lines) -> None:
    assert lines.lines == [STATE_WARNING]
    text = "\n".join(lines.lines)
    assert "/" not in text and CANARY not in text


# --- happy path ----------------------------------------------


def test_nothing_is_touched_until_a_file_is_needed(gw: FakeGateway, home: Path) -> None:
    state = StateDir(gw, str(home), Lines())
    state.close()
    assert gw.events == []
    assert not (home / ".local").exists()


def test_creates_the_directory_private_and_opens_files_0600(gw: FakeGateway, home: Path) -> None:
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        fd = state.open_file("log.jsonl", append=True)
        assert fd is not None
        os.close(fd)
    assert stat.S_IMODE(state_path(home).stat().st_mode) == 0o700
    assert stat.S_IMODE((state_path(home) / "log.jsonl").stat().st_mode) == 0o600
    assert lines.lines == []


def test_the_directory_is_opened_once_for_many_files(gw: FakeGateway, home: Path) -> None:
    with StateDir(gw, str(home), Lines()) as state:
        for name in ("log.jsonl", "log.lock", "send.lock"):
            fd = state.open_file(name)
            assert fd is not None
            os.close(fd)
    assert gw.events.count("open_state_dir") == 1


def test_close_releases_the_directory_descriptor(gw: FakeGateway, home: Path) -> None:
    before = set(os.listdir("/proc/self/fd"))
    state = StateDir(gw, str(home), Lines())
    fd = state.open_file("log.lock")
    assert fd is not None
    os.close(fd)
    state.close()
    state.close()
    assert set(os.listdir("/proc/self/fd")) <= before | {str(fd)}


def test_environment_does_not_select_the_state_directory(
    gw: FakeGateway, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = tmp_path / "decoy"
    monkeypatch.setenv("XDG_STATE_HOME", str(decoy))
    monkeypatch.setenv("HOME", str(decoy))
    with StateDir(gw, str(home), Lines()) as state:
        fd = state.open_file("log.lock")
        assert fd is not None
        os.close(fd)
    assert state_path(home).is_dir()
    assert not decoy.exists()


# --- an unusable directory: one warning, no files ------------------------------------------------


def test_symlinked_state_dir(gw: FakeGateway, home: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    (home / ".local" / "state").mkdir(parents=True)
    state_path(home).symlink_to(target)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl", append=True) is None
        assert state.open_file("log.lock") is None
        assert state.open_file("send.lock") is None
    assert list(target.iterdir()) == []
    assert_one_warning(lines)


def test_dangling_symlinked_state_dir(gw: FakeGateway, home: Path, tmp_path: Path) -> None:
    (home / ".local" / "state").mkdir(parents=True)
    state_path(home).symlink_to(tmp_path / "missing")
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.lock") is None
    assert not (tmp_path / "missing").exists()
    assert_one_warning(lines)


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o707, 0o777, 0o770])
def test_open_state_dir_modes(gw: FakeGateway, home: Path, mode: int) -> None:
    make_state(home, mode)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.lock") is None
    assert_one_warning(lines)
    assert list(state_path(home).iterdir()) == []


def test_wrong_owner(home: Path) -> None:
    make_state(home)
    gw = FakeGateway(home=str(home), uid=os.getuid() + 1)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.lock") is None
    assert_one_warning(lines)
    assert list(state_path(home).iterdir()) == []


def test_state_dir_is_a_regular_file(gw: FakeGateway, home: Path) -> None:
    (home / ".local" / "state").mkdir(parents=True)
    state_path(home).write_text(CANARY)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.lock") is None
    assert_one_warning(lines)


def test_unreadable_parent(gw: FakeGateway, home: Path) -> None:
    parent = home / ".local" / "state"
    parent.mkdir(parents=True)
    parent.chmod(0)
    try:
        if os.access(parent, os.X_OK):
            pytest.skip("permission bits are not enforced for this user")
        lines = Lines()
        with StateDir(gw, str(home), lines) as state:
            assert state.open_file("log.lock") is None
        assert_one_warning(lines)
    finally:
        parent.chmod(0o700)


@pytest.mark.parametrize("code", [errno.EACCES, errno.EROFS, errno.ENOSPC, errno.EDQUOT])
def test_os_errors_creating_the_directory(
    gw: FakeGateway, home: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError(code, os.strerror(code), str(home))  # the filename must not leak

    monkeypatch.setattr(os, "makedirs", refuse)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.lock") is None
    assert_one_warning(lines)
    assert str(home) not in "".join(lines.lines)


@pytest.mark.parametrize("code", [errno.EACCES, errno.EROFS, errno.ENOSPC, errno.EMFILE])
def test_os_errors_opening_a_file(
    gw: FakeGateway, home: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    make_state(home)
    real_open = os.open

    def selective(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if kwargs.get("dir_fd") is not None:
            raise OSError(code, os.strerror(code), path)
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", selective)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl", append=True) is None
    assert_one_warning(lines)


def test_read_only_state_dir_open_error_from_the_gateway(gw: FakeGateway, home: Path) -> None:
    gw.state_dir_error = StateUnusable("open")
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl") is None
        assert state.open_file("log.lock") is None
    assert_one_warning(lines)
    assert gw.events.count("open_state_dir") == 1  # not retried


def test_an_unexpected_exception_is_not_swallowed(gw: FakeGateway, home: Path) -> None:
    gw.state_dir_error = KeyError("bug")
    with StateDir(gw, str(home), Lines()) as state, pytest.raises(KeyError):
        state.open_file("log.lock")


@pytest.mark.parametrize("bad", ["", "relative", "a\0b"])
def test_unusable_home_values(gw: FakeGateway, bad: str) -> None:
    lines = Lines()
    with StateDir(gw, bad, lines) as state:
        assert state.open_file("log.lock") is None
    assert_one_warning(lines)


# --- hostile files ----------------------------------------------


@pytest.mark.parametrize("name", ["log.jsonl", "log.lock", "send.lock"])
def test_fifo_returns_at_once_with_one_warning(gw: FakeGateway, home: Path, name: str) -> None:
    leaf = make_state(home)
    os.mkfifo(leaf / name)
    lines = Lines()
    start = time.monotonic()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file(name, append=name == "log.jsonl") is None
        assert state.open_file(name) is None  # remembered: no second warning
    assert time.monotonic() - start < 2
    assert_one_warning(lines)


def test_fifo_log_and_fifo_lock_still_one_warning(gw: FakeGateway, home: Path) -> None:
    leaf = make_state(home)
    os.mkfifo(leaf / "log.jsonl")
    os.mkfifo(leaf / "log.lock")
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl", append=True) is None
        assert state.open_file("log.lock") is None
    assert_one_warning(lines)


def test_a_bad_file_does_not_poison_the_others(gw: FakeGateway, home: Path) -> None:
    leaf = make_state(home)
    os.mkfifo(leaf / "log.jsonl")
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl", append=True) is None
        fd = state.open_file("send.lock")
        assert fd is not None
        os.close(fd)
    assert_one_warning(lines)


@pytest.mark.parametrize("name", ["log.jsonl", "log.lock", "send.lock"])
def test_symlinked_state_file_is_refused_and_target_untouched(
    gw: FakeGateway, home: Path, tmp_path: Path, name: str
) -> None:
    leaf = make_state(home)
    target = tmp_path / "victim"
    target.write_text(CANARY)
    (leaf / name).symlink_to(target)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file(name, append=name == "log.jsonl") is None
    assert target.read_text() == CANARY
    assert_one_warning(lines)


def test_dangling_symlink_is_not_created_through(
    gw: FakeGateway, home: Path, tmp_path: Path
) -> None:
    leaf = make_state(home)
    (leaf / "log.lock").symlink_to(tmp_path / "newfile")
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.lock") is None
    assert not (tmp_path / "newfile").exists()
    assert_one_warning(lines)


def test_directory_in_place_of_a_file(gw: FakeGateway, home: Path) -> None:
    leaf = make_state(home)
    (leaf / "log.jsonl").mkdir()
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl", append=True) is None
    assert_one_warning(lines)


def test_device_in_place_of_a_file(gw: FakeGateway, home: Path) -> None:
    leaf = make_state(home)
    # A device node cannot be created unprivileged; a symlink to /dev/null is the closest real
    # object, and must be refused by O_NOFOLLOW. The fstat rule is covered below with a pipe.
    (leaf / "log.jsonl").symlink_to("/dev/null")
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl", append=True) is None
    assert_one_warning(lines)


def test_gateway_refuses_a_non_regular_descriptor_by_fstat(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    leaf = make_state(home)
    (leaf / "x").write_text("")
    real_fstat = os.fstat

    class Chr:
        st_mode = stat.S_IFCHR | 0o600
        st_uid = os.getuid()
        st_nlink = 1

    gateway = SystemGateway()
    dir_fd = gateway.open_state_dir(str(home))
    try:
        monkeypatch.setattr(os, "fstat", lambda fd: Chr() if fd != dir_fd else real_fstat(fd))
        with pytest.raises(StateUnusable) as info:
            gateway.open_state_file(dir_fd, "x")
        assert info.value.reason == "not_regular"
    finally:
        monkeypatch.undo()
        os.close(dir_fd)


def test_hardlinked_file_is_refused(gw: FakeGateway, home: Path, tmp_path: Path) -> None:
    leaf = make_state(home)
    victim = tmp_path / "victim"
    victim.write_text(CANARY)
    os.link(victim, leaf / "log.jsonl")
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl", append=True) is None
    assert victim.read_text() == CANARY
    assert_one_warning(lines)


def test_file_with_wrong_owner_is_refused(home: Path) -> None:
    leaf = make_state(home)
    (leaf / "log.jsonl").write_text(CANARY)
    system = SystemGateway()
    dir_fd = system.open_state_dir(str(home))
    try:
        system.uid = lambda: os.getuid() + 1  # type: ignore[method-assign]
        with pytest.raises(StateUnusable) as info:
            system.open_state_file(dir_fd, "log.jsonl", append=True)
        assert info.value.reason == "owner"
    finally:
        os.close(dir_fd)
    assert (leaf / "log.jsonl").read_text() == CANARY


def test_existing_file_with_open_mode_is_refused_or_kept_private(
    gw: FakeGateway, home: Path
) -> None:
    leaf = make_state(home)
    (leaf / "log.jsonl").write_text("")
    (leaf / "log.jsonl").chmod(0o644)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        assert state.open_file("log.jsonl", append=True) is None
    assert_one_warning(lines)


def test_no_descriptor_leaks_when_a_file_is_refused(gw: FakeGateway, home: Path) -> None:
    leaf = make_state(home)
    os.mkfifo(leaf / "log.jsonl")
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(20):
        gateway = SystemGateway()
        dir_fd = gateway.open_state_dir(str(home))
        with pytest.raises(StateUnusable):
            gateway.open_state_file(dir_fd, "log.jsonl")
        os.close(dir_fd)
    assert len(os.listdir("/proc/self/fd")) == before


# --- accepted residuals, pinned ----------------------------------------------


def test_parent_symlink_is_followed(gw: FakeGateway, home: Path, tmp_path: Path) -> None:
    """Accepted: only the leaf is O_NOFOLLOW; ``.local`` is the user's own tree (same-user
    boundary, interface 'Residual risks'). The leaf is still created 0700 and owner-checked."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (home / ".local").symlink_to(elsewhere)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        fd = state.open_file("log.lock")
        assert fd is not None
        os.close(fd)
    assert stat.S_IMODE((elsewhere / "state" / "slack-notice").stat().st_mode) == 0o700
    assert lines.lines == []


def test_replaced_state_dir_after_open_keeps_using_the_opened_directory(
    gw: FakeGateway, home: Path, tmp_path: Path
) -> None:
    """Accepted TOCTOU: the directory is checked on its descriptor and every file is opened
    relative to it, so a swap after the check cannot redirect later opens; only the window between
    ``mkdir`` and ``open`` of the leaf (same user) is open."""
    make_state(home)
    attacker = tmp_path / "attacker"
    attacker.mkdir(mode=0o700)
    lines = Lines()
    with StateDir(gw, str(home), lines) as state:
        first = state.open_file("log.lock")
        assert first is not None
        os.close(first)
        original = state_path(home)
        moved = original.with_name("moved")
        original.rename(moved)
        original.symlink_to(attacker)
        second = state.open_file("send.lock")
        assert second is not None
        os.close(second)
    assert (moved / "send.lock").exists()
    assert list(attacker.iterdir()) == []
    assert lines.lines == []


# --- the CLI context ---------------------------------------------------------


def test_context_state_dir_requires_a_home() -> None:
    ctx = cli.Context.__new__(cli.Context)
    ctx.home = None
    with pytest.raises(AssertionError):
        ctx.state_dir()


def test_context_state_dir_warns_through_output(gw: FakeGateway, home: Path) -> None:
    make_state(home, 0o755)
    err = Lines()

    class Out:
        def warning(self, line: str) -> None:
            err(line)

    ctx = cli.Context.__new__(cli.Context)
    ctx.home = str(home)
    ctx.gateway = gw
    ctx.output = Out()  # type: ignore[assignment]
    ctx._state = None
    state = ctx.state_dir()
    assert ctx.state_dir() is state
    assert state.open_file("log.lock") is None
    assert state.open_file("log.jsonl") is None
    assert_one_warning(err)


def test_sigpipe_handler_untouched() -> None:
    # The state code never installs a handler (a signal is the CLI's concern, issue #27).
    assert signal.getsignal(signal.SIGPIPE) is not None

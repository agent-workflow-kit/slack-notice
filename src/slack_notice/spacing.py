"""Send lock and 1 s spacing (interface, "Send spacing").

``acquire`` opens ``send.lock`` through the shared ``StateDir`` and takes an exclusive flock,
polled without blocking every 50 ms inside the deadline. A file of size 0 means no earlier
send; otherwise the call waits until one second has passed since the file's modification time,
ignoring a modification time in the future or more than one second old (so a clock that went
backwards never causes a wait, and no wait exceeds one second). A spacing wait that is not
shorter than the time left to the deadline ends the send at once (``SendLockTimeout``) without
sleeping. The file's content is never
read. ``SendLock.stamp`` writes one byte to a file of size 0 and sets the modification time to
the gateway's wall time when the POST is about to start; ``release`` ends the lock at the end
of step 6, before the log record.

State problems never block or fail a send: an unusable file, a failing lock call or a failing
stamp gives the one fixed warning of the run (``StateDir.warn``) and the send goes on, without
spacing where the lock could not be taken. Only the deadline raises (``SendLockTimeout``, which
the send command reports as exit 12 ``unavailable`` with ``details.phase`` ``lock``). Any
other ``BaseException`` (a signal handler's, ``KeyboardInterrupt``) propagates after the lock
and the descriptor were released. No text from the file or the filesystem is kept.

TODO(#25): the deadline is passed in as an absolute ``gateway.monotonic()`` value; the gate
and the signal handling (a signal during the lock wait is handled as the deadline) are #25 and
#27.
TODO(#28): the send command maps ``SendLockTimeout`` to the exit 12 envelope and a ``failed``
log record, calls ``stamp`` just before the POST and ``release`` after step 6.
"""

from __future__ import annotations

from types import TracebackType

from slack_notice.gateway import Gateway
from slack_notice.log import StateDir

LOCK_NAME = "send.lock"
SPACING_S = 1.0
POLL_S = 0.05


class SendLockTimeout(Exception):  # noqa: N818  (a deadline outcome, not an error class)
    """The deadline passed while waiting for the lock or for the spacing. Nothing was sent."""


class SendLock:
    """A held send lock; use as a context manager or call ``release``."""

    def __init__(self, state: StateDir, gateway: Gateway, fd: int) -> None:
        self._state = state
        self._gateway = gateway
        self._fd: int | None = fd
        self._locked = False
        self._stamped = False

    def mark_locked(self) -> None:
        """Record that the flock is held, so ``release`` unlocks it."""
        self._locked = True

    def __enter__(self) -> SendLock:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()

    def stamp(self) -> None:
        """Mark this send's start: one byte into an empty file, then the modification time.

        Once per lock; nothing after ``release``. A failure (``ENOSPC``, ``EROFS``, ...) is the
        one warning and never an exception: the send goes on.
        """
        if self._fd is None or self._stamped:
            return
        self._stamped = True
        gateway, fd = self._gateway, self._fd
        try:
            if gateway.file_size(fd) == 0 and gateway.write_fd(fd, b"\n") != 1:
                raise OSError("short write")
            gateway.set_mtime(fd, gateway.wall_time())
        except (OSError, ValueError, OverflowError):
            self._state.warn()

    def release(self) -> None:
        """Unlock and close; safe to call again."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if self._locked:
                try:
                    self._gateway.unlock(fd)
                except OSError:
                    pass  # closing the descriptor releases the flock anyway
        finally:
            self._gateway.close_fd(fd)


def _take_lock(gateway: Gateway, fd: int, deadline: float) -> None:
    """Poll the flock every ``POLL_S``; ``SendLockTimeout`` once the deadline has passed."""
    while True:
        if gateway.try_lock(fd):
            return
        remaining = deadline - gateway.monotonic()
        if not remaining > 0:  # also true for NaN: never an endless loop
            raise SendLockTimeout
        gateway.sleep(min(POLL_S, remaining))


def _spacing_wait(gateway: Gateway, fd: int) -> float:
    """Seconds to wait (0 to ``SPACING_S``) from the file's size and modification time."""
    if gateway.file_size(fd) == 0:
        return 0.0
    elapsed = gateway.wall_time() - gateway.file_mtime(fd)
    if 0.0 <= elapsed < SPACING_S:  # false for NaN, a future time and an old one
        return SPACING_S - elapsed
    return 0.0


def acquire(state: StateDir, gateway: Gateway, deadline: float) -> SendLock | None:
    """Take the send lock and wait out the spacing, both inside ``deadline``.

    ``deadline`` is an absolute ``gateway.monotonic()`` value. Returns the held lock, or
    ``None`` when there is no spacing (the state is unusable or the lock call failed; the one
    warning was given and the caller sends anyway). Raises ``SendLockTimeout`` when the
    deadline passes while waiting for the flock (after polling up to it), or at once, without
    sleeping, when the spacing wait is not shorter than the time that remains; the lock is
    released on every path.
    """
    fd = state.open_file(LOCK_NAME)
    if fd is None:
        return None
    lock: SendLock | None = None
    try:
        lock = SendLock(state, gateway, fd)
        try:
            _take_lock(gateway, fd, deadline)
        except OSError:
            state.warn()
            lock.release()
            return None
        lock.mark_locked()
        try:
            wait = _spacing_wait(gateway, fd)
        except (OSError, ValueError, OverflowError):
            state.warn()
            wait = 0.0
        if wait > 0:
            remaining = deadline - gateway.monotonic()
            if not wait < remaining:  # too long for the deadline (or NaN): end at once
                raise SendLockTimeout
            # todo(#27): a signal during this wait must be noticed within 100 ms (slice the
            # sleep or check the flag); the wait is up to 1 s unsliced here.
            gateway.sleep(wait)
        return lock
    except BaseException:
        if lock is None:
            gateway.close_fd(fd)
        else:
            lock.release()
        raise

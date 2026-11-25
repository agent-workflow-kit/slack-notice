"""State directory, log records and rotation.

``StateDir`` is the one handle through which the rest of the tool reaches the state directory
(interface, "Files"): lazy, one warning at most, never an exception for an unusable state.

TODO(#14): implement log records, rotation and the log lock.
TODO(#21): the send lock (spacing) uses ``StateDir.open_file("send.lock")``.
"""

from __future__ import annotations

from collections.abc import Callable
from types import TracebackType

from slack_notice.gateway import Gateway, StateUnusable

# Fixed text: no path, no reason from the filesystem, nothing from hostile input.
STATE_WARNING = (
    "slack-notice: the state directory or a state file cannot be used safely; "
    "the log record or send spacing may be skipped"
)


class StateDir:
    """The state directory for one run.

    Nothing is touched until ``open_file`` is first called ("used only when needed"). When the
    directory or a file is unusable, ``open_file`` returns ``None`` and ``warn`` is called once
    for the whole run (never again, whichever file fails next); the caller then writes no log
    record and takes no lock, and its exit code is unchanged. Other errors (bugs) propagate.
    Descriptors returned by ``open_file`` belong to the caller; ``close`` releases the directory.
    """

    def __init__(self, gateway: Gateway, home: str, warn: Callable[[str], None]) -> None:
        self._gateway = gateway
        self._home = home
        self._warn = warn
        self._dir_fd: int | None = None
        self._dir_failed = False
        self._warned = False
        self._closed = False

    def __enter__(self) -> StateDir:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _warn_once(self) -> None:
        if not self._warned:
            self._warned = True
            try:
                self._warn(STATE_WARNING)
            except (OSError, ValueError):
                pass  # a broken stderr never changes what open_file returns

    def open_file(self, name: str, *, append: bool = False) -> int | None:
        """A descriptor for ``name`` in the state directory, or ``None`` when unusable."""
        if self._dir_failed or self._closed:
            return None
        if self._dir_fd is None:
            try:
                self._dir_fd = self._gateway.open_state_dir(self._home)
            except StateUnusable:
                self._dir_failed = True
                self._warn_once()
                return None
        try:
            return self._gateway.open_state_file(self._dir_fd, name, append=append)
        except StateUnusable:
            self._warn_once()
            return None

    def close(self) -> None:
        self._closed = True
        fd, self._dir_fd = self._dir_fd, None
        if fd is not None:
            self._gateway.close_fd(fd)

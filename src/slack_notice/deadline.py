"""The deadline: a daemon worker, a three-state gate with a result slot, and the hard exit (#25).

Interface, "Webhook edge", Deadline paragraph. The network phase runs in a daemon worker thread;
the main thread waits for it in slices of at most 100 ms and decides at the deadline. The gate
(``idle``, ``writing``, ``abandoned``) and the result slot are guarded by ONE lock, so there is
one decision point for "definitely not sent" against "unknown":

- the worker moves ``idle -> writing`` immediately before its first call that can put request
  bytes on the socket (``enter_writing``, the ``before_write`` hook of ``post_once``) and gets
  ``False`` once the deadline was decided, so nothing is written after it;
- after a fully read 429 the result is recorded as not final and the gate moves back to idle in
  the same step (``record``); a failure that is not a complete response never moves it back;
- at the deadline (or a signal) the main thread looks at the slot first (``decide``): a final
  result that is there wins, a worker exception that is there is exit 1; otherwise an idle gate
  becomes ``abandoned`` and the result is the last result or a ``network_error`` with
  ``details.timeout`` true, and a writing gate is ``outcome_unknown``. The decision is made once
  and every later report of the worker is dropped.

The design never depends on the worker cooperating (``http.client`` caps neither the number of 1xx
frames nor chunk trailer lines, and a trickling peer resets per-operation timeouts): the worker is
never joined, its socket is not touched by the main thread, and the process ends through
``gateway.exit_now`` (``os._exit``) after the result is printed, flushed and logged.

What this module does not do (owners in the TODOs): retries (#26), the signal handler and exit
codes beyond ``Verdict.exit_code`` (#27), and the ``send`` flow that prints and logs (#28). The
lock wait and the input read are outside the gate: they happen in the main thread before the
worker starts and end the send with ``unavailable`` there.

``note_signal`` is called from a signal handler: it only sets a plain attribute and takes no lock
(a handler runs between bytecodes of the main thread, which may hold the gate lock).
"""

from __future__ import annotations

import enum
import threading
from collections.abc import Callable
from dataclasses import dataclass

from slack_notice.gateway import SLICE_SECONDS, Gateway
from slack_notice.webhook import (
    Outcome,
    Retry,
    Webhook,
    class_name,
    map_attempt,
    network_error,
    outcome_unknown,
    post_once,
)

WORKER_NAME = "slack-notice-worker"


class GateState(enum.Enum):
    IDLE = "idle"
    WRITING = "writing"
    ABANDONED = "abandoned"


@dataclass(frozen=True)
class Verdict:
    """How the network phase ended. Exactly one of ``outcome`` (exit 0 or 12) and ``error_class``
    (exit 1: the class name of what the worker raised, nothing else) is set. ``gate_writing``: the
    gate was writing when it ended (an exit 1 then has ``unknown_outcome`` true). ``deadline_hit``:
    the main thread decided (the deadline passed or a signal arrived) instead of the worker
    reporting."""

    outcome: Outcome | None
    error_class: str | None
    gate_writing: bool
    deadline_hit: bool

    @property
    def exit_code(self) -> int:
        return 1 if self.outcome is None else self.outcome.exit_code

    @property
    def unknown_outcome(self) -> bool:
        return self.gate_writing if self.outcome is None else self.outcome.unknown_outcome


def _silent_excepthook(args: threading.ExceptHookArgs) -> None:
    """Prints nothing: an exception text can hold the request path."""
    return None


class Deadline:
    """One send's deadline, gate, result slot and worker. ``at`` is an absolute
    ``gateway.monotonic()`` value. ``on_writing`` runs under the lock at the move to writing (it
    must be trivial and may raise: the gate then stays idle and the exception propagates)."""

    def __init__(
        self, gateway: Gateway, *, at: float, on_writing: Callable[[], None] | None = None
    ) -> None:
        self._gateway = gateway
        self._at = at
        self._on_writing = on_writing
        self._lock = threading.Lock()
        self._state = GateState.IDLE
        self._decided: Verdict | None = None
        self._final: Outcome | None = None
        self._last: Outcome | None = None
        self._error: tuple[str, bool] | None = None
        self._wake = threading.Event()
        self._started = False
        self._signalled = False
        self.worker: threading.Thread | None = None

    # -- state -----------------------------------------------------------------------------

    @property
    def state(self) -> GateState:
        with self._lock:
            return self._state

    @property
    def writing(self) -> bool:
        return self.state is GateState.WRITING

    @property
    def signalled(self) -> bool:
        return self._signalled

    def remaining(self) -> float:
        """Seconds to the deadline (negative once passed)."""
        return self._at - self._gateway.monotonic()

    def note_signal(self) -> None:
        """A signal arrived: it is the deadline. Lock-free (see the module docstring)."""
        self._signalled = True

    # -- the worker's side -----------------------------------------------------------------

    def enter_writing(self) -> bool:
        """``idle -> writing``; ``False`` (nothing may be written) once the deadline was decided,
        and also when the deadline has passed or a signal was noted but the main thread has not
        decided yet: the refusal makes that same decision (``decide(expired=True)``), so no
        request is written after the deadline. Already writing is a bug (``ValueError``): a retry
        first records its 429. If ``on_writing`` raises, the gate goes back to idle and the
        exception propagates."""
        with self._lock:
            if self._decided is not None or self._state is GateState.ABANDONED:
                return False
            if self._state is GateState.WRITING:
                raise ValueError("the gate is already writing")
            if self._signalled or not self.remaining() > 0:
                self._decide_locked(expired=True)
                self._wake.set()
                return False
            self._state = GateState.WRITING
            if self._on_writing is not None:
                try:
                    self._on_writing()
                except BaseException:
                    self._state = GateState.IDLE
                    raise
            return True

    def record(self, outcome: Outcome, *, final: bool) -> bool:
        """Store a result. ``final``: it ends the send. Not final: it will be retried and is kept
        as the last result; a writing gate moves back to idle, which only a fully read 429 may do.
        ``False`` when the deadline was already decided (the result is dropped)."""
        with self._lock:
            if self._decided is not None:
                return False
            if (
                self._state is GateState.WRITING
                and not final
                and outcome.retry is not Retry.RATE_LIMIT
            ):
                raise ValueError("only a fully read 429 moves the gate back to idle")
            if final:
                self._final = outcome
            else:
                self._last = outcome
                if self._state is GateState.WRITING:
                    self._state = GateState.IDLE
            return True

    def _fail(self, name: str) -> None:
        with self._lock:
            if self._decided is None and self._error is None:
                self._error = (name, self._state is GateState.WRITING)

    # -- the main thread's side ------------------------------------------------------------

    def decide(self, *, expired: bool, worker_lost: bool = False) -> Verdict | None:
        """The one decision point. ``None``: nothing yet (no result, not expired). Looks at the
        slot first; decided once, then the same verdict is returned. ``worker_lost``: the worker
        thread is dead and left nothing in the slot (it could not even report its failure): exit 1
        with ``RuntimeError`` at once."""
        with self._lock:
            return self._decide_locked(expired=expired, worker_lost=worker_lost)

    def _decide_locked(self, *, expired: bool, worker_lost: bool = False) -> Verdict | None:
        if self._decided is not None:
            return self._decided
        verdict: Verdict | None = None
        if self._final is not None:
            verdict = Verdict(self._final, None, self._state is GateState.WRITING, False)
        elif self._error is not None:
            name, writing = self._error
            verdict = Verdict(None, name, writing, False)
        elif worker_lost:
            verdict = Verdict(None, "RuntimeError", self._state is GateState.WRITING, False)
        elif expired:
            if self._state is GateState.WRITING:
                verdict = Verdict(outcome_unknown(), None, True, True)
            else:
                self._state = GateState.ABANDONED
                last = self._last or network_error(tls=False, timeout=True)
                verdict = Verdict(last, None, False, True)
        if verdict is not None:
            self._decided = verdict
        return verdict

    def run(self, work: Callable[[Deadline], Outcome]) -> Verdict:
        """Start the daemon worker once, wait in slices of at most 100 ms and return the verdict.
        The worker is never joined. ``threading.excepthook`` is replaced by a silent one for the
        life of the process (the tool ends through ``exit_now``); a library or test use must
        restore ``threading.excepthook`` itself. A worker that died with nothing in the slot is
        decided at once as exit 1 (``RuntimeError``)."""
        if self._started:
            raise RuntimeError("the worker was already started")
        self._started = True
        threading.excepthook = _silent_excepthook
        self.worker = threading.Thread(
            target=self._body, args=(work,), name=WORKER_NAME, daemon=True
        )
        self.worker.start()
        while True:
            self._wake.clear()
            expired = self._signalled or not self.remaining() > 0
            # Read before deciding: a dead worker has stored everything it ever will.
            lost = not self.worker.is_alive()
            verdict = self.decide(expired=expired, worker_lost=lost)
            if verdict is not None:
                return verdict
            self._wake.wait(max(0.0, min(SLICE_SECONDS, self.remaining())))

    def _body(self, work: Callable[[Deadline], Outcome]) -> None:
        try:
            try:
                outcome = work(self)
                if not isinstance(outcome, Outcome):
                    raise TypeError("the worker returned no outcome")
                self.record(outcome, final=True)
            except BaseException as exc:
                # The class name only: the exception, its traceback and its frames hold the path
                # and the body.
                self._fail(class_name(exc))
        except BaseException:
            # Nothing may escape the worker (no traceback, no excepthook text): if even reporting
            # the failure failed, the main thread decides at the deadline, or at once when it sees
            # the worker dead with an empty slot.
            pass
        finally:
            self._wake.set()


def attempt_work(
    gateway: Gateway, target: Webhook, body: bytes, *, timeout: float
) -> Callable[[Deadline], Outcome]:
    """The worker body of one attempt. TODO(#26): the retry loop replaces it (waits, the two
    counters, ``record(..., final=False)`` and ``rate_limited``'s ``retry_after_s``)."""

    def work(deadline: Deadline) -> Outcome:
        result = post_once(
            gateway,
            target,
            body,
            timeout=timeout,
            before_write=deadline.enter_writing,
            remaining=deadline.remaining,
        )
        return map_attempt(result, gate_writing=deadline.writing)

    return work


# --- the exit --------------------------------------------------------------------------------


def conclude(
    gateway: Gateway,
    code: int,
    *,
    emit: Callable[[], None],
    flush: Callable[[], None],
    record: Callable[[], None],
    bound: float = 1.0,
) -> None:
    """Interface step 7 and the exit: print the result and flush it, then the log step, then
    ``exit_now``, in that order and always reaching the exit. The print and the flush run in one
    daemon thread that is waited for at most ``bound`` seconds of real time (a pipe nobody reads
    must not hold the process past the deadline): when it does not finish, the log step and the
    exit follow anyway. A write failure (``OSError``, ``BrokenPipeError`` included) changes
    nothing: the exit code is the result's. Another exception from the print is exit 1; one from
    the flush or the log step changes nothing (the log is advisory and bounded by its own lock
    poll). Does not return."""
    final = [code]

    def print_step() -> None:
        try:
            emit()
        except OSError:
            pass
        except Exception:
            final[0] = 1
        try:
            flush()
        except Exception:
            pass

    try:
        printer = threading.Thread(target=print_step, name="slack-notice-print", daemon=True)
        printer.start()
        printer.join(bound)
        try:
            record()
        except Exception:
            pass
    finally:
        gateway.exit_now(final[0])

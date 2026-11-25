"""One real-process check of the step 5 signal rule (#27): a real SIGTERM, a really blocked worker.

The child runs the pieces #28 will wire (handler gate, ``Deadline.run`` on a daemon worker that
blocks on an event nothing sets, ``conclude`` with the system gateway and its ``os._exit``). It
writes a readiness marker once the worker is blocked, and the test signals only the pid ``Popen``
returned. Exit 12 with exactly one envelope on stdout is expected, and the child must end by
itself within the bound (the blocked worker is never joined). No network is involved.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import slack_notice
from tests.harness import assert_valid

CHILD = """
import json, os, sys, threading
from slack_notice.cli import _SignalGate, _exit_on_signal
from slack_notice.deadline import Deadline, conclude
from slack_notice.gateway import SystemGateway
from slack_notice.webhook import Outcome

mode = sys.argv[1]
gw = SystemGateway()
gate = _SignalGate()
ready = int(os.environ["READY_FD"])
with _exit_on_signal(gate):
    d = Deadline(gw, at=gw.monotonic() + 60)
    gate.arm(d.note_signal)

    def work(deadline):
        if mode == "writing":
            assert deadline.enter_writing()
        os.write(ready, b"ready\\n")
        threading.Event().wait()  # blocks until the process ends

    v = d.run(work)
    out = v.outcome
    conclude(
        gw, v.exit_code,
        emit=lambda: (gate.commit(), sys.stdout.write(json.dumps(out.envelope()) + "\\n")),
        flush=sys.stdout.flush, record=lambda: None,
    )
"""


@pytest.mark.parametrize(
    ("mode", "code", "unknown"),
    [("idle", "network_error", False), ("writing", "outcome_unknown", True)],
)
def test_a_real_sigterm_at_step_5_prints_one_envelope_and_exits_12(
    mode: str, code: str, unknown: bool, tmp_path: Path
) -> None:
    src = str(Path(slack_notice.__file__).resolve().parent.parent)
    ready_r, ready_w = os.pipe()
    env = {
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path),
        "PYTHONPATH": src,
        "PATH": "/usr/bin:/bin",
        "READY_FD": str(ready_w),
    }
    proc = subprocess.Popen(
        [sys.executable, "-c", CHILD, mode],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(ready_w,),
        env=env,
        cwd=tmp_path,
    )
    os.close(ready_w)
    try:
        ready, _, _ = select.select([ready_r], [], [], 20)
        assert ready, "the worker never blocked"
        assert os.read(ready_r, 16) == b"ready\n"
        os.kill(proc.pid, signal.SIGTERM)  # the pid Popen captured at launch
        out, err = proc.communicate(timeout=20)
        assert (proc.returncode, err) == (12, b"")
        envelope = assert_valid("cli/error", out)
        assert out.count(b"\n") == 1
        assert (envelope["error"]["code"], envelope["error"]["unknown_outcome"]) == (code, unknown)
        json.loads(out)
    finally:
        if proc.poll() is None:
            proc.kill()  # this Popen's own pid
            proc.wait()
        os.close(ready_r)


ENTRY_CHILD = """
import os, signal, sys, time
from slack_notice import cli

sys.argv = ["slack-notice", "send", "--json", "--dry-run", "--message", "m"]
code = cli.main()  # the process entry: no argv given
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    os.kill(os.getpid(), sig)
time.sleep(0.1)  # let every handler run
sys.exit(code)
"""


def test_signals_after_main_returns_change_neither_stderr_nor_the_exit_code(
    tmp_path: Path,
) -> None:
    src = str(Path(slack_notice.__file__).resolve().parent.parent)
    env = {
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path),
        "XDG_STATE_HOME": str(tmp_path),
        "PYTHONPATH": src,
        "PATH": "/usr/bin:/bin",
    }
    done = subprocess.run(
        [sys.executable, "-c", ENTRY_CHILD],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=env,
        cwd=tmp_path,
        timeout=30,
        check=False,
    )
    assert done.stderr == b""
    assert done.returncode == 0

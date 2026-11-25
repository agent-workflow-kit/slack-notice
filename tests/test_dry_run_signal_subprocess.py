"""One real-process check of the dry-run signal rule (#20): a real signal, a really blocked read.

The in-process tests in ``test_dry_run.py`` deliver signals with ``os.kill`` from inside the
code under test. This one starts the CLI as a child process that blocks reading a stdin pipe
nothing ever writes to, waits for a readiness marker written just before the blocking read, and
signals only the pid ``Popen`` returned. The result must be 128+N with nothing printed.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import slack_notice

CHILD = """
import os, sys
from slack_notice.cli import main
from slack_notice.gateway import SystemGateway

class Marked(SystemGateway):
    def read_source(self, fd_or_path, max_bytes, remaining):
        os.write(int(os.environ["READY_FD"]), b"ready\\n")  # written before the blocking read
        return super().read_source(fd_or_path, max_bytes, remaining)

sys.exit(main(sys.argv[1:], gateway=Marked()))
"""


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_real_signal_while_stdin_is_blocked_exits_128_plus_n(
    sig: signal.Signals, tmp_path: Path
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("{}\n", encoding="utf-8")
    src = str(Path(slack_notice.__file__).resolve().parent.parent)
    stdin_r, stdin_w = os.pipe()  # nothing is ever written: the child blocks in read
    ready_r, ready_w = os.pipe()
    env = {
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path),
        "PYTHONPATH": src,
        "PATH": "/usr/bin:/bin",
        "READY_FD": str(ready_w),
    }
    proc = subprocess.Popen(
        [sys.executable, "-c", CHILD, "send", "--dry-run", "--stdin-json", "--config", str(config)],
        stdin=stdin_r,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(ready_w,),
        env=env,
        cwd=tmp_path,
    )
    os.close(stdin_r)
    os.close(ready_w)
    try:
        ready, _, _ = select.select([ready_r], [], [], 20)
        assert ready, "the child never reached the blocking read"
        assert os.read(ready_r, 16) == b"ready\n"
        os.kill(proc.pid, sig)  # the pid Popen captured at launch
        out, err = proc.communicate(timeout=20)
        assert (proc.returncode, out, err) == (128 + sig, b"", b"")
    finally:
        if proc.poll() is None:
            proc.kill()  # this Popen's own pid
            proc.wait()
        os.close(stdin_w)
        os.close(ready_r)

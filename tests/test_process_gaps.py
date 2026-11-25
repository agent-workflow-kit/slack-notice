"""Two gaps the 0.x reviews left open (#83), both with real child processes.

- A send whose stdout and stderr are closed (docs/interface.md, Output: ``reserve_std_fds``): the
  exit code and the log record are not lost, and nothing the run opens later is written to.
- The send lock held by another process while a log record is written: the real locks, on a
  temporary state directory (the fake gateway's ``lock_held`` blocks the send lock and the log
  lock together, so it cannot tell them apart).

No child reaches the network: the first one runs the in-process fake gateway (no socket is ever
built), the second one only takes a file lock. Only the pids ``Popen`` / ``run`` returned are ever
waited for or killed, and events are ordered by pipe handshakes, never by sleeping.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import slack_notice
from slack_notice.log import STATE_WARNING
from tests.fake_gateway import FakeGateway
from tests.send_harness import SEND, go, state_path, write_config
from tests.test_send import HELLO, OK

SRC = str(Path(slack_notice.__file__).resolve().parent.parent)
ROOT = str(Path(__file__).resolve().parent.parent)
TESTS = Path(__file__).resolve().parent


def child_env(tmp_path: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path / "x"),
        "XDG_STATE_HOME": str(tmp_path / "y"),
        "PYTHONPATH": f"{SRC}:{ROOT}",
    }


# --- closed stdout and stderr -------------------------------------------------------------------


def run_closed(mode: str, answer: str, tmp_path: Path) -> tuple[int, Path, Path]:
    """Run closed_fd_child.py, which closes its own descriptors 1 and 2 (see its docstring)."""
    home = tmp_path / "childhome"
    home.mkdir(mode=0o700)
    directory = tmp_path / "canaries"
    directory.mkdir()
    done = subprocess.run(
        [
            sys.executable,
            str(TESTS / "closed_fd_child.py"),
            mode,
            answer,
            str(home),
            str(directory),
        ],
        env=child_env(tmp_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    return done.returncode, directory, home


def child_records(home: Path) -> list[dict[str, object]]:
    log = home / ".local" / "state" / "slack-notice" / "log.jsonl"
    return [json.loads(line) for line in log.read_bytes().splitlines()]


@pytest.mark.parametrize(
    ("answer", "code", "outcome"), [("ok", 0, "sent"), ("rejected", 12, "failed")]
)
def test_a_send_with_closed_stdout_and_stderr_keeps_its_exit_code_and_writes_to_no_reused_fd(
    answer: str, code: int, outcome: str, tmp_path: Path
) -> None:
    returncode, directory, home = run_closed("reserve", answer, tmp_path)
    report = json.loads((directory / "report.json").read_text("utf-8"))
    # the two descriptors were reopened on the null device, so the files opened afterwards
    # did not get the numbers 1 and 2
    assert (report["fd1_is_null"], report["fd2_is_null"]) == (True, True)
    assert report["out_fd"] > 2 and report["err_fd"] > 2
    # the result was not written into anything the run opened ...
    assert (directory / "out.canary").read_bytes() == b""
    assert (directory / "err.canary").read_bytes() == b""
    # ... the exit code is the result's (not 100 + code: the run ended through exit_now) ...
    assert returncode == code
    # ... and the step after the result print, the log record, still happened
    (record,) = child_records(home)
    assert (record["outcome"], record["exit"]) == (outcome, code)


def test_without_reserve_std_fds_the_result_lands_in_the_file_that_got_descriptor_1(
    tmp_path: Path,
) -> None:
    """The control: it shows that the test above can fail. The same child, minus the reopening,
    opens its canary on descriptor 1, and the ``--json`` result is written into it."""
    returncode, directory, _home = run_closed("control", "ok", tmp_path)
    report = json.loads((directory / "report.json").read_text("utf-8"))
    assert (report["out_fd"], report["err_fd"]) == (1, 2)
    assert returncode == 0
    document = json.loads((directory / "out.canary").read_bytes())
    assert document["outcome"] == "sent"


# --- the send lock held by another process while a log record is written ------------------------


def test_a_send_lock_held_by_another_process_still_logs_the_unavailable_result(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    home = str(fake_gateway._home)  # pyright: ignore[reportPrivateUsage]
    proc = subprocess.Popen(
        [sys.executable, str(TESTS / "lock_holder_child.py"), home],
        env=child_env(tmp_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert proc.stdin is not None and proc.stdout is not None
    try:
        assert proc.stdout.readline() == b"ready\n"  # the child holds send.lock from here on
        sent = go(SEND, fake_gateway, stdin=HELLO, config=write_config(tmp_path, "timeout: 3\n"))
        assert proc.poll() is None  # still the holder when the send gave up
        # The send waited on the real lock (a try that failed, more than once), and the log lock
        # was a different file: the record was written while the send lock was held elsewhere.
        assert fake_gateway.events.count("try_lock") > 2
        assert (sent.code, sent.exited) == (12, True)
        assert sent.error["code"] == "unavailable" and sent.error["details"] == {"phase": "lock"}
        assert fake_gateway.connections == []
        (record,) = sent.records
        assert (record["outcome"], record["code"], record["http_status"]) == (
            "failed",
            "unavailable",
            None,
        )
        assert STATE_WARNING not in sent.stderr
        # the holder lets go; the next send takes the lock and goes through
        proc.stdin.write(b"go\n")
        proc.stdin.flush()
        assert proc.wait(timeout=30) == 0
        fake_gateway.script(OK)
        again = go(SEND, fake_gateway, stdin=HELLO)
        assert again.code == 0
        assert [r["outcome"] for r in again.records] == ["failed", "sent"]
    finally:
        if proc.poll() is None:
            proc.kill()  # this Popen's own pid
            proc.wait()
        proc.stdin.close()
        proc.stdout.close()
    assert (state_path(fake_gateway) / "log.jsonl").is_file()

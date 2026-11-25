"""The real `send` in a real process: the production exit path and real stdin (#28).

The child runs ``python -m slack_notice`` with the system gateway. None of these scenarios
reaches the network (the credential is unset or no notification gets that far), and the config
file given with ``--config`` turns the log off so nothing is written to a real state directory.
Only the pid ``Popen`` returned is ever signalled or killed.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

import slack_notice
from tests.harness import assert_valid

SRC = str(Path(slack_notice.__file__).resolve().parent.parent)


def child_env(tmp_path: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path / "x"),
        "XDG_STATE_HOME": str(tmp_path / "y"),
        "PYTHONPATH": SRC,
    }


def config(tmp_path: Path, text: str = "log: false\n") -> str:
    path = tmp_path / "cfg" / "config.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_the_production_exit_path_ends_through_exit_now_with_the_result_on_stdout(
    tmp_path: Path,
) -> None:
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "slack_notice",
            "send",
            "--json",
            "--config",
            config(tmp_path),
            "--message",
            "hi",
        ],
        env=child_env(tmp_path),  # no SLACK_WEBHOOK: credential_invalid, nothing is contacted
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 12
    error = assert_valid("cli/error", done.stdout)["error"]
    assert (error["code"], error["details"]) == ("credential_invalid", {"env": "SLACK_WEBHOOK"})
    assert done.stderr == b"credential_invalid: " + error["message"].encode() + b"\n"


def test_a_closed_stdin_is_empty_input_and_a_refusal(tmp_path: Path) -> None:
    done = subprocess.run(
        [
            "/bin/sh",
            "-c",
            'exec "$0" -m slack_notice send --json --stdin-json --config "$1" <&-',
            sys.executable,
            config(tmp_path),
        ],
        env=child_env(tmp_path),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 20
    error = assert_valid("cli/error", done.stdout)["error"]
    assert (error["code"], error["reason"]) == ("refused", "invalid_payload")


def test_a_pipe_that_sends_ten_bytes_and_stalls_is_unavailable_input_within_the_deadline(
    tmp_path: Path,
) -> None:
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "slack_notice",
            "send",
            "--json",
            "--stdin-json",
            "--config",
            config(tmp_path, "log: false\ntimeout: 3\n"),
        ],
        env=child_env(tmp_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    started = time.monotonic()
    try:
        proc.stdin.write(b'{"message"')  # 10 bytes, then silence with the pipe left open
        proc.stdin.flush()
        code = proc.wait(timeout=30)
        elapsed = time.monotonic() - started
        out, err = proc.stdout.read(), proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()  # this Popen's own pid
            proc.wait()
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()
    assert code == 12 and elapsed < 3 + 3  # the deadline plus the 3 s of the interface
    error = assert_valid("cli/error", out)["error"]
    assert (error["code"], error["details"], error["retryable"]) == (
        "unavailable",
        {"phase": "input"},
        True,
    )
    assert err.startswith(b"unavailable: ")


@pytest.mark.parametrize("flags", [[], ["--quiet"]])
def test_the_dry_run_still_returns_normally_with_no_hard_exit(
    flags: list[str], tmp_path: Path
) -> None:
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "slack_notice",
            "send",
            "--dry-run",
            "--json",
            *flags,
            "--config",
            config(tmp_path),
            "--message",
            "hi",
        ],
        env=child_env(tmp_path),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0
    assert assert_valid("cli/send", done.stdout)["outcome"] == "dry_run"
    # The children use ``log: false`` and stop before the state directory: nothing here may
    # touch the real home or its state.

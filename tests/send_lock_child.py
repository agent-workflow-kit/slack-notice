"""Child process for the send-lock tests: take the real send lock through the real gateway.

Usage:
  send_lock_child.py hold <home> <ready-file> <release-file>
      Take the lock, create <ready-file>, keep the lock until <release-file> exists (bounded to
      20 s), then release it. Exit 0.
  send_lock_child.py section <home> <marker-file> <count>
      <count> times: take the lock, create <marker-file> exclusively (it already existing means
      another process is inside the critical section: exit 3), hold for 20 ms, remove it,
      release. Exit 0.

It never stamps the lock (so it never causes a one-second wait), never contacts anything and
uses only the home it is given.
"""

from __future__ import annotations

import os
import sys
import time


def main() -> int:
    from slack_notice.gateway import SystemGateway
    from slack_notice.log import StateDir
    from slack_notice.spacing import acquire

    mode, home = sys.argv[1], sys.argv[2]
    gateway = SystemGateway()
    with StateDir(gateway, home, lambda _line: None) as state:
        if mode == "hold":
            ready, release = sys.argv[3], sys.argv[4]
            lock = acquire(state, gateway, gateway.monotonic() + 20)
            if lock is None:
                return 4
            with lock:
                with open(ready, "w") as handle:
                    handle.write("ready")
                end = time.monotonic() + 20
                while not os.path.exists(release) and time.monotonic() < end:
                    time.sleep(0.005)
            return 0
        marker, count = sys.argv[3], int(sys.argv[4])
        for _ in range(count):
            lock = acquire(state, gateway, gateway.monotonic() + 20)
            if lock is None:
                return 4
            with lock:
                try:
                    os.close(os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
                except FileExistsError:
                    return 3
                time.sleep(0.02)
                os.unlink(marker)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

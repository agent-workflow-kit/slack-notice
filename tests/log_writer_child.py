"""Child process for the concurrent-writer test: append records through the real gateway.

Usage: log_writer_child.py <home> <go-file> <index> <count>. Waits (bounded) for the go file so
that the writers start together, then writes <count> records whose ``bytes`` is the writer index
and whose ``duration_ms`` is the record number. It never contacts anything and uses only the
home it is given.
"""

from __future__ import annotations

import os
import sys
import time


def main() -> int:
    home, go, index, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    from slack_notice.gateway import SystemGateway
    from slack_notice.log import StateDir, log_result

    deadline = time.monotonic() + 10
    while not os.path.exists(go) and time.monotonic() < deadline:
        time.sleep(0.005)
    gateway = SystemGateway()
    lost = 0
    with StateDir(gateway, home, lambda _line: None) as state:
        for number in range(count):
            written = log_result(
                state,
                gateway,
                enabled=True,
                version="1.2.3",
                exit_code=0,
                code=None,
                reason=None,
                unknown_outcome=False,
                gate_writing=False,
                level="info",
                bytes_=index,
                truncated=False,
                duration_ms=number,
                http_status=200,
                message_hash="0123456789abcdef",
                dedupe_hash=None,
                actor="auto:unknown",
                actor_source="default",
            )
            lost += 0 if written else 1
    return 3 if lost else 0


if __name__ == "__main__":
    raise SystemExit(main())

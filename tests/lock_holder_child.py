"""Child process that holds the real send lock until told to let go (pipe handshake, no polling).

Usage: lock_holder_child.py <home>

Takes ``send.lock`` through the real gateway and the real spacing code, writes ``ready`` and a
newline on stdout, then blocks reading one line from stdin (an end of file counts) and releases
the lock. It never stamps the lock, never contacts anything and uses only the home it is given.
Exit 0 after a release, 4 when the lock could not be taken.
"""

from __future__ import annotations

import sys


def main() -> int:
    from slack_notice.gateway import SystemGateway
    from slack_notice.log import StateDir
    from slack_notice.spacing import acquire

    gateway = SystemGateway()
    with StateDir(gateway, sys.argv[1], lambda _line: None) as state:
        lock = acquire(state, gateway, gateway.monotonic() + 20)
        if lock is None:
            return 4
        with lock:
            sys.stdout.write("ready\n")
            sys.stdout.flush()
            sys.stdin.readline()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Child process for the closed-descriptor test: a real send whose stdout and stderr were closed
by the parent, through the real ``cli.main`` and the real descriptor and exit code path.

Usage: closed_fd_child.py <reserve|control> <ok|rejected> <home> <dir>

It cannot reach the network by construction: the gateway is the in-process ``FakeGateway`` with a
scripted answer, so no socket is opened, nothing is resolved and ``SystemGateway`` never builds a
connection. Only ``exit_now`` is the real one (``os._exit``), so the exit code is what a real send
leaves behind.

Both modes enter through ``cli.main(None, ...)`` with ``sys.argv`` set, the process entry, so the
reservation is the one ``cli.main`` performs itself.

- ``reserve``: the unmodified entry.
- ``control``: the same with ``cli.reserve_std_fds`` replaced by a no-op; the test uses it to prove
  that the check can fail (the result then lands in the file that got descriptor 1).

The descriptors 1 and 2 are closed by the child itself, after its imports and before anything
else: with some interpreter builds (no ``getrandom``) importing ``random`` keeps ``/dev/urandom``
open on the lowest free descriptor, so a child that starts with 1 closed would find 1 taken by the
interpreter before any slack-notice code runs, which no entry code can undo.

At the run's first gateway call (after the entry's reservation) the child opens two canary files in
<dir> (the first free descriptors, so 1 and 2 when those are closed) and writes ``report.json``
there (the canaries' descriptors and whether descriptors 1 and 2 are the null device).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import NoReturn


def main() -> int:
    mode, answer, home, directory = sys.argv[1:5]
    from slack_notice import cli
    from tests.fake_gateway import Attempt, FakeGateway, Reply
    from tests.send_harness import ENV

    sys.stdout.flush()
    sys.stderr.flush()
    os.close(1)
    os.close(2)
    if mode == "control":
        # the real entry (``cli.main(None, ...)``) reserves the descriptors; only that is removed
        cli.reserve_std_fds = lambda: None

    def is_null(fd: int) -> bool:
        try:
            return os.fstat(fd).st_rdev == os.stat(os.devnull).st_rdev
        except OSError:
            return False

    class Child(FakeGateway):
        opened = False

        def monotonic(self) -> float:
            # The first gateway call of the run, so after the reservation ``cli.main`` makes (or,
            # in control mode, does not make): open the canaries on the first free descriptors,
            # which are 1 and 2 unless the reservation took them, and report.
            if not self.opened:
                self.opened = True
                out_fd = os.open(
                    os.path.join(directory, "out.canary"), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                )
                err_fd = os.open(
                    os.path.join(directory, "err.canary"), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                )
                report = {
                    "out_fd": out_fd,
                    "err_fd": err_fd,
                    "fd1_is_null": is_null(1),
                    "fd2_is_null": is_null(2),
                }
                Path(directory, "report.json").write_text(json.dumps(report), encoding="utf-8")
            return super().monotonic()

        def exit_now(self, code: int) -> NoReturn:
            os._exit(code)

    gateway = Child(home=home)
    if answer == "ok":
        gateway.script(Attempt())
    else:
        gateway.script(Attempt(reply=Reply(status=400, body=b'{"error":"invalid_blocks"}')))
    # Returns only if the production code did not end the process through exit_now.
    sys.argv = ["slack-notice", "send", "--json", "--message", "hi"]
    return 100 + cli.main(None, ENV, gateway)


if __name__ == "__main__":
    raise SystemExit(main())

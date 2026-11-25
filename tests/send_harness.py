"""Shared harness for the end-to-end `send` tests (#28).

``go`` runs ``cli.main`` in-process with a fake gateway and returns what a caller could see: the
exit code, both streams, the log records and the state directory's files. A real send ends
through ``gateway.exit_now``; the fake raises ``FakeProcessExit`` there, and ``go`` turns that
into the code (asserting that the hook was called exactly when main did not return).
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from slack_notice.cli import Streams, main
from slack_notice.gateway import SourceRead
from tests.fake_gateway import FakeGateway, FakeProcessExit
from tests.harness import assert_valid

CANARY = "CAN" + "ARY" + "_28w"
PATH = "/triggers/" + CANARY + "/seg"
URL = "https://hooks.slack.com" + PATH
ENV_NAME = "SLACK_WEBHOOK"
ENV = {ENV_NAME: URL}


def state_path(gateway: FakeGateway) -> Path:
    return Path(gateway._home) / ".local" / "state" / "slack-notice"  # pyright: ignore


@dataclass
class Sent:
    code: int
    out: bytes
    err: bytes
    gateway: FakeGateway
    exited: bool  # ended through gateway.exit_now (a real send), not by returning
    records: list[dict[str, Any]] = field(default_factory=list)
    state_files: dict[str, bytes] = field(default_factory=dict)

    @property
    def stdout(self) -> str:
        return self.out.decode("utf-8")

    @property
    def stderr(self) -> str:
        return self.err.decode("utf-8")

    @property
    def document(self) -> dict[str, Any]:
        """The one JSON document on stdout."""
        assert self.stdout.count("\n") == 1, self.stdout
        return json.loads(self.stdout)

    @property
    def error(self) -> dict[str, Any]:
        return assert_valid("cli/error", self.out)["error"]

    @property
    def everything(self) -> bytes:
        """Every byte the run left anywhere a caller could look."""
        return b"\n".join([self.out, self.err, *self.state_files.values()])


def write_config(tmp_path: Path, text: str = "{}\n") -> str:
    path = tmp_path / "cfg" / "config.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def read_state(
    gateway: FakeGateway, *, validate: bool = True
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    directory = state_path(gateway)
    files: dict[str, bytes] = {}
    if directory.is_dir():
        for entry in sorted(directory.iterdir()):
            files[entry.name] = entry.read_bytes()
    records = []
    for line in files.get("log.jsonl", b"").splitlines():
        if validate:
            records.append(assert_valid("log", line))
    return records, files


def go(
    argv: list[str],
    gateway: FakeGateway,
    *,
    stdin: bytes | SourceRead | None = None,
    env: Any = ENV,
    config: str | None = None,
    tty: bool = False,
    out: Any = None,
    err: Any = None,
    before: Callable[[], None] | None = None,
    validate_log: bool = True,
) -> Sent:
    if stdin is not None:
        gateway.source_script.append(stdin if isinstance(stdin, SourceRead) else SourceRead(stdin))
    kept_out, kept_err = io.BytesIO(), io.BytesIO()
    streams = Streams(
        kept_out if out is None else out, kept_err if err is None else err, lambda: tty
    )
    full = [*argv, *([] if config is None else ["--config", config])]
    if before is not None:
        before()
    exited = False
    before_exits = len(gateway.exit_codes)
    try:
        code = main(full, env, gateway, streams)
    except FakeProcessExit as end:
        code, exited = end.code, True
    assert gateway.exit_codes[before_exits:] == ([code] if exited else [])
    records, files = read_state(gateway, validate=validate_log)
    return Sent(
        code,
        kept_out.getvalue(),
        kept_err.getvalue(),
        gateway,
        exited,
        records,
        files,
    )


def stdin_json(**fields: Any) -> bytes:
    return json.dumps(fields).encode()


SEND = ["send", "--json", "--stdin-json"]

"""Log records, rotation and the log lock (issue #14).

Every line the code writes is validated against schemas/log.json from the bytes on disk.
Hostile objects are real filesystem objects under ``tmp_path``; the only subprocesses are the
writers of the concurrency test, which get a private home and are waited on or killed by the
``Popen`` handle that started them.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from slack_notice import __version__
from slack_notice.log import (
    KEEP,
    LOCK_NAME,
    LOG_NAME,
    MAX_WRITE,
    ROTATE_AT,
    STATE_WARNING,
    StateDir,
    append_record,
    build_record,
    dedupe_key_sha256,
    encode_record,
    format_ts,
    log_result,
    message_sha256,
)
from tests.fake_gateway import FakeGateway
from tests.harness import ROOT, assert_valid, load_schema

CANARY = "ca" + "nary-" + "9b1e"  # appears in no record: built from parts
GOLDEN = Path(__file__).resolve().parent / "golden" / "log.jsonl"
FIELDS = list(load_schema("log")["properties"])


class Lines:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "statehome"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def gw(home: Path) -> FakeGateway:
    return FakeGateway(home=str(home))


@pytest.fixture
def warned() -> Lines:
    return Lines()


@pytest.fixture
def state(gw: FakeGateway, home: Path, warned: Lines) -> Any:
    with StateDir(gw, str(home), warned) as state_dir:
        yield state_dir


def leaf(home: Path) -> Path:
    return home / ".local" / "state" / "slack-notice"


def sent(**over: Any) -> dict[str, Any]:
    fields: dict[str, Any] = dict(
        version="1.2.3",
        exit_code=0,
        code=None,
        reason=None,
        unknown_outcome=False,
        gate_writing=False,
        level="info",
        bytes_=120,
        truncated=False,
        duration_ms=42,
        http_status=200,
        message_hash="0123456789abcdef",
        dedupe_hash=None,
        actor="auto:unknown",
        actor_source="default",
    )
    fields.update(over)
    return fields


def record(wall: float = 1_700_000_000.0, **over: Any) -> dict[str, Any]:
    result = build_record(wall_time=wall, **sent(**over))
    assert result is not None
    return result


def read_lines(path: Path) -> list[bytes]:
    data = path.read_bytes()
    return data.splitlines(keepends=True) if data else []


def assert_file_valid(path: Path) -> list[dict[str, Any]]:
    """Every line validates against the schema and ends with exactly one LF."""
    records = []
    for line in read_lines(path):
        assert line.endswith(b"\n") and not line.endswith(b"\n\n") and line.count(b"\n") == 1
        records.append(assert_valid("log", line))
    return records


# --- hashes and timestamps -------------------------------------------------------------------


def test_message_hash_is_title_lf_message() -> None:
    import hashlib

    assert message_sha256("T", "m") == hashlib.sha256(b"T\nm").hexdigest()[:16]
    assert message_sha256(None, "m") == hashlib.sha256(b"\nm").hexdigest()[:16]
    assert message_sha256("", "m") == message_sha256(None, "m")
    assert message_sha256("é", "日本") == hashlib.sha256("é\n日本".encode()).hexdigest()[:16]
    assert message_sha256("a", "b") != message_sha256("ab", "")  # the LF separates the parts


def test_dedupe_hash_is_the_key_bytes() -> None:
    import hashlib

    assert dedupe_key_sha256("key-1") == hashlib.sha256(b"key-1").hexdigest()[:16]
    assert len(dedupe_key_sha256("k" * 1024)) == 16


@pytest.mark.parametrize(
    ("wall", "expected"),
    [
        (0.0, "1970-01-01T00:00:00.000Z"),
        (1_700_000_000.0, "2023-11-14T22:13:20.000Z"),
        (1_700_000_000.1239, "2023-11-14T22:13:20.123Z"),  # truncated, never rounded up
        (1_700_000_000.9999, "2023-11-14T22:13:20.999Z"),
        (-5.0, "1970-01-01T00:00:00.000Z"),  # a clock before the epoch is clamped
        (float("nan"), "1970-01-01T00:00:00.000Z"),
        (float("-inf"), "1970-01-01T00:00:00.000Z"),
        (float("inf"), "9999-12-31T23:59:59.000Z"),
        (1e30, "9999-12-31T23:59:59.000Z"),
    ],
)
def test_format_ts(wall: float, expected: str) -> None:
    assert format_ts(wall) == expected


# --- record rules ----------------------------------------------------------------------------

LOGGED = [
    ("sent", sent(), "sent", 0, None, None),
    (
        "refused",
        sent(
            exit_code=20,
            code="refused",
            reason="link_scheme",
            level=None,
            bytes_=None,
            truncated=None,
            message_hash=None,
            http_status=None,
        ),
        "refused",
        20,
        "refused",
        "link_scheme",
    ),
    (
        "failed",
        sent(exit_code=12, code="rate_limited", http_status=429),
        "failed",
        12,
        "rate_limited",
        None,
    ),
    (
        "failed no response",
        sent(exit_code=12, code="network_error", http_status=None),
        "failed",
        12,
        "network_error",
        None,
    ),
    (
        "unknown",
        sent(exit_code=12, code="outcome_unknown", unknown_outcome=True, http_status=None),
        "outcome_unknown",
        12,
        "outcome_unknown",
        None,
    ),
    (
        "upstream",
        sent(exit_code=12, code="upstream_error", unknown_outcome=True, http_status=503),
        "outcome_unknown",
        12,
        "upstream_error",
        None,
    ),
    (
        "wrong host 2xx",
        sent(exit_code=12, code="wrong_host_response", unknown_outcome=True, http_status=204),
        "outcome_unknown",
        12,
        "wrong_host_response",
        None,
    ),
    (
        "wrong host other",
        sent(exit_code=12, code="wrong_host_response", http_status=302),
        "failed",
        12,
        "wrong_host_response",
        None,
    ),
    (
        "internal after writing",
        sent(
            exit_code=1,
            code="whatever",
            gate_writing=True,
            http_status=None,
            level=None,
            bytes_=None,
            truncated=None,
            message_hash=None,
        ),
        "outcome_unknown",
        1,
        "internal",
        None,
    ),
    (
        "unavailable input phase",
        sent(
            exit_code=12,
            code="unavailable",
            http_status=None,
            level=None,
            bytes_=None,
            truncated=None,
            message_hash=None,
        ),
        "failed",
        12,
        "unavailable",
        None,
    ),
]


@pytest.mark.parametrize(
    ("fields", "outcome", "exit_code", "code", "reason"),
    [c[1:] for c in LOGGED],
    ids=[c[0] for c in LOGGED],
)
def test_logged_outcomes_validate(
    fields: dict[str, Any], outcome: str, exit_code: int, code: str | None, reason: str | None
) -> None:
    built = build_record(wall_time=1_700_000_000.0, **fields)
    assert built is not None
    parsed = assert_valid("log", encode_record(built))
    assert (parsed["outcome"], parsed["exit"], parsed["code"], parsed["reason"]) == (
        outcome,
        exit_code,
        code,
        reason,
    )
    assert list(parsed) == FIELDS  # all fields, always, in the documented order


@pytest.mark.parametrize(
    "fields",
    [
        sent(exit_code=1, code="internal", gate_writing=False),
        sent(exit_code=2, code="usage"),
        sent(exit_code=2, code="config_invalid"),
        sent(exit_code=22, code=None),
        sent(exit_code=130, code=None),
        sent(exit_code=143, code=None),
        sent(exit_code=10),
        sent(exit_code=-1),
    ],
)
def test_exits_that_are_not_logged(fields: dict[str, Any]) -> None:
    assert build_record(wall_time=1.0, **fields) is None


def test_exit_one_without_the_writing_gate_and_gate_with_other_exits() -> None:
    # gate_writing only matters for exit 1: exit 2 stays unlogged whatever the gate says
    assert build_record(wall_time=1.0, **sent(exit_code=2, gate_writing=True)) is None
    assert build_record(wall_time=1.0, **sent(exit_code=22, gate_writing=True)) is None


@pytest.mark.parametrize(
    "fields",
    [
        sent(exit_code=20, code="refused", reason=None),
        sent(exit_code=20, code="refused", reason="not_a_reason"),
        sent(exit_code=12, code="refused"),
        sent(exit_code=12, code="host_rejected", unknown_outcome=True),
        sent(exit_code=12, code="outcome_unknown", unknown_outcome=False),
        sent(level=None),
        sent(bytes_=None),
        sent(truncated=None),
        sent(message_hash=None),
        sent(message_hash="NOT-A-HASH"),
        sent(http_status=None),
        sent(http_status=204),
    ],
)
def test_malformed_calls_are_refused_not_written(fields: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        build_record(wall_time=1.0, **fields)


def test_a_malformed_call_warns_once_and_writes_nothing(
    gw: FakeGateway, state: StateDir, warned: Lines, home: Path
) -> None:
    assert log_result(state, gw, enabled=True, **sent(level=None)) is False
    assert warned.lines == [STATE_WARNING]
    assert not (leaf(home) / LOG_NAME).exists()


def test_http_status_is_dropped_where_no_response_arrived() -> None:
    for code in ("credential_invalid", "unavailable", "network_error"):
        built = record(
            exit_code=12,
            code=code,
            http_status=200,
            level=None,
            bytes_=None,
            truncated=None,
            message_hash=None,
        )
        assert built["http_status"] is None
        assert_valid("log", encode_record(built))
    refused = record(
        exit_code=20,
        code="refused",
        reason="empty_message",
        http_status=200,
        level=None,
        bytes_=None,
        truncated=None,
        message_hash=None,
    )
    assert refused["http_status"] is None


@pytest.mark.parametrize(
    "over",
    [
        {"level": f"info\n{CANARY}"},
        {"level": "INFO"},
        {"actor": f"human:{CANARY} \n"},
        {"actor": "root"},
        {"actor": "human:" + "a" * 65},
        {"actor": "auto:é"},
        {"actor_source": CANARY},
        {"version": f"1.0\n{CANARY}"},
        {"version": ""},
        {"message_hash": CANARY},
        {"message_hash": "0123456789ABCDEF"},
        {"message_hash": "0123456789abcdef\n"},
        {"dedupe_hash": f"{CANARY}{CANARY}"},
        {"bytes_": -4},
        {"bytes_": "12"},
        {"bytes_": True},
        {"duration_ms": -1},
        {"duration_ms": "9"},
        {"http_status": 99999},
        {"http_status": "200"},
        {"truncated": "yes"},
    ],
)
def test_hostile_field_values_never_reach_the_record(over: dict[str, Any]) -> None:
    over = dict(over)
    # a hostile level or hash on a sent record is a bug, not output: use a refusal for those
    if set(over) & {"level", "message_hash", "bytes_", "truncated"}:
        over.update(exit_code=20, code="refused", reason="invalid_payload")
    elif "http_status" in over:
        over.update(exit_code=12, code="rate_limited")
    line = encode_record(record(**over))
    parsed = assert_valid("log", line)
    assert CANARY.encode() not in line
    assert list(parsed) == FIELDS
    assert line.count(b"\n") == 1 and line.endswith(b"\n")


def test_records_hold_only_hashes_of_the_text(gw: FakeGateway, state: StateDir, home: Path) -> None:
    message = f"secret text {CANARY} https://example.invalid/hook"
    fields = sent(
        message_hash=message_sha256("title", message), dedupe_hash=dedupe_key_sha256(CANARY)
    )
    assert log_result(state, gw, enabled=True, **fields)
    raw = (leaf(home) / LOG_NAME).read_bytes()
    for needle in (CANARY, "secret text", "example.invalid", "title"):
        assert needle.encode() not in raw


def test_a_record_is_under_one_kib_even_when_every_field_is_at_its_limit() -> None:
    line = encode_record(
        record(
            version="9" * 64,
            actor="human:" + "a" * 64,
            actor_source="flag",
            bytes_=10**15,
            duration_ms=10**15,
            dedupe_hash="f" * 16,
            exit_code=12,
            code="wrong_host_response",
            unknown_outcome=True,
            http_status=204,
        )
    )
    assert len(line) < 1024
    assert len(line) + 1 <= MAX_WRITE  # room for a repair LF


def test_golden_lines_are_pinned() -> None:
    walls = [1_700_000_000.0, 1_700_000_001.234, 1_700_000_002.5]
    cases = [
        sent(
            message_hash=message_sha256("Build", "done"),
            dedupe_hash=dedupe_key_sha256("k1"),
            actor="human:alice",
            actor_source="tty",
            bytes_=33,
            duration_ms=187,
        ),
        sent(
            exit_code=20,
            code="refused",
            reason="empty_message",
            level=None,
            bytes_=None,
            truncated=None,
            message_hash=None,
            http_status=None,
            duration_ms=3,
        ),
        sent(
            exit_code=12,
            code="upstream_error",
            unknown_outcome=True,
            http_status=503,
            level="error",
            bytes_=900,
            truncated=True,
            duration_ms=2500,
            actor="auto:ci",
            actor_source="flag",
            message_hash=message_sha256(None, "x" * 5),
        ),
    ]
    lines = [encode_record(record(wall, **case)) for wall, case in zip(walls, cases, strict=True)]
    expected = GOLDEN.read_bytes().splitlines(keepends=True)
    assert lines == expected
    for line in lines:
        assert_valid("log", line)


# --- writing, modes, log: false ---------------------------------------------------------------


def test_first_record_creates_a_private_log_and_lock(
    gw: FakeGateway, state: StateDir, home: Path, warned: Lines
) -> None:
    assert log_result(state, gw, enabled=True, **sent())
    log = leaf(home) / LOG_NAME
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert stat.S_IMODE((leaf(home) / LOCK_NAME).stat().st_mode) == 0o600
    assert log.read_bytes().endswith(b"}\n")
    assert len(assert_file_valid(log)) == 1
    assert warned.lines == []


def test_records_append_in_order_with_one_lf_each(
    gw: FakeGateway, state: StateDir, home: Path
) -> None:
    for number in range(5):
        assert log_result(state, gw, enabled=True, **sent(duration_ms=number))
    records = assert_file_valid(leaf(home) / LOG_NAME)
    assert [r["duration_ms"] for r in records] == [0, 1, 2, 3, 4]


def test_log_false_touches_nothing(gw: FakeGateway, home: Path, warned: Lines) -> None:
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=False, **sent()) is False
    assert not (home / ".local").exists()
    assert gw.events == []
    assert warned.lines == []


def test_unlogged_exit_touches_nothing(gw: FakeGateway, home: Path, warned: Lines) -> None:
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent(exit_code=2, code="usage")) is False
        assert log_result(state, gw, enabled=True, **sent(exit_code=1, code="internal")) is False
    assert not (home / ".local").exists()
    assert warned.lines == []


def test_the_lock_is_released_and_descriptors_are_closed(
    gw: FakeGateway, state: StateDir, home: Path
) -> None:
    before = len(os.listdir("/proc/self/fd"))
    assert log_result(state, gw, enabled=True, **sent())
    assert len(os.listdir("/proc/self/fd")) <= before + 1  # only the state directory descriptor
    other = os.open(leaf(home) / LOCK_NAME, os.O_RDWR)
    try:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)  # would raise if still held
    finally:
        os.close(other)


def test_one_write_call_per_record(gw: FakeGateway, state: StateDir) -> None:
    assert log_result(state, gw, enabled=True, **sent())
    assert gw.events.count("write_fd") == 1


# --- rotation --------------------------------------------------------------------------------


def seed(home: Path, size: int, *, name: str = LOG_NAME, mode: int = 0o600, tag: str = "") -> None:
    """A state file of exactly ``size`` bytes made of whole valid records (filler line last)."""
    directory = leaf(home)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    line = encode_record(record(duration_ms=777))
    body = line * (size // len(line))
    rest = size - len(body)
    if rest:
        # pad with one comment-free JSON-ish filler of exact length (not a record)
        body += b" " * (rest - 1) + b"\n"
    assert len(body) == size
    path = directory / name
    path.write_bytes(body if not tag else body.replace(b"777", tag.encode()[:3].ljust(3, b"0")))
    path.chmod(mode)


@pytest.mark.parametrize(
    ("size", "rotates"), [(ROTATE_AT - 1, False), (ROTATE_AT, True), (ROTATE_AT + 1, True)]
)
def test_rotation_boundary(
    gw: FakeGateway, home: Path, warned: Lines, size: int, rotates: bool
) -> None:
    seed(home, size)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent(duration_ms=5))
    directory = leaf(home)
    assert (directory / f"{LOG_NAME}.1").exists() is rotates
    if rotates:
        assert (directory / f"{LOG_NAME}.1").stat().st_size == size
        new = read_lines(directory / LOG_NAME)
        assert len(new) == 1 and json.loads(new[0])["duration_ms"] == 5
    else:
        assert read_lines(directory / LOG_NAME)[-1].startswith(b'{"ts"')
        assert (directory / LOG_NAME).stat().st_size > size


def test_rotation_shifts_three_generations_and_drops_the_oldest(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    directory = leaf(home)
    seed(home, ROTATE_AT, tag="aaa")
    for gen, tag in ((1, "bbb"), (2, "ccc"), (3, "ddd")):
        seed(home, 2048, name=f"{LOG_NAME}.{gen}", tag=tag)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent(duration_ms=1))
    assert b"aaa" in (directory / f"{LOG_NAME}.1").read_bytes()
    assert b"bbb" in (directory / f"{LOG_NAME}.2").read_bytes()
    assert b"ccc" in (directory / f"{LOG_NAME}.3").read_bytes()
    assert b"ddd" not in b"".join(p.read_bytes() for p in directory.iterdir() if p.is_file())
    assert not (directory / f"{LOG_NAME}.4").exists()
    assert sorted(p.name for p in directory.iterdir()) == sorted(
        [LOG_NAME, LOCK_NAME] + [f"{LOG_NAME}.{n}" for n in range(1, KEEP + 1)]
    )


def test_rotation_with_missing_generations(gw: FakeGateway, home: Path, warned: Lines) -> None:
    seed(home, ROTATE_AT)
    seed(home, 100, name=f"{LOG_NAME}.2")  # no .1, no .3
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent())
    directory = leaf(home)
    assert (directory / f"{LOG_NAME}.1").stat().st_size == ROTATE_AT
    assert (directory / f"{LOG_NAME}.3").stat().st_size == 100
    assert not (directory / f"{LOG_NAME}.2").exists()


def test_rotated_file_keeps_its_mode_and_the_new_log_is_0600(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    seed(home, ROTATE_AT, mode=0o400 | 0o200)
    seed(home, 10, name=f"{LOG_NAME}.1", mode=0o400)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent())
    directory = leaf(home)
    modes = {
        n: stat.S_IMODE((directory / n).stat().st_mode)
        for n in (LOG_NAME, f"{LOG_NAME}.1", f"{LOG_NAME}.2")
    }
    assert modes == {LOG_NAME: 0o600, f"{LOG_NAME}.1": 0o600, f"{LOG_NAME}.2": 0o400}
    assert all(m & 0o177 == 0 for m in modes.values())


def test_the_record_lands_in_the_new_log_not_in_the_rotated_file(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    """The reopen test: the descriptor opened before rotation points at ``.1`` afterwards."""
    seed(home, ROTATE_AT)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent(duration_ms=31337))
    directory = leaf(home)
    assert b"31337" not in (directory / f"{LOG_NAME}.1").read_bytes()
    assert json.loads((directory / LOG_NAME).read_bytes())["duration_ms"] == 31337
    assert (directory / f"{LOG_NAME}.1").stat().st_size == ROTATE_AT


def test_a_rotation_failure_skips_the_record_with_one_warning(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    seed(home, ROTATE_AT)
    gw.rename_errors[LOG_NAME] = OSError(errno.EROFS, "read-only")
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert warned.lines == [STATE_WARNING]
    assert (leaf(home) / LOG_NAME).stat().st_size == ROTATE_AT  # nothing appended past the cap


def test_a_directory_in_a_rotation_slot_skips_the_record(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    seed(home, ROTATE_AT)
    seed(home, 100, name=f"{LOG_NAME}.2")
    (leaf(home) / f"{LOG_NAME}.3").mkdir()
    (leaf(home) / f"{LOG_NAME}.3" / "x").write_text("x")
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert warned.lines == [STATE_WARNING]
    assert (leaf(home) / LOG_NAME).stat().st_size == ROTATE_AT  # not grown past the cap


def test_a_symlink_in_a_rotation_slot_is_replaced_not_followed(
    gw: FakeGateway, home: Path, warned: Lines, tmp_path: Path
) -> None:
    target = tmp_path / "victim"
    target.write_text("untouched")
    seed(home, ROTATE_AT)
    (leaf(home) / f"{LOG_NAME}.1").symlink_to(target)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent())
    assert target.read_text() == "untouched"
    assert not (leaf(home) / f"{LOG_NAME}.1").is_symlink()
    assert (leaf(home) / f"{LOG_NAME}.2").is_symlink()  # the link itself moved on, unfollowed


def test_time_going_backwards_still_writes_valid_ordered_by_append(
    gw: FakeGateway, state: StateDir, home: Path
) -> None:
    gw._wall_start = 1_700_000_100.0
    assert log_result(state, gw, enabled=True, **sent(duration_ms=1))
    gw._wall_start = 1_600_000_000.0
    assert log_result(state, gw, enabled=True, **sent(duration_ms=2))
    gw._wall_start = -10.0
    assert log_result(state, gw, enabled=True, **sent(duration_ms=3))
    records = assert_file_valid(leaf(home) / LOG_NAME)
    assert [r["duration_ms"] for r in records] == [1, 2, 3]  # append order, not time order
    assert records[2]["ts"].startswith("1970-01-01T")


# --- lock contention -------------------------------------------------------------------------


def hold_lock(home: Path) -> int:
    directory = leaf(home)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(directory / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def test_a_held_lock_skips_the_record_after_about_one_second_with_one_warning(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    fd = hold_lock(home)
    try:
        with StateDir(gw, str(home), warned) as state:
            start = gw.monotonic()
            assert log_result(state, gw, enabled=True, **sent()) is False
            waited = gw.monotonic() - start
            assert log_result(state, gw, enabled=True, **sent()) is False  # still one warning
    finally:
        os.close(fd)
    assert 1.0 <= waited < 1.1
    assert warned.lines == [STATE_WARNING]
    assert not (leaf(home) / LOG_NAME).exists() or (leaf(home) / LOG_NAME).stat().st_size == 0


def test_the_lock_is_polled_every_20_ms(gw: FakeGateway, home: Path, warned: Lines) -> None:
    gw.lock_held = True
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    sleeps = [float(e.split(":")[1]) for e in gw.events if e.startswith("sleep:")]
    assert sleeps and max(sleeps) <= 0.02 + 1e-9
    assert 49 <= len(sleeps) <= 51
    assert 49 <= gw.events.count("try_lock") <= 52


def test_a_lock_released_during_the_wait_is_taken(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    fd = hold_lock(home)
    released = {"done": False}
    real_sleep = gw.sleep

    def sleep(seconds: float) -> None:
        real_sleep(seconds)
        if gw.events.count("try_lock") == 5 and not released["done"]:
            released["done"] = True
            os.close(fd)

    gw.sleep = sleep  # type: ignore[method-assign]
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent())
    assert released["done"] and warned.lines == []
    assert len(assert_file_valid(leaf(home) / LOG_NAME)) == 1


def test_a_failing_flock_is_a_warning_not_an_exception(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    gw.lock_error = OSError(errno.ENOLCK, "no locks")
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert warned.lines == [STATE_WARNING]


# --- write failures --------------------------------------------------------------------------


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EROFS, errno.EDQUOT, errno.EIO, errno.EFBIG])
def test_write_errors_warn_once_and_leave_the_log_unchanged(
    gw: FakeGateway, home: Path, warned: Lines, code: int
) -> None:
    seed(home, 500)
    before = (leaf(home) / LOG_NAME).read_bytes()
    gw.write_error = OSError(code, os.strerror(code), f"/secret/{CANARY}")
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert warned.lines == [STATE_WARNING]
    assert CANARY not in "".join(warned.lines)
    assert (leaf(home) / LOG_NAME).read_bytes() == before


def test_a_short_write_is_cut_back_to_the_previous_end(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    seed(home, 500)
    before = (leaf(home) / LOG_NAME).read_bytes()
    gw.write_limit = 40  # a full disk accepts the first bytes only
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert warned.lines == [STATE_WARNING]
    assert (leaf(home) / LOG_NAME).read_bytes() == before
    assert "truncate_fd" in gw.events


def test_a_short_write_whose_cleanup_also_fails_still_only_warns(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    gw.write_limit = 7
    gw.truncate_error = OSError(errno.EROFS, "read-only")
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert warned.lines == [STATE_WARNING]


def test_the_next_record_after_a_torn_last_line_starts_on_its_own_line(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    good = encode_record(record(duration_ms=1))
    leaf(home).mkdir(parents=True, mode=0o700)
    (leaf(home) / LOG_NAME).write_bytes(good + good[:57])  # a crash mid-record
    (leaf(home) / LOG_NAME).chmod(0o600)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent(duration_ms=2))
    lines = read_lines(leaf(home) / LOG_NAME)
    assert len(lines) == 3
    assert json.loads(lines[0])["duration_ms"] == 1
    with pytest.raises(ValueError):
        json.loads(lines[1])  # the torn line stays what it was
    last = assert_valid("log", lines[2])
    assert last["duration_ms"] == 2
    assert lines[2].count(b"\n") == 1


def test_a_log_without_a_trailing_lf_and_a_blank_file(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    leaf(home).mkdir(parents=True, mode=0o700)
    (leaf(home) / LOG_NAME).write_bytes(b"")
    (leaf(home) / LOG_NAME).chmod(0o600)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent())
        assert log_result(state, gw, enabled=True, **sent())
    assert len(assert_file_valid(leaf(home) / LOG_NAME)) == 2  # no stray blank line


def test_an_oversized_record_is_never_written(gw: FakeGateway, state: StateDir, home: Path) -> None:
    huge = record()
    huge["actor"] = "auto:" + "a" * 2000
    assert append_record(state, gw, huge) is False
    assert not (leaf(home) / LOG_NAME).exists()


# --- hostile state files ---------------------------------------------------------------------


@pytest.mark.parametrize("name", [LOG_NAME, LOCK_NAME])
def test_a_fifo_symlink_or_hardlink_skips_the_record_with_one_warning(
    gw: FakeGateway, home: Path, warned: Lines, tmp_path: Path, name: str
) -> None:
    directory = leaf(home)
    directory.mkdir(parents=True, mode=0o700)
    os.mkfifo(directory / name)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert warned.lines == [STATE_WARNING]
    (directory / name).unlink()
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (directory / name).symlink_to(victim)
    with StateDir(gw, str(home), Lines()) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert victim.read_text() == "keep"
    (directory / name).unlink()
    victim.chmod(0o600)
    os.link(victim, directory / name)
    with StateDir(gw, str(home), Lines()) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert victim.read_text() == "keep"


def test_a_group_readable_log_is_refused_not_appended_to(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    seed(home, 100, mode=0o640)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert (leaf(home) / LOG_NAME).stat().st_size == 100
    assert warned.lines == [STATE_WARNING]


def test_a_fifo_in_a_rotation_slot_does_not_block(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    seed(home, ROTATE_AT)
    os.mkfifo(leaf(home) / f"{LOG_NAME}.1")
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent())  # rename replaces the FIFO entry
    assert stat.S_ISREG((leaf(home) / f"{LOG_NAME}.1").stat().st_mode)


def test_an_unusable_state_dir_writes_nothing_and_warns_once(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    leaf(home).parent.mkdir(parents=True)
    leaf(home).mkdir(mode=0o755)
    with StateDir(gw, str(home), warned) as state:
        assert log_result(state, gw, enabled=True, **sent()) is False
        assert log_result(state, gw, enabled=True, **sent()) is False
    assert warned.lines == [STATE_WARNING]
    assert list(leaf(home).iterdir()) == []


def test_a_second_writer_cannot_enter_while_the_first_is_between_size_check_and_write(
    gw: FakeGateway, home: Path, warned: Lines
) -> None:
    """Deterministic interleaving: writer B runs completely at the moment writer A has checked
    the size and is about to rotate. Without the lock B would rotate too and A's record would
    land in a file B just moved; with it B waits out its second and skips."""
    seed(home, ROTATE_AT)
    b_warned = Lines()
    outcome: dict[str, bool] = {}
    real_size = gw.file_size
    calls = {"n": 0}

    def file_size(fd: int) -> int:
        size = real_size(fd)
        calls["n"] += 1
        if calls["n"] == 1:  # A's first size check
            with StateDir(gw, str(home), b_warned) as other:
                outcome["b"] = log_result(other, gw, enabled=True, **sent(duration_ms=2))
        return size

    gw.file_size = file_size  # type: ignore[method-assign]
    with StateDir(gw, str(home), warned) as state:
        outcome["a"] = log_result(state, gw, enabled=True, **sent(duration_ms=1))
    assert outcome == {"b": False, "a": True}
    assert b_warned.lines == [STATE_WARNING] and warned.lines == []
    directory = leaf(home)
    assert json.loads((directory / LOG_NAME).read_bytes())["duration_ms"] == 1
    assert (directory / f"{LOG_NAME}.1").stat().st_size == ROTATE_AT
    assert not (directory / f"{LOG_NAME}.2").exists()  # rotated exactly once


# --- concurrent writers (real processes) ----------------------------------------------------


def test_concurrent_processes_lose_no_record_across_a_rotation(home: Path, tmp_path: Path) -> None:
    writers, per_writer = 3, 15
    state_home = tmp_path / "childhome"
    state_home.mkdir(mode=0o700)
    seed(state_home, ROTATE_AT - 2000)  # the writers' records cross the 1 MiB cap once
    go = tmp_path / "go"
    private = tmp_path / "private"
    private.mkdir()
    env = {
        "HOME": str(private),
        "XDG_CONFIG_HOME": str(private / "c"),
        "XDG_STATE_HOME": str(private / "s"),
        "PATH": os.environ.get("PATH", ""),
    }
    child = Path(__file__).resolve().parent / "log_writer_child.py"
    src = str(ROOT / "src")
    procs = [
        subprocess.Popen(
            [sys.executable, "-I", str(child), str(state_home), str(go), str(i), str(per_writer)],
            env={**env, "PYTHONPATH": src},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for i in range(writers)
    ]
    try:
        go.write_text("go")
        codes = [p.wait(timeout=60) for p in procs]
    finally:
        for p in procs:  # only the handles this test started
            if p.poll() is None:
                p.kill()
                p.wait(timeout=10)
    assert codes == [0] * writers
    directory = leaf(state_home)
    seen: list[tuple[int, int]] = []
    names = [LOG_NAME] + [f"{LOG_NAME}.{n}" for n in range(1, KEEP + 1)]
    assert (directory / f"{LOG_NAME}.1").exists()  # a rotation really happened
    for name in names:
        path = directory / name
        if not path.exists():
            continue
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        for line in read_lines(path):
            if line.strip():
                parsed = json.loads(line)  # no torn or interleaved line anywhere
                if parsed["duration_ms"] != 777:
                    seen.append((parsed["bytes"], parsed["duration_ms"]))
    assert sorted(seen) == sorted((i, n) for i in range(writers) for n in range(per_writer))
    assert "log.jsonl.4" not in {p.name for p in directory.iterdir()}


# --- housekeeping ----------------------------------------------------------------------------


def test_the_version_in_a_record_is_the_package_version() -> None:
    assert assert_valid("log", encode_record(record(version=__version__)))["version"] == __version__

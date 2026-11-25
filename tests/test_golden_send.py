"""Golden files for the real ``send`` path (#30): every ``--json`` output, human line, request body
and log record, compared as raw bytes.

Each scenario runs ``cli.main`` in-process through a fake gateway whose clock is virtual (see
``GoldenGateway``): every byte of every output is deterministic. The version is injected, the
credential is built from parts at runtime and never appears in a golden file.

For scenario ``name`` the files under ``tests/golden/send/`` are, when non-empty:

- ``name.stdout``: what the run printed on stdout (the ``--json`` document or error envelope);
- ``name.stderr``: the human lines on stderr;
- ``name.body``: the request body that was posted (the same bytes on every attempt);
- ``name.log``: the whole ``log.jsonl`` the run left in the state directory.

A missing file means "empty". A mismatch prints what changed and what to do: the goldens are
reviewed by hand against docs/interface.md, never blindly regenerated, because a golden made from
the code can bake in a bug. The exit code of every scenario is in the table below, so a change of
exit code fails here too, next to the table of docs/interface.md (Exit codes).
"""

from __future__ import annotations

import http.client
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from slack_notice import cli
from slack_notice.gateway import SourceRead
from tests.fake_gateway import Attempt, FakeGateway, Reply, cert_verify_error
from tests.harness import assert_valid, load_schema
from tests.secret_scan import Corpus, Secret
from tests.send_harness import SEND, Sent, go, stdin_json, write_config

GOLDEN = Path(__file__).resolve().parent / "golden"
SEND_DIR = GOLDEN / "send"
VERSION = "1.2.3"
WALL_START = 1_700_000_000.0  # 2023-11-14T22:13:20.000Z
SUFFIXES = (".stdout", ".stderr", ".body", ".log")


class GoldenGateway(FakeGateway):
    """The fake gateway with a virtual clock: time moves only when the code sleeps or a scripted
    delay is spent, so ``ts`` and ``duration_ms`` are the same on every machine and run."""

    BASE = 1000.0

    def monotonic(self) -> float:
        with self._lock:  # pyright: ignore[reportPrivateUsage]
            return self.BASE + self._skew  # pyright: ignore[reportPrivateUsage]

    def wall_time(self) -> float:
        self.calls.append("wall_time")
        return self._wall_start + (self.monotonic() - self.BASE)  # pyright: ignore


def compare(path: Path, actual: bytes) -> None:
    """The one place a golden is compared (a missing file is an empty golden)."""
    expected = path.read_bytes() if path.exists() else b""
    if actual != expected:
        pytest.fail(
            f"golden mismatch: {path.relative_to(GOLDEN.parent.parent)}\n"
            f"  expected: {expected!r}\n"
            f"  actual:   {actual!r}\n"
            "A golden changes only on purpose: read the new bytes against docs/interface.md "
            "(Output, Log, Rendering) by hand before accepting them. Never accept a change "
            "just because the code produces it.",
            pytrace=False,
        )


# --- attempts with fixed virtual delays (binary fractions: exact in a float) ------------------


def at(status: int = 200, body: bytes = b'{"ok":true}', wait: float = 0.5) -> Attempt:
    """One attempt that takes 0.125 + 0.25 + 0.5 = 875 ms of virtual time to answer."""
    reply = Reply(status=status, body=body, first_byte_delay=wait)
    return Attempt(connect_delay=0.125, tls_delay=0.25, reply=reply)


def failing(**kwargs: Any) -> Attempt:
    kwargs.setdefault("connect_delay", 0.125)
    return Attempt(**kwargs)


OK = at()
RATE = at(429, b"{}")
SLOW_RATE = at(429, b"{}", wait=1.125)  # 1.5 s in all: the 2 s wait no longer fits in 3 s

LONG_MESSAGE = "word " * 1000  # over the 3000 character budget


@dataclass
class Scenario:
    name: str
    exit: int
    argv: list[str] = field(default_factory=lambda: list(SEND))
    stdin: bytes | SourceRead | None = None
    attempts: list[Attempt] = field(default_factory=list)
    config: str | None = None  # config file text; None means no config file
    tty: bool = False
    env: dict[str, str] | None = None  # None: the fake webhook environment
    setup: Callable[[FakeGateway, pytest.MonkeyPatch], None] | None = None
    connections: int | None = None  # expected number of connections (default: len(attempts))


HELLO = stdin_json(title="Build", message="all green", level="warn", link="https://a.example/x")
PLAIN = stdin_json(message="hi")
ACTOR = ["--actor", "auto:ci"]
SHORT = "timeout: 3s\n"


def raising_worker(*, after_writing: bool) -> Callable[[FakeGateway, pytest.MonkeyPatch], None]:
    def setup(_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> None:
        def make(*_a: Any, **_k: Any) -> Any:
            def work(deadline: Any) -> Any:
                if after_writing:
                    assert deadline.enter_writing()
                raise RuntimeError("boom")

            return work

        monkeypatch.setattr(cli, "attempt_work", make)

    return setup


def held_send_lock(gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> None:
    """Another process holds send.lock; the log lock is free.

    Kept here, not imported: the same few lines exist in tests/test_send_runtime.py as a private
    helper of that module, and importing one test module from another is worse than the copy.
    """
    from slack_notice import log

    real = log.log_result

    def freed(*args: Any, **kwargs: Any) -> bool:
        gateway.lock_held = False
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "log_result", freed)
    gateway.lock_held = True


def tls_failure() -> Attempt:
    return failing(tls_error=cert_verify_error())


SCENARIOS = [
    # --- exit 0: sent ---
    Scenario("sent", 0, [*SEND, *ACTOR, "--dedupe-key=k-1"], HELLO, [OK]),
    Scenario(
        "sent_non_ascii",
        0,
        [*SEND, "--actor", "human:alice"],
        stdin_json(
            title="Caf\u00e9 \u2615 \u65e5\u672c\u8a9e",
            message="na\u00efve \U0001f468\u200d\U0001f469\u200d\U0001f467 \U0001f680 ok",
            level="info",
        ),
        [OK],
    ),
    Scenario("sent_actor_from_tty", 0, ["send", "--json", "--message", "hi"], None, [OK], tty=True),
    Scenario("sent_no_actor", 0, SEND, PLAIN, [OK]),
    Scenario(
        "sent_escapes",
        0,
        SEND,
        stdin_json(message='q"uote \\ back\ttab\nline <!here> & </x>', level="action"),
        [OK],
        config="body_variable: slack_text\n",
    ),
    Scenario("sent_after_429", 0, SEND, HELLO, [RATE, OK]),
    Scenario("sent_message_cut", 0, SEND, stdin_json(message=LONG_MESSAGE, level="error"), [OK]),
    Scenario("sent_human", 0, ["send", "--stdin-json"], HELLO, [OK]),
    Scenario(
        "sent_flags_only", 0, ["send", "--json", "--title", "T", "--message", "M"], None, [OK]
    ),
    # --- exit 22: disabled ---
    Scenario("disabled", 22, SEND, HELLO, config="enabled: false\n"),
    Scenario("disabled_human", 22, ["send", "--stdin-json"], HELLO, config="enabled: false\n"),
    # --- dry runs (exit 0, nothing sent, nothing logged) ---
    Scenario("dry_run", 0, ["send", "--dry-run", "--json", "--stdin-json"], HELLO),
    Scenario("dry_run_human", 0, ["send", "--dry-run", "--stdin-json"], HELLO),
    Scenario(
        "dry_run_non_ascii",
        0,
        ["send", "--dry-run", "--json", "--stdin-json", "--dedupe-key=k-1"],
        stdin_json(title="\u65e5\u672c\u8a9e", message="caf\u00e9 \U0001f680", level="action"),
    ),
    Scenario(
        "dry_run_message_cut",
        0,
        ["send", "--dry-run", "--json", "--stdin-json"],
        stdin_json(message=LONG_MESSAGE),
    ),
    # --- exit 2: usage and configuration ---
    Scenario("usage_unknown_flag", 2, ["send", "--json", "--bogus"]),
    Scenario("usage_two_sources", 2, [*SEND, "--title", "T"], HELLO),
    Scenario("usage_json_equals", 2, ["send", "--json=1", "--stdin-json"]),
    Scenario("config_invalid", 2, SEND, HELLO, config="max_chars: 5\n"),
    # --- exit 20: refused (logged, nothing sent) ---
    Scenario("refused_unknown_field", 20, SEND, b'{"message":"m","extra":"x"}'),
    Scenario("refused_wrong_type", 20, SEND, b'{"message":["a"]}'),
    Scenario("refused_bad_level", 20, SEND, b'{"message":"m","level":"loud"}'),
    Scenario("refused_lone_surrogate", 20, SEND, b'{"message":"a\\ud800b"}'),
    Scenario("refused_not_json", 20, SEND, b"not json"),
    Scenario("refused_empty_message", 20, SEND, stdin_json(title="t", level="error")),
    Scenario(
        "refused_link_invalid", 20, SEND, stdin_json(message="m", link='https://a.example/"x')
    ),
    Scenario("refused_link_scheme", 20, SEND, stdin_json(message="m", link="ftp://a.example/")),
    Scenario("refused_human", 20, ["send", "--stdin-json"], stdin_json(title="t")),
    # --- exit 12: failed, nothing sent, permanent ---
    Scenario("credential_invalid", 12, SEND, HELLO, env={}),
    Scenario("host_rejected", 12, SEND, HELLO, [at(400, b'{"error":"invalid_blocks"}')]),
    Scenario("auth_required_403", 12, SEND, HELLO, [at(403, b"{}")]),
    Scenario("auth_required_404", 12, SEND, HELLO, [at(404, b"{}")]),
    Scenario("wrong_host_response_302", 12, SEND, HELLO, [at(302, b"")]),
    # --- exit 12: not sent, worth retrying ---
    Scenario("rate_limited", 12, SEND, HELLO, [RATE, RATE, RATE]),
    Scenario(
        "rate_limited_wait_does_not_fit",
        12,
        SEND,
        HELLO,
        [SLOW_RATE, OK],
        config=SHORT,
        connections=1,
    ),
    Scenario(
        "rate_limited_second_wait_does_not_fit",
        12,
        SEND,
        HELLO,
        [RATE, RATE, OK],
        config="timeout: 5s\n",
        connections=2,
    ),
    Scenario(
        "network_error",
        12,
        SEND,
        HELLO,
        [
            failing(connect_error=ConnectionRefusedError()),
            failing(connect_error=ConnectionRefusedError()),
        ],
    ),
    Scenario("network_error_tls", 12, SEND, HELLO, [tls_failure()]),
    Scenario(
        "network_error_deadline_cuts_wait",
        12,
        SEND,
        HELLO,
        [failing(connect_error=ConnectionRefusedError(), connect_delay=1.25), OK],
        config=SHORT,
        connections=1,
    ),
    Scenario("unavailable_input", 12, SEND, SourceRead(b'{"messag', timed_out=True)),
    Scenario("unavailable_lock", 12, SEND, HELLO, config="timeout: 3s\n", setup=held_send_lock),
    # --- exit 12: possibly delivered ---
    Scenario("upstream_error", 12, SEND, HELLO, [at(500, b"{}")]),
    Scenario("wrong_host_response_200_body", 12, SEND, HELLO, [at(200, b'{"ok":false}')]),
    Scenario("wrong_host_response_204", 12, SEND, HELLO, [at(204, b"")]),
    Scenario(
        "wrong_host_response_not_http",
        12,
        SEND,
        HELLO,
        [Attempt(reply=http.client.BadStatusLine("x"))],
    ),
    Scenario(
        "outcome_unknown_write_failure",
        12,
        SEND,
        HELLO,
        [Attempt(write_error=ConnectionResetError())],
    ),
    Scenario("outcome_unknown_reset", 12, SEND, HELLO, [Attempt(reply=ConnectionResetError())]),
    # --- exit 1: internal ---
    Scenario("internal_after_write", 1, SEND, HELLO, setup=raising_worker(after_writing=True)),
    Scenario("internal_before_write", 1, SEND, HELLO, setup=raising_worker(after_writing=False)),
]
NAMES = [s.name for s in SCENARIOS]


def run(scenario: Scenario, gateway: GoldenGateway, tmp_path: Path) -> Sent:
    gateway.script(*scenario.attempts)
    config = None if scenario.config is None else write_config(tmp_path, scenario.config)
    kwargs: dict[str, Any] = {} if scenario.env is None else {"env": scenario.env}
    return go(
        scenario.argv, gateway, stdin=scenario.stdin, config=config, tty=scenario.tty, **kwargs
    )


@pytest.fixture
def golden_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    home = tmp_path / "gwhome"
    home.mkdir(mode=0o700)
    gateway = GoldenGateway(home=str(home), login_name="tester", wall_start=WALL_START)
    monkeypatch.setattr(cli, "__version__", VERSION)
    yield gateway
    gateway.release_stalls()
    gateway.assert_clean()


def outputs(sent: Sent, gateway: FakeGateway) -> dict[str, bytes]:
    bodies = {body for connection in gateway.connections for _path, body in connection.requests}
    assert len(bodies) <= 1, "every attempt of one send posts the same body"
    return {
        ".stdout": sent.out,
        ".stderr": sent.err,
        ".body": bodies.pop() if bodies else b"",
        ".log": sent.state_files.get("log.jsonl", b""),
    }


@pytest.mark.parametrize("scenario", SCENARIOS, ids=NAMES)
def test_golden_send_outputs(
    scenario: Scenario,
    golden_gateway: GoldenGateway,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if scenario.setup is not None:
        scenario.setup(golden_gateway, monkeypatch)
    gateway = golden_gateway
    gateway.allow_unconsumed_script = scenario.connections is not None
    sent = run(scenario, gateway, tmp_path)
    assert sent.code == scenario.exit, (sent.stdout, sent.stderr)
    expected_connections = (
        len(scenario.attempts) if scenario.connections is None else scenario.connections
    )
    assert len(gateway.connections) == expected_connections
    for suffix, data in outputs(sent, gateway).items():
        compare(SEND_DIR / f"{scenario.name}{suffix}", data)


@pytest.mark.parametrize("name", NAMES)
def test_golden_send_outputs_match_the_schemas(name: str) -> None:
    """The committed golden bytes (not just a fresh run) are valid against the schemas."""
    stdout = SEND_DIR / f"{name}.stdout"
    if stdout.exists():
        document = json.loads(stdout.read_bytes())
        schema = "cli/error" if "error" in document else "cli/send"
        assert_valid(schema, stdout.read_bytes())
    log_file = SEND_DIR / f"{name}.log"
    if log_file.exists():
        for line in log_file.read_bytes().split(b"\n")[:-1]:
            assert_valid("log", line)


# --- coverage of the tables of docs/interface.md ----------------------------------------------


def goldens() -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for path in sorted(SEND_DIR.iterdir()):
        found.setdefault(path.stem, {})[path.suffix] = path.read_bytes()
    return found


def test_every_golden_file_belongs_to_a_scenario_and_no_scenario_is_empty() -> None:
    assert len(NAMES) == len(set(NAMES))
    found = goldens()
    assert set(found) == set(NAMES), set(found) ^ set(NAMES)
    for path in SEND_DIR.iterdir():
        assert path.suffix in SUFFIXES and path.stat().st_size > 0, path
    for name in NAMES:
        assert set(found[name]) & {".stdout", ".stderr"}, name


def error_envelopes() -> list[dict[str, Any]]:
    result = []
    for entry in goldens().values():
        if ".stdout" in entry:
            document = json.loads(entry[".stdout"])
            if "error" in document:
                result.append(document["error"])
    return result


def interface_exit_table() -> dict[int, set[str]]:
    """Exit code -> the backticked codes (or reasons) of that row of the Exit codes table."""
    text = (Path(__file__).resolve().parent.parent / "docs" / "interface.md").read_text("utf-8")
    section = text.split("## Exit codes", 1)[1].split("### Error envelope", 1)[0]
    table: dict[int, set[str]] = {}
    for row in section.splitlines():
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        if row.startswith("|") and len(cells) == 3 and cells[0].isdigit():
            table[int(cells[0])] = set(re.findall(r"`([a-z_]+)`", cells[2]))
    return table


def test_every_exit_code_and_every_error_code_of_the_table_has_a_json_golden() -> None:
    defs = load_schema("defs")["$defs"]
    schema_codes = set(defs["error_code"]["enum"])
    schema_reasons = set(defs["refusal_reason"]["enum"])
    table = interface_exit_table()
    assert set(table) == {0, 1, 2, 12, 20, 22}, table
    # the doc table lists the codes of the exit 1, 2 and 12 rows and the reasons of the 20 row
    assert table[1] | table[2] | table[12] | {"refused"} == schema_codes
    assert table[20] == schema_reasons
    codes = {e["code"] for e in error_envelopes()}
    assert codes == schema_codes
    reasons = {e["reason"] for e in error_envelopes() if e["code"] == "refused"}
    assert reasons == schema_reasons
    assert {s.exit for s in SCENARIOS} == set(table)
    outcomes = {
        json.loads(entry[".stdout"])["outcome"]
        for entry in goldens().values()
        if ".stdout" in entry and "outcome" in json.loads(entry[".stdout"])
    }
    assert outcomes == {"sent", "dry_run", "disabled"}


def log_records() -> list[dict[str, Any]]:
    records = []
    for entry in goldens().values():
        for line in entry.get(".log", b"").split(b"\n")[:-1]:
            records.append(json.loads(line))
    return records


def test_a_log_record_exists_for_every_outcome_and_code_of_the_schema() -> None:
    records = log_records()
    schema = load_schema("log")
    assert {r["outcome"] for r in records} == set(schema["properties"]["outcome"]["enum"])
    assert {r["exit"] for r in records} == set(schema["properties"]["exit"]["enum"])
    assert {(r["outcome"], r["code"], r["reason"]) for r in records} == {
        ("sent", None, None),
        ("refused", "refused", "invalid_payload"),
        ("refused", "refused", "empty_message"),
        ("refused", "refused", "link_invalid"),
        ("refused", "refused", "link_scheme"),
        ("failed", "host_rejected", None),
        ("failed", "auth_required", None),
        ("failed", "credential_invalid", None),
        ("failed", "wrong_host_response", None),
        ("failed", "rate_limited", None),
        ("failed", "network_error", None),
        ("failed", "unavailable", None),
        ("outcome_unknown", "upstream_error", None),
        ("outcome_unknown", "wrong_host_response", None),
        ("outcome_unknown", "outcome_unknown", None),
        ("outcome_unknown", "internal", None),
    }
    assert {r["actor_source"] for r in records} == {"flag", "tty", "default"}


def test_unlogged_scenarios_leave_no_log_golden() -> None:
    found = goldens()
    for name in (
        "dry_run",
        "dry_run_human",
        "dry_run_non_ascii",
        "dry_run_message_cut",
        "disabled",
        "disabled_human",
        "usage_unknown_flag",
        "usage_two_sources",
        "usage_json_equals",
        "config_invalid",
        "internal_before_write",
    ):
        assert ".log" not in found[name], name


def test_the_retry_goldens_pin_the_waits() -> None:
    by_name = {e["code"]: e for e in error_envelopes() if e["code"] == "rate_limited"}
    assert by_name["rate_limited"]["retry_after_s"] in (2, 2.0, 4, 4.0)
    waits = {}
    for name in (
        "rate_limited",
        "rate_limited_wait_does_not_fit",
        "rate_limited_second_wait_does_not_fit",
    ):
        waits[name] = json.loads(goldens()[name][".stdout"])["error"]["retry_after_s"]
    assert waits == {
        "rate_limited": 4,
        "rate_limited_wait_does_not_fit": 2,
        "rate_limited_second_wait_does_not_fit": 4,
    }
    tls = json.loads(goldens()["network_error_tls"][".stdout"])["error"]
    refused = json.loads(goldens()["network_error"][".stdout"])["error"]
    cut = json.loads(goldens()["network_error_deadline_cuts_wait"][".stdout"])["error"]
    assert (tls["retryable"], tls["details"]["tls"]) == (False, True)
    assert (refused["retryable"], refused["details"]["tls"]) == (True, False)
    assert cut["retryable"] is True


def test_a_429_is_retried_exactly_twice_even_when_a_third_wait_would_fit(
    golden_gateway: GoldenGateway, tmp_path: Path
) -> None:
    """docs/interface.md (Retries): up to two 429 retries, after 2 s and then 4 s; the third 429
    ends the send with retry_after_s 4 (it has no wait of its own). A 60 s deadline leaves room
    for a third wait, so only the retry count stops the send; a fourth answer is never asked for."""
    golden_gateway.allow_unconsumed_script = True
    sent = run(
        Scenario("x", 12, stdin=HELLO, config="timeout: 60s\n", attempts=[RATE] * 4 + [OK]),
        golden_gateway,
        tmp_path,
    )
    assert sent.code == 12
    assert len(golden_gateway.connections) == 3
    error = json.loads(sent.out)["error"]
    assert error["code"] == "rate_limited" and error["retry_after_s"] == 4.0
    sleeps = [c for c in golden_gateway.events if c.startswith("sleep:")]
    waits = [float(c.split(":", 1)[1]) for c in sleeps if float(c.split(":", 1)[1]) >= 1.0]
    assert waits == [2.0, 4.0]


# --- no secret, no machine, no clock in any golden --------------------------------------------


def all_golden_files() -> list[Path]:
    return sorted(p for p in GOLDEN.rglob("*") if p.is_file())


def test_no_golden_file_holds_the_webhook_url_or_any_part_of_it() -> None:
    corpus = Corpus()
    for path in all_golden_files():
        corpus.add(str(path.relative_to(GOLDEN)), path.read_bytes())
    assert corpus.hits(Secret()) == []
    for path in all_golden_files():
        data = path.read_bytes()
        assert b"hooks.slack.com" not in data and b"/triggers/" not in data, path


def test_no_golden_file_holds_a_path_a_home_or_a_real_timestamp(tmp_path: Path) -> None:
    for path in all_golden_files():
        text = path.read_text(encoding="utf-8")
        for needle in ("/home/", "/tmp/", "/storage/", "/Users/", "C:\\", str(tmp_path)):
            assert needle not in text, (path, needle)
        for line in text.split("\n"):
            if '"ts":"' in line:
                ts = json.loads(line)["ts"]
                assert ts.startswith("2023-11-14T22:1"), (path, ts)  # from the fake clock


def test_every_log_golden_of_the_send_path_carries_the_injected_version() -> None:
    """The release job bumps the real version: a golden must never carry it."""
    records = log_records()
    assert records and {r["version"] for r in records} == {VERSION}

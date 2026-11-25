"""The real `send` (steps 1 to 7) end to end against the fake gateway (#28).

Every test runs ``cli.main`` in-process with the fake gateway and scripted attempts: no real
sleeping, no network, no real Slack. The fake credential is built from parts.
"""

from __future__ import annotations

import http.client
import json
import os
import signal
import threading
from pathlib import Path
from typing import Any

import pytest

from slack_notice import __version__, cli, log, webhook
from slack_notice.gateway import SourceRead
from slack_notice.render import render
from tests.fake_gateway import (
    Attempt,
    FakeConnection,
    FakeGateway,
    Reply,
    cert_verify_error,
)
from tests.harness import assert_valid
from tests.send_harness import (
    CANARY,
    ENV,
    ENV_NAME,
    PATH,
    SEND,
    URL,
    Sent,
    go,
    state_path,
    stdin_json,
    write_config,
)

HELLO = stdin_json(title="Build", message="all green", level="warn", link="https://a.example/x")
OK = Attempt()


def log_text(sent: Sent) -> str:
    return sent.state_files.get("log.jsonl", b"").decode()


# --- the success path ---------------------------------------------------------------------------


def test_a_send_posts_the_rendered_body_and_prints_the_schema_object(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK)
    sent = go([*SEND, "--dedupe-key", "k-1"], fake_gateway, stdin=HELLO)
    assert sent.code == 0 and sent.exited and sent.stderr == ""
    document = assert_valid("cli/send", sent.out)
    assert sent.stdout.count("\n") == 1
    (connection,) = fake_gateway.connections
    ((path, body),) = connection.requests
    assert path == PATH
    # the body is posted as rendered, never re-serialized; its length is the reported bytes
    expected = render(
        cli.sanitize_loaded(json.loads(HELLO)),
        {"max_chars": 3000, "body_variable": "body", "level_prefix": cli_prefixes()},
    )
    assert body == expected.body
    assert list(document) == [
        "outcome",
        "tool",
        "level",
        "truncated",
        "bytes",
        "duration_ms",
        "http_status",
        "dedupe_key",
    ]
    assert document["outcome"] == "sent" and document["http_status"] == 200
    assert (document["level"], document["bytes"], document["truncated"]) == (
        "warn",
        len(body),
        False,
    )
    assert document["dedupe_key"] == "k-1" and "rendered" not in document


def cli_prefixes() -> dict[str, str]:
    from slack_notice.config import DEFAULTS

    return DEFAULTS["level_prefix"]


def test_the_human_line_is_on_stderr_and_stdout_is_empty(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK)
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO)
    assert (sent.code, sent.stdout) == (0, "")
    assert sent.stderr.startswith("sent (warn, ") and sent.stderr.endswith(" ms)\n")


def test_quiet_suppresses_the_sent_line_and_verbose_adds_one_line_per_phase(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK, OK)
    quiet = go(["send", "--quiet", "--stdin-json"], fake_gateway, stdin=HELLO)
    verbose = go(["send", "--verbose", "--stdin-json"], fake_gateway, stdin=HELLO)
    assert quiet.stderr == ""
    names = [line.split(":")[0] for line in verbose.stderr.splitlines()]
    # the log line comes last: the result is printed before the log step
    assert names[:3] == ["input", "render", "send"] and names[3].startswith("sent (")
    assert names[4:] == ["log"]
    assert CANARY not in verbose.stderr and "hooks.slack.com" not in verbose.stderr


def test_the_flags_path_never_reads_stdin(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK)
    sent = go(["send", "--json", "--message", "hi"], fake_gateway)
    assert sent.code == 0 and fake_gateway.source_reads == 0


def test_the_log_record_has_hashes_of_the_sanitized_text_and_never_the_key(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK)
    sent = go(
        [*SEND, "--dedupe-key", "my-key-123", "--actor", "auto:cron"], fake_gateway, stdin=HELLO
    )
    (record,) = sent.records
    assert record["outcome"] == "sent" and (record["exit"], record["code"]) == (0, None)
    assert record["message_sha256"] == log.message_sha256("Build", "all green")
    assert record["dedupe_key_sha256"] == log.dedupe_key_sha256("my-key-123")
    assert (record["level"], record["http_status"], record["truncated"]) == ("warn", 200, False)
    assert record["bytes"] == json.loads(sent.stdout)["bytes"]
    assert (record["actor"], record["actor_source"], record["version"]) == (
        "auto:cron",
        "flag",
        __version__,
    )
    assert b"my-key-123" not in sent.everything.replace(b'"dedupe_key":"my-key-123"', b"")
    assert "Build" not in log_text(sent) and "all green" not in log_text(sent)


def test_an_absent_title_hashes_as_the_empty_string_and_no_key_is_null(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK)
    sent = go(["send", "--message", "m"], fake_gateway)
    (record,) = sent.records
    assert record["message_sha256"] == log.message_sha256(None, "m")
    assert record["dedupe_key_sha256"] is None


def test_the_result_is_printed_and_flushed_before_the_log_record_exists(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK)
    seen: list[bool] = []

    class Spy:
        def __init__(self) -> None:
            self.data = b""

        def write(self, data: bytes) -> int:
            seen.append((state_path(fake_gateway) / "log.jsonl").exists())
            self.data += data
            return len(data)

        def flush(self) -> None:
            seen.append((state_path(fake_gateway) / "log.jsonl").exists())

    spy = Spy()
    sent = go(["send", "--json", "--message", "m"], fake_gateway, out=spy)
    assert seen and not any(seen)  # every write and flush came before the record
    assert len(sent.records) == 1 and json.loads(spy.data)["outcome"] == "sent"


def test_the_lock_is_released_before_the_log_record_is_written(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(OK)
    go(["send", "--message", "m"], fake_gateway)
    events = fake_gateway.events
    unlock = events.index("unlock")
    log_open = events.index("open_state_file:log.lock")
    assert unlock < log_open
    assert events.count("unlock") == 2  # the send lock, then the log lock; never overlapping


# --- disabled and exit 2 ------------------------------------------------------------------------


def test_disabled_exits_22_without_reading_stdin_or_the_environment(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    config = write_config(tmp_path, "enabled: false\n")
    sent = go([*SEND], fake_gateway, stdin=HELLO, config=config)
    assert (sent.code, sent.exited) == (22, False)
    assert assert_valid("cli/send", sent.out) == {"outcome": "disabled"}
    assert fake_gateway.source_reads == 0 and fake_gateway.connections == []
    assert "environ" not in fake_gateway.calls
    assert not state_path(fake_gateway).exists()


def test_disabled_without_json_is_one_stderr_line(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    config = write_config(tmp_path, "enabled: false\n")
    sent = go(["send", "--message", "m"], fake_gateway, config=config)
    assert (sent.code, sent.stdout, sent.stderr) == (22, "", "disabled in config\n")


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--json", "--stdin-json", "--message", "m"],
        ["send", "--json", "--stdin-json", "--file", "x.json", "--dedupe-key=k"],
        ["send", "--json", "--title", "t"],
        ["send", "--json", "--stdin-json", "--file", "/nonexistent-x"],
    ],
)
def test_exit_2_beats_disabled(argv: list[str], fake_gateway: FakeGateway, tmp_path: Path) -> None:
    config = write_config(tmp_path, "enabled: false\n")
    sent = go(argv, fake_gateway, config=config)
    assert sent.code == 2 and sent.error["code"] == "usage"
    assert fake_gateway.source_reads == 0


def test_a_bad_config_is_exit_2_before_enabled_and_before_input(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    config = write_config(tmp_path, "enabled: false\ntimeout: 1\n")
    sent = go(SEND, fake_gateway, stdin=HELLO, config=config)
    assert sent.code == 2 and sent.error["code"] == "config_invalid"
    assert fake_gateway.source_reads == 0


def test_a_file_problem_is_exit_2_and_not_logged(fake_gateway: FakeGateway, tmp_path: Path) -> None:
    sent = go(["send", "--json", "--file", str(tmp_path / "missing.json")], fake_gateway)
    assert (sent.code, sent.error["code"], sent.exited) == (2, "usage", False)
    assert sent.records == [] and not state_path(fake_gateway).exists()


def test_the_home_is_looked_up_once_and_the_state_dir_only_for_a_real_send(
    fake_gateway: FakeGateway,
) -> None:
    fake_gateway.script(OK)
    go(["send", "--message", "m"], fake_gateway)
    assert fake_gateway.home_lookups == 1


# --- refusals ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "reason", "pointer"),
    [
        (b"not json", "invalid_payload", ""),
        (stdin_json(title="t"), "empty_message", None),
        (stdin_json(message="m", link='https://a.example/"x'), "link_invalid", None),
        (stdin_json(message="m", link="ftp://a.example/"), "link_scheme", None),
    ],
)
def test_a_refusal_has_the_envelope_the_line_and_a_refused_record_and_a_dry_run_is_unlogged(
    body: bytes, reason: str, pointer: str | None, fake_gateway: FakeGateway
) -> None:
    sent = go(SEND, fake_gateway, stdin=body)
    assert (sent.code, sent.exited) == (20, True)
    error = sent.error
    assert (error["code"], error["reason"]) == ("refused", reason)
    assert (error["retryable"], error["unknown_outcome"]) == (None, None)
    if pointer is not None:
        assert error["details"] == {"pointer": pointer}
    assert sent.stderr == f"refused ({reason}): {error['message']}\n"
    (record,) = sent.records
    assert (record["outcome"], record["exit"], record["code"], record["reason"]) == (
        "refused",
        20,
        "refused",
        reason,
    )
    assert record["message_sha256"] is None and record["bytes"] is None
    assert fake_gateway.connections == [] and "environ" not in fake_gateway.calls
    # the same input as a dry run: the same envelope, nothing logged
    again = go(["send", "--dry-run", "--json", "--stdin-json"], fake_gateway, stdin=body)
    assert (again.code, again.error) == (20, error)
    assert len(again.records) == 1  # still only the first record


def test_a_refused_link_is_never_echoed(fake_gateway: FakeGateway) -> None:
    link = "https://" + CANARY + '.example/"x'
    sent = go(SEND, fake_gateway, stdin=stdin_json(message="m", link=link))
    assert sent.code == 20 and CANARY.encode() not in sent.everything


def test_a_refusal_with_a_valid_level_logs_the_level(fake_gateway: FakeGateway) -> None:
    sent = go(SEND, fake_gateway, stdin=stdin_json(level="error"))
    (record,) = sent.records
    assert (record["reason"], record["level"]) == ("empty_message", "error")


# --- input timeout ---------------------------------------------------------------------------------


def test_an_input_timeout_is_unavailable_input_logged_as_failed(fake_gateway: FakeGateway) -> None:
    sent = go(SEND, fake_gateway, stdin=SourceRead(b'{"messag', timed_out=True))
    assert (sent.code, sent.exited) == (12, True)
    error = sent.error
    assert error["code"] == "unavailable" and error["details"] == {"phase": "input"}
    assert (error["retryable"], error["unknown_outcome"]) == (True, False)
    assert error["message"] == webhook.unavailable("input").message
    assert error == webhook.unavailable("input").envelope()["error"]
    (record,) = sent.records
    assert (record["outcome"], record["code"], record["http_status"]) == (
        "failed",
        "unavailable",
        None,
    )
    assert fake_gateway.connections == []


def test_the_input_read_gets_the_whole_timeout_in_seconds(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    seen: list[float] = []
    original = fake_gateway.read_source

    def spy(source: Any, max_bytes: int, remaining: float) -> SourceRead:
        seen.append(remaining)
        return original(source, max_bytes, remaining)

    fake_gateway.read_source = spy  # type: ignore[method-assign]
    fake_gateway.script(OK)
    go(SEND, fake_gateway, stdin=HELLO, config=write_config(tmp_path, "timeout: 7\n"))
    assert seen == [7.0]


# --- the credential (step 5) --------------------------------------------------------------------


@pytest.mark.parametrize(
    "env",
    [
        {},
        {ENV_NAME: ""},
        {ENV_NAME: "   "},
        {ENV_NAME: "https://example.invalid/" + CANARY},
        {ENV_NAME: URL + "?x=1"},
        {ENV_NAME: "http://hooks.slack.com" + PATH},
    ],
)
def test_a_bad_credential_is_exit_12_with_the_variable_name_and_a_failed_record(
    env: dict[str, str], fake_gateway: FakeGateway
) -> None:
    sent = go(SEND, fake_gateway, stdin=HELLO, env=env)
    assert (sent.code, sent.exited) == (12, True)
    error = sent.error
    assert error["code"] == "credential_invalid" and error["details"] == {"env": ENV_NAME}
    assert (error["retryable"], error["unknown_outcome"]) == (False, False)
    assert error == webhook.credential_invalid(ENV_NAME).envelope()["error"]
    assert fake_gateway.connections == []
    (record,) = sent.records
    assert (record["outcome"], record["code"], record["http_status"]) == (
        "failed",
        "credential_invalid",
        None,
    )
    assert record["bytes"] is not None and record["message_sha256"] is not None
    assert CANARY.encode() not in sent.everything
    assert not (state_path(fake_gateway) / "send.lock").exists()  # no lock before the credential


def test_the_variable_comes_from_the_config_and_only_that_one_is_read(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    class Watched(dict[str, str]):
        reads: list[str] = []

        def __getitem__(self, key: str) -> str:
            self.reads.append(key)
            return super().__getitem__(key)

    env = Watched({"OTHER_HOOK": URL, ENV_NAME: "no"})
    Watched.reads = []
    fake_gateway.script(OK)
    sent = go(
        SEND,
        fake_gateway,
        stdin=HELLO,
        env=env,
        config=write_config(tmp_path, "webhook_env: OTHER_HOOK\n"),
    )
    assert sent.code == 0 and Watched.reads == ["OTHER_HOOK"]


def test_the_environment_is_read_through_the_gateway_lazily_and_only_by_a_real_send(
    tmp_path: Path,
) -> None:
    from tests.fake_gateway import FakeGateway as Fake

    home = tmp_path / "h2"
    home.mkdir(mode=0o700)
    gateway = Fake(home=str(home), environment=dict(ENV))
    gateway.script(OK)
    sent = go(["send", "--message", "m"], gateway, env=None)
    assert sent.code == 0 and gateway.calls.count("environ") == 1
    dry = Fake(home=str(home), environment=dict(ENV))
    go(["send", "--dry-run", "--message", "m"], dry, env=None)
    assert "environ" not in dry.calls
    refused = Fake(home=str(home), environment=dict(ENV))
    go(["send", "--message", " "], refused, env=None)
    assert "environ" not in refused.calls  # a refusal never reads the credential


def test_a_hostile_environment_mapping_is_credential_invalid_and_leaks_nothing(
    fake_gateway: FakeGateway,
) -> None:
    class Hostile(dict[str, str]):
        def __getitem__(self, key: str) -> str:
            raise RuntimeError(URL)

    sent = go(SEND, fake_gateway, stdin=HELLO, env=Hostile())
    assert sent.code == 12 and sent.error["code"] == "credential_invalid"
    assert CANARY.encode() not in sent.everything


# --- the Webhook edge table, end to end ---------------------------------------------------------

Row = tuple[list[Attempt], int, dict[str, Any]]


def reply(status: int, body: bytes = b"{}") -> Attempt:
    return Attempt(reply=Reply(status=status, body=body))


ROWS: dict[str, Row] = {
    "wrong body": (
        [reply(200, b'{"ok":false}')],
        12,
        dict(
            code="wrong_host_response",
            unknown=True,
            retryable=False,
            status=200,
            log="outcome_unknown",
            details={"http_status": 200},
        ),
    ),
    "2xx not 200": (
        [reply(204, b"")],
        12,
        dict(
            code="wrong_host_response",
            unknown=True,
            retryable=False,
            status=204,
            log="outcome_unknown",
            details={"http_status": 204},
        ),
    ),
    "400": (
        [reply(400, b'{"error":"invalid_blocks"}')],
        12,
        dict(
            code="host_rejected",
            unknown=False,
            retryable=False,
            status=400,
            log="failed",
            details={"host_error": "invalid_blocks", "http_status": 400},
        ),
    ),
    "401": (
        [reply(401)],
        12,
        dict(
            code="auth_required",
            unknown=False,
            retryable=False,
            status=401,
            log="failed",
            details={"http_status": 401},
        ),
    ),
    "403": (
        [reply(403)],
        12,
        dict(
            code="auth_required",
            unknown=False,
            retryable=False,
            status=403,
            log="failed",
            details={"http_status": 403},
        ),
    ),
    "404": (
        [reply(404)],
        12,
        dict(
            code="auth_required",
            unknown=False,
            retryable=False,
            status=404,
            log="failed",
            details={"http_status": 404},
        ),
    ),
    "410": (
        [reply(410)],
        12,
        dict(
            code="auth_required",
            unknown=False,
            retryable=False,
            status=410,
            log="failed",
            details={"http_status": 410},
        ),
    ),
    "429 three times": (
        [reply(429), reply(429), reply(429)],
        12,
        dict(
            code="rate_limited",
            unknown=False,
            retryable=True,
            status=429,
            log="failed",
            details={"http_status": 429},
            retry_after=4.0,
            sleeps=[2.0, 4.0],
        ),
    ),
    "500": (
        [reply(500)],
        12,
        dict(
            code="upstream_error",
            unknown=True,
            retryable=False,
            status=500,
            log="outcome_unknown",
            details={"http_status": 500},
        ),
    ),
    "302": (
        [reply(302)],
        12,
        dict(
            code="wrong_host_response",
            unknown=False,
            retryable=False,
            status=302,
            log="failed",
            details={"http_status": 302},
        ),
    ),
    "refused twice": (
        [
            Attempt(connect_error=ConnectionRefusedError()),
            Attempt(connect_error=ConnectionRefusedError()),
        ],
        12,
        dict(
            code="network_error",
            unknown=False,
            retryable=True,
            status=None,
            log="failed",
            details={"tls": False, "timeout": False},
            sleeps=[2.0],
        ),
    ),
    "certificate failure": (
        [Attempt(tls_error=cert_verify_error())],
        12,
        dict(
            code="network_error",
            unknown=False,
            retryable=False,
            status=None,
            log="failed",
            details={"tls": True, "timeout": False},
        ),
    ),
    "write failure": (
        [Attempt(write_error=ConnectionResetError())],
        12,
        dict(
            code="outcome_unknown",
            unknown=True,
            retryable=False,
            status=None,
            log="outcome_unknown",
            details=None,
        ),
    ),
    "reset after the write": (
        [Attempt(reply=ConnectionResetError())],
        12,
        dict(
            code="outcome_unknown",
            unknown=True,
            retryable=False,
            status=None,
            log="outcome_unknown",
            details=None,
        ),
    ),
    "not http": (
        [Attempt(reply=http.client.BadStatusLine("x"))],
        12,
        dict(
            code="wrong_host_response",
            unknown=True,
            retryable=False,
            status=None,
            log="outcome_unknown",
            details=None,
        ),
    ),
}


@pytest.mark.parametrize("name", sorted(ROWS))
def test_every_row_of_the_edge_table_end_to_end(name: str, fake_gateway: FakeGateway) -> None:
    attempts, code, want = ROWS[name]
    fake_gateway.script(*attempts)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert (sent.code, sent.exited) == (code, True)
    error = sent.error
    assert (error["code"], error["unknown_outcome"], error["retryable"]) == (
        want["code"],
        want["unknown"],
        want["retryable"],
    )
    assert (error["details"], error["reason"]) == (want["details"], None)
    assert error["retry_after_s"] == want.get("retry_after")
    assert sent.stderr == f"{error['code']}: {error['message']}\n"
    assert len(fake_gateway.connections) == len(attempts)
    for sleep in want.get("sleeps", []):
        assert f"sleep:{sleep}" in fake_gateway.events
    (record,) = sent.records
    assert (record["outcome"], record["exit"], record["code"], record["reason"]) == (
        want["log"],
        12,
        want["code"],
        None,
    )
    assert record["http_status"] == want["status"]
    assert record["message_sha256"] == log.message_sha256("Build", "all green")
    assert record["level"] == "warn" and isinstance(record["bytes"], int) and record["bytes"] > 0
    assert CANARY.encode() not in sent.everything


def test_a_429_then_ok_is_sent_after_a_two_second_wait(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(reply(429), OK)
    sent = go(SEND, fake_gateway, stdin=HELLO)
    assert sent.code == 0 and sent.document["http_status"] == 200
    assert "sleep:2.0" in fake_gateway.events and len(fake_gateway.connections) == 2
    assert [r["outcome"] for r in sent.records] == ["sent"]  # one record per send


def test_human_failure_output_is_stderr_only(fake_gateway: FakeGateway) -> None:
    fake_gateway.script(reply(500))
    sent = go(["send", "--stdin-json"], fake_gateway, stdin=HELLO)
    assert sent.code == 12 and sent.stdout == ""
    assert sent.stderr.startswith("upstream_error: ")


def test_error_from_outcome_matches_the_outcome_envelope_for_every_exit_12_outcome() -> None:
    outcomes = [
        webhook.credential_invalid("X_Y"),
        webhook.unavailable("input"),
        webhook.unavailable("lock"),
        webhook.outcome_unknown(),
        webhook.network_error(tls=True, timeout=False),
        webhook.network_error(tls=False, timeout=True),
        webhook.network_error(tls=True, timeout=False, no_usable_ca=True),
    ]
    for outcome in outcomes:
        assert cli.error_from_outcome(outcome).envelope() == outcome.envelope()

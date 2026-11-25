"""Offline tests of the live suite's helpers and the CI-safety guarantees (#33).

Nothing here touches the network or runs a live test: the fake gateway stands in for Slack, and
the one nested pytest run only collects. URL values are built from parts at run time.
"""

from __future__ import annotations

import http.client
import importlib
import json
import os
import pickle
import re
import ssl
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from slack_notice import webhook
from slack_notice.render import serialize
from tests import live_support as ls
from tests.fake_gateway import Attempt, FakeGateway, Reply
from tests.send_harness import go, stdin_json, write_config
from tests.test_send import OK

ROOT = Path(__file__).resolve().parent.parent
HOST = webhook.HOST
CANARY = "CAN" + "ARY" + "_33live"
SEGMENT_A = CANARY + "Aa0_-xyz"
SEGMENT_B = "second" + CANARY[-4:]


def fake_url(*segments: str) -> str:
    return ls.SCHEME + HOST + "/triggers/" + "/".join(segments or (SEGMENT_A, SEGMENT_B))


def trigger(*segments: str) -> ls.TriggerUrl:
    return ls.TriggerUrl(fake_url(*segments))


# --- the gate -------------------------------------------------------------------------------


def test_no_opt_in_skips() -> None:
    assert ls.decide({}).action == "skip"
    assert ls.decide({ls.OPT_IN_VAR: ""}).action == "skip"


def test_opt_in_naming_a_set_variable_runs() -> None:
    decision = ls.decide({ls.OPT_IN_VAR: "MY_URL", "MY_URL": fake_url()})
    assert (decision.action, decision.url_env) == ("run", "MY_URL")


@pytest.mark.parametrize(
    "name",
    [
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "BUILDKITE",
        "TRAVIS",
        "TEAMCITY_VERSION",
        "CODEBUILD_BUILD_ID",
        "DRONE",
        "BITBUCKET_BUILD_NUMBER",
    ],
)
def test_ci_always_refuses_even_with_a_valid_opt_in(name: str) -> None:
    env = {ls.OPT_IN_VAR: "MY_URL", "MY_URL": fake_url(), name: "true"}
    assert ls.decide(env).action == "refuse"


def test_ci_refuses_without_an_opt_in_too() -> None:
    assert ls.decide({"CI": "1"}).action == "refuse"


def test_naming_the_opt_in_variable_itself_refuses() -> None:
    assert ls.decide({ls.OPT_IN_VAR: ls.OPT_IN_VAR}).action == "refuse"


def test_an_unset_or_empty_named_variable_refuses() -> None:
    assert ls.decide({ls.OPT_IN_VAR: "MY_URL"}).action == "refuse"
    assert ls.decide({ls.OPT_IN_VAR: "MY_URL", "MY_URL": "  "}).action == "refuse"


@pytest.mark.parametrize("value", [None, "has space", "1BAD", "A" * 129])
def test_an_opt_in_that_is_not_a_variable_name_refuses_without_echoing_it(
    value: str | None,
) -> None:
    given = fake_url() if value is None else value  # a URL pasted instead of a name
    decision = ls.decide({ls.OPT_IN_VAR: given})
    assert decision.action == "refuse"
    assert given not in decision.reason and SEGMENT_A not in decision.reason


# --- the secret wrapper and the shape record -------------------------------------------------


def test_trigger_url_never_prints() -> None:
    url = trigger()
    for text in (repr(url), str(url), f"{url}", f"{url!r}", "%s" % url, repr([url])):  # noqa: UP031
        assert SEGMENT_A not in text and HOST not in text
    with pytest.raises(TypeError):
        pickle.dumps(url)
    with pytest.raises(AttributeError):
        url.x = 1  # type: ignore[attr-defined]  # pyright: ignore


def test_trigger_url_is_trimmed_like_the_tool() -> None:
    assert ls.TriggerUrl(" \t" + fake_url() + "\n").reveal() == fake_url()


def test_shape_of_a_matching_url_has_counts_and_classes_only() -> None:
    shape = ls.describe_shape(trigger())
    assert shape.matches_allowlist and shape.prefix_ok and shape.segment_count == 2
    assert shape.segment_lengths == (len(SEGMENT_A), len(SEGMENT_B))
    assert set(shape.charset) == {"upper", "lower", "digit", "underscore", "hyphen"}
    dumped = json.dumps(shape.summary())
    assert SEGMENT_A not in dumped and SEGMENT_B not in dumped and "triggers" not in dumped


@pytest.mark.parametrize(
    ("value", "extra"),
    [
        (fake_url("a", "b", "c", "d", "e"), None),  # five segments
        (fake_url("a") + "?x=1", "query"),
        (fake_url("a") + "/", "trailing_slash"),
        (fake_url("a", "b!"), None),
        (fake_url("a").replace(HOST, "example" + ".org"), None),
    ],
)
def test_a_url_outside_the_allowlist_is_reported_not_matching(
    value: str, extra: str | None
) -> None:
    shape = ls.describe_shape(ls.TriggerUrl(value))
    assert not shape.matches_allowlist
    if extra:
        assert extra in shape.extras
    assert SEGMENT_A not in json.dumps(shape.summary())


def test_the_other_host_has_no_segment_data() -> None:
    shape = ls.describe_shape(ls.TriggerUrl(fake_url("a").replace(HOST, "example" + ".org")))
    assert not shape.prefix_ok and shape.segment_count is None


def test_char_classes_name_classes_not_characters() -> None:
    assert ls.char_classes("aZ9_- é!") == [
        "digit",
        "hyphen",
        "lower",
        "non_ascii",
        "other_ascii",
        "underscore",
        "upper",
        "whitespace",
    ]


# --- the altered path -----------------------------------------------------------------------


def test_altered_last_segment_keeps_the_prefix_and_is_long_and_different() -> None:
    url = trigger("short")
    altered = ls.alter_last_segment(url)
    head = fake_url("short").rpartition("/")[0]
    assert altered.reveal().startswith(head + "/")
    last = altered.reveal().rpartition("/")[2]
    assert len(last) == 24 and last != "short"
    assert ls.describe_shape(altered).matches_allowlist


def test_altered_last_segment_is_as_long_as_a_longer_original() -> None:
    last = ls.alter_last_segment(trigger(SEGMENT_A * 3)).reveal().rpartition("/")[2]
    assert len(last) == len(SEGMENT_A * 3)


def test_altered_last_segment_uses_the_chooser_and_refuses_other_urls() -> None:
    chosen = ls.alter_last_segment(trigger(), lambda _alphabet: "Q").reveal()
    assert chosen.endswith("/" + "Q" * 24)
    with pytest.raises(ValueError, match="not a trigger URL") as caught:
        ls.alter_last_segment(ls.TriggerUrl("https" + "://" + "example" + ".org/x"))
    assert "example" not in str(caught.value)


# --- sizing ---------------------------------------------------------------------------------


@pytest.mark.parametrize("target", [12000, 11990, 500])
def test_message_for_body_size_serializes_to_exactly_the_target(target: int) -> None:
    title = "title " + CANARY
    message = ls.message_for_body_size("lab", target, title=title)
    assert ls.request_body_bytes(ls.DEFAULT_PREFIX["info"] + " " + title, message) == target
    assert message.startswith("lab start ") and message.endswith(" END-lab")


def test_the_sized_message_is_not_truncated_by_the_real_renderer(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    title = "slack-notice live test abc123 ascii12000"
    message = ls.message_for_body_size("ascii12000", 12000, title=title)
    cfg = write_config(tmp_path, "max_chars: 12000\n")
    sent = go(
        ["send", "--json", "--stdin-json", "--dry-run"],
        fake_gateway,
        stdin=stdin_json(title=title, message=message),
        config=cfg,
    )
    assert sent.document["bytes"] == 12000 and sent.document["truncated"] is False


@pytest.mark.parametrize(("unit", "width"), [("é", 2), ("中", 3), ("\U0001f600", 4)])
def test_unit_message_fits_the_cap_under_the_real_renderer(
    unit: str, width: int, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    title = "slack-notice live test abc123 case"
    message, count = ls.unit_message("case", unit, width, title)
    cfg = write_config(tmp_path, "max_chars: 12000\n")
    sent = go(
        ["send", "--json", "--stdin-json", "--dry-run"],
        fake_gateway,
        stdin=stdin_json(title=title, message=message),
        config=cfg,
    )
    assert sent.document["truncated"] is False and 11980 <= sent.document["bytes"] <= 12000
    assert message.count(unit) == count > 1000


def test_raw_limit_text_sizes() -> None:
    ascii_text = ls.raw_limit_text("lab", "x", 12001)
    assert len(serialize("body", ascii_text)) == 12001
    assert ascii_text.startswith(ls.MARKER) and ascii_text.endswith("END-lab")
    assert ls.raw_limit_text("lab", "é", 11000).count("é") == 11000
    assert len(serialize("body", ls.raw_limit_text("lab", "中", 6000))) > 18000


def test_the_fixed_test_message_hash_matches_the_log_helper() -> None:
    from slack_notice import log

    assert log.message_sha256("slack-notice", "validate: test message") == "cff763132117c5b1"


def test_too_small_a_target_is_an_error() -> None:
    with pytest.raises(ValueError, match="smaller"):
        ls.message_for_body_size("lab", 5)


# --- pacing ---------------------------------------------------------------------------------


def test_pacer_sleeps_only_the_missing_part() -> None:
    now = [100.0]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    pacer = ls.Pacer(1.5, clock=lambda: now[0], sleep=sleep)
    pacer.wait()
    assert slept == []  # the first action is not delayed
    now[0] += 0.5
    pacer.wait()
    assert slept == [pytest.approx(1.0)]
    now[0] += 5
    pacer.wait()
    assert len(slept) == 1


def test_pacer_mark_makes_the_next_wait_count_from_the_end_of_an_action() -> None:
    now = [0.0]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    pacer = ls.Pacer(1.5, clock=lambda: now[0], sleep=sleep)
    pacer.wait()  # a series starts at t=0 ...
    now[0] += 4.0  # ... and its last send ends at t=4
    pacer.mark()
    now[0] += 0.5
    pacer.wait()
    assert slept == [pytest.approx(1.0)]


def test_gaps_are_the_differences_between_request_starts() -> None:
    items = [ls.Exchange(t, 1, b"") for t in (1.0, 2.1, 4.35)]
    assert ls.gaps(items) == [1.1, 2.25]
    assert ls.gaps(items[:1]) == []


# --- the recorder and the report -------------------------------------------------------------


def test_the_report_lists_every_item_with_a_state() -> None:
    rec = ls.Recorder("r1")
    rec.observe("V4", "shape", {"segment_count": 2})
    rec.manual("V3", "big", "arrives or not")
    rec.manual("V4", "x", "y")
    data = json.loads(rec.to_json())
    assert set(data["items"]) == set(ls.ITEMS)
    assert data["items"]["V4"]["state"] == "observed; also observe manually"
    assert data["items"]["V3"]["state"] == "observe manually"
    assert data["items"]["V18"]["state"] == "not run"
    text = rec.to_text()
    assert "LOOK AT THE DESTINATION: big" in text and "V4: " in text


def test_the_report_counts_5xx_and_latency_from_tallies() -> None:
    rec = ls.Recorder()
    rec.tally(
        [
            ls.Exchange(0.0, 1, b"", status=200, elapsed_ms=120),
            ls.Exchange(1.0, 1, b"", status=503, elapsed_ms=300),
            ls.Exchange(2.0, 1, b"", status=429, elapsed_ms=90),
        ]
    )
    data = json.loads(rec.to_json())["items"]
    assert data["V5"]["observed"]["5xx_seen_in_this_run"] == 1
    assert data["V5"]["observed"]["statuses_seen"] == {"200": 1, "429": 1, "503": 1}
    assert data["T"]["observed"]["time_to_response_ms"] == {
        "count": 3,
        "min": 90,
        "median": 120,
        "max": 300,
    }


def test_the_report_redacts_url_material_and_is_still_produced() -> None:
    rec = ls.Recorder()
    rec.add_secret(fake_url())
    rec.observe("V2", "bad", "leaked " + SEGMENT_A)  # a long path segment
    rec.observe("V2", "whole", fake_url())
    for text in (rec.to_json(), rec.to_text()):
        assert SEGMENT_A not in text and SEGMENT_B not in text and ls.SCHEME + HOST not in text
        assert "<trigger url redacted>" in text
    assert rec.redactions >= 4
    assert json.loads(rec.to_json())["items"]["V2"]["observed"]["bad"].startswith("leaked ")


@pytest.mark.parametrize("word", [HOST, "triggers", "/triggers/", "slack.com"])
def test_fixed_prefix_words_in_a_report_are_not_secrets(word: str) -> None:
    rec = ls.Recorder()
    rec.add_secret(fake_url())
    rec.observe("V2", "x", f"{word} and hooks.slack.com seen")
    text = rec.to_text()
    assert word in text and rec.redactions == 0
    assert "hooks.slack.com" in rec.to_json()


def test_only_the_segments_after_the_trigger_prefix_are_registered() -> None:
    rec = ls.Recorder()
    rec.add_secret(fake_url())
    assert set(rec._secrets) == {fake_url(), SEGMENT_A, SEGMENT_B}
    rec.add_secret(ls.SCHEME + HOST + "/triggers/" + "short7x/" + SEGMENT_A + "?q=" + SEGMENT_B)
    assert "short7x" not in rec._secrets and HOST not in rec._secrets


def test_ca_sources_reports_the_loaded_counts_and_the_used_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Context:
        def __init__(self, count: int) -> None:
            self.count = count

        def cert_store_stats(self) -> dict[str, int]:
            return {"x509_ca": self.count}

    def build(candidates: Any) -> Context:
        if candidates.cafile:
            return Context(7)
        if candidates.fallback_files:
            return Context(3)
        raise ls.NoUsableCA

    monkeypatch.setattr(ls, "build_tls_context", build)
    both = ls.ca_sources(ls.CaCandidates("/a", "/b", ("/c",)))
    assert both == {
        "loaded_ca_certs": {"cafile": 7, "capath": None, "fallback": 3},
        "used": ["cafile"],
    }
    only_fallback = ls.ca_sources(ls.CaCandidates(None, None, ("/c",)))
    assert only_fallback["used"] == ["fallback"]
    nothing = ls.ca_sources(ls.CaCandidates(None, None, ()))
    assert nothing == {
        "loaded_ca_certs": {"cafile": None, "capath": None, "fallback": None},
        "used": ["none"],
    }


def test_unknown_item_is_a_key_error() -> None:
    with pytest.raises(KeyError):
        ls.Recorder().observe("V99", "k", 1)


def test_write_makes_private_files_and_report_directory_honors_the_variable(
    tmp_path: Path,
) -> None:
    rec = ls.Recorder("r2")
    json_path, text_path = rec.write(tmp_path / "out")
    assert json_path.name == "report.json" and text_path.name == "report.txt"
    assert json_path.stat().st_mode & 0o777 == 0o600
    assert ls.report_directory({ls.REPORT_VAR: str(tmp_path / "x")}) == tmp_path / "x"
    made = ls.report_directory({})
    try:
        assert made.is_dir() and made.name.startswith("slack-notice-live-")
    finally:
        made.rmdir()


# --- the gateway wrapper, against the fake gateway --------------------------------------------


def untrusting_free_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def live_gateway(fake: FakeGateway, **kwargs: Any) -> ls.LiveGateway:
    return ls.LiveGateway(connect=fake.https_connection, tls=untrusting_free_context, **kwargs)


def test_a_marked_send_runs_through_the_real_cli_and_is_recorded(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(OK)
    gateway = live_gateway(fake_gateway)
    notification = {"title": ls.MARKER + " r1 plain", "message": "plain start END"}
    result = ls.run_cli(
        ["send", "--json"],
        url=trigger(),
        gateway=gateway,
        work=tmp_path / "work",
        notification=notification,
    )
    assert result.code == 0
    document = result.document
    assert document is not None and document["outcome"] == "sent"
    (exchange,) = result.exchanges
    assert exchange.status == 200 and exchange.response_body == b'{"ok":true}'
    assert exchange.request_bytes == document["bytes"] == len(exchange.request_body)
    assert exchange.elapsed_ms is not None and exchange.error is None
    assert SEGMENT_A.encode() not in result.out + result.err


def test_an_unmarked_body_is_refused_before_it_reaches_the_connection(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(OK)
    fake_gateway.allow_unconsumed_script = True
    gateway = live_gateway(fake_gateway)
    conn = gateway.https_connection(
        HOST, 443, timeout=5.0, context=gateway.tls_context(), user_agent="x"
    )
    conn.connect()
    with pytest.raises(ls.MarkerRefused):
        conn.post("/triggers/x", b'{"body":"hello"}')
    assert gateway.exchanges == []
    conn.close()


def test_the_test_message_marker_must_be_allowed_explicitly(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(OK)
    result = ls.run_cli(
        ["validate", "--json", "--test-message"],
        url=trigger(),
        gateway=live_gateway(fake_gateway, markers=(ls.MARKER, ls.TEST_MESSAGE_MARKER)),
        work=tmp_path / "work",
    )
    assert result.code == 0
    (exchange,) = result.exchanges
    assert (
        exchange.request_body
        == '{"body":"\U0001f535 INFO slack-notice\\nvalidate: test message"}'.encode()
    )
    assert len(exchange.request_body) == 57


def test_a_validate_test_message_without_the_extra_marker_posts_nothing(
    fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(OK)
    fake_gateway.allow_unconsumed_script = True
    gateway = live_gateway(fake_gateway)
    result = ls.run_cli(
        ["validate", "--json", "--test-message"],
        url=trigger(),
        gateway=gateway,
        work=tmp_path / "work",
    )
    assert result.code != 0 and gateway.exchanges == []


@pytest.mark.parametrize("code", [130, 143])
def test_an_interrupt_exit_code_stops_the_run(
    code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(*_args: Any, **_kwargs: Any) -> int:
        raise ls.LiveExit(code)

    monkeypatch.setattr(ls, "main", interrupted)
    with pytest.raises(KeyboardInterrupt):
        ls.run_cli(["send"], url=trigger(), gateway=ls.LiveGateway(), work=tmp_path / "w")


def test_exit_now_raises_instead_of_ending_the_process() -> None:
    gateway = ls.LiveGateway()
    with pytest.raises(ls.LiveExit) as caught:
        gateway.exit_now(12)
    assert caught.value.code == 12
    with pytest.raises(ValueError, match="exit code"):
        gateway.exit_now(300)


# --- raw requests -----------------------------------------------------------------------------


class StubResponse:
    status = 200
    reason = "OK"
    version = 11
    will_close = True

    def __init__(self, headers: dict[str, str], body: bytes) -> None:
        self._headers, self._body = headers, body

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    def getheader(self, name: str) -> str | None:
        return self._headers.get(name)

    def read(self, amount: int) -> bytes:
        return self._body[:amount]


class StubConnection:
    sock = None

    def __init__(self, response: StubResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, str, bytes | None, dict[str, str]]] = []

    def request(
        self, method: str, path: str, body: bytes | None = None, headers: Any = None
    ) -> None:
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self) -> StubResponse:
        return self.response


def test_raw_exchange_keeps_whitelisted_headers_and_hides_the_location() -> None:
    secret_location = fake_url()
    response = StubResponse(
        {"content-type": "application/json", "location": secret_location, "x-other": "1"},
        b'{"ok":true}',
    )
    conn = StubConnection(response)
    result = ls.raw_exchange(conn, "GET", "/triggers/x")
    assert result.location_present and result.headers == {"content-type": "application/json"}
    assert secret_location not in json.dumps(result.summary())
    method, _path, body, headers = conn.requests[0]
    assert (method, body, headers["Connection"]) == ("GET", None, "close")


def test_raw_exchange_records_header_count_and_head_size_not_values() -> None:
    response = StubResponse({"content-type": "text/plain", "x-secret-ish": "v" * 30}, b"")
    result = ls.raw_exchange(StubConnection(response), "GET", "/p")
    summary = result.summary()
    assert summary["header_count"] == 2
    assert (
        summary["header_bytes"]
        == len("content-type") + len("text/plain") + 4 + len("x-secret-ish") + 30 + 4
    )
    assert "tls_version" not in summary and not hasattr(result, "tls_version")


def test_raw_exchange_refuses_a_get_body_and_an_unmarked_post() -> None:
    conn = StubConnection(StubResponse({}, b""))
    with pytest.raises(ValueError, match="no body"):
        ls.raw_exchange(conn, "GET", "/p", body=b"x")
    with pytest.raises(ls.MarkerRefused):
        ls.raw_exchange(conn, "POST", "/p", body=b'{"body":"x"}')
    with pytest.raises(ls.MarkerRefused):
        ls.raw_exchange(conn, "POST", "/p")
    with pytest.raises(ValueError, match="only GET and POST"):
        ls.raw_exchange(conn, "PUT", "/p", body=ls.MARKER.encode())
    assert conn.requests == []


def test_raw_exchange_posts_a_marked_body_with_extra_headers() -> None:
    conn = StubConnection(StubResponse({"retry-after": "7"}, b"x" * 9000))
    body = json.dumps({"body": ls.MARKER + " ok"}).encode()
    result = ls.raw_exchange(conn, "POST", "/p", body=body, headers={"Idempotency-Key": "k"})
    assert result.headers == {"retry-after": "7"} and len(result.body) == 200
    assert conn.requests[0][3]["Idempotency-Key"] == "k"


def test_open_raw_connection_builds_without_connecting() -> None:
    conn = ls.open_raw_connection(ls.LiveGateway(tls=untrusting_free_context))
    assert isinstance(conn, http.client.HTTPSConnection) and conn.sock is None
    assert (conn.host, conn.port) == (HOST, 443)


# --- CI safety: nothing live runs by accident --------------------------------------------------


def live_test_names() -> list[str]:
    source = (ROOT / "tests" / "test_live.py").read_text(encoding="utf-8")
    return re.findall(r"^def (test_\w+)\(", source, re.MULTILINE)


def child_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    home = tmp_path / "childhome"
    home.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_STATE_HOME": str(home / ".state"),
        "XDG_CACHE_HOME": str(home / ".cache"),
    }
    env.update(extra)
    return env


def collect(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *args],
        cwd=ROOT,
        env=child_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_every_live_test_is_marked_by_the_module_marker() -> None:
    import tests.test_live as module

    marks: Any = getattr(module, "pytestmark", None)
    names = [mark.name for mark in (marks if isinstance(marks, list) else [marks])]
    assert "live" in names
    assert len(live_test_names()) >= 15


def test_no_live_test_is_collected_by_default(tmp_path: Path) -> None:
    default = collect(tmp_path, "tests/test_live.py")
    assert "tests/test_live.py::" not in default.stdout
    assert "deselected" in default.stdout, default.stdout + default.stderr


def test_the_live_marker_alone_selects_exactly_the_live_tests(tmp_path: Path) -> None:
    chosen = collect(tmp_path, "-m", "live", "tests/test_live.py")
    ids = [line for line in chosen.stdout.splitlines() if line.startswith("tests/test_live.py::")]
    assert sorted(item.split("::")[1] for item in ids) == sorted(live_test_names())
    everything = collect(tmp_path, "-m", "live", "tests")
    live_ids = [
        x
        for x in everything.stdout.splitlines()
        if "::" in x and not x.startswith("tests/test_live.py::")
    ]
    assert live_ids == []  # no other module carries the marker


def test_collecting_never_runs_a_live_test(tmp_path: Path) -> None:
    # Even with the opt-in variable set, collection runs no fixture and no test body.
    env = child_env(tmp_path, **{ls.OPT_IN_VAR: "SOME_NAME", "SOME_NAME": fake_url()})
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "-m",
            "live",
            "tests/test_live.py",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0 and "tests collected" in done.stdout


FORBIDDEN_IN_CI = re.compile(
    r"-m\s+['\"]?live|make\s+live|SLACK_NOTICE_LIVE|test_live|--run-live", re.IGNORECASE
)


def test_no_ci_workflow_runs_live_tests() -> None:
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    assert workflows, "expected the CI workflow files"
    for path in workflows:
        assert not FORBIDDEN_IN_CI.search(path.read_text(encoding="utf-8")), path.name


def test_the_default_make_targets_and_pytest_config_exclude_live() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipes = {}
    for match in re.finditer(r"^([a-z-]+):([^\n]*)\n((?:\t[^\n]*\n)*)", makefile, re.MULTILINE):
        recipes[match.group(1)] = match.group(2) + match.group(3)
    assert "live" not in recipes["verify"] and "live" not in recipes["test"]
    assert "live" in recipes  # `make live` exists and is separate
    assert "not live" in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_the_live_target_requires_the_opt_in_variable() -> None:
    recipe = re.search(r"^live:[^\n]*\n((?:\t[^\n]*\n)+)", (ROOT / "Makefile").read_text(), re.M)
    assert recipe is not None
    assert ls.OPT_IN_VAR in recipe.group(1) and "-m live" in recipe.group(1)


def test_the_live_target_keeps_going_after_a_failure_and_keeps_locals_out_of_tracebacks() -> None:
    recipe = re.search(r"^live:[^\n]*\n((?:\t[^\n]*\n)+)", (ROOT / "Makefile").read_text(), re.M)
    assert recipe is not None
    run = [line for line in recipe.group(1).splitlines() if "pytest" in line][0]
    assert "--tb=short" in run
    assert not re.search(r"\s-\w*x\w*\b|--exitfirst|--maxfail", run)
    assert not re.search(r"\s-l\b|--showlocals", run)


def test_the_docstring_table_names_only_existing_live_tests() -> None:
    source = (ROOT / "tests" / "test_live.py").read_text(encoding="utf-8")
    header = source.split('"""', 2)[1]
    defined = set(re.findall(r"^def (test_\w+)", source, re.M))
    named = set(re.findall(r"\btest_\w+", header))
    assert named and named <= defined, sorted(named - defined)


@pytest.mark.parametrize("name", ["live_support.py", "test_live.py", "test_live_support.py"])
def test_the_live_files_hold_no_url_literal_and_no_real_looking_secret(name: str) -> None:
    text = (ROOT / "tests" / name).read_text(encoding="utf-8")
    assert ":" + "//" not in text.replace('"://"', "")  # only the assembled scheme separator
    assert "x" + "ox" not in text and "/triggers/" + "T0" not in text


def test_the_module_guard_fixture_fails_in_ci_and_skips_without_opt_in() -> None:
    source = (ROOT / "tests" / "test_live.py").read_text(encoding="utf-8")
    body = source.split("def live() -> Iterator[Live]:", 1)[1].split("yield session", 1)[0]
    assert "decide(os.environ)" in body
    assert body.index('"refuse"') < body.index('"skip"') < body.index("TriggerUrl(")


def test_the_live_tests_read_only_their_own_variables() -> None:
    source: Callable[[str], str] = lambda n: (ROOT / "tests" / n).read_text(encoding="utf-8")  # noqa: E731
    assert "os.environ[" in source("test_live.py")
    assert re.findall(r"os\.environ\[([^\]]+)\]", source("test_live.py")) == [
        "decision.url_env",
        '"HOME"',
    ]


# --- the live test bodies, run offline against a fake gateway and stub connections -----------

tl = importlib.import_module("tests.test_live")


class ClockedGateway(ls.LiveGateway):
    """The live gateway wrapper on the fake gateway's connection and (instant) clock."""

    def __init__(self, fake: FakeGateway, **kwargs: Any) -> None:
        super().__init__(connect=fake.https_connection, tls=untrusting_free_context, **kwargs)
        self._fake = fake

    def monotonic(self) -> float:
        return self._fake.monotonic()

    def wall_time(self) -> float:
        return self._fake.wall_time()

    def sleep(self, seconds: float) -> None:
        self._fake.sleep(seconds)


@pytest.fixture
def session(fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> Any:
    rec = ls.Recorder()
    url = trigger()
    rec.add_secret(url.reveal())
    live = tl.Live(url, rec)
    live.pacer = ls.Pacer(1.5, clock=fake_gateway.monotonic, sleep=fake_gateway.sleep)
    live.created = []  # type: ignore[attr-defined]

    def factory(**kwargs: Any) -> ClockedGateway:
        gateway = ClockedGateway(fake_gateway, **kwargs)
        live.created.append(gateway)  # type: ignore[attr-defined]
        return gateway

    monkeypatch.setattr(tl, "LiveGateway", factory)
    return live


def all_starts(live: Any) -> list[float]:
    return [e.started for gateway in live.created for e in gateway.exchanges]


def test_v1_series_are_spaced_at_least_the_pacer_gap_apart(
    session: Any, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(*[OK] * 12)
    tl.test_v1_burst_at_the_lock_spacing(session, tmp_path)
    tl.test_v1_sustained_at_the_lock_spacing(session, tmp_path)
    starts = all_starts(session)
    assert len(starts) == 12
    between = ls.gaps([ls.Exchange(t, 1, b"") for t in starts])
    assert between[3] >= 1.5 - 1e-6  # the gap between the two series
    assert all(gap >= 0.9 for gap in between)


def test_v1_fails_when_a_send_was_throttled_and_retried(
    session: Any, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(Attempt(reply=Reply(status=429, body=b"{}")), *[OK] * 4)
    with pytest.raises(AssertionError, match="expected 4 requests"):
        tl.test_v1_burst_at_the_lock_spacing(session, tmp_path)


def test_v2_altered_path_records_status_and_body_of_the_exchange(
    session: Any, fake_gateway: FakeGateway, tmp_path: Path
) -> None:
    fake_gateway.script(Attempt(reply=Reply(status=404, body=b'{"error":"gone"}')))
    tl.test_v2_altered_path_status(session, tmp_path)
    seen = session.rec.observations["V2"]["altered_last_segment_post"]
    assert seen["exchange_status"] == 404 and seen["response_body"] == '{"error":"gone"}'
    assert seen["code"] == "auth_required"


class ExplodingConnection:
    """A raw connection whose request fails with a message that quotes the request path."""

    sock = None

    def request(self, method: str, path: str, **_kwargs: Any) -> None:
        raise OSError(f"broken while sending {method} {path}")

    def close(self) -> None:
        pass


class OkConnection(StubConnection):
    def close(self) -> None:
        pass


def test_a_failed_raw_request_is_recorded_by_class_and_the_test_goes_on(
    session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    made: list[Any] = []

    def open_connection(_gateway: Any, timeout: float = 15.0) -> Any:
        made.append(1)
        return ExplodingConnection() if len(made) == 1 else OkConnection(StubResponse({}, b"{}"))

    monkeypatch.setattr(tl, "open_raw_connection", open_connection)
    tl.test_v3_raw_limits(session)
    observed = session.rec.observations["V3"]
    assert len(made) == 5 and observed["raw-ascii-12001"] == {"error": "OSError"}
    assert observed["raw-ascii-12500"]["status"] == 200
    assert session.rec.statuses == {200: 4}
    text = session.rec.to_text() + session.rec.to_json()
    assert SEGMENT_A not in text and "broken while sending" not in text


def test_every_raw_case_survives_a_failing_connection(
    session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tl, "open_raw_connection", lambda *_a, **_k: ExplodingConnection())
    tl.test_v2_get_probe(session)
    tl.test_raw_error_shapes(session)
    tl.test_o1_idempotency_header(session)
    observed = session.rec.observations
    assert observed["V2"]["get_on_live_url"] == {"error": "OSError"}
    assert "get_tells_live_from_dead" not in observed["V2"]
    assert len([k for k in observed["R"] if k.startswith("raw_")]) == 5
    assert observed["O1"]["post_2_with_Idempotency-Key"] == {"error": "OSError"}
    assert SEGMENT_A not in session.rec.to_text()


def test_failed_raw_requests_are_counted_and_shown_in_the_report(
    session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tl, "open_raw_connection", lambda *_a, **_k: ExplodingConnection())
    session.raw("V3", "a", "GET", session.path)
    session.raw("V3", "b", "GET", session.path)
    assert session.rec.raw_failures == 2
    assert "raw requests failed: 2" in session.rec.to_text()
    assert session.rec.observations["T"]["raw_requests_failed"] == 2
    assert "raw requests failed" not in ls.Recorder().to_text()


def test_raw_pacing_marks_the_end_of_a_raw_request(
    session: Any, fake_gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        tl, "open_raw_connection", lambda *_a, **_k: OkConnection(StubResponse({}, b"{}"))
    )
    session.raw("V3", "a", "GET", session.path)
    fake_gateway.sleep(0.2)
    before = fake_gateway.monotonic()
    session.raw("V3", "b", "GET", session.path)
    assert fake_gateway.monotonic() - before == pytest.approx(1.3, abs=0.05)

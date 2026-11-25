"""The live suite (#33): posts marked test messages to the maintainer's own workflow.

NEVER runs by accident and NEVER in CI: every test is marked ``live`` (excluded by ``addopts``),
and the ``live`` fixture additionally skips unless ``SLACK_NOTICE_LIVE_URL_ENV`` names the
variable that holds the trigger URL, and refuses when ``CI`` is set. How to run, what is posted
and how to record the results: docs/live-testing.md. Run with ``make live``.

Every message carries the fixed marker ``slack-notice live test`` (the gateway wrapper refuses a
body without it). The URL never appears in output: it lives in a ``TriggerUrl`` and the report
holds counts and character classes only.

Which test settles which item of the live verification checklist (issue #37, design.md):

| Item | Test(s) |
|---|---|
| V1 sustained rate | test_v1_burst_at_the_lock_spacing, test_v1_sustained_at_the_lock_spacing |
| V2 wrong URL statuses, GET | test_v2_altered_path_status, test_v2_get_probe |
| V3 characters or bytes | test_v3_cli_ascii_at_the_cap, test_v3_cli_non_ascii, test_v3_raw_limits |
| V4 URL shape (first) | test_v4_trigger_url_matches_allowlist |
| V5 a 5xx after processing | none reproducible: every status seen is listed in the report |
| V18 CA paths | test_v18_ca_paths_and_trust_store (plus the plain message) |
| V21 HTTP/1.1, Connection: close | test_v21_plain_message |
| idempotency header | test_o1_idempotency_header |
| two machines | manual (listed in the report) |
| #32 test message | test_validate_test_message |
| #19 rendering | test_emoji_per_level, test_auto_link, test_text_is_literal |
| #23/#24 wire shapes | test_raw_error_shapes, test_v2_get_probe, test_tls_and_dns_details |
| #23 TLS failure | test_tls_verification_failure |
"""

from __future__ import annotations

import json
import os
import ssl
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from slack_notice import render, webhook
from slack_notice.gateway import SystemGateway
from slack_notice.render import serialize
from tests.live_support import (
    MARKER,
    SCHEME,
    TEST_MESSAGE_MARKER,
    CliResult,
    LiveGateway,
    MarkerRefused,
    Pacer,
    RawResult,
    Recorder,
    TriggerUrl,
    alter_last_segment,
    ca_sources,
    decide,
    describe_shape,
    gaps,
    message_for_body_size,
    open_raw_connection,
    raw_exchange,
    raw_limit_text,
    report_directory,
    run_cli,
    unit_message,
)

pytestmark = pytest.mark.live

POST_HEADERS = {"Content-Type": "application/json"}


class Live:
    """The session: the URL, the recorder and the pacing, with the send helpers."""

    def __init__(self, url: TriggerUrl, recorder: Recorder) -> None:
        self.url = url
        self.rec = recorder
        self.pacer = Pacer()
        self.allowlisted: bool | None = None

    @property
    def path(self) -> str:
        return self.url.reveal()[len(SCHEME + webhook.HOST) :]

    def title(self, label: str) -> str:
        return f"{MARKER} {self.rec.run_id} {label}"

    def look(self, item: str, label: str, expect: str) -> None:
        self.rec.manual(item, label, expect)
        print(f"\nLOOK AT THE DESTINATION [{item}] {label}\n    expect: {expect}")

    def send(
        self,
        tmp: Path,
        label: str,
        message: str,
        *,
        level: str = "info",
        link: str | None = None,
        config: str = "max_chars: 12000\ntimeout: 30s\n",
        url: TriggerUrl | None = None,
        wait: bool = True,
        gateway: LiveGateway | None = None,
    ) -> CliResult:
        if wait:
            self.pacer.wait()
        notice: dict[str, Any] = {"title": self.title(label), "message": message, "level": level}
        if link is not None:
            notice["link"] = link
        result = run_cli(
            ["send", "--json"],
            url=url or self.url,
            gateway=gateway or LiveGateway(),
            work=tmp / "work",
            notification=notice,
            config=config,
        )
        self.pacer.mark()
        self.rec.tally(result.exchanges)
        return result

    def raw(
        self,
        item: str,
        label: str,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> RawResult | None:
        """One raw request. A failure is recorded under ``item``/``label`` as the exception class
        name only (http.client messages can quote the request target, which is the secret) and
        the test goes on with the next case; ``None`` is returned then."""
        self.pacer.wait()
        gateway = LiveGateway()
        conn = open_raw_connection(gateway)
        try:
            result = raw_exchange(conn, method, path, body=body, headers=headers)
        except MarkerRefused:
            raise  # a bug in the suite, not a network event
        except Exception as exc:
            self.rec.observe(item, label, {"error": type(exc).__name__})
            return None
        finally:
            conn.close()
            self.pacer.mark()
        self.rec.tally_raw(result)
        return result


@pytest.fixture(scope="session")
def live() -> Iterator[Live]:
    decision = decide(os.environ)
    if decision.action == "refuse":
        pytest.fail(decision.reason, pytrace=False)
    if decision.action == "skip":
        pytest.skip(decision.reason)
    assert decision.url_env is not None
    url = TriggerUrl(os.environ[decision.url_env])
    recorder = Recorder()
    recorder.add_secret(url.reveal())
    session = Live(url, recorder)
    recorder.observe(
        "N",
        "not_reproducible_here",
        [
            "a revoked trigger (revoke it in Slack, then run validate --test-message)",
            "a 5xx after processing, a 429 with Retry-After (never provoked on purpose)",
            "a redirect, a reset after the request was written, an early close on a big body",
            "a truly foreign state dir, quota errors, other filesystems (see issue 37)",
        ],
    )
    recorder.manual(
        "O2",
        "two machines at once",
        "run this suite from two machines in the same minute; count 429 results and arrivals",
    )
    yield session
    directory = report_directory(os.environ)
    json_path, text_path = recorder.write(directory)
    print(f"\nlive report written: {json_path}\n                     {text_path}", file=sys.stderr)
    print("Open the text report and check each LOOK AT THE DESTINATION entry.", file=sys.stderr)


@pytest.fixture(autouse=True)
def record_outcome(request: pytest.FixtureRequest, live: Live) -> Iterator[None]:
    yield
    report = getattr(request.node, "rep_call", None)
    if report is not None:
        live.rec.outcomes[request.node.name] = report.outcome


@pytest.fixture
def allowlisted(live: Live) -> Live:
    """A session whose trigger URL matched the allowlist (V4); else the test is skipped."""
    if live.allowlisted is None:
        live.allowlisted = describe_shape(live.url).matches_allowlist
    if not live.allowlisted:
        pytest.skip("V4 failed: the trigger URL does not match the allowlist")
    return live


def sent_ok(result: CliResult) -> dict[str, Any]:
    document = result.document
    assert result.code == 0, f"exit {result.code}: {result.error.get('code')}"
    assert document is not None and document["outcome"] == "sent"
    assert document["http_status"] == 200
    return document


# --- V4: the first live assertion ---------------------------------------------------------


def test_v4_trigger_url_matches_allowlist(live: Live) -> None:
    shape = describe_shape(live.url)
    live.allowlisted = shape.matches_allowlist
    live.rec.observe("V4", "shape", shape.summary())
    print(f"\nV4 observed shape (counts and classes only): {json.dumps(shape.summary())}")
    assert shape.matches_allowlist, f"the trigger URL does not match the allowlist: {shape}"
    print("Record these in docs/design.md (V4): segment count and character classes above.")


# --- V18 and V21 --------------------------------------------------------------------------


def test_v18_ca_paths_and_trust_store(allowlisted: Live) -> None:
    paths = ssl.get_default_verify_paths()
    gateway = SystemGateway()
    candidates = gateway.ca_candidates()
    context = gateway.tls_context()  # raises NoUsableCA when nothing usable exists
    stats = context.cert_store_stats()
    allowlisted.rec.observe(
        "V18",
        "compiled_paths",
        {
            "openssl_cafile": paths.openssl_cafile,
            "openssl_cafile_is_file": os.path.isfile(paths.openssl_cafile),
            "openssl_capath": paths.openssl_capath,
            "openssl_capath_is_dir": os.path.isdir(paths.openssl_capath),
            "tool_cafile": candidates.cafile,
            "tool_capath": candidates.capath,
            "ca_certs_loaded": stats.get("x509_ca"),
            "sources": ca_sources(candidates),
            "python": sys.version.split()[0],
        },
    )
    print(f"\nV18: {allowlisted.rec.observations['V18']}")


def test_v21_plain_message(allowlisted: Live, tmp_path: Path) -> None:
    result = allowlisted.send(
        tmp_path, "plain", "plain start: one ordinary message END-plain", level="info"
    )
    document = sent_ok(result)
    (exchange,) = result.exchanges
    assert exchange.response_body == b'{"ok":true}', "the success body is not exactly the form"
    allowlisted.rec.observe(
        "V21",
        "plain_message",
        {
            "exit": result.code,
            "outcome": document["outcome"],
            "http_status": document["http_status"],
            "response_body": exchange.response_body.decode(),
            "request_bytes": exchange.request_bytes,
            "time_to_response_ms": exchange.elapsed_ms,
            "note": "http.client HTTP/1.1, Connection: close, accepted",
        },
    )
    allowlisted.look("V21", "plain", "one message 'plain start: one ordinary message END-plain'")


def test_validate_test_message(allowlisted: Live, tmp_path: Path) -> None:
    allowlisted.pacer.wait()
    gateway = LiveGateway(markers=(MARKER, TEST_MESSAGE_MARKER))
    result = run_cli(
        ["validate", "--json", "--test-message"],
        url=allowlisted.url,
        gateway=gateway,
        work=tmp_path / "work",
    )
    allowlisted.pacer.mark()
    allowlisted.rec.tally(result.exchanges)
    document = result.document
    assert result.code == 0 and document is not None and document["ok"] is True
    check = {item["name"]: item["ok"] for item in document["checks"]}
    assert check == {"config": True, "credential": True, "test_message": True}
    (exchange,) = result.exchanges
    expected = '{"body":"\U0001f535 INFO slack-notice\\nvalidate: test message"}'.encode()
    assert exchange.request_body == expected and len(expected) == 57
    log = Path(os.environ["HOME"], ".local", "state", "slack-notice", "log.jsonl")
    record = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["message_sha256"] == "cff763132117c5b1" and record["dedupe_key_sha256"] is None
    allowlisted.rec.observe("R", "validate_test_message", "exit 0, 57-byte body, hash as recorded")
    allowlisted.look(
        "R",
        "validate --test-message",
        "one message titled slack-notice, text 'validate: test message'",
    )


# --- V3: limits ---------------------------------------------------------------------------


def test_v3_cli_ascii_at_the_cap(allowlisted: Live, tmp_path: Path) -> None:
    title = allowlisted.title("ascii12000")
    message = message_for_body_size("ascii12000", 12000, title=title)
    document = sent_ok(allowlisted.send(tmp_path, "ascii12000", message))
    assert document["bytes"] == 12000 and document["truncated"] is False
    allowlisted.rec.observe(
        "V3",
        "cli_ascii_at_cap",
        {
            "bytes": document["bytes"],
            "truncated": document["truncated"],
            "message_chars": len(message),
        },
    )
    allowlisted.look(
        "V3",
        "ascii12000",
        "a message ending 'END-ascii12000' (a request body of exactly 12000 bytes). "
        "MISSING = the server drops a body of 12000 bytes",
    )


def test_v3_cli_non_ascii(allowlisted: Live, tmp_path: Path) -> None:
    cases = (("latin2byte", "é", 2), ("cjk3byte", "中", 3), ("emoji4byte", "\U0001f600", 4))
    for label, unit, width in cases:
        message, count = unit_message(label, unit, width, allowlisted.title(label))
        result = allowlisted.send(tmp_path, label, message)
        document = sent_ok(result)
        assert document["bytes"] <= 12000
        allowlisted.rec.observe(
            "V3",
            f"cli_{label}",
            {"chars": count, "bytes": document["bytes"], "truncated": document["truncated"]},
        )
        allowlisted.look(
            "V3",
            label,
            f"a message ending 'END-{label}' with about {count} {unit}-characters "
            f"({document['bytes']} bytes). MISSING = bytes decide the limit even under the cap",
        )


def test_v3_raw_limits(allowlisted: Live) -> None:
    """Raw posts above the tool's own cap, to tell characters from bytes (the CLI cannot). Each
    is a marked message that Slack either shows whole or drops with a success status."""
    cases: list[tuple[str, str, int]] = [
        ("raw-ascii-12001", "x", 12001),
        ("raw-ascii-12500", "x", 12500),
        ("raw-latin-11000chars", "é", 11000),
        ("raw-cjk-6000chars", "中", 6000),
        ("raw-emoji-4000chars", "\U0001f600", 4000),
    ]
    for label, unit, size in cases:
        text = raw_limit_text(label, unit, size)
        body = serialize("body", text)
        result = allowlisted.raw("V3", label, "POST", allowlisted.path, body, POST_HEADERS)
        if result is not None:
            allowlisted.rec.observe(
                "V3",
                label,
                {
                    "chars": len(text),
                    "bytes": len(body),
                    "status": result.status,
                    "body": result.body,
                },
            )
        allowlisted.look(
            "V3",
            label,
            f"ARRIVED whole (ends 'END-{label}') or MISSING; {len(text)} chars, {len(body)} bytes. "
            "Status 200 either way. Record which: whole = characters decide, missing = bytes",
        )


# --- rendering ----------------------------------------------------------------------------


def test_emoji_per_level(allowlisted: Live, tmp_path: Path) -> None:
    shapes = {
        "info": "blue circle INFO",
        "warn": "orange circle WARN",
        "action": "yellow circle ACTION",
        "error": "red circle ERROR",
    }
    for level, words in shapes.items():
        result = allowlisted.send(
            tmp_path,
            f"emoji-{level}",
            f"emoji-{level} start prefix check END-emoji-{level}",
            level=level,
        )
        sent_ok(result)
        allowlisted.look(
            "R",
            f"emoji-{level}",
            f"first line starts with the {words} (Slack may show it as a :shortcode:), "
            "second line 'emoji-" + level + " start prefix check END-emoji-" + level + "'",
        )
    allowlisted.rec.observe("R", "emoji_levels_sent", list(shapes))


def test_auto_link(allowlisted: Live, tmp_path: Path) -> None:
    inline = SCHEME + "example" + ".org/live-inline"
    link = SCHEME + "example" + ".org/live-link"
    result = allowlisted.send(
        tmp_path, "auto-link", f"auto-link start bare {inline} END-auto-link", link=link
    )
    sent_ok(result)
    allowlisted.rec.observe("R", "auto_link", "sent; links are checked by eye")
    allowlisted.look(
        "R",
        "auto-link",
        "both example.org URLs (in the text and on the last line) are clickable links",
    )


def test_text_is_literal(allowlisted: Live, tmp_path: Path) -> None:
    literal = (
        "literal start *bold* _italic_ `code` ~strike~ &amp; &lt;b&gt; <@U0000000> "
        "<not-a-link|label> two\nlines END-literal"
    )
    sent_ok(allowlisted.send(tmp_path, "literal", literal))
    allowlisted.look(
        "R",
        "literal",
        "every marker character shows exactly as typed (no bold, no code, entities literal, no "
        "mention) and 'two' / 'lines' are on separate lines",
    )
    long_text = "cut start " + "word " * 700 + "END-cut"
    link = SCHEME + "example" + ".org/live-cut"
    result = allowlisted.send(
        tmp_path, "cut", long_text, link=link, config="max_chars: 2000\ntimeout: 30s\n"
    )
    assert sent_ok(result)["truncated"] is True
    allowlisted.look(
        "R",
        "cut",
        f"the text ends with '{render.MARKER}' directly followed by the link line below",
    )


# --- V1: rate -----------------------------------------------------------------------------


def _paced_run(live: Live, tmp: Path, label: str, count: int) -> None:
    results: list[CliResult] = []
    live.pacer.wait()
    for number in range(1, count + 1):
        results.append(
            live.send(
                tmp,
                f"{label}-{number}of{count}",
                f"{label} {number} of {count} END-{label}-{number}",
                wait=False,
            )
        )
    exchanges = [item for result in results for item in result.exchanges]
    spacing = gaps(exchanges)
    codes = [result.error.get("code", "sent") for result in results]
    live.rec.observe(
        "V1",
        label,
        {
            "sends": count,
            "outcomes": codes,
            "request_gaps_s": spacing,
            "statuses": [item.status for item in exchanges],
            "total_s": round(sum(result.elapsed_s for result in results), 2),
        },
    )
    print(f"\nV1 {label}: outcomes={codes} gaps={spacing}")
    assert all(result.code == 0 for result in results), f"not all sent: {codes}"
    statuses = [item.status for item in exchanges]
    # A retried 429 shows as an extra exchange: throttling must fail the test, not be absorbed.
    assert len(exchanges) == count, f"expected {count} requests, saw {len(exchanges)}: {statuses}"
    assert all(status == 200 for status in statuses), f"not all 200: {statuses}"
    assert all(gap >= 0.9 for gap in spacing), f"spacing below the 1 s lock: {spacing}"
    live.look(
        "V1",
        label,
        f"{count} messages '{label} N of {count}', in order, none missing "
        "(a missing one was throttled or dropped)",
    )


def test_v1_burst_at_the_lock_spacing(allowlisted: Live, tmp_path: Path) -> None:
    _paced_run(allowlisted, tmp_path, "burst", 4)


def test_v1_sustained_at_the_lock_spacing(allowlisted: Live, tmp_path: Path) -> None:
    _paced_run(allowlisted, tmp_path, "sustained", 8)


# --- V2: wrong URL, GET ---------------------------------------------------------------------


def test_v2_altered_path_status(allowlisted: Live, tmp_path: Path) -> None:
    altered = alter_last_segment(allowlisted.url)
    allowlisted.rec.add_secret(altered.reveal())
    result = allowlisted.send(tmp_path, "altered-path", "never delivered: wrong path", url=altered)
    details = result.error.get("details") or {}
    exchange = result.exchanges[0] if result.exchanges else None
    allowlisted.rec.observe(
        "V2",
        "altered_last_segment_post",
        {
            "exit": result.code,
            "code": result.error.get("code"),
            "http_status": details.get("http_status"),
            "retryable": result.error.get("retryable"),
            "exchange_status": None if exchange is None else exchange.status,
            "response_body": (
                None
                if exchange is None
                else exchange.response_body.decode("utf-8", errors="replace")[:200]
            ),
        },
    )
    assert result.code == 12 and result.error.get("code") == "auth_required"
    allowlisted.rec.observe("V2", "revoked_trigger", "observe manually: revoke, then run validate")


def test_v2_get_probe(allowlisted: Live) -> None:
    altered = alter_last_segment(allowlisted.url)
    allowlisted.rec.add_secret(altered.reveal())
    altered_path = altered.reveal()[len(SCHEME + webhook.HOST) :]
    live_get = allowlisted.raw("V2", "get_on_live_url", "GET", allowlisted.path)
    dead_get = allowlisted.raw("V2", "get_on_altered_url", "GET", altered_path)
    slash_get = allowlisted.raw(
        "V2", "get_on_live_url_with_trailing_slash", "GET", allowlisted.path + "/"
    )
    for key, result in (
        ("get_on_live_url", live_get),
        ("get_on_altered_url", dead_get),
        ("get_on_live_url_with_trailing_slash", slash_get),
    ):
        if result is not None:
            allowlisted.rec.observe("V2", key, result.summary())
    if live_get is not None and dead_get is not None:
        allowlisted.rec.observe(
            "V2", "get_tells_live_from_dead", live_get.status != dead_get.status
        )
    allowlisted.look(
        "V2",
        "GET probe",
        "no new message from the GETs; a workflow failure notice would be worth recording",
    )


# --- everything else the fakes cannot show ----------------------------------------------------


def test_raw_error_shapes(allowlisted: Live) -> None:
    prefix = f'{{"body": "{MARKER} raw-'
    cases: list[tuple[str, bytes, dict[str, str]]] = [
        ("invalid-json", (prefix + "invalid-json (unterminated").encode(), POST_HEADERS),
        (
            "object-value",
            json.dumps({"body": {"x": f"{MARKER} raw-object-value"}}).encode(),
            POST_HEADERS,
        ),
        (
            "wrong-variable",
            json.dumps({"not_the_variable": f"{MARKER} raw-wrong-variable END"}).encode(),
            POST_HEADERS,
        ),
        (
            "text-plain",
            json.dumps({"body": f"{MARKER} raw-text-plain END"}).encode(),
            {"Content-Type": "text/plain"},
        ),
        (
            "no-user-agent",
            json.dumps({"body": f"{MARKER} raw-no-user-agent END"}).encode(),
            POST_HEADERS,
        ),
    ]
    for label, body, headers in cases:
        result = allowlisted.raw("R", f"raw_{label}", "POST", allowlisted.path, body, headers)
        if result is not None:
            allowlisted.rec.observe("R", f"raw_{label}", result.summary())
    allowlisted.look(
        "R",
        "raw shapes",
        "ARRIVES: 'raw-text-plain END' and 'raw-no-user-agent END'. DOES NOT ARRIVE: invalid-json, "
        "object-value, wrong-variable (a workflow failure notice may appear instead)",
    )


def test_o1_idempotency_header(allowlisted: Live) -> None:
    body = serialize("body", f"{MARKER} idempotency-header start END-idem")
    headers = {**POST_HEADERS, "Idempotency-Key": f"live-{allowlisted.rec.run_id}"}
    results = [
        allowlisted.raw(
            "O1", f"post_{number}_with_Idempotency-Key", "POST", allowlisted.path, body, headers
        )
        for number in (1, 2)
    ]
    allowlisted.rec.observe(
        "O1",
        "statuses_with_Idempotency-Key",
        [None if result is None else result.status for result in results],
    )
    allowlisted.look(
        "O1",
        "idempotency header",
        "'idempotency-header start END-idem' arrives ONCE (header honored) or TWICE (ignored)",
    )


def test_tls_verification_failure(allowlisted: Live, tmp_path: Path) -> None:
    def untrusting() -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context  # no CA loaded: the handshake must fail verification

    allowlisted.pacer.wait()
    gateway = LiveGateway(tls=untrusting)
    result = run_cli(
        ["send", "--json"],
        url=allowlisted.url,
        gateway=gateway,
        work=tmp_path / "work",
        notification={"title": allowlisted.title("tls"), "message": "never sent: no trust"},
    )
    allowlisted.pacer.mark()
    details = result.error.get("details") or {}
    allowlisted.rec.observe(
        "T",
        "verification_failure",
        {
            "exit": result.code,
            "code": result.error.get("code"),
            "tls": details.get("tls"),
            "retryable": result.error.get("retryable"),
            "requests_written": len(result.exchanges),
        },
    )
    assert result.code == 12 and result.error.get("code") == "network_error"
    assert details.get("tls") is True and result.exchanges == []


def test_tls_and_dns_details(allowlisted: Live) -> None:
    gateway = LiveGateway()
    addresses = gateway.resolve(webhook.HOST, webhook.PORT)
    conn = open_raw_connection(gateway)
    try:
        conn.connect()
        sock: Any = conn.sock
        cert = sock.getpeercert() or {}
        details = {
            "addresses": len(addresses),
            "ipv6_addresses": sum(1 for item in addresses if ":" in item),
            "tls_version": sock.version(),
            "cipher": (sock.cipher() or ("",))[0],
            "san_entries": len(cert.get("subjectAltName", ())),
        }
    finally:
        conn.close()
    allowlisted.rec.observe("T", "dns_and_tls", details)
    print(f"\nT: {details}")

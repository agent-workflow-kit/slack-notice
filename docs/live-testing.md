# slack-notice: live testing

The live suite posts marked test messages to your own Slack workflow and records what Slack does, to settle the items under [Live verification](design.md#live-verification) (V1 to V5, V18, V21) and the unverified-against-Slack assumptions collected in the live verification checklist issue. It is never part of `make verify` and never runs in CI: the tests carry the `live` marker (excluded by `addopts`), skip unless you opt in, and refuse to run when `CI` is set.

## Prerequisites

- A workflow with a webhook trigger and one text variable named `body`, whose message step shows that variable (see the README). Use a workflow whose destination is you: about 40 messages arrive.
- The trigger URL in a dedicated environment variable, for example `export SLACK_NOTICE_LIVE_WEBHOOK=...` (never on a command line that is logged). Never reuse a production variable such as `SLACK_WEBHOOK`: the suite posts about 34 marked messages plus the failed-run notices below, so point it at a workflow of your own, not one other people read.
- A checkout with the dev environment (`uv sync`).

## Run

```sh
export SLACK_NOTICE_LIVE_URL_ENV=SLACK_NOTICE_LIVE_WEBHOOK
export SLACK_NOTICE_LIVE_REPORT="$HOME/slack-notice-live-report"
make live
```

`SLACK_NOTICE_LIVE_URL_ENV` holds the NAME of the variable that holds the URL, never the URL itself (a value that is not a variable name is refused). The tool under test still reads the URL only from its configured credential variable; the suite hands it the value under `SLACK_WEBHOOK` inside the test process. `SLACK_NOTICE_LIVE_REPORT` is optional: without it the report goes to a new private temporary directory whose path is printed at the end. `make live` is `pytest -m live tests/test_live.py -s -v -x --tb=short`: `-x` stops the whole run at the first failure or Ctrl-C, and `--tb=short` keeps tracebacks free of local variables. Never add `-l`/`--showlocals` or set `PYTEST_ADDOPTS` with it: `http.client` locals hold the secret request path and cannot be redacted.

 Without the opt-in variable every live test is skipped.

The run takes about two minutes. It posts at most one request per 1.5 seconds across the suite, and its burst and sustained tests use the tool's own 1 second send spacing: nothing is looped to stress Slack.

## What is posted

Every message contains the fixed marker `slack-notice live test` (the suite's gateway wrapper refuses any request body without it) and a short run id, so the messages can be told apart from real ones. In order, with the item each settles:

| Test | Messages | Settles |
|---|---|---|
| `test_v4_trigger_url_matches_allowlist` | none | V4: the URL matches the allowlist; segment count and character classes recorded |
| `test_v18_ca_paths_and_trust_store` | none | V18: compiled CA paths and trust store of this Python |
| `test_v21_plain_message` | 1 | V21: HTTP/1.1 with `Connection: close` is accepted; the 200 body is exactly `{"ok":true}` |
| `test_validate_test_message` | 1 | the 57-byte test message body and its log hash |
| `test_v3_cli_ascii_at_the_cap` | 1 | V3: a 12000-byte body |
| `test_v3_cli_non_ascii` | 3 | V3: 2-, 3- and 4-byte characters up to the cap |
| `test_v3_raw_limits` | 5 | V3: raw posts above the tool's cap (12001 and 12500 bytes, then 11000, 6000 and 4000 non-ASCII characters) |
| `test_emoji_per_level` | 4 | the four default emoji arrive intact |
| `test_auto_link` | 1 | Slack auto-links a bare URL in the text and on the link line |
| `test_text_is_literal` | 2 | no markup, mention or entity is interpreted; the cut marker precedes the link line |
| `test_v1_burst_at_the_lock_spacing` | 4 | V1: four sends at the lock's 1 s spacing, none throttled |
| `test_v1_sustained_at_the_lock_spacing` | 8 | V1: eight sends at the lock's 1 s spacing, none throttled |
| `test_v2_altered_path_status` | none arrive | V2: a random last segment (24 or more characters) is answered with a status the tool maps to `auth_required` |
| `test_v2_get_probe` | none | V2: the status of a `GET` on your URL, on the altered URL and on your URL with a trailing slash; no body is sent |
| `test_raw_error_shapes` | 5 (2 arrive) | status and body for invalid JSON, an object value, a wrong variable name, `text/plain` and no User-Agent |
| `test_o1_idempotency_header` | 2 | whether `Idempotency-Key` makes Slack deliver once |
| `test_tls_verification_failure` | none | the tool's answer when the certificate cannot be verified (no request is written) |
| `test_tls_and_dns_details` | none | number of addresses, TLS version and cipher, certificate name count |

Slack may post a workflow failure notice to the workflow owner, or deliver an unmarked or empty message, for any of the malformed requests: the three `GET`s of `test_v2_get_probe`, and the five raw shapes of `test_raw_error_shapes` (invalid JSON, an object value, a wrong variable name, `text/plain`, no User-Agent). Note each one that happens.

## Record the results

The run writes `report.json` and `report.txt` (mode 0600) to the report directory. They list every item with its observed values or `observe manually`, and for each message that only your eyes can check a `LOOK AT THE DESTINATION` entry with what to expect. Slack accepts a request and drops it silently in several cases, so exit 0 and status 200 prove only acceptance: open the destination and check each entry in `report.txt`. The report holds counts, statuses, sizes and character classes only; any trigger URL material that would reach it is replaced by fixed text (the report is still written, so a full run is never lost).

Then record the results. Post ONE results comment on the live verification checklist issue (#37) per run and per platform, stating the platform (the suite must be run on each platform that matters: V18 compiled CA paths, the TLS error classes and the CA path source differ by platform), and refer to the #37 bullets by name:

- V4: copy the segment count and the character classes into the V4 row of [design.md](design.md#live-verification). If the URL does not match the allowlist, the grammar in [interface.md](interface.md#webhook-edge) needs a spec change first; do not widen the pattern on a guess.
- V1, V2, V3, V5, V18, V21 and the open items: answer each #37 bullet in that comment with the date and the result, and update design.md and interface.md before any default is relaxed.
- V2 observes only the alteration of the last path segment (the status and scrubbed body of that one post). That Slack answers 403, 404 or 410 for the other wrong-URL cases is assumed from [interface.md](interface.md), not observed here.
- V18 records the compiled CA paths, how many certificates each of the tool's sources (compiled file, compiled directory, fallback bundles) loads, and which of them the tool itself uses. It makes no network request.
- V1 asserts that each series made exactly one request per message and every status is 200; a retried 429 therefore fails the test. The suite waits 1.5 seconds between any two requests, including between series.
- The first live assertion (V4) is a release criterion: 0.1.0 is not tagged until it passes.

## Not covered

Not reproducible without harming the workflow or needing a second machine, so listed in the report as manual: a revoked trigger (revoke it in Slack and run `slack-notice validate --test-message`), a 5xx after processing, a 429 with `Retry-After`, a redirect, a reset after the request was written, and two machines sending to one workflow (run the suite from both at once and count 429 results and arrivals). A deliberate rate probe above the tool's 1 second spacing is left out on purpose: it would be a stress test, and the spacing is the specified behavior.

Items of the #37 checklist this suite does not cover live, to be checked by hand or not at all: a server idle close, the exact size limit between 12500 and 15000 ASCII characters, a repeated `--test-message` run answered with 429 (#78), a cut inside a ZWJ emoji sequence (#19), `http` to `https` redirects, a revoked trigger, 5xx and 3xx answers, a real 429 with `Retry-After`, and platform or NFS state-directory behavior.

## Safety summary

- The tests are marked `live`, excluded by `addopts`, skipped without `SLACK_NOTICE_LIVE_URL_ENV` and refused when `CI` (or another CI marker) is set.
- `tests/test_live_support.py` runs in normal CI and checks that no live test is collected by default, that no workflow file or default make target runs them, and that the guard conditions work.
- The URL is wrapped so that it never prints, and the live files hold no URL literal.

# slack-notice: implementation plan

Implements [interface.md](interface.md) and [design.md](design.md). The issues for each stage are expanded into bite-sized test-first steps when they are picked up; this plan fixes the order, the conventions and the module map.

## Conventions for every stage

- **Gateway boundary.** All HTTP (`http.client`), TLS context, clock and lock-file access goes through `src/slack_notice/gateway.py`; modules never import `urllib`, `http.client`, `time` or `fcntl` directly. Tests substitute a fake gateway.
- **Fake gateway.** Process tests call `cli.main(argv, env, gateway)` with a fake gateway in-process, because the URL must be on `hooks.slack.com` and verification cannot be disabled; no test-only environment seam is allowed. The fake gateway exposes a response script (each row of the interface's Webhook edge table, including a 200 with a wrong body, a 3xx and a 5xx), a delay, a stalled name resolution, a stall after the first byte, a trickled response, a TLS failure and a post-write failure. There are no sibling tools to pin.
- **Process and live split.** Only the `live` tests (pytest marker, never in CI) touch the network: they post to the maintainer's own workflow and are listed in the live-verification issue.
- **Golden files.** `--json` outputs, rendered bodies and log records have golden files; a golden hash test (fixed input, expected `message_sha256`) and a golden serialization test (`ensure_ascii=False`, compact separators, key order); schemas have positive and negative samples.
- **Spike regressions.** Every behavior in design.md's live-verification table becomes a fake-gateway test or a `live` test.
- **Secrets.** A test sets a recognizable fake URL and asserts it appears in no argv, output, log, error or file; a test injects `InvalidURL` and `ValueError` carrying the fake URL and asserts it is absent from stdout, stderr and the log.
- **Environment.** A test with a fake proxy variable and a fake `SSL_CERT_FILE` asserts zero connections reach the proxy and the fake CA is not trusted; a redirect test asserts a second server receives zero requests.
- **`make verify`** passes before every commit; each paragraph in markdown is one line.

## Module map

| Module | Stage | Responsibility |
|---|---|---|
| `gateway.py` | 0 | HTTP, TLS context, clock, lock file. |
| `cli.py` | 0, 3, 4 | Parsing, dispatch, exit codes, output. |
| `config.py` | 1 | Config, drop-ins, YAML, durations. |
| `log.py` | 1 | State directory, log records and rotation. |
| `payload.py` | 2 | Input reading, validation, sanitizer, link rule. |
| `render.py` | 2 | Body layout and cuts. |
| `spacing.py` | 3 | Send lock and 1 s spacing. |
| `webhook.py` | 3 | URL allowlist, request, response mapping, retries, deadline. |

## Stage 0: Scaffold and gateway

**Goal**: A package that installs, prints `--version`, and has the gateway and the fake gateway in place.
**Success Criteria**: `make verify` green; schemas load; the fake gateway serves each response row.
**Tests**: version output golden; fake gateway contract tests; schema positive and negative samples.
**Status**: Not Started

## Stage 1: Config, state directory and log

**Goal**: Config loading with validation and the safe state directory and log, before anything that needs them.
**Success Criteria**: invalid config exits 2 naming the key and never the value; log records match the schema and never contain text; rotation works; a state problem never changes an exit code.
**Tests**: config precedence (flags, config, defaults; no environment override); drop-in merge; file rules (65536-byte cap, non-regular file, parse error names the path, missing `--config` file); duration table (`10`, `"10s"`, `"1m"`, `"500ms"` out of range for a 3s minimum, `"1h"` refused, `.nan`, `true`, `"1e3"` refused, `-1`); `level_prefix` the sanitizer would change is `config_invalid`; Pydantic messages hold no input value; `webhook_env` that looks like a URL says "must be a variable name"; unusable state directory (symlinked dir, mode 0755, read-only, wrong owner): exit code of the send unchanged and one warning; concurrent rotation with two processes; `HOME` unset; relative `XDG_STATE_HOME` ignored; log golden files; `log: false`. Pydantic and PyYAML are added here.
**Status**: Not Started

## Stage 2: Input, sanitizer and rendering

**Goal**: Validate and render a notification without any network.
**Success Criteria**: `send --dry-run` prints the exact body for stdin, file and flag input, with cuts and the sanitizer applied.
**Tests**: sanitizer table (controls, bidi, ZWSP, CRLF, lone surrogates, tabs, and rows for U+061C, U+2028, U+2029, U+0085, tag character U+E0041, U+00AD, U+FE0F, U+FFFE, U+FFFF, U+FDD0, a U+3164-only message (`empty_message`), `"a\n \n \nb"` collapsing, a title with LF and U+2028 on one line, a fullwidth space only (`empty_message`)); input table (empty stdin, `[]`, `null`, `"x"`, BOM, `{"message":"a","message":"b"}`, `NaN`, 100000-deep nesting, 1 MiB + 1 bytes, a FIFO as `--file`, `--file /dev/zero`, a directory, a symlink to a regular file accepted); flag and combination errors; link table (`HTTPS://x.example` accepted and rendered lowercase, `https://a.example\n` refused, `https://a.example\@evil.example`, `https://:80/`, `http://[::1]/`, `javascript:x` link_scheme, `example.com:80/x` link_scheme, non-ASCII, 1025 characters); layout cases (levels, no title, no link, default emoji prefixes, long message at both boundaries, 3000 four-byte characters within 12000 bytes); cut table with exact outputs; every refusal reason; flag and stdin parity; usage error with `--json` prints the envelope.
**Status**: Not Started

## Stage 3: Webhook send, spacing and the deadline

**Goal**: A real `send` against the fake gateway with the full response table.
**Success Criteria**: every row of the Webhook edge table maps to its exit code and envelope; spacing queues concurrent callers; the URL is checked and never leaked; total wall time never exceeds `timeout` plus 1 s.
**Tests**: response table; 429 three times (waits 2 s and 4 s), connect-refused retried once, 5xx not retried, `Retry-After` of `nan`, `-5`, `1e999`, an HTTP date and `5` (clamped to 30 and to the deadline); a failure after the first byte is `outcome_unknown` with no retry; envelope flags per code (`retryable`, `unknown_outcome`, `retry_after_s`); deadline tests (stalled name resolution, stall after the first byte, response trickled byte by byte, SIGTERM); concurrent sends spaced by the lock's mtime, a future mtime ignored, a lock wait that outlasts the deadline exits 12 `unavailable`; URL allowlist table (valid with 1 to 4 segments, a query, a port, userinfo, a trailing dot, an empty segment, another host, empty, unset): `credential_invalid` with `details.env`; a token containing CR LF; `enabled: false` exits 22 without draining stdin; exit-1 handler prints only a class name; golden hash and serialization tests.
**Status**: Not Started

## Stage 4: `validate`, live verification and docs

**Goal**: `validate [--test-message]`, the live suite and user documentation.
**Success Criteria**: validate checks match the interface; the live suite passes against the maintainer's workflow and settles the still-to-verify items V1 to V6; README documents workflow setup and cron use.
**Tests**: validate golden files (no prompt in any case; `enabled` reported; `--test-message` on a disabled tool exits 22); live tests (plain message, limit-sized message, non-ASCII byte versus character limit, the four default emoji arrive intact, auto-link, burst and sustained-rate spacing, 403/404/410 where reproducible, a `GET` on a trigger URL).
**Status**: Not Started

## Version roadmap

- **0.x**: Stages 0 to 4.
- **1.0** when the live suite has passed and the tool has run in daily use through a routing tool for two weeks without an interface change.
- **1.x, additive**: a configurable `min_interval` after the sustained-rate test; a `chat.postMessage` transport for users who can obtain an app token (formatting, mentions, self-DM); an optional headless-Claude transport; classic incoming webhook support; a read-only `GET` probe if V2 shows it works; `limits` in `validate --json`.
- **2.0**: nothing planned.

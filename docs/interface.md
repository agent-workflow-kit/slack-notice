# slack-notice: interface

Status: 0.1.0-design, 2026-11-17. Written before implementation (architecture section 18.1). This document is the single normative source for slack-notice's rules; `docs/design.md`, the README and the architecture link to its headings and do not restate them.

slack-notice sends one plain-text notification to Slack through a Slack workflow's webhook trigger. It is stateless: it keeps no database, only `log.jsonl` and a lock file. It runs no hooks and takes no policy decisions: when to send, what to send and how often belong to its caller.

References: architecture (`../awkit-docs/architecture.md`) sections 5.1, 13.2, 13.3, 15 and 20; design guide (`../awkit-docs/design-guide.md`).

## Concepts

### Transport

0.x has one transport, the **workflow trigger**: a Slack Workflow Builder workflow that starts from "a webhook" and sends a message containing one text variable. The URL looks like `https://hooks.slack.com/triggers/…` and is a secret (anyone holding it can post to the workflow). The workflow decides where the message goes (a person or a channel) and what it looks like around the variable; the message appears from the workflow's app, not from a person. The classic incoming webhook (`/services/…`), `chat.postMessage` with a token and the official Slack CLI are not supported in 0.x ([Residual risks](#residual-risks)).

The user's workflow has exactly one text variable (name set by config `body_variable`, default `body`); everything the tool sends is folded into that one string.

### Notification

A notification is a JSON object ([schemas/notification.json](../schemas/notification.json)):

| Field | Type | Required | Rule |
|---|---|---|---|
| `title` | string | no | One line (newlines become spaces); at most 256 characters after sanitizing, cut at the limit with `…` and `truncated: true` when longer. At most 100000 characters of input. |
| `message` | string | yes | At most 100000 characters of input. Must not be empty after sanitizing (else exit 20 `refused`, reason `empty_message`). |
| `level` | `info`, `warn`, `action`, `error` | no | Default `info`. Ordered `info < warn < action < error`; the order matters to callers, not to slack-notice. |
| `link` | string | no | `http` or `https` URL, at most 1024 characters, no whitespace or control characters, no userinfo (`user:pass@`). Anything else exits 20 `refused`, reason `link_invalid` (`link_scheme` for another scheme). The schema checks only this syntactic gate (http or https, no userinfo, no whitespace or control characters, at most 1024 characters); the tool names `link_invalid` or `link_scheme`. |

Unknown fields exit 20 `refused`, reason `invalid_payload` (`details.pointer`); input over 100000 characters (title or message) does the same; slack-notice never forwards free-form data. Input is read from stdin as JSON (`send --stdin-json`, also the default when stdin is not a terminal and no text flag is given), from a file (`--file <path|->`), or from flags (`--title`, `--message`, `--level`, `--link`). Flag text is untrusted and goes through the same [sanitizer](#sanitizer) and rendering as stdin text; flags exist for humans. Giving both a JSON source and a text flag exits 2 `usage`.

### Sanitizer

Applied to `title` and `message` before rendering, in this order:

1. Invalid UTF-8 or lone surrogates: exit 20 `refused`, reason `invalid_payload`.
2. CRLF and CR become LF.
3. Control characters (category Cc) except LF are removed; the tab becomes a space.
4. Invisible and direction-changing format characters are removed: U+200B to U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066 to U+2069, U+FEFF.
5. Runs of more than two LF become two; leading and trailing whitespace is trimmed.

Nothing else is escaped: the trigger variable is plain text, and Slack does not parse markup, mentions or `<url|label>` links in it, so entity escaping would show up as visible `&amp;`. The link is added only through `link`, as a bare URL.

### Rendering

The body string is built as:

```text
<prefix> <title>
<message>
<link>
```

`<prefix>` is the level's entry in config `level_prefix` (defaults `INFO`, `WARN`, `ACTION`, `ERROR`; any one-line string up to 16 characters). The first line is the prefix alone when there is no title. The link line is omitted without a link.

The body is limited to config `max_chars` characters (default 3000, 2000 to 12000, counted in Unicode code points). When it is longer, the message is cut and ends with `…[truncated]` so that the whole body fits, and the result has `truncated: true`; the link is never cut. A title longer than 256 characters after sanitizing is cut with `…` at that limit and also sets `truncated: true`; it is not refused. The server does not truncate: a body over its limit is dropped with a success status, which is why the tool enforces its own limit.

## Commands

### `send`

`slack-notice send [--stdin-json | --file <path|->] [--title <t>] [--message <m>] [--level <l>] [--link <url>] [--dedupe-key <k>]`

Order, with the exit code of each refusal:

1. Parse flags (exit 2 `usage`).
2. Load config (exit 2 `config_invalid`). `enabled: false` prints `{"outcome": "disabled"}` and exits 22 here, before any input is read.
3. Read and validate input (exit 2 `usage` for a conflicting source; exit 20 `refused` with reason `invalid_payload`, `empty_message`, `link_invalid` or `link_scheme`).
4. Render the body ([Rendering](#rendering)). With `--dry-run`, print the result with `rendered` and exit 0: the credential is not read, nothing is sent and nothing is logged.
5. Read the webhook URL from the environment variable named by `webhook_env` and validate its shape ([Webhook edge](#webhook-edge)); exit 20 `refused` with reason `credential_missing` (`details.env`) or exit 2 `config_invalid`. Check the state directory (exit 12 `state_unsafe`).
6. Take the send lock and wait out `min_interval` since the last send ([Send spacing](#send-spacing)), then POST the body ([Webhook edge](#webhook-edge)) and map the response to an exit code ([Exit codes](#exit-codes)).
7. Append the [log record](#log) and print the result.

`--dedupe-key` (grammar `^[A-Za-z0-9._:@/-]{1,128}$`) is accepted for uniformity with other notifiers and recorded (hashed) in the log; Slack has no deduplication, so it changes nothing about delivery.

### `validate`

`slack-notice validate [--probe]`

Checks the config, that the credential variable is set, and that its value has the shape of a workflow-trigger URL (`https`, host `hooks.slack.com`, path under `/triggers/`, no query or fragment). When the config loads, it prints `{ok, checks: [{name, ok, message}]}` ([schemas/cli/validate.json](../schemas/cli/validate.json)) and, with `--probe`, a `probe` object `{sent, delivery_not_observable}`. It exits 0 when every check passes. Otherwise it still prints the document, with `ok: false`, and exits with the exit code of the first failing check: 20 (`refused`, with its reason `credential_missing`) for a missing credential, 2 (`config_invalid`) for a wrong-shaped URL, 12 for a failed probe. When the config cannot load, it prints the [error envelope](#error-envelope) instead and exits 2 `config_invalid`. The checks are named `credential`, `credential_shape` and, with `--probe`, `probe`.

`--probe` also sends one clearly marked test notification (`INFO slack-notice validate: test message`). It asks for confirmation on `/dev/tty` unless `--yes` is given. A successful probe proves the URL is accepted, not that the message arrives: Slack accepts a request with a wrong variable name and drops it silently, so the output has `probe: {sent: true, delivery_not_observable: true}` and tells the user to look in Slack. It exits 0 on `sent`, with the same failure exits as `send` (the document then has `ok: false`, `probe.sent: false` and a failing `probe` check). The probe is a send and is logged like one.

## Global flags

| Flag | Meaning |
|---|---|
| `--json` | Machine output on stdout ([Output](#output)). |
| `--config <path>` | Config file instead of `~/.config/slack-notice/config.yaml` (drop-ins are read next to it). |
| `--dry-run` | `send` only: render and print, send nothing, read no credential, write no log record (also for a refusal found in a dry run). |
| `--yes` | `validate --probe` only: skip the confirmation. Never overrides a refusal. |
| `--actor <actor>` | Recorded in the log (`actor_source` `flag`). Without it: `human:<user>` when stdin is a terminal (`tty`), else `auto:unknown` (`default`) (design guide section 4.4); a caller passes `auto:<name>`. |
| `--verbose`, `--quiet` | More or less human output on stderr. |
| `--version` | Print `slack-notice <version>`. |

## Send spacing

Slack throttles a workflow webhook (about one request per second sustained; a burst of twelve in four seconds was refused in testing) and drops what it throttles. `send` therefore takes an exclusive lock on `~/.local/state/slack-notice/tmp/send.lock` (opened without following symlinks) and sleeps until `min_interval` (default 1 s) has passed since the previous send's start, which is stored in the lock file. Concurrent callers queue; the wait counts against `timeout`, and a caller still waiting when `timeout` ends exits 12 `unavailable` (`reason: locked`) without sending. This spaces calls from one machine only.

## Webhook edge

- The URL comes only from the environment variable named by `webhook_env`; it is never read from a file by slack-notice, never logged, never in argv, output, errors or the log. Surrounding whitespace is trimmed. The shape check above is enforced on every send; a URL for another host or scheme exits 2 `config_invalid` (`details.key: webhook_env`) so a mistaken variable cannot send the body elsewhere.
- Request: `POST` over HTTPS with certificate verification always on (no option to disable it), `Content-Type: application/json`, `User-Agent: slack-notice/<version>`, a body of exactly `{"<body_variable>": "<text>"}`, through the Python standard library's HTTP client in `gateway.py`. Redirects are not followed. At most 4 KiB of the response is read.
- `body_variable` matches `^[A-Za-z_][A-Za-z0-9_]{0,63}$`.

| Response | Result |
|---|---|
| 200 with `{"ok":true}` | `sent` (exit 0). |
| 200 with anything else | Exit 12 `wrong_host_response`, `retryable: false`, `unknown_outcome: true`. |
| 400 | Exit 12 `host_rejected`, `retryable: false`; `details.host_error` is the response's error string if it is a short token (`invalid_input`, `invalid_workflow_input`), else null. |
| 401, 403, 404, 410 | Exit 12 `auth_required`, `retryable: false` (the URL is wrong or was revoked; the message says to regenerate the trigger URL). |
| 429 | Retried up to twice with waits of 2 s and 4 s (or `Retry-After` when sent, at most 30 s) within `timeout`; then exit 12 `rate_limited`, `retryable: true`, `retry_after_s` the last wait or null. |
| 5xx | Retried once after 2 s within `timeout`; then exit 12 `upstream_error`, `retryable: true`. |
| Any other status | Exit 12 `wrong_host_response`, `retryable: false`, `unknown_outcome: false`. |
| Connection, DNS or TLS failure before the request is fully sent | Exit 12 `network_error`, `retryable: true`. |
| Timeout or connection loss after the request is fully sent | Exit 12 `outcome_unknown`, `retryable: true`, `unknown_outcome: true`. slack-notice never retries this case itself: a retry can send the message twice. |

A throttled or dropped request often still returns success, so exit 0 means only that Slack accepted the request. Output says `sent`, never `delivered`.

## Output

With `--json`, `send` prints one object ([schemas/cli/send.json](../schemas/cli/send.json)): `{outcome, tool, level, truncated, bytes, duration_ms, http_status, dedupe_key, rendered}`. `outcome` is `sent`, `dry_run` or `disabled`; a disabled run prints only `{"outcome": "disabled"}`. `bytes` is the UTF-8 size of the body; `http_status` is null for a dry run; `dedupe_key` echoes the caller's own `--dedupe-key` (or null); `rendered` (the body string, no secrets) is present only for a dry run. Without `--json`, human text goes to stderr and stdout is empty.

Errors print the [error envelope](#error-envelope) on stdout with `--json` and a one-line message on stderr otherwise.

## Exit codes

Codes 0–21 follow design guide section 4.2. slack-notice defines one code of 22 or above.

| Exit | Meaning | Codes, or reasons for exit 20 |
|---|---|---|
| 0 | Accepted by Slack (`sent`) or a dry run. | |
| 1 | Internal error. | `internal` |
| 2 | Usage or invalid configuration. | `usage`, `config_invalid` |
| 12 | Failed for a reportable reason. | `host_rejected`, `auth_required`, `rate_limited`, `upstream_error`, `network_error`, `outcome_unknown`, `wrong_host_response`, `unavailable` (`reason: locked`), `state_unsafe` |
| 20 | Refused before sending: `code` is `refused`, `reason` required. | Reasons: `invalid_payload`, `empty_message`, `link_invalid`, `link_scheme`, `credential_missing` |
| 22 | Nothing sent: the tool is disabled in config. | `disabled` (not an error; output `{"outcome": "disabled"}`) |

Exits 10, 11, 13 and 21 are never used: slack-notice stores no objects, has no hooks and asks no human. A caller treats exit 22 as a successful no-op.

### Error envelope

`{"error": {"code", "message", "reason", "details", "retryable", "retry_after_s", "unknown_outcome"}}` ([schemas/cli/error.json](../schemas/cli/error.json)); only `code` and `message` are required. Exit 20 has `code: refused` with `reason` set to one of the refusal reasons; `unavailable` (exit 12) has `reason: locked`; `reason` is null elsewhere. `retryable`, `retry_after_s` and `unknown_outcome` are booleans (`retry_after_s` a number or null) on exit 12 and null elsewhere. `details` by code or reason: `config_invalid` → `key`; reason `invalid_payload` → `pointer`; reason `credential_missing` → `env`; `host_rejected` → `host_error`, `http_status`; `unavailable` → `lock`. Messages never contain the URL or any part of it.

Exit 12 values:

| Code | `retryable` | `unknown_outcome` |
|---|---|---|
| `host_rejected`, `auth_required`, `state_unsafe` | `false` | `false` |
| `wrong_host_response` | `false` | `true` for a 200 with a bad body, else `false` |
| `rate_limited`, `upstream_error`, `network_error`, `unavailable` | `true` | `false` |
| `outcome_unknown` | `true` | `true` |

## Hooks

None in 0.x. slack-notice sends one message and takes no policy decisions; gating and routing belong to the caller (a producer's hooks, or the routing tool above it). A `post-send` hook that itself notifies on failure could call this tool again and loop, which is the other reason there are none. Adding hooks later is additive.

## Config

`~/.config/slack-notice/config.yaml` (respecting `XDG_CONFIG_HOME`), then `config.d/*.yaml` in lexical order; maps merge, other lists replace. Schema: [schemas/config.json](../schemas/config.json); example: [config.example.yaml](../config.example.yaml). Invalid config exits 2 `config_invalid` naming the key (`details.key`). `timeout` and `min_interval` use the design guide's duration grammar (a number of seconds or a string such as `10s`, `1m`, `500ms`); the tool enforces the stated ranges at load. Precedence: flags, then environment (scalar keys only, [Environment variables](#environment-variables)), then config, then defaults. There is no per-repo override: the tool has no notion of a repository.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` makes `send` exit 22 without reading input or the credential. |
| `webhook_env` | `SLACK_WEBHOOK` | Name of the environment variable holding the trigger URL (the URL itself is never in config). |
| `body_variable` | `body` | Name of the workflow's text variable. |
| `level_prefix` | `{info: INFO, warn: WARN, action: ACTION, error: ERROR}` | One-line prefixes, at most 16 characters each. |
| `max_chars` | `3000` | Body limit, 2000 to 12000. |
| `min_interval` | `1s` | Minimum time between sends from this machine, 1s to 60s. |
| `timeout` | `10s` | Budget for one `send`, including waiting for the lock and retries, 1s to 120s. |
| `log` | `true` | `false` writes no `log.jsonl`. |

## Environment variables

- `SLACK_NOTICE_<KEY>` sets a scalar config key (`SLACK_NOTICE_ENABLED`, `SLACK_NOTICE_WEBHOOK_ENV`, `SLACK_NOTICE_BODY_VARIABLE`, `SLACK_NOTICE_MAX_CHARS`, `SLACK_NOTICE_MIN_INTERVAL`, `SLACK_NOTICE_TIMEOUT`, `SLACK_NOTICE_LOG`); `level_prefix` cannot be set from the environment.
- The variable named by `webhook_env` holds the credential. Under cron or any hook, that variable must be in the calling process's environment; the docs recommend a mode-0600 env file sourced by the cron line. slack-notice never reads shell startup files or secret files itself.

## Log

`~/.local/state/slack-notice/log.jsonl` (respecting `XDG_STATE_HOME`), mode 0600, appended without following symlinks; one record per outcome that reaches `send` step 3 or later ([schemas/log.json](../schemas/log.json)): `{ts, tool, version, outcome, exit, code, reason, level, bytes, truncated, duration_ms, http_status, message_sha256, dedupe_key_sha256, actor, actor_source}`. All fields are always present; nullable ones are null when not known. `outcome` is `sent` (exit 0), `refused` (exit 20), `failed` (exit 12 except an unknown outcome) or `outcome_unknown` (exit 12 `outcome_unknown`). Not logged: exit 1, exit 2, exit 22 (`disabled`) and dry runs. `code` is `refused` for exit 20, the error code for exit 12 and null on success; `reason` is the refusal reason, `locked` for `unavailable`, else null. `actor_source` is `flag` (from `--actor`), `tty` (stdin is a terminal) or `default` (`auto:unknown`). `message_sha256` and `dedupe_key_sha256` are the first 16 hex characters of the SHA-256 of the rendered body and of the key. Records never contain a title, message, link, URL or any credential. The file rotates at 1 MiB, keeping 3 files (`log.jsonl.1` to `.3`). A log write failure warns on stderr and never changes the exit code. There is no audit file: a notification changes nothing in a system of record.

## Files

| Path | Content |
|---|---|
| `~/.config/slack-notice/config.yaml`, `config.d/*.yaml` | Config. |
| `~/.local/state/slack-notice/log.jsonl` (and `.1` to `.3`) | Log records. |
| `~/.local/state/slack-notice/tmp/send.lock` | Send spacing lock and the last send's start time. |

`~/.local/state/slack-notice/` and `tmp/` are created with mode 0700 and opened without following symlinks, and checked to be directories owned by the user with mode 0700 on every send (else exit 12 `state_unsafe`). There is no database and no migration.

## Labels

slack-notice creates no long-lived objects and takes no labels.

## TUI

None in v1.

## Residual risks

- **Silent drops.** Slack answers a request with a wrong variable name, a missing variable, an oversized body or an empty object with success and delivers nothing. The tool prevents the cases it can (its own limit, a non-empty body, a fixed variable name) but cannot see a misnamed `body_variable`; `validate --probe` relies on a human looking.
- **No delivery confirmation and no deduplication.** Exit 0 means Slack accepted the request. A retry after `outcome_unknown` can send the message twice.
- **The URL is a bearer secret.** Any process of the same user that can read the environment variable or the file it came from can post to the workflow. The workflow's failure notices (for example for an oversized body) go to the workflow's owner, not to the caller.
- **Throttling is shared.** Spacing covers one machine; other machines or tools using the same workflow share Slack's limit, and throttled requests are lost.
- **Plain text only.** No formatting, no clickable `<url|label>` links and no mentions are produced by anything in the text; a bare URL may or may not be auto-linked by Slack, and `:shortcode:` text may become an emoji. The tool does not rely on either.
- **Limits counted in characters.** The 3000 default is far below the 12500 characters delivered in testing; whether the server counts characters or bytes for non-ASCII text is unverified ([design.md](design.md), Live verification).
- **Not supported in 0.x:** posting as a person or into a self-conversation, formatted messages (these need an app with a token), the classic incoming webhook, and the Slack CLI (its `slack api` command takes text only in argv, logs it in plaintext, exits 0 on API errors, and its login token cannot post).

## Platform notes

Linux and WSL are required. macOS is expected to work (standard library only) but is not a required platform. Windows native is not supported.

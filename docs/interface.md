# slack-notice: interface

Status: 0.1.0-design, 2026-11-17 (review pass 1 resolved). Written before implementation (architecture section 18.1). This document is the single normative source for slack-notice's rules; `docs/design.md`, the README and the architecture link to its headings and do not restate them.

slack-notice sends one plain-text notification to Slack through a Slack workflow's webhook trigger. It is stateless: it keeps no database, only `log.jsonl` and two lock files. It runs no hooks and takes no policy decisions: when to send, what to send and how often belong to its caller.

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
| `link` | string | no | Printable ASCII, 1 to 1024 characters, `http` or `https` URL without userinfo; see the link rule below. Anything else exits 20 `refused`, reason `link_invalid` (`link_scheme` for another scheme). |

link is optional and is checked in this order. (1) It is a string of 1 to 1024 printable ASCII characters (U+0021 to U+007E); anything else, including whitespace, control characters, non-ASCII characters and an empty string, is reason link_invalid (callers percent-encode paths and give hosts as punycode). (2) If it starts with a scheme token ([A-Za-z][A-Za-z0-9+.-]*:) whose lowercase form is not http or https, the reason is link_scheme. (3) It must match (?i:https?)://(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:[/?#][\x21-\x7e]*)? as a whole, and a port must be 1 to 65535, else link_invalid (no userinfo, no empty host, no backslash between host and path). The scheme is lowercased wherever the link is rendered. The schema pattern is a coarse gate for the same rule; the tool is authoritative. A link names a place to open and is never a promise that it is safe: a caller that builds links from untrusted text takes that risk.

Slack auto-links any bare URL in the text, so there is no `link_hosts` key: the URL is visible to the reader before they open it.

Exactly one source is used: JSON on stdin (send --stdin-json, also the default when stdin is not a terminal and no text flag is given), JSON from --file <path> (--file - is stdin, the same source), or flags. A JSON source together with --title, --message, --level or --link, or --stdin-json together with --file <path>, exits 2 usage. Flags alone need --message; stdin that is a terminal with no source and no --message exits 2 usage. A --file that does not exist, cannot be read or is not a regular file (the tool opens it with O_NONBLOCK and checks the opened descriptor; a symlink to a regular file is fine) exits 2 usage.

At most 1048576 bytes are read from a source. More, input that is not valid UTF-8 or that begins with a byte order mark, JSON that fails to parse, nests too deeply (RecursionError), repeats an object key or contains NaN or Infinity, a top-level value that is not an object, or input that does not arrive within the deadline ([Webhook edge](#webhook-edge)) exits 20 refused, reason invalid_payload, details.pointer "".

Fields: an unknown field, a field of the wrong type (null is a wrong type: absent fields are omitted), a level outside info, warn, action, error, or a title or message of more than 100000 characters exits 20 invalid_payload with details.pointer set to "/<field>". A flag value is checked like the same JSON field and uses the same pointer. A message that is empty after sanitizing is empty_message (the schema has no minLength for it). Error messages and details never contain an input value, only the pointer and the rule.

Flag and combination errors (an unknown flag, a missing value, a bad --actor) exit 2 usage. slack-notice never forwards free-form data. Flag text is untrusted and goes through the same [sanitizer](#sanitizer) and rendering as stdin text; flags exist for humans.

### Sanitizer

Applied to title and message before rendering, in this order. Every pattern in this document is matched against the whole string (re.fullmatch); a trailing newline never passes.

1. Input is read as bytes and decoded as strict UTF-8, never through the locale. Invalid UTF-8 or a lone surrogate: exit 20 refused, reason invalid_payload.
2. CRLF, CR, U+0085, U+2028 and U+2029 become LF. The tab becomes a space.
3. These characters are removed: every character of category Cc other than LF, and of categories Cf, Cs and Co; the noncharacters U+FDD0 to U+FDEF and U+FFFE and U+FFFF of every plane; and the blank-looking fillers U+034F, U+115F, U+1160, U+17B4, U+17B5, U+180B to U+180D, U+2800, U+3164, U+FE00 to U+FE0F, U+FFA0 and U+E0100 to U+E01EF. This removes zero-width, direction and tag characters, the soft hyphen and the byte order mark. It also removes the zero-width joiner and variation selector 16, so some emoji sequences are shown as separate or text-style emoji.
4. Trailing whitespace of every line is removed (str.rstrip), then runs of more than two LF become two, then leading and trailing whitespace is removed (str.strip, Unicode whitespace).
5. title only: every LF becomes a space, runs of spaces become one space, and the result is stripped again.

A message that is empty after step 4 is refused with reason empty_message. A title that is empty after step 5 is absent.

No markup is escaped: the trigger variable is plain text, and Slack does not parse markup, mentions or `<url|label>` links in it, so entity escaping would show up as visible `&amp;`. Slack does auto-link any bare URL in the text, whether it came from `link`, `message` or `title`.

### Rendering

The body string is built as:

```text
<prefix> <title>
<message>
<link>
```

`<prefix>` is the level's entry in config `level_prefix`. The defaults are `🔵 INFO`, `🟠 WARN`, `🟡 ACTION` and `🔴 ERROR` (U+1F535, U+1F7E0, U+1F7E1, U+1F534 followed by a space and the level name); any one-line string of 1 to 16 characters that the [sanitizer](#sanitizer) leaves unchanged is allowed. The first line is the prefix alone, with no trailing space, when there is no title. The link line is omitted without a link. In short: `body = prefix_line + LF + message + (LF + link)`.

The body is limited to config `max_chars` code points (default 3000, 2000 to 12000) and to 12000 UTF-8 bytes (fixed, not configurable), whichever is reached first. The server does not truncate: a body over its limit is dropped with a success status, which is why the tool enforces its own limits. A request body is the JSON document of [Output](#output) and is serialized the way it describes, so non-ASCII text is not expanded into escapes.

Limits count Unicode code points. A title longer than its limit L is cut to its first L-1 characters plus … (L in all, before the level prefix is added) and truncated is true. The prefix is added after the cut and does not count. A message cut for length keeps as many characters as fit, has trailing whitespace removed, and ends with the marker so that the result, marker included, is within the limit; truncated is true. A cut may split a combining or emoji sequence; that is accepted. When the title is empty and the prefix is not, the title line is the prefix alone with no trailing space; when both are empty the title line is absent.

For slack-notice the limit is the whole body, both limits (characters and bytes) are honoured by the cut, the marker is `…[truncated]` and the link is never cut. The title limit is 256 (so the title line is at most 16 + 1 + 256 characters), and 256 + 16 + 1024 + 2 is below the `max_chars` minimum, so the message always has room. The marker and the default prefixes differ from the sibling notifiers on purpose: slack-notice has one text field and no separate title.

## Commands

### `send`

`slack-notice send [--stdin-json | --file <path|->] [--title <t>] [--message <m>] [--level <l>] [--link <url>] [--dedupe-key <k>] [--decision-id <id>]`

Order, with the exit code of each refusal:

1. Parse flags (exit 2 `usage`).
2. Load config (exit 2 `config_invalid`). `enabled: false` prints `{"outcome": "disabled"}` (with `--json`) or one line on stderr and exits 22 here, before any input is read.
3. Read and validate input ([Notification](#notification); exit 2 `usage` for a conflicting source; exit 20 `refused` with reason `invalid_payload`, `empty_message`, `link_invalid` or `link_scheme`). The [deadline](#webhook-edge) starts here.
4. Render the body ([Rendering](#rendering)). With `--dry-run`, print the result with `rendered` and exit 0: the credential is not read, nothing is sent, no state directory is used and nothing is logged.
5. Read the webhook URL from the environment variable named by `webhook_env` and validate it ([Webhook edge](#webhook-edge)); exit 12 `credential_invalid` (`details.env`) when it is unset, empty or has the wrong shape.
6. Take the send lock and wait for the spacing ([Send spacing](#send-spacing)), then POST the body ([Webhook edge](#webhook-edge)) and map the response to an exit code ([Exit codes](#exit-codes)).
7. Append the [log record](#log) and print the result.

--dedupe-key takes any non-empty string of at most 1024 characters (valid UTF-8, else exit 2 usage). It is only hashed; the send output echoes the caller's own key or null. --decision-id (repeatable) is accepted for uniformity with the design guide and ignored: the log is hash-only and there is no audit file. Slack has no deduplication, so the key changes nothing about delivery, only the log.

### `validate`

`slack-notice validate [--test-message]`

validate never prompts. It prints {ok, enabled, checks: [{name, ok, message}]} (schemas/cli/validate.json), where enabled is the configured value. Checks run in the order listed for the tool; a failed check ends the run and later checks are omitted, so ok is true only when every printed check is ok. It exits 0 when ok is true, otherwise with the exit code of the failing check (config: 2; credential and test_message: the exit code of the corresponding failure, 12 or 20). When the config cannot be loaded it prints the error envelope instead and exits 2. Without --json it prints one line per check on stderr.

--test-message sends one notification through the normal render and send path (level info, title "slack-notice", message "validate: test message"; no dedupe key or tag) and adds the check test_message; its message says that delivery is not observable and tells the user to look at the destination. It is a send: it is logged like a send, and it exits 22 like send when the tool is disabled. slack-notice has no --probe (below). Automation does not call --test-message.

The checks of slack-notice, in order, are `config`, `credential` (the unset, empty and wrong-shape test in one; exit 12 `credential_invalid`) and, with `--test-message`, `test_message`. slack-notice has no `--probe` and no `platform` or `powershell` check: it has no read-only call that tells a live trigger URL from a dead one (spike A: a `GET` returned 200 and delivered nothing, and was never verified as a validity test), so a revoked URL is found only by `--test-message`. With `enabled: false`, `validate --test-message` makes no call and exits 22 with `{"outcome": "disabled"}`; plain `validate` still runs and reports `enabled: false`. A successful `test_message` proves the URL is accepted, not that the message arrives: Slack accepts a request with a wrong variable name and drops it silently, so look in Slack. A doctor runs `validate --json` without flags.

## Global flags

| Flag | Meaning |
|---|---|
| `--json` | Machine output on stdout ([Output](#output)). |
| `--config <path>` | Config file instead of `~/.config/slack-notice/config.yaml` (drop-ins are read next to it). |
| `--dry-run` | `send` only: render and print, send nothing, read no credential, write no log record (also for a refusal found in a dry run). |
| `--actor <actor>` | Recorded in the log (`actor_source` `flag`); see the rule below. |
| `--verbose`, `--quiet` | More or less human output on stderr. `--verbose` never prints a request line, a header, a URL or a response body. |
| `--version` | Print `slack-notice <version>`. |

`--actor` must match `^(human|auto):[A-Za-z0-9._@/-]{1,64}$` (else exit 2 usage). Without it the actor is human:<user> when stdin is a terminal (actor_source tty) and auto:unknown otherwise (default), where <user> is the login name from the password database with every character outside [A-Za-z0-9._@-] replaced by `_` and cut to 64 characters; the design guide's me.name does not exist here because the tool has no me key. A caller passes `auto:<name>`.

## Send spacing

Slack throttles a workflow webhook: a burst of 12 requests in about 3 seconds got 429 in testing; no sustained rate was measured, and 1 s spacing is a conservative guess. `send` takes an exclusive flock on `send.lock` in the state directory (polled without blocking every 50 ms inside the deadline, opened relative to the state directory descriptor) and waits until one second has passed since the lock file's modification time, ignoring a modification time in the future or more than 1 s old; it sets the modification time (`os.utime`) when it starts the POST and holds the lock until the send ends, retries included. A caller still waiting when the deadline passes exits 12 `unavailable` (`retryable: true`) without sending. The lock is not fair; callers serialize ([Calling from automation](#calling-from-automation)). This spaces calls from one machine only. If the state directory is unusable there is no spacing ([Files](#files)). The spacing is fixed at 1 s; a configurable interval can return additively after a sustained-rate test.

## Webhook edge

- The URL comes only from the environment variable named by `webhook_env`; it is never read from a file by slack-notice, never in argv, a URL printed anywhere, output, errors, verbose lines or the log. The URL (surrounding whitespace trimmed; empty after trimming is unset) must match `https://hooks\.slack\.com/triggers/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+){0,3}` as a whole: no port, userinfo, query, fragment, trailing dot, empty segment or other host. The check proves the variable holds a workflow-trigger URL, not that the URL is yours. Unset, empty or non-matching exits 12 `credential_invalid` (`details.env`), checked whole before any header or URL is built, so a mistaken variable cannot send the body elsewhere.
- Request: All HTTP goes through gateway.py using http.client.HTTPSConnection, built from the validated host and port; urllib is not used. Proxy environment variables are not read and no proxy is supported in 0.x. Redirects are never followed and a Location header is never read, printed or logged: a 3xx answer is wrong_host_response. Headers are Content-Type: application/json, Accept: application/json, Connection: close and User-Agent: slack-notice/<version>. HTTP debug output is never enabled and --verbose never prints a request line, a header, a URL or a response body. The body is exactly `{"<body_variable>": "<text>"}`.
- The TLS context is ssl.SSLContext(PROTOCOL_TLS_CLIENT) with check_hostname on, CERT_REQUIRED and a minimum of TLS 1.2. Trust comes from ssl.get_default_verify_paths().openssl_cafile and .openssl_capath (the compiled defaults); SSL_CERT_FILE and SSL_CERT_DIR are ignored. If neither default path exists, the first existing file of /etc/ssl/certs/ca-certificates.crt, /etc/pki/tls/certs/ca-bundle.crt and /etc/ssl/cert.pem is used; if none exists the send is network_error with details.tls true. There is no option to disable verification.
- The response is read in chunks of at most 1 KiB until the cap of 4 KiB is reached; a body that is longer, is not valid UTF-8 or fails the hardened JSON parse of the input rules (duplicate keys and NaN refused, RecursionError caught) is a bad body. The success form is `{"ok":true}`: a 200 whose body parses as a JSON object with `ok` equal to `true` (other keys ignored).
- Secrets: a credential is validated whole before any header or URL is built, else exit 12 credential_invalid. No exception text from http.client, ssl or socket is ever printed or logged: the exit 1 handler prints the exception class name and a fixed message only, and an exception from the network layer is mapped by its class to one of the codes below. A credential, or any part of it, never appears in argv, a URL printed anywhere, a log record, an error message, a verbose line or an exit 1 message.
- `body_variable` matches `^[A-Za-z_][A-Za-z0-9_]{0,63}$`.

**Deadline.** Config timeout is one wall-clock deadline for the whole send, counted from the start of input reading (step 3) to the end of step 6. It covers reading input, waiting for the send lock, name resolution, connecting, TLS, writing the request, reading the response, retry waits. The network phase runs in a worker thread; the main thread waits for it with the time that remains and, at the deadline, reports the result below, writes the log record, prints the output and exits without waiting for the worker. A first SIGINT or SIGTERM is treated as the deadline having passed.

The result at the deadline depends on how far the request got. Before the first byte of the request was written exit 12 network_error (retryable true, details.timeout true), or unavailable when waiting for the send lock. After the first byte was written: exit 12 outcome_unknown. Input that has not arrived at the deadline is invalid_payload (see [Notification](#notification)). A wait (a retry wait or the lock wait) that is longer than the time that remains ends the send at once with the code of the last result, without sleeping.

Status to code mapping (the flags of each code are in [Error envelope](#error-envelope)):

| Response | Result |
|---|---|
| 200 with the success form | `sent` (exit 0). |
| Any 2xx other than the success form, including a 200 whose body is not the success form | Exit 12 `wrong_host_response` with `unknown_outcome` true. |
| 400 | Exit 12 `host_rejected`; `details.host_error` is the string value of the response's key `error` when it matches `[a-z_]{1,64}`, else null; `details.http_status` 400. |
| 401, 403, 404, 410 | Exit 12 `auth_required` with `details.http_status`; the message says to regenerate the trigger URL. Only 401 `invalid_auth` was seen in testing; 403, 404 and 410 are assumed. |
| 429 | Retried (below); then exit 12 `rate_limited`. |
| 5xx | Exit 12 `upstream_error` with `unknown_outcome` true; not retried. |
| 3xx, and any other status not listed | Exit 12 `wrong_host_response` with `unknown_outcome` false. |
| Failure before the first request byte was written (name resolution, connection refused or timed out, TLS handshake failure) | Retried once (below); then exit 12 `network_error`. A certificate verification failure is not retried and has `details.tls` true. |
| Any failure after the first request byte was written (timeout, reset, early end of the response) | Exit 12 `outcome_unknown`; never retried. |

429: retried up to twice, after 2 s and then 4 s, or after the Retry-After value when it is 1 to 3 digits (seconds, at most 30; any other form is ignored); a wait longer than the time left in the deadline ends the send at once with rate_limited and retry_after_s set to that wait. A failure before the first request byte was written (name resolution, connection refused or timed out, a TLS handshake failure that is not a certificate verification failure) is retried once after 2 s inside the deadline, then is network_error. Nothing else is retried: a 5xx is upstream_error with unknown_outcome true, and any failure after the first request byte was written (timeout, reset, early end of the response) is outcome_unknown. Any 2xx other than the success form, including a 200 whose body is not the success form, is wrong_host_response with unknown_outcome true; any other status that is not listed is wrong_host_response with unknown_outcome false.

The log outcome is outcome_unknown whenever the envelope's unknown_outcome is true, and failed for any other exit 12.

A throttled request is answered 429, not success; what Slack drops silently with a success status is an oversized body or a misnamed variable. Exit 0 means only that Slack accepted the request. Output says `sent`, never `delivered`.

## Output

Global flags may appear before or after the subcommand. The tool looks for --json in argv before it parses anything, so a usage error with --json prints the envelope (code usage) on stdout; --help and --version are exempt. Errors always print one line on stderr; with --json they also print the error envelope on stdout. With --json a successful send prints one object on stdout; without it human text goes to stderr and stdout is empty (a dry run prints the rendered text on stderr). A disabled tool prints {"outcome":"disabled"} on stdout with --json and one line on stderr without it, and exits 22 either way. stderr is advisory (warnings, verbose lines); the contract is the exit code plus the stdout JSON.

With `--json`, `send` prints one object ([schemas/cli/send.json](../schemas/cli/send.json)): `{outcome, tool, level, truncated, bytes, duration_ms, http_status, dedupe_key, rendered}`. `outcome` is `sent`, `dry_run` or `disabled`; a disabled run prints only `{"outcome": "disabled"}`. `http_status` is null for a dry run; `dedupe_key` echoes the caller's own `--dedupe-key` (or null); `rendered` (the body string, no secrets) is present only for a dry run.

Every JSON document that the tool sends, hashes or measures is serialized with json.dumps(obj, ensure_ascii=False, separators=(",", ":")), keys in the order given in this document, and encoded as UTF-8. bytes in the output and the log is the length of the request payload in that form (slack-notice: the request body, `{"<body_variable>": text}`).

## Exit codes

Codes 0 to 21 follow design guide section 4.2. Exit 0: sent or a dry run. Exit 1: internal error. Exit 2: usage or invalid configuration (codes usage, config_invalid). Exit 12: failed for a reportable reason (the codes of the tool, below). Exit 20: refused before sending because of the payload; code refused with a required reason. Exit 22: nothing sent because the tool is disabled in config (not an error; output {"outcome":"disabled"}). Exits 10, 11, 13 and 21 are never used: the tool stores no objects, has no hooks and never prompts. A caller treats exit 22 as a successful no-op.

| Exit | Meaning | Codes, or reasons for exit 20 |
|---|---|---|
| 0 | Accepted by Slack (`sent`) or a dry run. | |
| 1 | Internal error. | `internal` |
| 2 | Usage or invalid configuration. | `usage`, `config_invalid` |
| 12 | Failed for a reportable reason. | `host_rejected`, `auth_required`, `credential_invalid`, `rate_limited`, `upstream_error`, `network_error`, `outcome_unknown`, `wrong_host_response`, `unavailable` |
| 20 | Refused before sending because of the payload: `code` is `refused`, `reason` required. | Reasons: `invalid_payload`, `empty_message`, `link_invalid`, `link_scheme` |
| 22 | Nothing sent: the tool is disabled in config. | `disabled` |

Exit 20 means only that the payload was refused: a producer fault, never retried. An environment fault (no usable credential) is an exit 12 code, so a router has one rule: 20 drop and surface, 12 look at `retryable` and `unknown_outcome`, 22 no-op. A state-directory problem is never an error ([Files](#files)).

### Error envelope

The error envelope is {"error": {"code", "message", "reason", "details", "retryable", "retry_after_s", "unknown_outcome"}} ([schemas/cli/error.json](../schemas/cli/error.json)); only code and message are required and the other keys are present with null when they do not apply. reason is set only on exit 20. retry_after_s is set only for rate_limited (the last wait performed, or the wait that did not fit the deadline). retryable means that sending the same notification again is safe. unknown_outcome means that the notification may already have been delivered. They are set as follows.

- Exit 2 and exit 20: retryable null, unknown_outcome null.
- Exit 1: retryable false; unknown_outcome true when the failure happened after the first byte of the request was written, else false. The envelope on exit 1 is best effort: exit 1 with no envelope means the outcome is unknown.
- Exit 12: both are booleans: not sent and permanent (false, false): host_rejected, auth_required, credential_invalid; not sent and worth retrying (true, false): rate_limited, unavailable, network_error (but false, false for a certificate failure, details.tls true); request accepted or possibly accepted (false, true): outcome_unknown, upstream_error and wrong_host_response when the host answered 2xx and the answer is not the success form (any other wrong_host_response is false, false).

details by code or reason: config_invalid: key (a config key, or the file path for a file that cannot be read or parsed); reason invalid_payload: pointer; credential_invalid: env; auth_required: http_status (401, 403, 404 or 410); host_rejected: http_status and host_error; network_error: tls, timeout. A message never contains an input value or a credential.

## Hooks

None in 0.x. slack-notice sends one message and takes no policy decisions; gating and routing belong to the caller (a producer's hooks, or the routing tool above it). A `post-send` hook that itself notifies on failure could call this tool again and loop, which is the other reason there are none. Adding hooks later is additive.

## Calling from automation

Canonical call: slack-notice send --stdin-json --json --actor auto:<name>, the payload on stdin, absent fields omitted (never null). Decide by exit code: 0 sent; 22 disabled, a successful no-op; 20 the payload was refused, do not retry (a caller may retry once without link after link_invalid or link_scheme, putting the URL in the message); 12 read retryable and unknown_outcome: retry only when retryable is true, and when unknown_outcome is true the notification may already have been delivered; 2 a usage or config fault of the caller or the deployment; 1 an internal error (no envelope means the outcome is unknown). The tool exits before reading stdin when it is disabled or its config is invalid, so a caller ignores EPIPE or SIGPIPE on the stdin write and decides by the exit code alone. The tool does no queueing: a caller sends one notification at a time per tool and does not start several in parallel. To send to several destinations use one config file per destination with --config. A permission profile for an agent allows only send --stdin-json --json --actor ... and denies --config, --file and the text flags, because those choose the destination and read arbitrary files. Messages that consist of a single token are not special for slack-notice.

## Config

Config is read from ~/.config/slack-notice/config.yaml (XDG_CONFIG_HOME is honoured when it is an absolute path), then config.d/*.yaml in lexical order; maps merge. A missing default config file means defaults; a missing file named by --config exits 2 config_invalid with details.key "--config". Files are parsed with yaml.safe_load, must be at most 65536 bytes and regular files (symlinks are followed; the opened descriptor is checked), and the top level must be a mapping; a file that cannot be read or parsed exits 2 config_invalid with details.key set to its path. Unknown keys are refused. Booleans are only the YAML booleans true and false; a boolean is never accepted for a number, and a number must be finite. There are no environment overrides and no per-repo override: precedence is flags, then config, then defaults. The environment variable that holds a credential is named by the config key shown in the table; it is the only variable the tool reads for a secret.

Durations (timeout and others) are a number of seconds, or a string matching [0-9]+(\.[0-9]+)?(ms|s|m)? (no unit means seconds); the tool enforces the range of each key at load with a check that is false for NaN (lo <= x <= hi). Invalid config exits 2 config_invalid, details.key naming the key; a message names the key and the rule and never the value (for a name key that looks like a URL it says "must be a variable name").

Schema: [schemas/config.json](../schemas/config.json); example: [config.example.yaml](../config.example.yaml). The `webhook_env` name matches `^[A-Za-z_][A-Za-z0-9_]{0,127}$`. `level_prefix` values are run through the sanitizer rule (one line) at load; a value that the sanitizer would change is `config_invalid` (it is not silently rewritten).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` makes `send` exit 22 without reading input or the credential. |
| `webhook_env` | `SLACK_WEBHOOK` | Name of the environment variable holding the trigger URL (the URL itself is never in config). |
| `body_variable` | `body` | Name of the workflow's text variable. |
| `level_prefix` | `{info: "🔵 INFO", warn: "🟠 WARN", action: "🟡 ACTION", error: "🔴 ERROR"}` | One-line prefixes, 1 to 16 characters each. |
| `max_chars` | `3000` | Body limit in code points, 2000 to 12000 (a 12000-byte cap also applies). |
| `timeout` | `10s` | The one deadline of a `send` ([Webhook edge](#webhook-edge)), including waiting for the lock and retries, 3s to 120s. |
| `log` | `true` | `false` writes no `log.jsonl`. |

## Environment variables

- The variable named by `webhook_env` holds the credential. Under cron or any hook, that variable must be in the calling process's environment; the docs recommend a mode-0600 env file sourced by the cron line. slack-notice never reads shell startup files or secret files itself.
- `XDG_CONFIG_HOME`, `XDG_STATE_HOME` (absolute paths only) and `HOME` locate config and state. No other variable is read, and there are no `SLACK_NOTICE_*` overrides.

## Log

The log lives in the state directory ([Files](#files)); one record per outcome that reaches `send` step 3 or later ([schemas/log.json](../schemas/log.json)): `{ts, tool, version, outcome, exit, code, reason, level, bytes, truncated, duration_ms, http_status, message_sha256, dedupe_key_sha256, actor, actor_source}`. All fields are always present.

log.jsonl holds one record per outcome that reaches step 3 or later. Not logged: exit 1, exit 2, exit 22 and dry runs. A write takes an exclusive flock on log.lock for the few microseconds it needs, rotates when the file is 1 MiB or more (log.jsonl.2 to .3, .1 to .2, log.jsonl to .1), and appends the record with one write of less than 1 KiB. A log write failure (including a full disk) warns on stderr and never changes the exit code. config log false writes nothing.

outcome is sent (exit 0), refused (exit 20), outcome_unknown (exit 12 whenever the envelope's unknown_outcome is true) or failed (any other exit 12). code is refused for exit 20, the error code for exit 12 and null on success; reason is the refusal reason for exit 20 and null otherwise. actor_source is flag, tty or default. duration_ms (integer, never null) is the time from the start of step 3 to just before the log write. Nullable and always present: level (null when no valid level was read), bytes, truncated and message_sha256 and dedupe_key_sha256 (null for a refusal before rendering, or when not computed), http_status (null unless a response arrived). Records never contain a title, message, link, URL, base URL, service, host or credential. There is no audit file: a notification changes nothing in a system of record.

message_sha256 is the first 16 hex characters of the SHA-256 of the UTF-8 bytes of the sanitized title (empty string when absent), a LF, and the sanitized message, before any cut, prefix or link, so the same input gives the same value in every notifier. dedupe_key_sha256 is the first 16 hex characters of the SHA-256 of the key's UTF-8 bytes. Both are null when not computed (a refusal before the text was sanitized, or no key).

## Files

| Path | Content |
|---|---|
| `~/.config/slack-notice/config.yaml`, `config.d/*.yaml` | Config. |
| `$XDG_STATE_HOME/slack-notice/log.jsonl` (and `.1` to `.3`) | Log records. |
| `$XDG_STATE_HOME/slack-notice/log.lock` | Lock taken while a log record is written and the log rotated. |
| `$XDG_STATE_HOME/slack-notice/send.lock` | Send spacing lock; its modification time is the last send's start. |

The state directory is $XDG_STATE_HOME/slack-notice when XDG_STATE_HOME is set to an absolute path, else $HOME/.local/state/slack-notice (HOME from the password database when unset). It is created with mode 0700, opened with O_DIRECTORY and O_NOFOLLOW, and checked on that descriptor to be owned by the user with no group or other permissions; every file below it is opened relative to that descriptor (dir_fd), the log with O_APPEND and mode 0600. It is used only when it is needed (a log record or the send lock). If it cannot be used the tool warns once on stderr, writes no log record and takes no lock, and the exit code is unchanged: a state problem never blocks or fails a send. There is no database and no migration.

## Labels

slack-notice creates no long-lived objects and takes no labels.

## TUI

None in v1.

## Residual risks

- **Silent drops.** Slack answers a request with a wrong variable name, a missing variable, an oversized body or an empty object with success and delivers nothing (a throttled request is answered 429 instead). The tool prevents the cases it can (its own limits, a non-empty body, a fixed variable name) but cannot see a misnamed `body_variable`; `validate --test-message` relies on a human looking.
- **No delivery confirmation and no deduplication.** Exit 0 means Slack accepted the request. A resend after `outcome_unknown` or a 5xx can send the message twice; the envelope says so (`unknown_outcome: true`) and is not retryable.
- **The URL is a bearer secret.** Any process of the same user that can read the environment variable or the file it came from can post to the workflow. The workflow's failure notices (for example for an oversized body) go to the workflow's owner, not to the caller.
- **Throttling is shared.** Spacing covers one machine; other machines or tools using the same workflow share Slack's limit, and throttled requests are lost.
- **Plain text only.** No formatting, no clickable `<url|label>` links and no mentions are produced by anything in the text; Slack auto-links any bare URL in the text, whether it came from `link`, `message` or `title` (spike A F4), and `<url|label>` is not interpreted. `:shortcode:` text may become an emoji.
- **Limits.** Whether the server counts characters or bytes for non-ASCII text is unverified ([design.md](design.md), Live verification); the 12000-byte cap keeps either reading safe.
- **Level is advisory.** The prefix does not authenticate the sender: a producer can write `ERROR:` in a title.
- **Same-user threat boundary.** A process that can write the user's config or set an XDG path can redirect the tool; the state directory is checked but the config is trusted.
- **Log hash.** `message_sha256` is a 64-bit unsalted hash; a short message can be confirmed against the log by a reader of the 0600 file.
- **Silencing.** A drop-in or the config can disable the tool (exit 22, one stderr line, nothing logged); a user who relies on it for alerts should check `validate`, which reports `enabled`.
- **No proxy, no custom CA.** Proxy variables, `SSL_CERT_FILE` and `SSL_CERT_DIR` are ignored in 0.x, so a machine that can reach Slack only through a proxy or an inspecting gateway cannot use the tool.
- **Not supported in 0.x:** posting as a person or into a self-conversation, formatted messages (these need an app with a token), the classic incoming webhook, and the Slack CLI (its `slack api` command takes text only in argv, logs it in plaintext, exits 0 on API errors, and its login token cannot post).

## Platform notes

Linux and WSL are required. macOS is expected to work (standard library plus the config parser) but is not a required platform. Windows native is not supported.

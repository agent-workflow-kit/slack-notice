# slack-notice

slack-notice sends one plain-text notification to Slack through the webhook trigger of a Slack workflow. You give it a title, a message, a level and an optional link; it sanitizes the text, folds it into the single text variable of your workflow, posts it and tells you by exit code and one line of JSON whether Slack accepted it.

It is a command-line tool and nothing more. It does not decide when to send, keeps no database and no queue, runs no hooks and never prompts. It cannot post as a person, format messages, mention users, send to a channel by name or confirm that a message was delivered. The classic incoming webhook, `chat.postMessage` with a token and the Slack CLI are not supported. Linux and WSL are supported; macOS is expected to work; native Windows is not supported.

The normative specification is [docs/interface.md](docs/interface.md). This README is the short path from a Slack workflow to a first notification.

## How the examples are checked

Command blocks in this README that can run offline are executed by the test suite through the real command-line entry point against a fake network gateway (see `tests/test_readme.py`), and their exit codes and JSON output are checked against the schemas in `schemas/`. Blocks marked `manual` in the source (installation, live Slack steps, shell setup) are not executed by any test. The other HTML-comment markers (`test`, `expect`, `expect-stderr`, `test-config`) are test annotations and not part of what you type, and a trailing `# exit N` in a command block annotates the expected exit code and is not part of the command.

## 1. Create the workflow in Slack

slack-notice talks to a workflow that starts from a webhook. The exact screens change over time, so check Slack's own documentation for Workflow Builder and webhook triggers; the steps below name only what the tool needs.

1. Create a workflow whose trigger is a webhook.
2. Give the trigger exactly one variable of type text. The default name slack-notice expects is `body`. If you name it anything else, set `body_variable` in the config (below).
3. Add a step that sends a message to the person or channel you want, and put that variable into the message text.
4. Publish the workflow and find its webhook trigger URL (where Slack shows it may vary), then copy it.

The workflow decides where the message goes and how it looks around the variable; the message appears as the workflow's app, not as a person. Everything slack-notice sends (level prefix, title, message and link) arrives in that one variable.

The trigger URL is a secret: anyone who has it can post to your workflow. Never paste it into a config file, a command line, a ticket or a chat.

## 2. Install

Python 3.12 or newer is required (3.12 and 3.13 are tested). With [uv](https://docs.astral.sh/uv/):

<!-- manual -->

```sh
uv tool install git+https://github.com/agent-workflow-kit/slack-notice
```

From a checkout of this repository:

<!-- manual -->

```sh
uv tool install .
```

The command is `slack-notice`. Check that your shell finds it:

<!-- test -->

```sh
slack-notice --version
```

If the shell says the command is not found, put the directory printed by `uv tool dir --bin` on your `PATH` (`uv tool update-shell` can do that for you).

slack-notice needs direct HTTPS access to `hooks.slack.com`; proxies and custom CAs are not supported in 0.x (see section 10).

For development, `uv sync` installs the dev tools and `make verify` runs the checks. The runtime dependencies are PyYAML and Pydantic; HTTP uses the standard library.

## 3. Give the tool the URL

The URL reaches slack-notice only through an environment variable. The config holds the variable's name (`webhook_env`, default `SLACK_WEBHOOK`), never the URL. slack-notice reads no file and no shell startup script to find it, and it never accepts the URL as an argument.

Keep the URL in a file that only you can read, written with an editor so it never lands in your shell history or the process list. Create the file, then edit it so that it holds this one line, with `<trigger URL>` replaced by your trigger URL:

<!-- manual -->

```sh
( umask 077; mkdir -p ~/.config/slack-notice; touch ~/.config/slack-notice/env )
```

<!-- manual -->

```sh
export SLACK_WEBHOOK='<trigger URL>'
```

Load it into the shell that runs the tool (POSIX shells such as bash and zsh):

<!-- manual -->

```sh
. ~/.config/slack-notice/env
```

The export lasts only for that shell. Source the file again in each new shell, or in the script or scheduler line that calls slack-notice.

Surrounding whitespace (such as a trailing newline) is ignored. An unset or empty variable, a value that is not a Slack workflow trigger URL and a value longer than 1024 characters all give exit 12 `credential_invalid`, before anything is sent.

## 4. Check the setup

<!-- test -->

```sh
slack-notice validate
```

A passing run prints these lines on stderr and nothing on stdout:

<!-- expect-stderr -->

```text
config: ok (configuration is valid)
credential: ok (the webhook credential is set and has the form of a workflow trigger URL)
```

<!-- test -->

```sh
slack-notice validate --json
```

Plain `validate` never prompts, makes no network call and sends nothing; `--test-message` is the exception. It checks that the config loads (`config`) and that the credential variable holds a value shaped like a trigger URL (`credential`). It cannot tell a live URL from a revoked one. A tool disabled in the config still reports configuration and credential faults, and `--json` includes `enabled` in its document, and the effective `limits` (`max_chars`, `max_bytes`, `timeout_s`, `spacing_s`) whenever the config loaded.

Without `--json` it prints one line per check on stderr, `<name>: ok (<message>)` or `<name>: failed (<message>)`; `--quiet` keeps only the failed lines. Exit 0 means every check passed, exit 2 means the config is invalid, exit 12 means the credential check failed.

Then send one real test message by hand. If your workflow's variable is not named `body`, set `body_variable` first (section 5), or Slack may accept the message and drop it:

<!-- test -->

```sh
slack-notice validate --test-message
```

A passing run adds a `test_message: ok (...)` line after the two lines above, and stdout stays empty:

<!-- expect-stderr -->

```text
config: ok (configuration is valid)
credential: ok (the webhook credential is set and has the form of a workflow trigger URL)
test_message: ok (the test message was accepted by Slack; delivery is not observable, so look at the destination to confirm it arrived)
```

`--test-message` is a real send of one message (level `info`, title `slack-notice`, message `validate: test message`) through the normal path, so it uses the send lock, the spacing, the deadline and the retries, and it writes a log record. Exit 0 means Slack accepted it. Exit 12 means the credential check or the test send failed; for the send, the message names no cause and the cause is in the log record when logging is on. A failed credential check ends the run with exit 12 and sends nothing. Exit 22 means the tool is disabled in the config and no call was made. Look in Slack to confirm the message arrived: Slack accepts a request that names the wrong variable and drops it silently, and only a person can see that. Scripts and schedulers should not call `--test-message`; use plain `validate --json` and read `enabled`.

## 5. Configuration

The config is optional: without it the defaults below apply. It is `.config/slack-notice/config.yaml` under your home directory, with the home directory taken from the password database (`HOME` and `XDG_CONFIG_HOME` are not read, and a home directory that cannot be used is exit 2); `getent passwd "$USER"` shows it. So the `~` of the env file in section 3 is your shell's home, while the config is read from the password-database home. Files named `*.yaml` in a `config.d` directory beside it are read afterwards in lexical order and merged over it key by key. `--config <path>` reads another file instead, and its drop-ins come from the `config.d` beside that file. Precedence is config over the built-in defaults: no flag changes a setting and there are no environment overrides. An unknown key, a wrong type or an out-of-range value is exit 2 `config_invalid` naming the key. The file is strict YAML (for example `no` and `off` stay strings and are rejected where a boolean belongs) and at most 64 KiB. [config.example.yaml](config.example.yaml) lists every key.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` makes `send` exit 22 without reading input or the credential. |
| `webhook_env` | `SLACK_WEBHOOK` | Name of the environment variable that holds the trigger URL. |
| `body_variable` | `body` | Name of the workflow's text variable. |
| `level_prefix` | `info`, `warn`, `action`, `error` with a colored dot and the level name | One-line prefix per level, 1 to 16 characters each. |
| `max_chars` | `3000` | Body limit in characters, 2000 to 12000. |
| `timeout` | `10s` | The one deadline of a send, 3s to 120s; a number of seconds or a string such as `10s` or `1m`. |
| `log` | `true` | `false` writes no `log.jsonl`. |

A config that sets the variable name used by your workflow and the variable holding the URL:

<!-- test-config -->

```yaml
webhook_env: SLACK_WEBHOOK
body_variable: message_text
timeout: 20s
```

To send to several workflows, keep one config file per destination and select it with `--config`.

## 6. Send a notification

The example commands in this section send a real message to your workflow when you run them, except those with `--dry-run`. A notification has an optional `title`, a required `message`, an optional `level` (`info`, `warn`, `action` or `error`; default `info`) and an optional `link` (an `http` or `https` URL in printable ASCII). The caller's own text should travel on stdin or in a file, never in arguments or the environment. Flags exist for humans at a terminal.

<!-- test -->

```sh
printf '%s' '{"title": "Build", "message": "all green", "level": "warn", "link": "https://a.example/x"}' | slack-notice send --stdin-json --json
```

`--file <path>` reads the same JSON from a file (`--file -` is stdin). Create `notice.json` with the JSON object above:

<!-- manual -->

```sh
printf '%s' '{"title": "Build", "message": "all green", "level": "warn", "link": "https://a.example/x"}' > notice.json
```

Then send it:

<!-- test -->

```sh
slack-notice send --file notice.json --json
```

From flags, for a human:

<!-- test -->

```sh
slack-notice send --title "Backup" --message "Finished" --level warn
```

`--dry-run` shows exactly what would be sent without reading the credential, sending, using the state directory or logging. The rendered text is the level prefix and the title on the first line, then the message, then the link:

<!-- test -->

```sh
printf '%s' '{"title": "Build", "message": "all green", "level": "warn", "link": "https://a.example/x"}' | slack-notice send --stdin-json --json --dry-run
```

<!-- expect -->

```json
{"outcome":"dry_run","tool":"slack-notice","level":"warn","truncated":false,"bytes":58,"duration_ms":0,"http_status":null,"dedupe_key":null,"rendered":"🟠 WARN Build\nall green\nhttps://a.example/x"}
```

A real send with `--json` prints one such object with `outcome` `sent` and the HTTP status Slack answered with. Without `--json`, stdout is empty and stderr gets one human line such as `sent (warn, 875 ms)`.

`--dedupe-key=<hex>` is a caller's identifier for the notification. It is only hashed into the log; Slack does not deduplicate, so it changes nothing about delivery. A key that starts with `-` needs the `=` form. `--decision-id <id>` is accepted for uniformity and ignored. `--actor auto:<name>` records who called in the log.

<!-- test -->

```sh
printf '%s' '{"message": "nightly job finished"}' | slack-notice send --stdin-json --json --actor auto:nightly --dedupe-key=6e696768746c79
```

A payload the tool refuses is never sent:

<!-- test -->

```sh
printf '%s' '{"message": "   "}' | slack-notice send --stdin-json --json  # exit 20
```

Other global flags: `--config <path>`, `--verbose` (one line per phase on stderr, never a URL or body), `--quiet` and `--version`. Flags are exact: no abbreviations, and `--flag=value` always works.

## 7. Exit codes

A script decides by exit code and, for 12, by the `retryable` and `unknown_outcome` fields of the error document that `--json` prints on stdout (`{"error": {"code", "message", "reason", "details", "retryable", "retry_after_s", "unknown_outcome"}}`).

| Exit | Meaning | Codes (reasons for exit 20) | In a script |
|---|---|---|---|
| 0 | Accepted by Slack (`sent`), or a dry run. | | Done. |
| 1 | Internal error. | `internal` | A fault; with no error document the outcome is unknown. |
| 2 | Usage or invalid configuration. | `usage`, `config_invalid` | A fault in the caller or the deployment; do not retry. |
| 12 | Failed for a reportable reason. | `host_rejected`, `auth_required`, `credential_invalid`, `rate_limited`, `upstream_error`, `network_error`, `outcome_unknown`, `wrong_host_response`, `unavailable` | Read `retryable` and `unknown_outcome` (below). |
| 20 | The payload was refused before sending. | `invalid_payload`, `empty_message`, `link_invalid`, `link_scheme` | A producer fault; never retry. |
| 22 | Nothing sent: `enabled` is false in the config. | `disabled` | Not an error; treat it as a successful no-op. |

A process that receives SIGTERM, SIGINT or SIGHUP before the send starts exits with 128 plus the signal number, prints nothing and writes no log record.

For exit 12:

- `retryable: true` and `unknown_outcome: false` (`rate_limited`, `unavailable`, and `network_error` unless `details.tls` is true): nothing was sent and sending again is safe. Back off on your own schedule; inside its deadline the tool has already waited and retried for `rate_limited` (2 s, then 4 s) and `network_error` (2 s, once), but not for `unavailable`. `retry_after_s` is set only for `rate_limited`; it is the tool's own backoff value (written like `4.0`), not a hint from Slack. A `network_error` can also mean the machine has no direct route to `hooks.slack.com` (see section 10).
- `retryable: false` and `unknown_outcome: false` (`host_rejected`, `auth_required`, `credential_invalid`, `network_error` with `details.tls` true (a certificate or TLS failure), and a `wrong_host_response` for an unexpected status, a 3xx or an unlisted 4xx): nothing was sent and retrying is unlikely to help until a person fixes the config or the URL or regenerates the trigger URL. A `wrong_host_response` may be transient; retry it only under your own cap.
- `unknown_outcome: true` (`outcome_unknown`, `upstream_error`, and a `wrong_host_response` after a 2xx answer, after a final 1xx or out-of-range status, or after an answer that is not HTTP): the message may already have been delivered. Do not blindly resend, because Slack does not deduplicate; record it as possibly sent.

`unavailable` also covers input that did not arrive in time and a wait for the send lock that the deadline could not cover; nothing was sent. A caller that kills the tool should wait at least the configured `timeout` plus 10 seconds, and then treats the outcome as unknown.

## 8. What the output means

`sent`, and exit 0, mean only that Slack accepted the request. They do not mean the message was delivered or read. In testing, Slack answered success and dropped the message when the variable name did not match the workflow, and it dropped an oversized body the same way; the tool prevents the oversized case with its own limits but cannot see a misnamed `body_variable`. That is why a first message should be confirmed by eye in Slack. There is no delivery confirmation and no deduplication.

Sends on one machine are spaced: a send waits until one second has passed since the previous one started, across processes (a lock file in the state directory). The wait counts against the send's `timeout`; a wait that cannot fit in the time left ends the send at once with exit 12 `unavailable`. Spacing covers one machine only, and other machines or tools that post to the same workflow share Slack's limit, so throttled messages (answered 429) are retried twice, after 2 s and 4 s, and then fail as `rate_limited`.

By default every send that got as far as reading its input appends one record to `log.jsonl` in `.local/state/slack-notice` under your home directory (rotated at 1 MiB, three old files kept). A record holds the time, version, outcome, exit code, error code or reason, level, size, whether the text was cut, duration, HTTP status, a 16-hex-character hash of the sanitized title and message, a hash of the dedupe key and the actor. It never holds the title, message, link or URL. The hash is short and unsalted, so someone who can read the file could confirm a guess at a short message. Dry runs, usage and config errors, disabled runs and an internal error (exit 1) that happens while no request is being written are not logged. A problem with the state directory only prints one warning on stderr: the record or the spacing may be skipped, and the send is never failed for it.

## 9. Limits and what is not escaped

- Plain text only. The text goes into the workflow variable as is. Nothing is escaped, so `&`, `<` and `>` appear as typed, and Slack does not turn markup, mentions or `<url|label>` into formatting or links. Slack does link any bare URL it finds in the text and may turn `:shortcode:` text into an emoji.
- Control and invisible characters are removed, line endings become LF, trailing whitespace is trimmed and runs of blank lines shrink to one ([Sanitizer](docs/interface.md#sanitizer)).
- The title is one line, cut at 256 characters with a trailing `…`. `max_chars` (default 3000 characters) limits the whole rendered body (prefix line, title, message and link), and a fixed cap of 12000 bytes applies to the request body. A message that does not fit is cut to what is left after the other parts and ends with `…[truncated]`, and `truncated` is `true` in the output. The link is never cut.
- Input is limited to 1 MiB and 100000 characters per text field.
- The level prefix at the start of the first line (for example the default `🟠 WARN`) is advisory: a producer can write the same words in a title.

## 10. Security notes

- The trigger URL is a bearer secret. It is read only from the environment variable named by `webhook_env`, is checked against the exact shape of a Slack workflow trigger URL before any request is built, and is never written to argv, output, errors, verbose lines or the log. Any process of your user that can read the variable or the file you keep it in can post to your workflow, so keep that file at mode 0600.
- The tool connects only to `hooks.slack.com` on port 443, verifies the certificate and host name (TLS 1.2 or newer), and never follows redirects. There is no switch to disable verification.
- Proxy settings are not supported in 0.x, and neither is a custom CA. The tool ignores the proxy environment variables and also `SSL_CERT_FILE` and `SSL_CERT_DIR`, never as a fallback and never as an override; it trusts the system CA bundle compiled into your Python (its bundle file or its certificate directory) or, failing that, the usual system bundle locations. If the machine has a direct route to Slack the variables are simply ignored. A host whose only route to Slack is a proxy fails to connect (exit 12 `network_error`, retried once), and a TLS-inspecting gateway or an unknown CA fails certificate verification (exit 12 `network_error` with `details.tls` true, not retryable).
- The environment and the config are trusted: a process that can change either (including `PYTHONPATH`, `LD_PRELOAD` or your config files, or `--config`, which selects the destination) is inside the trust boundary. The tool never reads `HOME`, `XDG_*` or any `SLACK_NOTICE_*` variable.
- Signals: SIGTERM, SIGINT and SIGHUP are handled by the tool. A SIGHUP that was ignored by the parent (as under `nohup`) is not ignored by slack-notice: it acts on the signal, so `nohup` does not protect a send from a hangup. Before the send starts the process exits 128+N; afterwards the signal counts as the deadline passing.
- A drop-in or the config can set `enabled: false`, which silences the tool (exit 22, one stderr line, nothing logged). If you rely on it for alerts, check `validate`, which reports `enabled`.
- Messages that fail inside Slack (for example an oversized body) may notify the workflow's owner rather than the caller.

The full list is in [Residual risks](docs/interface.md#residual-risks).

## 11. Automation

Callers such as cron or an agent should use `send --stdin-json --json --actor auto:<name>`, decide by exit code and cap their own retries. Under cron or any scheduler, the variable named by `webhook_env` must be in the calling process's environment, because the tool reads no file or startup script ([Environment variables](docs/interface.md#environment-variables)). The contract is in [Calling from automation](docs/interface.md#calling-from-automation); the cron setup, shell and script snippets and the health-check recipe are in [docs/automation.md](docs/automation.md).

## Documentation

- [docs/interface.md](docs/interface.md): the normative interface (commands, flags, exit codes, config, output, transport, files, residual risks)
- [docs/design.md](docs/design.md): decisions and internals
- [docs/live-testing.md](docs/live-testing.md): the opt-in live suite that posts to your own workflow (never part of `make verify` or CI)
- [docs/plan.md](docs/plan.md): the staged implementation plan
- [config.example.yaml](config.example.yaml): every config key with its default

## License

MIT, see LICENSE.

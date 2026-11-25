# slack-notice

slack-notice sends one plain-text notification to Slack through the webhook trigger of a Slack workflow. You give it a title, a message, a level and an optional link; it sanitizes the text, folds it into the single text variable of your workflow, posts it and tells you by exit code and one line of JSON whether Slack accepted it.

It is a command-line tool and nothing more. It does not decide when to send, keeps no database and no queue, runs no hooks and never prompts. It cannot post as a person, format messages, mention users, send to a channel by name or confirm that a message was delivered. The classic incoming webhook, `chat.postMessage` with a token and the Slack CLI are not supported. Linux and WSL are supported; macOS is expected to work; native Windows is not supported.

The normative specification is [docs/interface.md](docs/interface.md). This README is the short path from a Slack workflow to a first notification.

## How the examples are checked

Command blocks in this README that can run offline are executed by the test suite through the real command-line entry point against a fake network gateway (see `tests/test_readme.py`), and their exit codes and JSON output are checked against the schemas in `schemas/`. Blocks marked `manual` in the source (installation, live Slack steps, shell setup) are not executed by any test.

## 1. Create the workflow in Slack

slack-notice talks to a workflow that starts from a webhook. The exact screens change over time, so as of writing, check Slack's own documentation for Workflow Builder and webhook triggers; the steps below name only what the tool needs.

1. Create a workflow whose trigger is a webhook.
2. Give the trigger exactly one variable of type text. The default name slack-notice expects is `body`. If you name it anything else, set `body_variable` in the config (below).
3. Add a step that sends a message to the person or channel you want, and put that variable into the message text.
4. Publish the workflow and copy the trigger URL it shows you.

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

The command is `slack-notice`. For development, `uv sync` installs the dev tools and `make verify` runs the checks. The runtime dependencies are PyYAML and Pydantic; HTTP uses the standard library.

## 3. Give the tool the URL

The URL reaches slack-notice only through an environment variable. The config holds the variable's name (`webhook_env`, default `SLACK_WEBHOOK`), never the URL. slack-notice reads no file and no shell startup script to find it, and it never accepts the URL as an argument.

Keep the URL in a file that only you can read, written with an editor so it never lands in your shell history or the process list. Create the file, then edit it so that it holds one line that exports `SLACK_WEBHOOK` with the trigger URL as its value:

<!-- manual -->

```sh
( umask 077; mkdir -p ~/.config/slack-notice; touch ~/.config/slack-notice/env )
```

Load it into the shell that runs the tool:

<!-- manual -->

```sh
set -a; . ~/.config/slack-notice/env; set +a
```

Surrounding whitespace (such as a trailing newline) is ignored. A value that is not a Slack workflow trigger URL, or is longer than 1024 characters, is refused before anything is sent, with exit 12 `credential_invalid`.

## 4. Check the setup

<!-- test -->

```sh
slack-notice validate
slack-notice validate --json
```

`validate` never prompts, makes no network call and sends nothing. It checks that the config loads (`config`) and that the credential variable holds a value shaped like a trigger URL (`credential`). It cannot tell a live URL from a revoked one. A tool disabled in the config still reports configuration and credential faults, and `--json` includes `enabled` in its document.

Without `--json` it prints one line per check on stderr, `<name>: ok (<message>)` or `<name>: failed (<message>)`; `--quiet` keeps only the failed lines. Exit 0 means every check passed, exit 2 means the config is invalid, exit 12 means the credential check failed.

Then send one real test message by hand:

<!-- test -->

```sh
slack-notice validate --test-message
```

`--test-message` is a real send of one message (level `info`, title `slack-notice`, message `validate: test message`) through the normal path, so it uses the send lock, the spacing, the deadline and the retries, and it writes a log record. Exit 0 means Slack accepted it. Exit 12 means the check failed; the message names no cause, and the cause is in the log record when logging is on. A failed credential check ends the run with exit 12 and sends nothing, and a disabled tool exits 22 without a call. Look in Slack to confirm the message arrived: Slack accepts a request that names the wrong variable and drops it silently, and only a person can see that. Scripts and schedulers should not call `--test-message`; use plain `validate --json` and read `enabled`.

## 5. Configuration

The config is optional: without it the defaults below apply. It is `.config/slack-notice/config.yaml` under your home directory, with the home directory taken from the password database (`HOME` and `XDG_CONFIG_HOME` are not read, and a home directory that cannot be used is exit 2). Files named `*.yaml` in a `config.d` directory beside it are read afterwards in lexical order and merged over it key by key. `--config <path>` reads another file instead, and its drop-ins come from the `config.d` beside that file. Precedence is config over the built-in defaults: no flag changes a setting and there are no environment overrides. An unknown key, a wrong type or an out-of-range value is exit 2 `config_invalid` naming the key. The file is strict YAML (for example `no` and `off` stay strings and are rejected where a boolean belongs) and at most 64 KiB. [config.example.yaml](config.example.yaml) lists every key.

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

A notification has an optional `title`, a required `message`, an optional `level` (`info`, `warn`, `action` or `error`; default `info`) and an optional `link` (an `http` or `https` URL in printable ASCII). The caller's own text should travel on stdin or in a file, never in arguments or the environment. Flags exist for humans at a terminal.

<!-- test -->

```sh
printf '%s' '{"title": "Build", "message": "all green", "level": "warn", "link": "https://a.example/x"}' | slack-notice send --stdin-json --json
```

`--file <path>` reads the same JSON from a file (`--file -` is stdin). The following uses a file named `notice.json` that holds the JSON object above:

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

- `retryable: true` and `unknown_outcome: false` (`rate_limited`, `network_error`, `unavailable`): nothing was sent and sending again is safe. Back off on your own schedule; the tool has already waited and retried inside its deadline. `retry_after_s` is the tool's own backoff value (written like `4.0`), not a hint from Slack.
- `retryable: false` and `unknown_outcome: false` (`host_rejected`, `auth_required`, `credential_invalid`, and a `wrong_host_response` for an unexpected 3xx to 5xx status): nothing was sent and retrying cannot help until a person fixes the config or regenerates the trigger URL.
- `unknown_outcome: true` (`outcome_unknown`, `upstream_error`, and a `wrong_host_response` after a 2xx answer): the message may already have been delivered. Do not blindly resend, because Slack does not deduplicate; record it as possibly sent.

`unavailable` also covers input that did not arrive in time and a wait for the send lock that the deadline could not cover; nothing was sent. A caller that kills the tool should wait at least the configured `timeout` plus 10 seconds, and then treats the outcome as unknown.

## 8. What the output means

`sent`, and exit 0, mean only that Slack accepted the request. They do not mean the message was delivered or read. Slack answers success and drops the message when the variable name does not match the workflow, and it drops an oversized body the same way; the tool prevents the oversized case with its own limits but cannot see a misnamed `body_variable`. That is why a first message should be confirmed by eye in Slack. There is no delivery confirmation and no deduplication.

Sends on one machine are spaced: a send waits until one second has passed since the previous one started, across processes (a lock file in the state directory). The wait counts against the send's `timeout`; a wait that cannot fit in the time left ends the send at once with exit 12 `unavailable`. Spacing covers one machine only, and other machines or tools that post to the same workflow share Slack's limit, so throttled messages (answered 429) are retried twice, after 2 s and 4 s, and then fail as `rate_limited`.

By default every send that got as far as reading its input appends one record to `log.jsonl` in `.local/state/slack-notice` under your home directory (rotated at 1 MiB, three old files kept). A record holds the time, version, outcome, exit code, error code or reason, level, size, whether the text was cut, duration, HTTP status, a 16-hex-character hash of the sanitized title and message, a hash of the dedupe key and the actor. It never holds the title, message, link or URL. The hash is short and unsalted, so someone who can read the file could confirm a guess at a short message. Dry runs, usage and config errors and disabled runs are not logged. A problem with the state directory only prints one warning on stderr: the record or the spacing may be skipped, and the send is never failed for it.

## 9. Limits and what is not escaped

- Plain text only. The text goes into the workflow variable as is. Nothing is escaped, so `&`, `<` and `>` appear as typed, and Slack does not turn markup, mentions or `<url|label>` into formatting or links. Slack does link any bare URL it finds in the text and may turn `:shortcode:` text into an emoji.
- Control and invisible characters are removed, line endings become LF, trailing whitespace is trimmed and runs of blank lines shrink to one ([Sanitizer](docs/interface.md#sanitizer)).
- The title is one line, cut at 256 characters with a trailing `…`. Message and title together are limited by `max_chars` (default 3000 characters) and by a fixed cap of 12000 bytes on the request body. A message that does not fit is cut and ends with `…[truncated]`, and `truncated` is `true` in the output. The link is never cut.
- Input is limited to 1 MiB and 100000 characters per text field.
- The level prefix at the start of the first line (for example the default `🟠 WARN`) is advisory: a producer can write the same words in a title.

## 10. Security notes

- The trigger URL is a bearer secret. It is read only from the environment variable named by `webhook_env`, is checked against the exact shape of a Slack workflow trigger URL before any request is built, and is never written to argv, output, errors, verbose lines or the log. Any process of your user that can read the variable or the file you keep it in can post to your workflow, so keep that file at mode 0600.
- The tool connects only to `hooks.slack.com` on port 443, verifies the certificate and host name (TLS 1.2 or newer), and never follows redirects. There is no switch to disable verification.
- Proxy settings are not supported in 0.x. The tool ignores the proxy environment variables, and it also ignores `SSL_CERT_FILE` and `SSL_CERT_DIR`; it trusts the system CA bundle compiled into your Python or, failing that, the usual system bundle locations. A machine that can reach Slack only through a proxy or a TLS-inspecting gateway cannot use the tool, and a custom CA cannot be added. Instead of falling back, the send fails with exit 12 `network_error`.
- The environment and the config are trusted: a process that can change either (including `PYTHONPATH`, `LD_PRELOAD` or your config files, or `--config`, which selects the destination) is inside the trust boundary. The tool never reads `HOME`, `XDG_*` or any `SLACK_NOTICE_*` variable.
- Signals: SIGTERM, SIGINT and SIGHUP are handled by the tool. A SIGHUP that was ignored by the parent (as under `nohup`) is not ignored by slack-notice: it acts on the signal, so `nohup` does not protect a send from a hangup. Before the send starts the process exits 128+N; afterwards the signal counts as the deadline passing.
- A drop-in or the config can set `enabled: false`, which silences the tool (exit 22, one stderr line, nothing logged). If you rely on it for alerts, check `validate`, which reports `enabled`.
- Messages that fail inside Slack (for example an oversized body) produce notices that go to the workflow's owner, not to the caller.

The full list is in [Residual risks](docs/interface.md#residual-risks).

## 11. Automation

Callers such as cron or an agent should use `send --stdin-json --json --actor auto:<name>`, decide by exit code and cap their own retries. The contract is in [Calling from automation](docs/interface.md#calling-from-automation).

## Documentation

- [docs/interface.md](docs/interface.md): the normative interface (commands, flags, exit codes, config, output, transport, files, residual risks)
- [docs/design.md](docs/design.md): decisions and internals
- [docs/live-testing.md](docs/live-testing.md): the opt-in live suite that posts to your own workflow (never part of `make verify` or CI)
- [docs/plan.md](docs/plan.md): the staged implementation plan
- [config.example.yaml](config.example.yaml): every config key with its default

## License

MIT, see LICENSE.

# slack-notice

Sends one plain-text notification to Slack through a Slack workflow's webhook trigger.

## Status

Designed (interface 0.1.0-design); not yet implemented. The normative specification is [docs/interface.md](docs/interface.md); decisions are in [docs/design.md](docs/design.md) and the staged plan in [docs/plan.md](docs/plan.md).

## Layer

L1 (primitive). Works fully standalone; it does not need the `awkit` harness.

## What it does

- Sends a notification (`title`, `message`, `level`, `link`) as one text message. Everything is folded into the single text variable of your Slack workflow ([Rendering](docs/interface.md#rendering)).
- Reads the notification from stdin as JSON, from a file, or, for human use, from flags. All text is sanitized the same way; control and invisible characters are removed ([Sanitizer](docs/interface.md#sanitizer)).
- Keeps its own length limits (characters and a fixed 12000-byte cap; a cut message ends with `…[truncated]`, a cut title with `…`), because Slack drops an oversized message and still reports success.
- Spaces sends on one machine, 1 s apart, so Slack's throttling does not lose messages ([Send spacing](docs/interface.md#send-spacing)).
- Keeps no database. It writes a log of what it sent, refused or failed (never the text, the link or the URL; dry runs and disabled runs are not logged) and a lock file. It runs no hooks and never prompts, and decides nothing about when to send; that belongs to the caller ([Calling from automation](docs/interface.md#calling-from-automation)).

## The one transport

0.x talks to a Slack Workflow Builder workflow that starts from a webhook. The URL (`https://hooks.slack.com/triggers/...`) is a secret: anyone holding it can post to the workflow. The workflow decides where the message goes and appears as the workflow's app, not as a person. The classic incoming webhook, `chat.postMessage` with a token and the Slack CLI are not supported ([Transport](docs/interface.md#transport)).

## Install

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) to install it.

```sh
uv tool install git+https://github.com/agent-workflow-kit/slack-notice
```

## Set up the workflow webhook

1. In Slack, open Workflow Builder and create a workflow that starts from a webhook.
2. Give the trigger one text variable named `body` (if you choose another name, set `body_variable` in the config).
3. Add a step that sends a message to the person or channel you want, with the message text set to that variable.
4. Publish the workflow and copy the webhook URL.
5. Put the URL in an environment variable, by default `SLACK_WEBHOOK` (the name is the config key `webhook_env`). Treat it as a secret: create the env file with `umask 077`, never truncate an existing one, and source it from your shell or cron line. slack-notice never reads files or shell startup scripts to find it.
6. Run `slack-notice validate` to check the config and the credential. Then run `slack-notice validate --test-message` once by hand and look in Slack. Slack accepts a request with a wrong variable name and drops it silently, so only you can confirm the message arrived. Automation never calls `--test-message`.

```sh
mkdir -p ~/.config/slack-notice
( umask 077; printf 'SLACK_WEBHOOK=%s\n' 'https://hooks.slack.com/triggers/...' >> ~/.config/slack-notice/env )
```

A cron line sources the env file and uses the absolute path of the binary (cron has no `uv tool` PATH):

```text
0 9 * * * set -a; . "$HOME/.config/slack-notice/env"; set +a; "$HOME/.local/bin/slack-notice" send --stdin-json --json --actor auto:cron < "$HOME/notice.json"
```

## Usage

```sh
# From JSON on stdin (the form callers use)
printf '%s' '{"title": "Build done", "message": "All checks passed", "level": "info", "link": "https://example.com/run/1"}' | slack-notice send --stdin-json

# From a file, with machine output
slack-notice send --file notice.json --json

# From flags, for a human at a terminal
slack-notice send --title "Backup" --message "Finished" --level warn

# Show the exact text that would be sent, without reading the credential or sending
slack-notice send --file notice.json --dry-run --json

# Check config and the credential (never prompts, never sends)
slack-notice validate

# Send one marked test message through the normal path; look in Slack to confirm it arrived
slack-notice validate --test-message
```

Text from other programs travels in a file or stdin, never in argv or the environment. Levels are `info`, `warn`, `action` and `error`; they select a prefix in the message. Output says `sent`, never `delivered`: exit 0 means Slack accepted the request.

## Commands

| Command | Purpose |
|---|---|
| `slack-notice send [--stdin-json \| --file <path>\|-] [--title <t>] [--message <m>] [--level <l>] [--link <url>] [--dedupe-key <k>]` | Send one notification. |
| `slack-notice validate [--test-message]` | Check config and the credential variable; with `--test-message`, send one test notification. |

Global flags: `--json`, `--config <path>`, `--dry-run`, `--actor <actor>`, `--verbose`, `--quiet`, `--version`. `--decision-id` is accepted and ignored.

## Exit codes

0 accepted by Slack (or a dry run); 2 usage or invalid config; 12 failed for a reportable reason (`host_rejected`, `auth_required`, `credential_invalid`, `rate_limited`, `upstream_error`, `network_error`, `outcome_unknown`, `wrong_host_response`, `unavailable`; read `retryable` and `unknown_outcome`); 20 the payload was refused before sending (`code: refused`) with a `reason` (`invalid_payload`, `empty_message`, `link_invalid`, `link_scheme`); 22 nothing sent because the tool is disabled in config. A caller treats 22 as a successful no-op. See [Exit codes](docs/interface.md#exit-codes).

## Limitations

Plain text only: no formatting, no mentions and no clickable labelled links. There is no delivery confirmation and no deduplication. A burst of 12 requests in about 3 seconds got 429 in testing (no sustained rate was measured; 1 s spacing is a conservative guess); a throttled request is answered 429, while Slack silently drops an oversized body or a misnamed variable with a success status. Proxies and custom CA environment variables are not supported in 0.x. See [Residual risks](docs/interface.md#residual-risks).

## Config and environment

- Config: `~/.config/slack-notice/config.yaml` plus `config.d/*.yaml`; every key is documented in [config.example.yaml](config.example.yaml) and [Config](docs/interface.md#config).
- Environment: only the variable named by `webhook_env` (the URL) and `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and `HOME` are read; there are no `SLACK_NOTICE_*` overrides ([Environment variables](docs/interface.md#environment-variables)).
- State: `~/.local/state/slack-notice/` holds `log.jsonl` and the lock files ([Files](docs/interface.md#files)). A state problem only warns and never fails a send.

## Dependencies

No other awkit tool. Python standard library (`http.client`) for HTTP; PyYAML and Pydantic for config.

## Documentation

- [docs/interface.md](docs/interface.md): normative interface
- [docs/plan.md](docs/plan.md): staged implementation plan
- [docs/design.md](docs/design.md): decisions and internals
- [awkit architecture](../awkit-docs/architecture.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/architecture.md))
- [awkit design guide](../awkit-docs/design-guide.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/design-guide.md))

## License

MIT, see LICENSE.

# slack-notice: implementation plan

Implements [interface.md](interface.md) and [design.md](design.md). The issues for each stage are expanded into bite-sized test-first steps when they are picked up; this plan fixes the order, the conventions and the module map.

## Conventions for every stage

- **Gateway boundary.** All HTTP, clock and lock-file access goes through `src/slack_notice/gateway.py`; modules never import `urllib`, `time` or `fcntl` directly. Tests substitute fakes.
- **Fakes.** A fake Slack server in `tests/` returns each row of the interface's Webhook edge table, including delayed responses, a drop after the request is sent, a redirect and a 200 with a wrong body. There are no sibling tools to pin.
- **Process and live split.** Process tests run the CLI as a subprocess against the fake server and check exit codes, stdout and stderr. `live` tests (pytest marker, never in CI) post to the maintainer's own workflow and are listed in the live-verification issue.
- **Golden files.** `--json` outputs, rendered bodies and log records have golden files; schemas have positive and negative samples.
- **Spike regressions.** Every behavior in design.md's live-verification table becomes a fake-server test or a `live` test.
- **Secrets.** A test sets a recognizable fake URL and asserts it appears in no argv, output, log, error or file.
- **`make verify`** passes before every commit; each paragraph in markdown is one line.

## Module map

| Module | Stage | Responsibility |
|---|---|---|
| `gateway.py` | 0 | HTTP, clock, lock file. |
| `cli.py` | 0, 3, 4 | Parsing, dispatch, exit codes, output. |
| `payload.py` | 1 | Input parsing, validation, sanitizer. |
| `render.py` | 1 | Body layout and truncation. |
| `config.py` | 2 | Config, drop-ins, env overrides. |
| `log.py` | 2 | Log records and rotation. |
| `spacing.py` | 3 | Send lock and minimum interval. |
| `webhook.py` | 3 | URL shape check, request, response mapping, retries. |

## Stage 0: Scaffold and gateway

**Goal**: A package that installs, prints `--version`, and has the gateway and the fake server in place.
**Success Criteria**: `make verify` green; schemas load; the fake server serves each response row.
**Tests**: version output golden; fake server contract tests; schema positive and negative samples.
**Status**: Not Started

## Stage 1: Input, sanitizer and rendering

**Goal**: Validate and render a notification without any network.
**Success Criteria**: `send --dry-run` prints the exact body for stdin, file and flag input, with truncation and the sanitizer applied.
**Tests**: sanitizer table (controls, bidi, ZWSP, CRLF, lone surrogates, tabs); layout cases (levels, no title, no link, long message at the boundary, non-ASCII); every refusal reason; flag and stdin parity.
**Status**: Not Started

## Stage 2: Config, state directory and log

**Goal**: Config loading with validation and the safe state directory and log.
**Success Criteria**: invalid config exits 2 naming the key; log records match the schema and never contain text; rotation works.
**Tests**: config precedence and env overrides; drop-in merge; state directory checks (wrong owner or mode, symlink); log golden files and rotation; `log: false`.
**Status**: Not Started

## Stage 3: Webhook send and spacing

**Goal**: A real `send` against the fake server with the full response table.
**Success Criteria**: every row of the Webhook edge table maps to its exit code and envelope; spacing queues concurrent callers; the URL is checked and never leaked.
**Tests**: response table; 429 and 5xx retry timing; drop after send gives `outcome_unknown` with no retry; concurrent sends spaced by `min_interval`; lock timeout exits 12 `unavailable`; URL shape refusals; `enabled: false` exits 22.
**Status**: Not Started

## Stage 4: `validate`, live verification and docs

**Goal**: `validate [--probe]`, the live suite and user documentation.
**Success Criteria**: validate checks match the interface; the live suite passes against the maintainer's workflow and settles the still-to-verify items; README documents workflow setup and cron use.
**Tests**: validate golden files; `--probe` confirmation on `/dev/tty` and `--yes`; live tests (plain message, limit-sized message, non-ASCII byte versus character limit, auto-link, burst spacing).
**Status**: Not Started

## Version roadmap

- **0.x**: Stages 0 to 4.
- **1.0** when the live suite has passed and the tool has run in daily use through a routing tool for two weeks without an interface change.
- **1.x, additive**: a `chat.postMessage` transport for users who can obtain an app token (formatting, mentions, self-DM); an optional headless-Claude transport; classic incoming webhook support; Retry-After handling if Slack starts sending it.
- **2.0**: nothing planned.

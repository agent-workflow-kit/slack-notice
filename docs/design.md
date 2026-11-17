# slack-notice: design

Status: 0.1.0-design, 2026-11-17. The rules are in [interface.md](interface.md), the single normative source; this document records decisions, modules and tests and links to interface headings without restating them. Architecture: `../awkit-docs/architecture.md` (v1.22).

## Role and layer

L1 primitive: send one plain-text notification to Slack through a Slack workflow's webhook trigger. Works fully standalone. It is one of three sibling channel notifiers with the same contract (`ha-notice`, `wsl-notice`), each designed to be called by a routing tool above it without knowing that tool exists.

## Uses

| Dependency | Layer | Binding | Notes |
|---|---|---|---|
| Slack workflow webhook trigger over HTTPS | L0 third party | none (not an edge of the tool graph) | One POST; see [Webhook edge](interface.md#webhook-edge). |
| Python standard library HTTP client | L0 | none | No third-party HTTP dependency. |
| Pydantic (config validation) | library | none | Required by the design guide for config; the only third-party runtime dependency. The scaffold's `pyproject.toml` lists none yet; adding it is part of stage 2. |

No tool dependencies: slack-notice composes nothing.

## Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | Stateless: no state database, no outbox, no retries after exit; one `log.jsonl`. See [Files](interface.md#files), [Log](interface.md#log). | Deduplication, quiet hours, history and deferral belong to the routing tool; a tool-level outbox would duplicate them (user decision S-2). |
| D-2 | Common input contract: `title`, `message`, `level`, `link`; unknown fields refused; text from stdin, a file or flags, all sanitized alike. See [Notification](interface.md#notification). | Architecture 13.2 rule 2; the design guide treats short argv text as untrusted (S-3). |
| D-3 | One transport in 0.x: the workflow trigger, plain text in one variable. See [Transport](interface.md#transport). | The user cannot create a Slack app, so the Web API, the classic webhook and the Slack CLI's tokens are out; the spikes below show why (S-5). |
| D-4 | Body layout `<prefix> <title>` / message / bare link, no escaping, own length limit with a visible marker. See [Rendering](interface.md#rendering), [Sanitizer](interface.md#sanitizer). | Slack parsed no markup, mention or `<url\|label>` link in the variable; entities showed literally; oversized bodies are dropped with a success status (spike A). |
| D-5 | Exit codes and outcomes as in [Exit codes](interface.md#exit-codes); exit 20 is code `refused` with a reason; exit 22 for a disabled tool; `unknown_outcome` and no automatic retry after a timeout that follows a sent request. | A duplicate is worse than a lost message for a caller that can retry; the endpoint has no deduplication (S-7). |
| D-6 | `config_invalid` is exit 2 (as pr-comment), not 20. | Follows the existing precedent in the design guide's exit-code table. |
| D-7 | Webhook URL only from the environment variable named in config, shape-checked on every send (`https`, host `hooks.slack.com`, `/triggers/` path). See [Webhook edge](interface.md#webhook-edge). | Design guide section 7; the shape check stops a mistaken variable from sending the body to another host. |
| D-8 | Send spacing by lock file, one second by default. See [Send spacing](interface.md#send-spacing). | Twelve requests in four seconds were throttled and lost (spike A). |
| D-9 | No hooks in 0.x and no audit file. See [Hooks](interface.md#hooks), [Log](interface.md#log). | Policy lives above; a failure-notifying hook could loop; a notification changes no system of record (S-5, S-6). |
| D-10 | `validate --probe` sends a marked test message and says delivery is not observable. See [`validate`](interface.md#validate). | A wrong variable name returns success and delivers nothing; only a human can tell. |

## Resolved open topics

- Payload shape: [Notification](interface.md#notification). Invalid payloads exit 20 `refused` with reason `invalid_payload` and a JSON pointer.
- Channel config: [Config](interface.md#config). No per-repo overrides.
- Escaping: none for this transport, by test; control and invisible characters are removed instead ([Sanitizer](interface.md#sanitizer)).

## Live verification

Verified in design (private spikes, 2026-11-17; the user's own workflow, test messages only):

| Behavior | Result |
|---|---|
| Success | 200, `{"ok":true}`, no message id. |
| Silent drops with 200 | Missing or empty variable, wrong variable name, GET, oversized body. |
| Loud failures | Invalid JSON 400, object-valued variable 400, altered path 401. |
| Content type | `text/plain` and none accepted. |
| Length | 12500 characters delivered; 15000 and up dropped whole. |
| Rate limit | 429 after about twelve requests in four seconds, no `Retry-After`; throttled sends lost. |
| Formatting | None rendered: no bold, italic, code, links, mentions. |
| Destination | The workflow app's own conversation; workflow failures post to the workflow owner. |
| Duplicates | A plain retry sends twice. |

Still to verify (live tests in the plan, conservative defaults until then): whether the length limit counts bytes for non-ASCII text; whether a bare URL is auto-linked; whether `:shortcode:` text becomes an emoji; whether a request header for idempotency exists (none is documented); how the one-second default `min_interval` behaves when two machines share a workflow; whether `Retry-After` is ever sent.

Researched and rejected for 0.x (private notes): the official Slack CLI (login token has no `chat:write`, parameters only in argv, plaintext debug log, exit 0 on API errors); a CLI service token (app-building scopes only); the Slack MCP server (needs a registered, approved app; reusing Claude's token or app identity is outside its issued purpose); a headless Claude run per notification (cost per message and prompt injection). These are 1.x candidates behind the same `send` contract if the user ever gets an app token.

## Modules

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing, command dispatch, exit-code mapping, output. |
| `config.py` | Config loading, drop-ins, env overrides, Pydantic validation. |
| `payload.py` | Input parsing, notification validation, sanitizer. |
| `render.py` | Body layout and truncation. |
| `webhook.py` | URL shape check, request building, response mapping and retries. |
| `spacing.py` | Send lock and minimum interval. |
| `log.py` | Log record writing and rotation. |
| `gateway.py` | The only place that opens network connections, clocks and the lock file; tests substitute fakes. |

## Data model, concurrency, errors

No stored objects. One lock file serializes sends on a machine ([Send spacing](interface.md#send-spacing)); everything else is independent. Errors use the envelope in [Error envelope](interface.md#error-envelope); log failures never change an exit code.

## Test strategy

- All HTTP and time go through `gateway.py`; a fake HTTP server in `tests/` returns each row of [Webhook edge](interface.md#webhook-edge), including slow responses and a connection drop after the request.
- Golden files for `--json` output and rendered bodies (levels, no title, no link, truncation boundary, non-ASCII), schema tests with positive and negative samples, a sanitizer table test (controls, bidi, ZWSP, CRLF), and a test that the URL appears in no argv, output, log or error.
- `live` tests (never in CI) post marked messages to the user's own workflow: one plain, one at the length limit, one burst for spacing; the still-to-verify items above become assertions when run.

## Platforms

Linux and WSL required; macOS expected (standard library only), untested.

# slack-notice: design

Status: 0.1.0-design, 2026-11-17 (review pass 2 resolved). The rules are in [interface.md](interface.md), the single normative source; this document records decisions, modules and tests and links to interface headings without restating them. Architecture: `../awkit-docs/architecture.md` (v1.22).

## Role and layer

L1 primitive: send one plain-text notification to Slack through a Slack workflow's webhook trigger. Works fully standalone. It is one of three sibling channel notifiers with the same contract (`ha-notice`, `wsl-notice`), each designed to be called by a routing tool above it without knowing that tool exists.

## Uses

| Dependency | Layer | Binding | Notes |
|---|---|---|---|
| Slack workflow webhook trigger over HTTPS | L0 third party | none (not an edge of the tool graph) | One POST; see [Webhook edge](interface.md#webhook-edge). |
| Python standard library `http.client` and `ssl` | L0 | none | No third-party HTTP dependency; `urllib` is not used (it reads proxy and CA environment variables and follows redirects). |
| PyYAML (`safe_load` through a `SafeLoader` subclass) | library | none | The design guide mandates YAML config; only the safe loader is used, through a subclass that rejects duplicate mapping keys and restricts the implicit resolvers: `true` and `false` are the only booleans and decimal integers and decimal fractions the only numbers (`no`, `off` stay strings; `010`, `08`, `1:30`, `0x10`, `.inf` and the other YAML 1.1 number lookalikes are refused, because the string `010` would pass the duration grammar), and refuses tags, anchors, aliases (so `<<: *alias` is refused because the alias is; a literal `<<` key is an ordinary string key, whose refusal as an unknown key is #11), non-string keys and deep nesting (so an alias bomb never expands), files are opened with `O_NONBLOCK`, must be regular and are capped at 64 KiB, and any parser error or `RecursionError` is `config_invalid`. |
| Pydantic (config validation) | library | none | Required by the design guide for config. Pydantic errors are converted to messages from `loc` and `type` only, because the default message contains the input value. PyYAML and Pydantic (with its own dependencies pydantic-core, annotated-types, typing-extensions and typing-inspection) are the only third-party runtime dependencies (`pydantic>=2.9`, added with the config validation; models are strict, and every message comes from the key path and the rule, never from `input`). |
| `jsonschema` and `referencing` (development only) | test library | none | Validate samples and real tool output against `schemas/` (draft 2020-12, local cross-file `$ref`s resolved from the files, never the network) in `tests/harness.py`. Never imported by `src/`, so the installed tool has no runtime dependency on them. `referencing` is already a dependency of `jsonschema`; it is declared directly because the harness imports it. The `schemas` job of the shared awkit-ci `python-ci.yml` workflow (called from `ci.yml`) runs `check-jsonschema --check-metaschema` on `schemas/**/*.json` and validates `config.example.yaml` against `schemas/config.json`; the harness checks the same draft and metaschema. |

No tool dependencies: slack-notice composes nothing.

## Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | Stateless: no state database, no outbox, no retries after exit; one `log.jsonl`. See [Files](interface.md#files), [Log](interface.md#log). | Deduplication, quiet hours, history and deferral belong to the routing tool; a tool-level outbox would duplicate them (maintainer decision, 2026-11-17). |
| D-2 | Common input contract: `title`, `message`, `level`, `link`; unknown fields refused; text from stdin, a file or flags, all sanitized alike; one input-reading rule (1 MiB cap, regular files only, duplicate keys, `NaN`, deep nesting and a BOM refused). Input is read by the main thread in slices of at most 100 ms (a worker thread would lose the race rule of D-11; the slice is the cost). Input that does not arrive within the deadline is exit 12 `unavailable` (nothing was sent, retryable), so exit 20 keeps one meaning: the bytes that arrived are bad. A signal before step 5 ends the process with 128+N and no record. See [Notification](interface.md#notification). | Architecture 13.2 rule 2; the design guide treats short argv text as untrusted (maintainer decision, 2026-11-17). The 1 MiB cap is above 100000 characters at 4 bytes each plus JSON escapes. |
| D-3 | One transport in 0.x: the workflow trigger, plain text in one variable. See [Transport](interface.md#transport). | The user cannot create a Slack app, so the Web API, the classic webhook and the Slack CLI's tokens are out; the spikes below show why (maintainer decision, 2026-11-17). |
| D-4 | Body layout `<prefix> <title>` / message / bare link, no escaping, own limits (characters and a fixed 12000-byte cap) with a visible marker. See [Rendering](interface.md#rendering), [Sanitizer](interface.md#sanitizer). | Slack parsed no markup, mention or `<url\|label>` link in the variable; entities showed literally; oversized bodies are dropped with a success status (spike A). The cut is defined once; the byte cap applies to the serialized request body, so JSON escaping counts. The marker and the default prefixes differ from the sibling notifiers on purpose because slack-notice has one text field and no separate title. |
| D-5 | Exit codes and outcomes as in [Exit codes](interface.md#exit-codes); exit 20 is code `refused` with a reason and means only that the payload was refused; exit 22 for a disabled tool. 429 (waits fixed at 2 s and 4 s; the `Retry-After` header is never read) and failures before the first request byte are retried; a 5xx is `upstream_error` with `unknown_outcome` true and is not retried; any failure after the first byte is `outcome_unknown`; unknown outcomes are `retryable: false`. | Retry only what cannot have been processed. Slack has no idempotency (spike A) and a proxy 502 or 504 can follow processing, so a caller that follows `retryable` can never duplicate. Amends the earlier "retry 5xx once" decision (maintainer decision, 2026-11-17). |
| D-6 | `config_invalid` is exit 2 (as pr-comment), not 20. | Follows the existing precedent in the design guide's exit-code table. |
| D-7 | Webhook URL only from the environment variable named in config, validated whole by one anchored allowlist (`https://hooks.slack.com/triggers/` plus 1 to 4 segments) on every send; an unusable credential is exit 12 `credential_invalid`, not a config error. See [Webhook edge](interface.md#webhook-edge). | Design guide section 7; the shape check stops a mistaken variable from sending the body to another host; the config is valid when the credential is not. Environment faults are exit 12 so a router has one rule: 20 drop, 12 read the flags, 22 no-op (maintainer decision, 2026-11-17). |
| D-8 | Send spacing: fixed 1 s, by the modification time of `send.lock`; no `min_interval` key. See [Send spacing](interface.md#send-spacing). | A burst of 12 requests in about 3 seconds was throttled and lost (spike A); no sustained rate was measured. The mtime holds no parsed content, so a hostile or future value cannot stall sends. A new lock file has size 0, which means "no earlier send" (its creation time is not a send), and the first send marks it with one byte. The lock is released at the end of step 6, before the log record is written. The key (and its `min_interval >= timeout` trap) can return additively after the live test (V1). |
| D-9 | No hooks in 0.x and no audit file. See [Hooks](interface.md#hooks), [Log](interface.md#log). | Policy lives above; a failure-notifying hook could loop; a notification changes no system of record (maintainer decision, 2026-11-17). |
| D-10 | `validate` never prompts; `validate --test-message` sends one marked test notification; there is no `--probe` and no `--yes`. See [`validate`](interface.md#validate). | A wrong variable name returns success and delivers nothing; only a human can tell. slack-notice differs from its siblings because no read-only call exists: a `GET` on a trigger URL returned 200 without delivering and was never verified as a validity test (V2). A doctor runs `validate --json` without flags; test messages are manual. Plain `validate` of a disabled tool ignores `enabled` except to report it and exits by its checks; `--test-message` of a disabled tool prints `{"outcome":"disabled"}` and exits 22 before any check (exit 22 means the requested action was not performed; plain validate is a doctor call). |
| D-11 | One monotonic deadline for the whole send (config `timeout`), enforced by a daemon worker thread, a three-state gate (idle, writing, abandoned) with a result slot under one lock, and `os._exit`, not `SIGALRM`. See [Webhook edge](interface.md#webhook-edge). | `http.client` timeouts are per operation: a server that trickled the status line and headers one byte per 0.4 s completed after 31.6 s with a 1 s socket timeout, and name resolution is not covered by a socket timeout, so a single-threaded deadline would need the tool to own all HTTP parsing and was rejected. The gate closes the race between a deadline and the first request byte (the result is `network_error` only while the gate is idle, so nothing was written), returns to idle after a fully read 429 so a retry is judged like the first attempt, lets a response that is complete at the deadline win through the result slot, and `os._exit` ends the process with the worker still blocked. The result is printed and flushed before the log step; the documented worst case is the timeout plus 3 s and callers kill no earlier than the timeout plus 10 s. |
| D-12 | HTTP through `http.client.HTTPSConnection` with its own TLS context; no proxy, no redirects, `SSL_CERT_FILE` and `SSL_CERT_DIR` ignored, no exception text printed. | The default `ssl` context honours `SSL_CERT_FILE` (verified), and `urllib` follows redirects and reads proxy variables: an injected variable could redirect or intercept the secret URL. Proxies and custom CAs are unsupported in 0.x. The interpreter and loader variables (`PYTHONPATH`, `LD_PRELOAD`, `OPENSSL_CONF`) are trusted: the tool closes the variables it reads itself, not every environment attack. |
| D-13 | Config: no `SLACK_NOTICE_*` environment overrides; precedence flags, config, defaults; one duration grammar as in design guide section 5; strict YAML loader with a 64 KiB cap. See [Config](interface.md#config). | An environment variable that selects the destination or the secret is the path a hostile `.envrc` or injected `export` would use. |
| D-14 | A state-directory problem never fails a send: one stderr warning, no log record, no lock. Every state file is opened with `O_NOFOLLOW` and `O_NONBLOCK` and must be a regular file owned by the user with one link and no permission bits beyond 0600 (a directory: owned, none beyond 0700); the log lock is polled for at most 1 s; the log step comes after the result is printed and is outside the deadline but bounded; an exit 1 after the request started is logged as `outcome_unknown`. See [Files](interface.md#files). | The log is advisory; a notifier that can be blocked by its own bookkeeping (a FIFO named `log.jsonl`, a lock held by a stuck process) defeats its purpose. `state_unsafe` is removed. |
| D-15 | Default `level_prefix` uses the four circle emoji (blue, orange, yellow, red). | The approved layout is `<emoji> LEVEL Title`; spike A delivered a Unicode emoji (stored as its shortcode on read-back), so there was no reason to drop it. Each is one code point with no joiner or variation selector, so the sanitizer does not change it. |
| D-16 | No configuration or state location is selected by the environment: config is `.config/slack-notice/config.yaml` and state is `.local/state/slack-notice`, both under the home directory of the password database; `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are not read (user decision, 2026-11-17). A failed lookup, or a home that is empty, relative or not a directory, is exit 2 `config_invalid` (`details.key` `home`) before any input is read; there is no fallback. | The same reason as the removed `SLACK_NOTICE_*` overrides: an environment variable that chooses where config or the secret comes from. Deviation from design guide section 5 ("respect XDG"), recorded as a carry-forward of the guide. Tests use `--config` and the fake gateway's `home_dir()`. |

## Resolved open topics

- Payload shape: [Notification](interface.md#notification). Invalid payloads exit 20 `refused` with reason `invalid_payload` and a JSON pointer.
- Channel config: [Config](interface.md#config). No per-repo overrides.
- Escaping: none for this transport, by test; characters are removed by one table of categories (Cc other than LF, Cs, Co, Cn) and an explicit list of invisible format and filler code points ([Sanitizer](interface.md#sanitizer)). Category Cn is removed, so which code points are unassigned follows the Unicode version of the running Python; the golden test is therefore pinned to a fixed code-point list, not to an enumeration of `unicodedata`. The explicit list deliberately keeps the variation selectors U+FE00 to U+FE0F, ZWNJ and ZWJ (Persian, Indic scripts and emoji sequences need them) and the Arabic number signs; a text made only of whitespace, joiners or combining marks (Mn, Mc, Me) is empty by the emptiness rule. The cost is that the braille blank, the Mongolian free variation selectors and the tag block (flags become their base emoji) are removed although some script shows them.

## Live verification

Verified in design (private spikes, 2026-11-17; the user's own workflow, test messages only):

| Behavior | Result |
|---|---|
| Success | 200, `{"ok":true}`, no message id. |
| Silent drops with 200 | Missing or empty variable, wrong variable name, GET, oversized body. |
| Loud failures | Invalid JSON 400, object-valued variable 400, altered path 401. |
| Content type | `text/plain` and none accepted. |
| Length | 12500 characters delivered; 15000 and up dropped whole. |
| Rate limit | The 12th of 13 requests in about 3 seconds got 429, no `Retry-After`; a throttled request is answered 429 and was not delivered; 6 to 7 s spacing never limited; nothing was measured in between. |
| Formatting | None rendered: no bold, italic, code, links, mentions. |
| Bare URLs | Auto-linked by Slack wherever they appear in the text (spike A F4); `<url\|label>` is not interpreted. |
| Emoji | A Unicode emoji is delivered and stored as its `:shortcode:` on read-back. |
| Destination | The workflow app's own conversation; workflow failures post to the workflow owner. |
| Duplicates | A plain retry sends twice. |

Still to verify (live tests in the plan, conservative defaults until then):

| Id | Claim | Conservative default |
|---|---|---|
| V1 | Sustained rate Slack accepts. | Fixed 1 s spacing; a sustained-rate live test in stage 4 settles whether a configurable interval is worth adding. |
| V2 | Slack answers 403, 404 or 410 for a revoked or wrong URL; a `GET` on a trigger URL tells a live URL from a dead one (only 401 was seen, for an altered path). | All four statuses map to `auth_required`; no probe call. |
| V3 | The length limit counts characters, not bytes (12,500 ASCII delivered, 15,000 dropped). | A fixed 12000-byte cap next to `max_chars`. |
| V4 | The segment count and character set of real trigger URLs. | 1 to 4 segments of `[A-Za-z0-9_-]+`. The first live assertion of stage 4 is that the maintainer's own trigger URL matches the allowlist; it is a release criterion (0.1.0 is not tagged until it passes) and the observed segment count and character set are recorded here. The pattern is not widened on a guess. |
| V5 | A 5xx can follow processing by Slack (never observed). | Treated as an unknown outcome and not retried. |
| V18 | The compiled default CA paths of a uv-managed Python on the user's machine. | A bundle file is usable by loading, not by existence; a directory can only be used as given. The fixed fallback list in [Webhook edge](interface.md#webhook-edge) applies when the compiled cafile does not load a certificate and the compiled capath is not an existing directory. |
| V21 | `hooks.slack.com` accepts HTTP/1.1 through `http.client` with `Connection: close` (spike A used curl over HTTP/2). | As specified; the first live plain-message test is the assertion. If it fails every send would be `wrong_host_response`, found on that test. |

Also open: whether a request header for idempotency exists (none is documented) and how fixed 1 s spacing behaves when two machines share a workflow.

Researched and rejected for 0.x (private notes): the official Slack CLI (login token has no `chat:write`, parameters only in argv, plaintext debug log, exit 0 on API errors); a CLI service token (app-building scopes only); the Slack MCP server (needs a registered, approved app; reusing Claude's token or app identity is outside its issued purpose); a headless Claude run per notification (cost per message and prompt injection). These are 1.x candidates behind the same `send` contract if the user ever gets an app token.

## Why the notifiers differ

The sibling notifiers share the contract but differ where the transport differs. slack-notice has a 3 s minimum timeout (one spacing wait plus one retry) while the others have different floors; one `max_chars` limit for the whole body because there is one text field (the others have a separate title and body limit); its own cut marker and default prefixes; no `link_hosts` key because Slack shows a bare URL to the reader; a send lock because only Slack throttles a workflow webhook; no tag-conditional retry because Slack has no deduplication; and a deadline enforced by a worker thread because the network phase cannot be interrupted from the main thread. The sibling names appear here only; the interface, README and CLAUDE.md name none.

## Modules

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing, command dispatch, exit-code mapping, output. |
| `config.py` | Config loading, drop-ins, YAML parsing, duration grammar, Pydantic validation (no environment overrides). |
| `payload.py` | Input reading (byte cap, hardened JSON), notification validation, sanitizer, link rule. |
| `render.py` | Body layout and cuts (characters and bytes). |
| `webhook.py` | URL allowlist, request building, response mapping, retries and the deadline gate. |
| `spacing.py` | Send lock and fixed 1 s spacing. |
| `log.py` | Log record writing and rotation. |
| `gateway.py` | The only place that opens network connections (`http.client`, TLS context, `Accept-Encoding: identity`), reads clocks, resolves names, reports `home_dir()`, `is_directory(path)` (the home check) and `uid()`, offers `read_source(fd_or_path, max_bytes, remaining)` (bytes or a timed-out result that the CLI maps to exit 12 `unavailable` with `details.phase` `input`), lists the CA path candidates and opens the state files. It also lists a config directory (`list_directory(path)`, names only) and makes a path absolute for display (`absolute_path(path)`, used for `details.key`). It also offers `wall_time()` (log timestamps), `sleep()`, `login_name()` (`None` without a password entry), `read_regular_file(path, max_bytes)` (config-style files, `O_NONBLOCK`, regular files only, `NotRegularFile` otherwise), `try_lock(fd)` and `unlock(fd)` (non-blocking exclusive `flock`), `file_size(fd)`, `read_at(fd, count, offset)`, `write_fd(fd, data)` (one `write`, possibly short), `truncate_fd(fd, size)` and `rename_state_file(dir_fd, source, target)` (the log append and rotation), and raises `StateUnusable` (fixed reason token) for an unsafe state directory or file. Response objects expose only the status and body reads (no header, so `Retry-After` and `Location` are unreachable). Tests substitute a fake gateway. |

## Data model, concurrency, errors

No stored objects. One lock file serializes sends on a machine ([Send spacing](interface.md#send-spacing)); a second lock file guards log rotation; everything else is independent. Errors use the envelope in [Error envelope](interface.md#error-envelope); log failures never change an exit code.

## Test strategy

- Process tests substitute the gateway in-process (`cli.main(argv, env, gateway)`): the URL must be on `hooks.slack.com` and verification cannot be disabled, so a real local server cannot stand in, and no test-only environment seam is allowed. The fake gateway exposes a response script, a delay, a stalled name resolution, a TLS failure, a post-write failure and a trickled response, and returns each row of [Webhook edge](interface.md#webhook-edge). Only the `live` tests touch the network. Process tests never use a test-only environment seam.
- Golden files for `--json` output, rendered bodies (levels, no title, no link, truncation boundary, non-ASCII, 3000 four-byte characters within 12000 bytes) and the hash and serialization of a fixed input; schema tests with positive and negative samples; a sanitizer table test; a link table test; an input table test; a duration table test; and a test that the URL (and a fake secret carried by an injected exception) appears in no argv, output, log or error.
- `live` tests (never in CI) post marked messages to the user's own workflow: one plain, one at the length limit, one burst and a sustained-rate run for spacing, the four default emoji; the still-to-verify items above become assertions when run.

## Platforms

Linux and WSL required; macOS expected (standard library only), untested.

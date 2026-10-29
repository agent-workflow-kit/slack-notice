# slack-notice: design

Status: Seeded from awkit architecture v1.4; not yet designed.

## Role and layer

Send a notification to Slack via an incoming webhook. Layer: L1 (primitive). Works fully standalone.

## Responsibilities

From architecture §5.1 (verbatim):

One small tool per channel: `send --stdin-json` (a JSON object with `title`, `message`, `level`, `link`) or, for trusted human use, `send --title ... --message ... [--level info|warn|action|error] [--link URL]`. Levels are ordered `info < warn < action < error`.

- Uses: curl/HTTP (desktop: the platform's native notifier).
- `slack-notice`: Slack incoming webhook; the URL comes from the env var named by config (`webhook_env`).
- All channel tools escape platform markup in title and message (no mentions, no link injection); links are only added via `link`/`--link`.

## Uses

- curl/HTTP (Slack incoming webhook): binding TBD (A/B/C), decided in this design session

## Relevant architecture sections

Read these sections of `../awkit-docs/architecture.md` before designing:

- §3.4: cross-cutting principles (hooks, untrusted text travels in files)
- §6: conventions summary
- §13.2: prompt injection: transport rule 2 (`send --stdin-json`)
- §13.3: credentials: environment variables only, never logged
- §14: audit (external actions)
- §15: notifications: producers, levels, how notice-route calls channel tools
- §20: this tool's constraints and open topics
- design guide §7, §12: credentials; channel output escaping

## Constraints (decided)

From architecture §20:

- none.

## Open topics

From architecture §20:

- payload shape
- channel config
- per-platform escaping

## Decisions

| Decision | Rationale | Date |
|---|---|---|

## Questions for the design session

1. What exact payload shape does `send --stdin-json` accept (required vs optional fields, extra fields, size limits), and how are invalid payloads reported?
2. What channel config does this tool need (keys, defaults, per-repo overrides), and how is it validated?
3. How exactly is platform markup escaped for this channel so that title and message cannot produce mentions or injected links?

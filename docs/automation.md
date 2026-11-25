# Calling slack-notice from cron and other automation

This page is the how-to for callers that run without a person: cron, other schedulers, scripts and agents. The rules themselves are in [interface.md](interface.md), the single normative source, in particular [Calling from automation](interface.md#calling-from-automation), [Exit codes](interface.md#exit-codes), [Environment variables](interface.md#environment-variables) and [Webhook edge](interface.md#webhook-edge); if this page and the interface ever disagree, the interface wins. The README covers the one-time setup (the workflow, the install, the config file and `validate`).

Every fenced block below carries a marker comment in the line before it. `test-cron`, `test-sh` and `test-py` blocks are executed by `tests/test_automation_doc.py` in real subprocesses that cannot reach the network (the commands are stand-ins or run offline: `validate`, or `send --dry-run`); `golden` blocks must equal a file of `tests/golden` byte for byte; `manual` blocks are not run (they set up files on your machine).

## 1. The credential must be in the calling environment

slack-notice reads the workflow trigger URL only from the environment variable named by `webhook_env` (default `SLACK_WEBHOOK`). It never reads a shell startup file, a secret file or a config entry for it. A scheduler starts jobs with a minimal environment and does not read your profile, so a variable that you exported in your interactive shell is not there. Without it every send exits 12 `credential_invalid`.

Keep the URL in an env file that only you can read, and have the scheduled command source it. Create it once, with the mode set before the secret is written:

<!-- manual -->

```sh
mkdir -p "$HOME/.config/slack-notice"
umask 077
printf '%s\n' "export SLACK_WEBHOOK='<paste your workflow trigger URL here>'" > "$HOME/.config/slack-notice/env"
chmod 600 "$HOME/.config/slack-notice/env"
ls -l "$HOME/.config/slack-notice/env"
```

The env file must be mode 0600 and owned by you: the URL is a secret, because anyone who holds it can post to your workflow. The check is yours to make, since slack-notice never opens this file: the `ls -l` above must show `-rw-------`. A file that others can read (a group or world read bit) is a leak: run `chmod 600` on it, and treat the URL as exposed if it was ever readable by someone else. Do not put the URL in the crontab itself (`NAME=value` lines there are easy to list, copy into a dotfiles repository or mail), and never on a command line.

The `export` in the file is needed: a plain `SLACK_WEBHOOK=...` assignment is visible to the shell that sources the file but is not passed to the child process, and `validate` then reports `credential: failed`.

## 2. The cron line

Cron runs each command with `/bin/sh` (a POSIX shell; not your login shell, unless the crontab sets `SHELL`), so the line below calls `sh -c` explicitly and uses only POSIX syntax: `.` (not `source`) reads the env file and `&&` runs the tool only if the file was read. Things that differ from your terminal, which vary a little between cron implementations (check yours):

- The environment is minimal: typically `HOME`, `LOGNAME` and `SHELL` are set and `PATH` is just `/usr/bin:/bin`. No profile or rc file is read. Call the tool by absolute path (`$HOME/.local/bin/slack-notice` is where a per-user install usually puts it; `command -v slack-notice` in your terminal tells you) and give `.` an absolute file name too (a relative name is searched in `PATH` by some shells).
- A percent sign in a crontab command is a newline unless it is written `\%`, and everything after the first unescaped one is fed to the command as stdin. This matters for `date +%F` and for any payload that holds a percent sign: put such text in a file, as below, or in a wrapper script, not in the crontab line.
- Cron mails whatever the job prints (on most systems to the crontab's owner). A successful send with `--json` prints one line on stdout, so redirect it to a file you rotate, or set `MAILTO` deliberately, if you do not want a mail per run.
- slack-notice finds its config and its state directory through the home directory of the password database, not through `HOME`; a job that runs as another user uses that user's files.

A nightly notice with a fixed payload, and a quiet health check that prints only when something is wrong:

<!-- test-cron -->

```crontab
30 2 * * * sh -c '. "$HOME/.config/slack-notice/env" && "$HOME/.local/bin/slack-notice" send --stdin-json --json --actor auto:nightly < "$HOME/.config/slack-notice/nightly.json" >> "$HOME/.local/state/slack-notice-cron.out" 2>&1'
*/30 * * * * sh -c '. "$HOME/.config/slack-notice/env" && "$HOME/.local/bin/slack-notice" validate --quiet'
```

The second line runs `validate`, which makes no network call and sends nothing, so it can run as often as you like (see [section 6](#6-health-check-and-doctor-recipe)). When the env file is missing, `.` fails, the tool is never started, and the shell's error message is what cron mails.

For anything longer than one line, put the logic in a script (a wrapper) that starts with `. "$HOME/.config/slack-notice/env"` and call the script from cron; the same quoting and percent rules apply to the crontab line that calls it.

## 3. The canonical call and what to do with each exit code

The canonical call is `slack-notice send --stdin-json --json --actor auto:<name> [--dedupe-key=<hex>]` with the payload on stdin, absent fields omitted (never null). A caller that has a key passes a hex digest of it with the `=` form, never the raw id. Decide by the exit code alone; the JSON on stdout adds detail. This is the table from [Calling from automation](interface.md#calling-from-automation), reproduced here and checked against it by a test:

| Exit | Meaning | Caller action |
|---|---|---|
| 0 | sent | Record it. |
| 22 | disabled, a successful no-op | Nothing. A shell caller writes `rc=$?; [ "$rc" = 22 ] && rc=0`. |
| 20 | the payload was refused | Do not retry; surface once per reason. After link_invalid or link_scheme a caller may retry once without link, putting the URL in the message. |
| 12 (false, false) | not sent; `host_rejected`, `auth_required` and `credential_invalid` need a person to change the config or the credential; `wrong_host_response` after a status in 300..599 that is not listed may be transient (a final 1xx or a status outside 100..599 is possibly delivered, see the (false, true) row) | Do not retry; surface once per code and destination. For `wrong_host_response` a router may retry later under the same cap as the next row. |
| 12 (true, false) | not sent, worth retrying (`rate_limited`, `network_error`, `unavailable`, including `unavailable` with `details.phase` `input`) | Retry later with the caller's own backoff and one cap (`rate_limited` has already waited 2 s and 4 s inside the deadline, `network_error` 2 s once and `unavailable` only for the lock or the input; retry_after_s is the tool's own wait, the wait that follows the 429 (2 s after the first, 4 s after the second and for the third, which has none; when the deadline cuts that wait or it does not fit, still that wait), not a server hint). |
| 12 (false, true) | possibly delivered | Do not retry; record it as possibly sent. `wrong_host_response` after a final 1xx or a status outside 100..599 is also possibly delivered. A persistent 2xx with a bad body (`wrong_host_response`) means the URL is not a trigger URL. |
| 128+N | the tool was stopped by signal N before the send started | Nothing was sent; the caller that sent the signal knows. |
| 2, 1 | a usage or config fault, or an internal error | Do not retry; surface as a fault of the deployment. Exit 1 with no envelope: the outcome is unknown. |

The pair `(false, true)` in the table is `(retryable, unknown_outcome)` of the error envelope. Exit 22 is not an error: a tool that is switched off in its config sends nothing and prints `{"outcome":"disabled"}`. Exit 20 means only that the payload was refused, a fault of the producer, and is never retried. The caller prevents refusals by cutting title and message to at most 100000 characters, always supplying a non-empty message, using one of the four levels, and percent-encoding links.

The unknown outcome is the one that needs care. `unknown_outcome` true means the message may already be in Slack: a blind retry can post it twice, and Slack does not deduplicate. Treat it as possibly sent, record it, and let a person look. Exit 1 may come with no envelope, and then the outcome is unknown too.

The snippet below applies the table in a POSIX shell. It reads the envelope with a real JSON parser (here `python3`; `jq -r` does the same) and never with `grep`, `sed` or `eval`; a document that does not parse reads as null, which the snippet treats as "do not retry". It retries nothing itself: `retry-later` is the one action that is safe to repeat, and it is for the caller's own scheduler, with a cap.

<!-- test-sh -->

```sh
payload='{"title":"Nightly","message":"report finished"}'
out=$(printf '%s' "$payload" | slack-notice send --stdin-json --json --actor auto:nightly)
rc=$?
field() {
    printf '%s' "$out" | python3 -c 'import json, sys
try:
    value = json.load(sys.stdin)["error"][sys.argv[1]]
except (ValueError, KeyError, TypeError):
    value = None
print(json.dumps(value))' "$1"
}
case $rc in
    0)  action=sent ;;
    22) action=disabled; rc=0 ;;
    20) action=refused ;;
    12) retryable=$(field retryable); unknown=$(field unknown_outcome)
        if [ "$unknown" = true ]; then action=possibly-sent
        elif [ "$retryable" = true ] && [ "$unknown" = false ]; then action=retry-later
        else action=surface; fi ;;
    1)  action=internal-outcome-unknown ;;
    2)  action=deployment-fault ;;
    *)  action=stopped-by-signal ;;
esac
printf 'action=%s\n' "$action"
exit "$rc"
```

Example envelopes, byte for byte as the tool prints them (the examples are the golden files of the test suite). A disabled tool, exit 22:

<!-- golden send/disabled.stdout -->

```json
{"outcome":"disabled"}
```

A rate limit, exit 12 and `(true, false)`. `retry_after_s` is a float, written `2.0` or `4.0`, and null for every code except `rate_limited`:

<!-- golden send/rate_limited.stdout -->

```json
{"error":{"code":"rate_limited","message":"the host is rate limiting requests","reason":null,"details":{"http_status":429},"retryable":true,"retry_after_s":4.0,"unknown_outcome":false}}
```

A credential that is unset or has the wrong shape, exit 12 and `(false, false)`; `details.env` names the variable the tool looked at:

<!-- golden send/credential_invalid.stdout -->

```json
{"error":{"code":"credential_invalid","message":"the webhook credential is unset or not a workflow trigger URL","reason":null,"details":{"env":"SLACK_WEBHOOK"},"retryable":false,"retry_after_s":null,"unknown_outcome":false}}
```

A connection that failed and then ran into the deadline during the retry wait, exit 12 and `(true, false)`. `details.timeout` is false here: it is true only when the deadline cut a wait or a request in a way that the tool itself timed out, and a deadline that ends the wait after a connection error still reports the connection error:

<!-- golden send/network_error_deadline_cuts_wait.stdout -->

```json
{"error":{"code":"network_error","message":"the connection to the host failed","reason":null,"details":{"tls":false,"timeout":false},"retryable":true,"retry_after_s":null,"unknown_outcome":false}}
```

Parse envelopes as JSON and do not depend on the order of the keys inside `details`. The `--json` output of a successful send holds no message text; the only text the tool echoes is the caller's own `--dedupe-key`.

## 4. Timeouts, kills and stdin

- The send has one deadline, the config `timeout` (default 10 s, between 3 s and 120 s), counted from the start of input reading. The tool prints its result within 1 s of the deadline and ends within 3 s of it. A caller that enforces its own time limit sets it to no less than `timeout` plus 10 s.
- If the caller does kill the tool, it gets no envelope and must treat the outcome as unknown. Prefer SIGTERM to SIGKILL: before the send starts, SIGTERM ends the tool with exit 143 (128+15) and nothing is sent; afterwards the tool treats it as the deadline passing and reports it. A signal that arrives while the tool reads the credential counts as the deadline too.
- The tool may exit without having read all of stdin (a refusal, a disabled tool, a usage error). A caller that writes the payload to a pipe must ignore EPIPE (and SIGPIPE) on that write and decide by the exit code alone.

In a shell the pipe is safe by construction: in `printf '%s' "$payload" | slack-notice ...` the writer is `printf`, a broken pipe stops only `printf`, and the pipeline's status is the status of the tool (do not set `pipefail` for it). A here-document or `< file` avoids the pipe altogether, as the cron line does.

In a script language, write the payload, treat a broken pipe as normal, wait for the tool and read its exit code. This Python function does that: `Popen.communicate` swallows the broken pipe on the stdin write, and a time limit sends SIGTERM and not SIGKILL. On a time limit the outcome is unknown, and `returncode` is then negative (`-15` is SIGTERM); a negative code is how Python reports a signal, whereas a shell reports 128+N. Other languages need the same three steps: ignore or catch EPIPE, wait, decide by the exit code.

<!-- test-py -->

```python
import json
import subprocess


def notify(payload, timeout_s=10.0, name="nightly"):
    """Return (exit code, parsed stdout or None). A negative code means we signalled it."""
    command = ["slack-notice", "send", "--stdin-json", "--json", "--actor", "auto:" + name]
    data = json.dumps(payload).encode("utf-8")
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
        try:
            out, _ = process.communicate(data, timeout=timeout_s + 10)
        except subprocess.TimeoutExpired:
            process.terminate()  # SIGTERM; the outcome is now unknown
            out, _ = process.communicate()
    try:
        document = json.loads(out)
    except ValueError:
        document = None
    return process.returncode, document if isinstance(document, dict) else None
```

## 5. One send at a time

The tool serializes the sends of one machine for you: each `send` takes a lock in the state directory and waits until one second has passed since the last send began, up to its own deadline. That lock is not fair, it covers one machine only, and a send that cannot get its turn before the deadline ends with exit 12 `unavailable` (retryable), having sent nothing. So the tool serializes one machine's sends, but the caller still sends one notification at a time: no fan-out, no parallel jobs that each call the tool, and a producer that stalls while the tool waits for its stdin gets `unavailable` with `details.phase` `input`. Across machines nothing is coordinated: each machine spaces only its own sends, and Slack throttles a workflow trigger (a burst of 12 requests in about 3 seconds got 429 in testing), so stagger the schedules of jobs on different machines. To send to several destinations, keep one config file per destination and pass `--config <path>` to each call, one after the other.

The spacing and the log depend on a usable state directory. If it cannot be used (a wrong owner, a symlink, a read-only file system) the tool warns once on stderr and goes on without spacing and without a log record; the exit code is not changed. A caller that must have spacing serializes on its own.

## 6. Health check and doctor recipe

`slack-notice validate [--json] [--config <path>]` never prompts, makes no network call, uses no state directory, writes no log record and reads no stdin. It checks the config and that the credential variable is set and has the form of a workflow trigger URL. Exit 0 means ok, 2 means the config is invalid (the error envelope is printed), and 12 means the credential check failed: the variable is unset, empty or has the wrong shape. A failed credential check is a `validate` document with `ok` false, and with `--json` nothing is written to stderr. The document is `{ok, enabled, checks: [{name, ok, message}]}`; a doctor reads `enabled`, because a tool that is switched off still reports its config and credential faults, and a failed credential check of a tool with `enabled` false is information, not an alarm. Without `--json`, `validate` prints one line per check on stderr, `<name>: ok (<message>)` or `<name>: failed (<message>)`, and `--quiet` keeps only the failed ones, which is what the second cron line of [section 2](#2-the-cron-line) relies on.

A healthy tool, as the doctor sees it with `validate --json`:

<!-- golden validate/ok.stdout -->

```json
{"ok":true,"enabled":true,"checks":[{"name":"config","ok":true,"message":"configuration is valid"},{"name":"credential","ok":true,"message":"the webhook credential is set and has the form of a workflow trigger URL"}]}
```

The credential unset (for example because the env file was not sourced), exit 12:

<!-- golden validate/credential_unset.stdout -->

```json
{"ok":false,"enabled":true,"checks":[{"name":"config","ok":true,"message":"configuration is valid"},{"name":"credential","ok":false,"message":"the webhook credential is unset or not a workflow trigger URL"}]}
```

Read the document with a JSON parser, as in the snippet of [section 3](#3-the-canonical-call-and-what-to-do-with-each-exit-code): the tool is healthy when the exit code is 0 and `ok` is true; `enabled` false means that it is switched off on purpose.

`validate --test-message` is different: it is a real send. It posts one notification (level info, title `slack-notice`, message `validate: test message`) through the normal path, so it takes the send lock, honors the one-second spacing, is subject to the deadline and the retries, and writes a log record like any send. It exits 12 when the message was not accepted, and the check says nothing about the cause (the log record does). A success proves that Slack accepted the request, not that the message arrived: Slack accepts a request with a wrong variable name and drops it silently, so look at the destination. It is the only way to find a revoked trigger URL, and it is meant for a person at setup time or after a change. Do not put it in a frequent cron line or any automatic loop: each run posts a message to your Slack destination.

## 7. What the tool logs, signals and nohup

Operators can rely on these facts; the rules are in [Log](interface.md#log) and [Webhook edge](interface.md#webhook-edge).

- The log is `.local/state/slack-notice/log.jsonl` under the home directory of the password database (mode 0600), one JSON object per line, one record per send that got as far as reading its input. It rotates when it reaches 1 MiB and keeps `log.jsonl.1` to `log.jsonl.3`. Config `log: false` turns it off.
- A record holds the time, the outcome and exit code, the error code and reason, the level, the size of the request, the duration, the HTTP status, a short hash of the message and one of the dedupe key, and the actor. It holds no title, message, link, URL, host or credential. The hashes, the size and the truncation flag are null for a refusal and for an input timeout, because they are only computed after the text is sanitized and rendered; the level is null when no valid level was read, which includes a link refusal for an input without a level.
- Exit codes 2 and 22, dry runs, and a signal before the send starts (128+N) leave no record. A failure to write the log (a full disk, a lock that is held, a rotation that fails) skips the record with one warning on stderr and never changes the exit code. The result is printed and flushed before the log step, and the process ends no later than `timeout` plus 3 s.
- `--quiet` suppresses every stderr line except errors and warnings, so it also suppresses the dry-run text and the `sent (...)` line; the `--json` document on stdout is unaffected. Do not parse stderr: it is advisory, and the contract is the exit code plus the stdout JSON.
- The tool handles SIGINT, SIGTERM and SIGHUP once. A signal before the send starts exits with 128+N (130 for SIGINT, 129 for SIGHUP, 143 for SIGTERM), prints nothing and logs nothing; later signals count as the deadline passing, and once the result is being printed they are ignored. The handlers replace an inherited ignore, so running the tool under `nohup` does not protect it from a hang-up: it acts on SIGHUP. Run long-lived jobs under a scheduler or a service manager, not a terminal.
- A closed standard descriptor (0, 1 or 2, as in a daemonized job) is reopened on `/dev/null` when the process starts, so a connection never lands on descriptor 0 to 2. Writes to stderr and stdout are bounded: a stalled reader cannot delay the exit by more than about a second.

## 8. Checklist

- The env file exists, is mode 0600, and exports the variable named by `webhook_env`; the scheduled command sources it by absolute path.
- The tool is called by absolute path, with `--stdin-json --json --actor auto:<name>`, and the payload comes from a file or a pipe, never from the command line.
- The caller decides by exit code: 22 is not an error, 20 is never retried, and a retry of exit 12 happens only for `retryable` true with `unknown_outcome` false, with a cap.
- The caller's own time limit is at least `timeout` plus 10 s, and a kill means an unknown outcome.
- One notification at a time; staggered schedules across machines.
- `validate` (cheap, offline) is the health check; `validate --test-message` (a real send) is for a person.

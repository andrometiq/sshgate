# Journey E2E

The journey runs installed SSHGate binaries through MCP stdio, the real Telegram
signer, and two SSH targets. The disposable controller owns the fake Telegram
process. Use an internal Docker network, no published ports, synthetic identities
and secrets, and no external assessment providers. The fake is only a Telegram
transport: it never signs, executes commands, or invents terminal card edits.

## Fake Telegram process

Build `go build -o /tmp/fake-telegram ./tests/journey/cmd/fake-telegram`.
Run `fake-telegram --api 127.0.0.1:0 --admin 127.0.0.1:0 --user-id 99999` inside
the controller. Both listeners require numeric loopback addresses. Its single
stdout JSON line contains `api_url` and `admin_url`; startup failures go to stderr.
Set the signer's `SSHGATE_TELEGRAM_API_URL` to `api_url` and configure the same
synthetic allowed user ID. SIGINT/SIGTERM stops both listeners. Polling waits at
most one second per call so shutdown remains bounded.

The Bot API accepts form-encoded `getMe`, `getUpdates`, `sendMessage`,
`editMessageText`, `editMessageReplyMarkup`, and `answerCallbackQuery` under
`/bot<SYNTHETIC_TOKEN>/<method>`. Updates remain available until a higher offset
acknowledges them; `limit` is supported (1–100). Unknown methods return HTTP 400
and leave a failure in the transcript. Every Bot API rejection returns a JSON
error with a numeric `error_code`, including invalid routes, forms and polling
parameters. Negative offsets are deliberately rejected.

## Controller admin API

Admin routes exist only on `admin_url`. Keep this address private to the
controller; loopback is network isolation, not authentication against other local
processes. POST bodies are JSON; responses use `{ "ok": true, "result": ... }`.
Invalid controls return non-2xx and `ok:false`.

| Route | Body | Effect |
| --- | --- | --- |
| POST `/policy` | `{"policy":"hold"}` | Set policy for subsequently rendered actionable cards. |
| POST `/start` | `{"chat_id":12345}` | Queue `/start` from the configured operator in that private chat. |
| POST `/release` | `{"message_id":2,"action":"approve"}` | Deliver one held callback; action defaults to approve. |
| POST `/replay` | `{"message_id":2,"action":"deny"}` | Deliver a saved callback, including after edits or acknowledgement. |
| GET `/events` | — | Return `result.events` and `result.failures`. |

Policies are `approve_now`, `deny`, `hold` (default),
`approve_after_sync_wait`, and `never`. Immediate policies tap once when an
Approve/Deny keyboard is rendered. Hold and after-sync policies require an explicit
release for that message ID. The controller must observe the terminal MCP response
and expiry evidence **before** releasing an after-sync card; the fake cannot observe
MCP itself. `never` rejects release; deliberate late taps use replay. Releasing an
already delivered card returns 409. Changing policy never changes existing cards.

Find the actionable card in `sendMessage` or edit events by its inline keyboard,
not by taking the first message in a multipart review. Both an Approve-labelled and
a Deny-labelled callback button are required. Labels choose the action; callback
data is opaque and copied verbatim. The callback preserves the rendered chat,
message ID/text/markup and configured operator ID. Replay preserves the callback
query ID and payload but assigns a new update ID, so an acknowledging poller sees
the duplicate. Saved callbacks survive removal of the original keyboard.

## Evidence and acceptance

Collect `/events` before stopping the fake. Each event has a sequence, UTC time,
method, form fields and JSON result; edits include markup and callback answers
include their query ID. API token paths are not recorded. Assert `failures` is
empty: an HTTP error alone is insufficient because the real backend can retry it.
Events are retained in memory for one disposable run; bound the run and collected
artifact size in the controller. Do not use real tokens, keys or secret fixtures
in this service's requests or exported artifacts.

The complete journey artifact bundle also contains bounded MCP output, scenario
timeline, service journals, gate/signer audits, doctor output, image digests and
binary hashes/build metadata. Exclude key/token files, output-bearing raw journals
and secret fixtures. Collect evidence before teardown and always remove containers
and volumes. Missing infrastructure and missing scheduled scenarios are failures.

J1 unit acceptance:

```sh
go test -race -timeout 30m ./tests/journey/faketg/...
```

The tests cover protocol transcripts, offset acknowledgement, all tap policies,
multipart callback binding, duplicates, unknown methods, admin separation, and
approve/deny through the real Telegram backend with its local API override.

The fake rejects text outside 1–4096 Unicode characters and callback data outside
1–64 bytes before storing a message or capturing a card. Every inline button must
have nonempty text and callback data; malformed buttons and unsupported fields
(including URL actions) are rejected before any message, card or update is saved. Callback answers require
an issued query ID; repeated answers to that ID are accepted (including replay).
Supported answer fields are `text` (at most 200 characters), `show_alert` (boolean),
and `cache_time` (nonnegative integer); other fields fail explicitly.
Text edits without markup clear the keyboard. Edits that leave effective text and
markup unchanged fail with `MESSAGE_NOT_MODIFIED`. Saved replay payloads remain
independent of the current message.

In-process regression tests can configure `Service.Controls` before serving.
`PollWaiting` signals that a poll has found no updates and captured its notification
channel; `PollTimeout` replaces the wall-clock timeout. An untriggered timeout
channel proves that notification alone wakes a waiting poll. Timeout and request
cancellation have separate tests.

`HoldMessageResponse` supplies a `BeforeMessageResponse` hook, a captured-message
channel, and an idempotent release function. With `hold` policy, wait for the card,
POST `/release` to deliver its callback, and observe callback processing while the
send response remains blocked. Then release the response. This forces the old
backend's callback-before-pending-registration ordering without sleeps or retries;
backend regressions can supply their own processing barrier if the fixed handler
waits for registration. Always defer the response release, including on test
failure. Ordinary `approve_now` and `deny` do not use this hook: they tap as soon
as the fake captures the delivered card.

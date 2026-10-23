# Approval command refusals

The approval command gate silently counts `wrong_user` and `not_private` refusals.
It sends no response and writes no per-message audit entry. After one elapsed
minute, the poller writes one audit summary and one log line with the total and
per-reason counts. The next poll iteration flushes a due summary, including when
no more commands arrive; a stalled poll can delay it. Unflushed counts are
process-local and are lost on shutdown.

Authenticated private-chat refusals (`forwarded`, `redelivered` and
`unknown_command`) share a limit of one audit entry and one linked-DM reply per
elapsed minute. Excess refusals are silently dropped. This bounds their use of
the notification queue. Only `redelivered` sets the audit replay flag. Registered
commands that pass the gate do not consume this refusal budget.

The legacy `/start` handler silently counts well-formed wrong-user messages in
the same summary. Its allowed-user linking behavior is unchanged.

Callback taps retain their existing handling: unauthorized taps receive a
`not authorized` answer and a per-tap log entry. This remains an accepted
limitation for operator-linked legacy group chats; the callback-binding
carry-forward tests pin these answers.

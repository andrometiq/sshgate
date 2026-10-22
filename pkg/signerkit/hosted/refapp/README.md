# Approval views

The pending page reads both the legacy `pending` list and `v2_pending`. Each list
keeps its own continuation: a legacy offset and an opaque `v2_cursor`. Refresh
starts both lists again. The audit page also shows `v2_entries`, including the
advisory binding retained after details are pruned.

Request links use `?id=` for legacy requests and `?h=` for v2 record handles.
V2 pages render the stored `approvalreview` model as text, preserving its already
neutralized display. The detail response supplies the challenge and allowed
voting actions. Both planes send that challenge with each vote, and send a TOTP
code when step-up is required. A changed view reloads the challenge; a busy
response keeps it for an explicit retry and clears a spent step-up code.

Run `make test-refapp-js` for the browser adapter and page tests. They use a DOM
stub that rejects HTML insertion and a same-origin fetch stub; no network is used.

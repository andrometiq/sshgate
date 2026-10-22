# Command job workers

`StartCommandJobs` explicitly enables command execution and recovery on a service.
The production entry point does not call it yet: production execution wiring is
pending the intake scope decision. Admission is unchanged. Admin and transfer
jobs retain their existing submission path but get no command worker, Claim,
SSH dispatch, or execution report.

Each command job has one actor driven by `approvalplan.JobNext`. An unacknowledged
job keeps submitting after the notification response bound and after restart. A
lost Submit is reconciled by Get before an idempotent resend. Transient answers
back off; definitive answers become durable outcomes. Notification replies use
only evidence observed during that attempt, including the actor's Submit answer.

The actor uses `jobplan.Runner` for fresh route checks, bounded output, and the
pre-Start signature-window guard. A confirmed marker precedes Start. An orphan
marker becomes indeterminate without another dispatch. Signature envelopes stay
in memory and are released at the last signed Start, a window refusal, or finality.
An unsigned tail does not require another Claim.

Results and their completion time commit before the canonical final report.
Only a definite size refusal permits retrying a result without bodies. Lost
report acknowledgements resend the same report from retained digests. Successful
await writes queue a delivery fact for the actor; await reads do not write it.
Close latches out commits, cancels effects, and joins the workers. Interrupted
effects leave recovery to the next epoch.

With command workers enabled, retention runs at startup, on due timer wakes,
and before admission. Production admission remains unchanged until that wiring
is enabled. Timer wakes inspect a commit-maintained due index and load only due
records.
It uses `final_at` for ages: bodies expire after seven days; budget pressure can
remove them after delivery is at least 24 hours old. A settled report and absent
bodies allow token removal. File deletion additionally waits until
`submit_not_after + 24h` and either 30 days after finality or count pressure.
Pressure reclaims oldest final jobs first. Active actors and submission handlers
pin files; Get, admission, commits and deletion share the service lock. An await
response delivered after file deletion is ignored. Every removal is durable;
restart uses the persisted finality, delivery, removal and report slots.

Wait answers remain wakeups: each actor's Get supplies the authoritative answer,
including `not_found` after acknowledgement. A batch containing a missing signer
record can therefore back off until its actor records the definitive Get answer.
A signer without Wait remains accepted for isolated command-worker adapters;
production's wire client implements Wait. Actors cache their committed record,
refresh it on commits, and let nudges shorten retry waits.

The `sshgate_sizefault` test uses the real JobStore and EncodeR2. Its test-only
Go overlay changes `approvalplan.R2Reservation`'s return expression from
`len(b) + 4*int((maxOutputBytes+2)/3) + R2BodyOverhead` to
`len(b) + R2BodyOverhead`. This simulates an underestimated body reservation
without replacing the store or encoder, and proves `request_too_large` retries
without bodies while retaining result metadata. Run it with
`flock "$LOCK" go test -timeout 30m -tags sshgate_sizefault -overlay <overlay.json> -run TestCommandJobRealStoreSizeRefusal ./src/executor`.
The normal reservation is deliberately too large for a valid record to trigger
that defensive path.

Process crash hooks and the hosted-proxy harness have separate prerequisites. The contention measurement
remains behind `sshgate_perf` and is not part of the race suite.

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

Retention and storage-pressure work belong to C2d. Process crash hooks and the
hosted-proxy harness have separate prerequisites. The contention measurement
remains behind `sshgate_perf` and is not part of the race suite.

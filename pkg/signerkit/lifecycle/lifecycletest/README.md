# Lifecycle store conformance

Call `lifecycletest.Run(t, factory)` from an external test package. The factory
must return a new empty `lifecycle.Store` on every call and register its resource
cleanup with `t.Cleanup`. Engines are closed before that cleanup runs. The suite
never closes the store: restart cases reuse it with a fresh `lifecycle.New`, so
all engine projections and epochs are rebuilt by `startup.go`.

The suite checks R1 transition invariants using `approvalplan/statetest`, encoded
record preservation, reservation stability, replay, ownership isolation, clock
facts, grant termination, and seeded command schedules. Recovery cases enumerate
landed and unlanded notification, edit, renotify, decision, flush and mint cuts.
The stop matrix holds notifier, assist and audit calls across the cancellation
that follows the latch, then checks commits, external calls and restart recovery.
An armed edit retry is checked separately, with live failure contrasts. A
300-record failed-sink case checks startup's independent unflushed driver and
deadline ordering beyond one flush batch.

Pure transitions construct crash fixtures; production engine APIs perform
recovery and effects. The store factory does not simulate filesystem crashes:
B1's durability and uncertain-write/reopen tests remain separate. Executor R2,
legacy transport and hosted-owner shutdown checks belong to their own suites.

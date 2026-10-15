package approvalplan

import "time"

// Work is the signer reconciler's work for one record (SA-1 rule 4, SA-8):
// what the tick, Startup and the post-commit pass drive. Flush retries are
// not here: Unflushed lists them on their own schedule (SA-7).
type Work struct {
	// Clock: Clock has a slot to fill at now.
	Clock bool
	// Notify is the next notify step on the record after Clock.
	Notify NotifyStep
	// Shed and Delete: the record is eligible by age now.
	Shed   bool
	Delete bool
	// DueAt is next_due_at after Clock; zero when nothing is time-driven.
	DueAt time.Time
}

// Next is the signer reconciler's work list for a record at now. It judges
// the record as Clock would leave it, because every pass applies Clock first.
func Next(rec R1, now Now, epoch string, s Settings, grantLive bool) Work {
	now = now.norm()
	after, events := Clock(rec, now, epoch)
	return Work{
		Clock:  len(events) > 0,
		Notify: NotifyNext(after, now, epoch, s),
		Shed:   shedAllowed(after, now, s, grantLive, false),
		Delete: deleteAllowed(after, now, s, grantLive, false),
		DueAt:  NextDueAt(after, now, s),
	}
}

// Unflushed reports whether the record has events the sink does not hold
// yet: SA-7's retry list, driven each second independently of next_due_at.
func Unflushed(rec R1) bool { return rec.Header.AuditedThrough < rec.Header.OutboxSeq }

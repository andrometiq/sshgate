package approvalplan_test

import (
	"strings"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// grant requests and approves a scope-all grant on web-1 for principal.
func (r *rig) grant(id, principal string, d time.Duration) string {
	r.t.Helper()
	if ans := r.s.Submit(principal, st.GrantDraft(id, "web-1", d, r.clock.Wall)); ans.Code != "" {
		r.t.Fatalf("grant %s: %+v", id, ans)
	}
	key := ap.RecordKey(principal, id)
	r.approve(key)
	return key
}

// covered reports whether a fresh write of principal is decided by a grant.
func (r *rig) covered(n int, principal string) bool {
	r.t.Helper()
	id := st.ID(n)
	r.s.Submit(principal, st.JobDraft(id, ap.CoordinatorExecutor, r.clock.Wall, st.Write("w", 60)))
	d := r.rec(ap.RecordKey(principal, id)).Header.Decision
	return d != nil && strings.HasPrefix(d.DecidedBy, ap.GrantDecidedPrefix)
}

func TestGrantLiveness(t *testing.T) {
	r := newRig(t)
	g := r.grant(st.ID(1), st.PrincipalA, time.Hour)
	if sum := r.view(g); sum.Class != ap.ClassLive || sum.GrantID != st.ID(1) || !sum.GrantExpiresAt.Equal(r.rec(g).Header.Decision.DecidedAt.Add(time.Hour)) {
		t.Fatalf("grant view %+v", sum)
	}
	if !r.covered(10, st.PrincipalA) {
		t.Fatal("a live grant did not cover its principal's write")
	}
	if r.covered(11, st.PrincipalB) {
		t.Fatal("principal A's grant covered principal B")
	}
	key := ap.RecordKey(st.PrincipalA, st.ID(10))
	sum := r.view(key)
	if sum.AssistState != ap.AssistNotApplicable || sum.NotificationStatus != ap.NotificationNotApplicable {
		t.Fatalf("grant-decided view %+v", sum)
	}
	r.s.FlushPass()
	r.s.RevokeAlias("web-1")
	if ans := r.claim(key, st.ID(10)); ans.Claim != ap.ClaimMaterializationError || ans.Reason != ap.MintReasonGrantNotLive {
		t.Fatalf("claim after revoke %+v", ans)
	}
	if r.covered(12, st.PrincipalA) {
		t.Fatal("a revoked grant covered a write")
	}

	r.grant(st.ID(2), st.PrincipalA, time.Hour)
	r.s.Restart()
	if r.covered(13, st.PrincipalA) {
		t.Fatal("a grant survived a new epoch")
	}
}

// Supersession through the newest-grant mark (r5.1): revoking the newest
// grant never revives an older one, and neither does pruning it.
func TestGrantSupersession(t *testing.T) {
	r := newRig(t)
	r.s.Submit(st.PrincipalA, st.GrantDraft(st.ID(1), "web-1", 24*time.Hour, r.clock.Wall))
	g2 := ap.RecordKey(st.PrincipalA, st.ID(1))
	r.s.Submit(st.PrincipalA, st.GrantDraft(st.ID(2), "web-1", time.Hour, r.clock.Wall))
	g1 := ap.RecordKey(st.PrincipalA, st.ID(2))
	r.approve(g2)
	r.approve(g1)
	r.s.RevokeAlias("web-1")
	if r.rec(g2).Header.RevokedAt != nil {
		t.Fatal("revoke touched the superseded grant, which is not live")
	}
	if r.covered(10, st.PrincipalA) {
		t.Fatal("revoking the newest grant revived the older one")
	}
	r.s.FlushPass()
	if ans := r.apply(g1, ap.ShedRecord{Pressure: true}); !ans.Changed {
		t.Fatalf("shed of the revoked grant: %+v", ans)
	}
	if r.covered(11, st.PrincipalA) {
		t.Fatal("shedding the superseding grant revived the older one")
	}
}

// Review 4's grant case against the held pair: a step back after the wall
// end never revives a grant, with the tick running or paused.
func TestGrantStepBackNeverRevives(t *testing.T) {
	for _, tickPaused := range []bool{false, true} {
		r := newRig(t)
		r.grant(st.ID(1), st.PrincipalA, time.Hour)
		r.clock.Advance(time.Hour + time.Minute)
		if !tickPaused {
			r.s.Tick()
		}
		r.clock.StepWall(-7 * time.Minute)
		if r.covered(10, st.PrincipalA) || r.covered(11, st.PrincipalA) {
			t.Fatalf("tickPaused=%v: a grant past its end covered a write after a step back", tickPaused)
		}
	}
	// S3: an 8 h suspend with an 8 h wall step back still ends a 1 h grant.
	r := newRig(t)
	r.grant(st.ID(1), st.PrincipalA, time.Hour)
	r.clock.Advance(8 * time.Hour)
	r.clock.StepWall(-8 * time.Hour)
	if r.covered(10, st.PrincipalA) {
		t.Fatal("a suspend hidden by a wall step back left the grant live")
	}
}

func TestHeldPair(t *testing.T) {
	now := ap.Now{Wall: st.T0, Elapsed: time.Hour}
	h := ap.Acquire(now, st.T0.Add(60*time.Second), 60*time.Second)
	at := func(wall, elapsed time.Duration) ap.Now {
		return ap.Now{Wall: st.T0.Add(wall), Elapsed: time.Hour + elapsed}
	}
	cases := []struct {
		now           ap.Now
		passed, k16ok bool
	}{
		{at(0, 0), false, true},
		{at(57*time.Second, 57*time.Second), false, true},
		{at(58*time.Second, 58*time.Second), false, false},
		{at(-time.Hour, 60*time.Second), true, false},
		{at(60*time.Second, 0), true, false},
	}
	for i, c := range cases {
		if h.Passed(c.now) != c.passed || h.PassesK16(c.now) != c.k16ok {
			t.Errorf("case %d: passed=%v k16=%v", i, h.Passed(c.now), h.PassesK16(c.now))
		}
	}
	// A wall reading behind at acquisition cannot stretch the elapsed half.
	behind := ap.Acquire(ap.Now{Wall: st.T0.Add(-time.Hour), Elapsed: time.Hour}, st.T0.Add(60*time.Second), 60*time.Second)
	if behind.ElapsedEnd != time.Hour+60*time.Second {
		t.Fatalf("elapsed end %s", behind.ElapsedEnd)
	}
	if past := ap.Acquire(now, st.T0.Add(-time.Second), time.Minute); past.ElapsedEnd != now.Elapsed {
		t.Fatalf("a wall end already passed acquires %s", past.ElapsedEnd)
	}
}

func TestGrantCoverageBindings(t *testing.T) {
	for _, name := range []string{"matching", "fingerprint", "reveal", "admin route", "admin bytes", "outside scope", "sub principal", "principal", "shed"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			gkey := r.grant(st.ID(1), st.PrincipalA, time.Hour)
			g := r.rec(gkey)
			key := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
			rec := r.rec(key)
			step := &rec.Payload.Plan.CommandJob.Steps[0]
			switch name {
			case "fingerprint":
				step.Target.TrustedHostFingerprint = st.Fingerprint("other")
			case "reveal":
				step.Route = ap.RouteSignedReveal
			case "admin route":
				step.Route = ap.RouteSignedAdmin
			case "admin bytes":
				step.ExactCommand = "SSHGATE_REVOKE"
			case "outside scope":
				g.Payload.Plan.StandingGrant.Scope = ap.GrantScopeCommands
				g.Payload.Plan.StandingGrant.Commands = []string{"different"}
			case "sub principal":
				rec.Header.SubPrincipal = "local-uid:1002"
			case "principal":
				rec.Header.Principal = st.PrincipalB
			case "shed":
				g = ap.Shed(g)
			}
			if got := ap.GrantCovers(g, rec); got != (name == "matching") {
				t.Fatalf("coverage=%v", got)
			}
		})
	}
	for _, name := range []string{"expired", "revoked", "other epoch", "superseded"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			gkey := r.grant(st.ID(1), st.PrincipalA, time.Minute)
			if name == "expired" {
				r.clock.Advance(50 * time.Second)
			}
			key := r.submit(st.ID(2), ap.CoordinatorExecutor, st.Write("w", 60))
			r.s.FlushPass()
			if r.rec(key).Header.Decision == nil {
				t.Fatal("not grant decided")
			}
			switch name {
			case "expired":
				r.clock.Advance(11 * time.Second)
			case "revoked":
				r.s.RevokeAlias("web-1")
			case "other epoch":
				r.s.NewEpoch()
			case "superseded":
				r.grant(st.ID(3), st.PrincipalA, time.Hour)
			}
			a := r.claim(key, st.ID(2))
			if a.Claim != ap.ClaimMaterializationError || a.Reason != ap.MintReasonGrantNotLive {
				t.Fatalf("grant=%s answer=%+v", gkey, a)
			}
		})
	}
}

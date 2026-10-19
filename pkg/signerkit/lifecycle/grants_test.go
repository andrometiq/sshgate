package lifecycle

import (
	"context"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func TestListGrantsPublishedOwnershipAndExpiry(t *testing.T) {
	e, clock, _, _ := engineFixture(t)
	if _, err := e.Submit(context.Background(), st.PrincipalA, st.GrantDraft(st.ID(1), "web-1", time.Hour, st.T0, "touch /tmp/example")); err != nil {
		t.Fatal(err)
	}
	approve(t, e, 1)
	// Holding the writer lock must not block this read.
	e.mu.Lock()
	grants, err := e.ListGrants(st.PrincipalA)
	e.mu.Unlock()
	if err != nil || len(grants) != 1 || grants[0].RequestID != st.ID(1) || grants[0].TrustedHostFingerprint != st.Fingerprint("web-1") || grants[0].RegistryEntryDigest != st.Route("web-1").Digest() || !grants[0].ExpiresAt.Equal(st.T0.Add(time.Hour)) {
		t.Fatalf("grants: %+v %v", grants, err)
	}
	if other, err := e.ListGrants(st.PrincipalB); err != nil || len(other) != 0 {
		t.Fatalf("owner leak: %+v %v", other, err)
	}
	grants[0].Commands[0] = "changed"
	again, err := e.ListGrants(st.PrincipalA)
	if err != nil || again[0].Commands[0] != "touch /tmp/example" {
		t.Fatalf("mutable view: %+v %v", again, err)
	}
	// Reads follow published membership: expiry shows only once the writer observes it.
	clock.StepWall(time.Hour)
	if pending, err := e.ListGrants(st.PrincipalA); err != nil || len(pending) != 1 {
		t.Fatalf("read led the writer: %+v %v", pending, err)
	}
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if expired, err := e.ListGrants(st.PrincipalA); err != nil || len(expired) != 0 {
		t.Fatalf("expiry: %+v %v", expired, err)
	}
	// A wall rollback after the writer saw expiry must not revive the grant.
	clock.StepWall(-time.Hour)
	if revived, err := e.ListGrants(st.PrincipalA); err != nil || len(revived) != 0 {
		t.Fatalf("revived after rollback: %+v %v", revived, err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = e.ListGrants(st.PrincipalA)
	checkCode(t, err, ap.CodeLifecycleUnavailable)
}

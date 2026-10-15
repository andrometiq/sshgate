package lifecycle

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

type transferFreezer struct{}

func digest(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
func (transferFreezer) Freeze(_ context.Context, d ap.ApprovalDraft, principal, sub string, now time.Time) (ap.ApprovalPlanV1, error) {
	p := st.Freeze(d, principal, now, time.Hour)
	tr := *d.Transfer
	identity := "sshgate-id-pub-v1 ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	box := "sshgate-box-pub-v1 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	tr.Source.KeyLabel, tr.Source.PublicKey, tr.Source.PublicKeySHA256, tr.Source.KeyEntryDigest = "web-1", identity, digest(identity), digest("source")
	tr.Destination.KeyLabel, tr.Destination.PublicKey, tr.Destination.PublicKeySHA256, tr.Destination.KeyEntryDigest = "db-1", box, digest(box), digest("destination")
	tr.TransferID = "x8Kq3YVvH4f2m9WqZr0B1g"
	tr.SendCommand = "SSHGATE_XFER_SEND Ym94 eDhL ZGVzdA L2V0Yy9zZWNyZXQ"
	tr.RecvCommand = "SSHGATE_XFER_RECV aWQ eDhL c3Jj ZGVzdA MDYwMA L3Nydi9zZWNyZXQ"
	tr.SendCommandSHA256, tr.RecvCommandSHA256 = digest(tr.SendCommand), digest(tr.RecvCommand)
	p.Transfer = &tr
	return p, nil
}

type digestFunc func(context.Context, ap.Transfer) (ap.XferDigests, error)

func (f digestFunc) Current(c context.Context, tr ap.Transfer) (ap.XferDigests, error) {
	return f(c, tr)
}

func TestTransferClaimChecksDigestsBeforeMint(t *testing.T) {
	for _, which := range []string{"current", "stale_source", "stale_destination", "lookup_failure"} {
		t.Run(which, func(t *testing.T) {
			e, _, store, _ := engineFixture(t)
			e.config.Freezer = transferFreezer{}
			source, destination := st.Route("web-1"), st.Route("db-1")
			d := ap.ApprovalDraft{Version: ap.DraftVersion, Kind: ap.KindTransfer, RequestID: st.ID(1), Rationale: "Copy the secret", ExecutorClaimTokenHash: ap.ClaimTokenHash(st.Token(st.ID(1))), SubmitNotAfter: st.T0.Add(ap.SubmitWindowMax), Coordinator: ap.CoordinatorExecutor, Transfer: &ap.Transfer{Source: ap.TransferEndpoint{Target: source, RegistryEntryDigest: source.Digest(), Path: "/etc/secret"}, Destination: ap.TransferEndpoint{Target: destination, RegistryEntryDigest: destination.Digest(), Path: "/srv/secret"}, Mode: ap.TransferMode, SignatureTTLSeconds: 300}}
			sum, err := e.Submit(context.Background(), st.PrincipalA, d)
			if err != nil {
				t.Fatal(err)
			}
			voteApprove(t, e, 1)
			flushRecord(t, e, 1)
			reads, mints := 0, 0
			e.config.XferDigests = digestFunc(func(_ context.Context, tr ap.Transfer) (ap.XferDigests, error) {
				reads++
				if e.mu.TryLock() {
					e.mu.Unlock()
					t.Error("digests outside critical section")
				}
				got := ap.XferDigests{Source: tr.Source.KeyEntryDigest, Destination: tr.Destination.KeyEntryDigest}
				switch which {
				case "stale_source":
					got.Source = digest("rotated")
				case "stale_destination":
					got.Destination = digest("rotated")
				case "lookup_failure":
					return got, fmt.Errorf("lookup failed")
				}
				return got, nil
			})
			e.config.Minter = mintFunc(func(_ context.Context, p ap.ApprovalPlanV1, at time.Time) ([]string, error) {
				mints++
				if reads != 1 || !at.Equal(st.T0) || p.Transfer == nil {
					t.Fatal("mint before digest check")
				}
				return []string{"send-signature", "receive-signature"}, nil
			})
			before := store.commits
			ans, err := e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum))
			if which == "lookup_failure" {
				if err == nil || mints != 0 || store.commits != before {
					t.Fatal("failed lookup minted or committed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if which != "current" {
				if ans.Reason != ap.MintReasonStaleTransferKey || mints != 0 || store.commits != before+1 {
					t.Fatalf("stale keys minted: %+v", ans)
				}
				return
			}
			if ans.Claim != ap.ClaimSignatures || len(ans.Signatures) != 2 || mints != 1 {
				t.Fatal(ans)
			}
			if _, err = e.Claim(context.Background(), st.PrincipalA, st.ID(1), claimOf(1, sum)); err != nil || reads != 1 || mints != 1 {
				t.Fatal("repeat resolves or mints again")
			}
		})
	}
}

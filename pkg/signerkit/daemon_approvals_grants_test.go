package signerkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	lct "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle/lifecycletest"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

type grantSurfaceNotifier struct {
	*lct.Notifier
	cards chan lc.Notification
}

func (n *grantSurfaceNotifier) Burst(ctx context.Context, fn func(lc.BurstSession) error) error {
	return fn(n)
}
func (n *grantSurfaceNotifier) SendCard(_ context.Context, card lc.Notification) (int64, error) {
	n.cards <- card
	return 4, nil
}

func (n *grantSurfaceNotifier) EditCard(_ context.Context, _ int64, card lc.Notification) (lc.EditOutcome, error) {
	n.cards <- card
	return lc.EditConfirmed, nil
}

func TestApprovalGrantSurfaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := &grantSurfaceNotifier{Notifier: lct.NewNotifier(nil), cards: make(chan lc.Notification, 10)}
		h := newApprovalDispatchHarness(t, true, func(c *lc.Config) {
			c.Notifier = n
			c.AssistPool = assist.NewPool(1, assist.Timers{Now: c.Clock.Wall})
			c.AssistInputBuilder = lct.AssistBuilder{}
		})
		engine, err := h.service.approvals.Current()
		if err != nil {
			t.Fatal(err)
		}
		add := func(id int, principal, alias string) {
			draft := st.GrantDraft(st.ID(id), alias, time.Hour, st.T0, "touch /tmp/example")
			draft.StandingGrant.TrustedHostFingerprint = approvalDispatchDraft(st.ID(90), ap.CoordinatorExecutor, st.T0, st.Write("true", 60)).CommandJob.Steps[0].Target.TrustedHostFingerprint
			if _, err := engine.Submit(context.Background(), principal, draft); err != nil {
				t.Fatal(err)
			}
			card := <-n.cards
			synctest.Wait()
			for len(n.cards) > 0 {
				card = <-n.cards
			}
			answer, err := engine.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Flags: ap.LocalVoteFlags, Card: &ap.CardTap{Handle: card.Handle, Challenge: card.Challenge, MsgID: 4}})
			if err != nil || answer.Noise {
				t.Fatalf("vote: %+v %v", answer, err)
			}
		}
		otherUID := h.uid + 1
		other := fmt.Sprintf("local-uid:%d", otherUID)
		add(10, h.principal, "web-1")
		add(11, h.principal, "web-1")
		add(12, other, "web-1")
		add(13, h.principal, "aaa")
		h.service.daemon.grants = map[string]grant{}
		h.service.daemon.grants["legacy"] = grant{id: "legacy-id", alias: "legacy", scope: "all", expiry: st.T0.Add(time.Hour)}
		request := func(kind, alias string, uid *uint32, direct bool) []byte {
			frame, _ := json.Marshal(map[string]string{"kind": kind, "request_id": "surface-request", "alias": alias})
			var out bytes.Buffer
			conn := struct {
				io.Reader
				io.Writer
			}{bytes.NewReader(append(frame, '\n')), &out}
			var err error
			if direct {
				err = h.service.daemon.HandleSignRequest(context.Background(), conn)
			} else {
				var peer *PeerCredentials
				if uid != nil {
					peer = &PeerCredentials{UID: *uid}
				}
				err = h.service.HandleSignRequestWithPeer(context.Background(), conn, peer)
			}
			if err != nil {
				t.Fatal(err)
			}
			return out.Bytes()
		}
		list := func(uid *uint32) []grantInfo {
			var response listGrantsResponse
			if err := json.Unmarshal(request("list_grants", "", uid, false), &response); err != nil || response.Status != "ok" {
				t.Fatalf("list: %+v %v", response, err)
			}
			return response.Grants
		}
		own := list(&h.uid)
		if len(own) != 3 || own[0].Alias != "aaa" || own[1].GrantID != "legacy-id" || own[2].GrantID != st.ID(11) {
			t.Fatalf("own grants: %+v", own)
		}
		second := list(&otherUID)
		if len(second) != 2 || second[1].GrantID != st.ID(12) {
			t.Fatalf("other grants: %+v", second)
		}
		if got := list(nil); len(got) != 1 || got[0].GrantID != "legacy-id" {
			t.Fatalf("peerless: %+v", got)
		}
		first := request("list_grants", "", &h.uid, false)
		for range 10 {
			if !bytes.Equal(first, request("list_grants", "", &h.uid, false)) {
				t.Fatal("unstable list order")
			}
		}
		if !bytes.Equal(request("list_grants", "legacy", &h.uid, false), request("list_grants", "legacy", nil, true)) {
			t.Fatal("v1 list bytes changed")
		}
		h.service.daemon.grants["web-1"] = grant{id: "old", alias: "web-1", scope: "all", expiry: st.T0.Add(time.Hour)}
		expected := request("revoke_grant", "absent", nil, true)
		for range 2 {
			if got := request("revoke_grant", "web-1", &otherUID, false); !bytes.Equal(got, expected) {
				t.Fatalf("revoke bytes %s != %s", got, expected)
			}
		}
		if _, ok := h.service.daemon.grants["web-1"]; ok {
			t.Fatal("v1 grant retained")
		}
		for _, principal := range []string{h.principal, other} {
			grants, err := engine.ListGrants(principal)
			if err != nil {
				t.Fatal(err)
			}
			for _, g := range grants {
				if g.Alias == "web-1" {
					t.Fatal("revoked or superseded grant revived")
				}
			}
		}
		for _, pair := range []struct {
			principal string
			id        int
		}{{h.principal, 11}, {other, 12}} {
			record, err := h.store.Load(ap.RecordKey(pair.principal, st.ID(pair.id)))
			if err != nil || record.Header.RevokedAt == nil {
				t.Fatalf("grant not revoked: %v", err)
			}
		}
		if err := engine.Reconcile(); err != nil {
			t.Fatal(err)
		}
		if got := list(&h.uid); len(got) != 2 {
			t.Fatalf("older grant revived: %+v", got)
		}
		if err := h.service.Close(); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"list_grants", "revoke_grant"} {
			var response struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal(request(kind, "web-1", &h.uid, false), &response); err != nil || response.Status != "error" {
				t.Fatalf("stopped runtime %s: %+v %v", kind, response, err)
			}
		}
	})
}

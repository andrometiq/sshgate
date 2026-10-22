package hosted

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

func TestHumanVoteOrdinaryWorkerLifecycle(t *testing.T) {
	for _, stop := range []string{"close", "worker-exit"} {
		t.Run(stop, func(t *testing.T) {
			e, db, _ := approvalEngineFixture(t, false)
			auth, err := NewAuthManager(db, AuthConfig{RPID: "localhost", RPOrigins: []string{"https://localhost"}, SessionTTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			session, err := auth.IssueSession(context.Background(), "operator")
			if err != nil {
				t.Fatal(err)
			}
			s := NewServer("test-key", db, nil)
			s.MachineClientID = "client"
			s.AttachHuman(&HumanAPI{Auth: auth, Store: db})
			t.Cleanup(func() { s.Close() })
			submitApproval(t, e, 1)
			submitApproval(t, e, 2)
			first := readApproval(t, db, 1)
			second := readApproval(t, db, 2)
			request := func(method, path string, body []byte) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, bytes.NewReader(body))
				r.Header.Set("Origin", "https://localhost")
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.ID})
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				return w
			}
			pendingDetail := request("GET", "/ui/v2/request/"+second.RecordHandle, nil)
			if pendingDetail.Code != http.StatusOK {
				t.Fatalf("pending detail: %d %s", pendingDetail.Code, pendingDetail.Body)
			}
			var pendingView uiV2Request
			if err := json.Unmarshal(pendingDetail.Body.Bytes(), &pendingView); err != nil {
				t.Fatal(err)
			}
			pendingBody, err := json.Marshal(voteRequest{Challenge: pendingView.VoteChallenge.Challenge})
			if err != nil {
				t.Fatal(err)
			}
			pendingPath := "/ui/v2/request/" + second.RecordHandle + "/deny"
			assertBusy := func() {
				t.Helper()
				w := request("POST", pendingPath, pendingBody)
				if w.Code != http.StatusServiceUnavailable || w.Body.String() != "{\"error\":\"busy — retry\"}\n" {
					t.Fatalf("unavailable worker: %d %s", w.Code, w.Body)
				}
			}
			assertBusy()
			// Race real requests with ownership changes; already admitted requests may finish.
			concurrent := func(change func()) {
				t.Helper()
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := 0; i < 12; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						w := request("POST", pendingPath, []byte(`{}`))
						if w.Code != http.StatusBadRequest && w.Code != http.StatusServiceUnavailable {
							t.Errorf("concurrent request: %d %s", w.Code, w.Body)
						}
					}()
				}
				close(start)
				change()
				wg.Wait()
			}
			concurrent(func() {
				if err := s.StartOrdinaryWorkers(e); err != nil {
					t.Fatal(err)
				}
			})
			path := "/ui/v2/request/" + first.RecordHandle
			detail := request("GET", path, nil)
			if detail.Code != http.StatusOK {
				t.Fatalf("detail: %d %s", detail.Code, detail.Body)
			}
			var view uiV2Request
			if err := json.Unmarshal(detail.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(voteRequest{Challenge: view.VoteChallenge.Challenge})
			if err != nil {
				t.Fatal(err)
			}
			voted := request("POST", path+"/deny", body)
			if voted.Code != http.StatusOK {
				t.Fatalf("vote: %d %s", voted.Code, voted.Body)
			}
			votes := readApproval(t, db, 1).Record.Header.Votes
			if len(votes) != 1 || votes[0].Operator != "operator" || votes[0].Decision != ap.ActionDeny {
				t.Fatalf("persisted votes: %+v", votes)
			}
			concurrent(func() {
				if stop == "close" {
					s.Close()
				} else {
					s.ordinaryMu.Lock()
					cancel, joined := s.ordinaryCancel, s.ordinaryJoined
					s.ordinaryMu.Unlock()
					cancel()
					<-joined
				}
			})
			assertBusy()
			remaining := readApproval(t, db, 2).Record.Header
			if len(remaining.Votes) != 0 || remaining.Decision != nil {
				t.Fatalf("unavailable worker changed pending approval: %+v", remaining)
			}
		})
	}
}

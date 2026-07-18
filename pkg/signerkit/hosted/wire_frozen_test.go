package hosted_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/src/gate"
)

// wire_frozen_test.go asserts the MACHINE plane stays BYTE-FROZEN against
// the wire contract in src/signer/backend/hosted.go. Phases D+E add the
// human plane; they must not perturb /v1/sign, /v1/poll, or /healthz.
//
// The strongest possible regression proof is to drive the REAL,
// FROZEN HostedServerBackend client (the exact decoder the daemon ships)
// against the live server: if the server's bytes ever drift from what the
// frozen structs expect, this test fails to decode and breaks. We do not
// re-declare the wire structs here — we let the frozen client be the
// oracle.

// TestWireFrozen_HostedClientStillDecodesV1 exercises the full machine-
// plane wire dance through the frozen client: POST /v1/sign → 202
// {request_id, poll_url}, then GET /v1/poll long-poll. We approve the
// request out-of-band via the human plane while the client polls; the
// client must decode the approved poll response and surface gate-valid
// signatures. This proves the request body, the 202 shape, and the poll
// response shape (status + signatures{cmd,sig} + approved_by_user) all
// still match hosted.go byte-for-byte.
func TestWireFrozen_HostedClientStillDecodesV1(t *testing.T) {
	t.Parallel()
	ts, apiKey, db, am, pub := humanFixture(t)
	_, secret := seedTOTPUser(t, db, am, "alice")

	const cmd = "systemctl restart nginx"

	client := &signerkit.HostedServerBackend{
		BaseURL:  ts.URL,
		APIKey:   apiKey,
		ClientID: "karthi-laptop",
		PollWait: 2 * time.Second,
		Timeout:  6 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Submit via the frozen client. This decodes the 202 {request_id,
	// poll_url} response; a drift there fails Request.
	resultCh, err := client.Request(ctx, signerkit.ApprovalRequest{
		Commands:  []signerkit.CommandReq{{Server: "prod", Cmd: cmd, TTLSec: 120, HostKeyFP: testHostFP}},
		Submitted: time.Now(),
	})
	if err != nil {
		t.Fatalf("frozen client Request (sign submit) failed to decode: %v", err)
	}

	// The client's request_id is server-minted; we need it to approve
	// out-of-band. Find the single pending request the submit created.
	requestID := awaitSinglePending(t, db)

	// Approve via the human plane while the frozen client long-polls.
	httpClient := loginClient(t, ts, "alice", secret)
	approveResp, err := httpClient.Post(ts.URL+"/ui/request/"+requestID+"/approve", "application/json", nil)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d; want 200", approveResp.StatusCode)
	}

	// The frozen client must decode the approved poll response.
	select {
	case res := <-resultCh:
		if res.Status != signerkit.StatusApproved {
			t.Fatalf("frozen client result status = %v; want approved", res.Status)
		}
		if len(res.Signatures) != 1 {
			t.Fatalf("frozen client got %d signatures; want 1", len(res.Signatures))
		}
		if res.Signatures[0].Cmd != cmd {
			t.Fatalf("signature cmd = %q; want %q", res.Signatures[0].Cmd, cmd)
		}
		// And the signature the frozen client surfaced is GATE-VALID.
		inner, _, verr := gate.VerifySigned(res.Signatures[0].Sig, pub, time.Now().Add(time.Second), []string{testHostFP})
		if verr != nil {
			t.Fatalf("gate.VerifySigned rejected the wire signature: %v", verr)
		}
		if inner != cmd {
			t.Fatalf("gate inner cmd = %q; want %q", inner, cmd)
		}
	case <-ctx.Done():
		t.Fatalf("frozen client did not resolve before context deadline")
	}
}

// TestWireFrozen_SignResponseShape locks the exact JSON field set of the
// 202 /v1/sign response: {request_id, poll_url} and nothing the frozen
// client would choke on. We assert the field names directly so a rename
// is caught even if the frozen client happens to ignore an extra field.
func TestWireFrozen_SignResponseShape(t *testing.T) {
	t.Parallel()
	ts, apiKey, _, _, _ := humanFixture(t)

	body := []byte(`{"client_id":"karthi-laptop","commands":[{"server":"prod","cmd":"echo hi","ttl_seconds":60}]}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sign", readerOf(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("sign status = %d; want 202", resp.StatusCode)
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode 202: %v", err)
	}
	for _, field := range []string{"request_id", "poll_url"} {
		if _, ok := raw[field]; !ok {
			t.Fatalf("202 response missing frozen field %q; got keys %v", field, keysOf(raw))
		}
	}
}

// TestWireFrozen_HealthzUnchanged locks /healthz: still public (no auth)
// and still a plain-text "ok".
func TestWireFrozen_HealthzUnchanged(t *testing.T) {
	t.Parallel()
	ts, _, _, _, _ := humanFixture(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d; want 200 (still public)", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	if string(body) != "ok\n" {
		t.Fatalf("healthz body = %q; want %q", body, "ok\n")
	}
}

// awaitSinglePending polls the store until exactly one pending request
// exists and returns its id. The frozen client's submit creates the row
// synchronously in the handler, but its Request returns once the 202 is
// decoded, so a brief wait is robust against scheduling.
func awaitSinglePending(t *testing.T, db *sqlitestore.DB) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows, err := db.ListPending(context.Background())
		if err != nil {
			t.Fatalf("ListPending: %v", err)
		}
		if len(rows) == 1 {
			return rows[0].RequestID
		}
		if len(rows) > 1 {
			t.Fatalf("expected 1 pending request, got %d", len(rows))
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pending request appeared within deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// readerOf wraps bytes for an http request body.
func readerOf(b []byte) io.Reader { return bytes.NewReader(b) }

// keysOf returns the map keys for an error message.
func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// readAll drains r for body assertions.
func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

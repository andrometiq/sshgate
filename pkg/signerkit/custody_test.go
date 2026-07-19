package signerkit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// altSignerKey returns a distinct fixed-seed Ed25519 key (seed ramp offset
// 0xA0) for rotation/precedence tests, so a signature can be attributed to one
// identity and provably not the other.
func altSignerKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0xA0 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

// TestCustody_ErrNoSigner: a Daemon with neither Key nor Signer refuses to mint
// with the typed ErrNoSigner (replacing today's ed25519.Sign panic).
func TestCustody_ErrNoSigner(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	if _, err := d.signBytes([]byte("x")); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("signBytes with no identity: err=%v; want ErrNoSigner", err)
	}
}

// TestCustody_NoSigner_SignResponse drives the full sign path with no key and
// asserts the "sign: no signer configured" error response (C7 wording).
func TestCustody_NoSigner_SignResponse(t *testing.T) {
	t.Parallel()
	audit, err := NewMemAuditLog()
	if err != nil {
		t.Fatalf("mem audit: %v", err)
	}
	t.Cleanup(func() { audit.Close() })
	mock := NewMockBackend()
	mock.Approve("r_nokey", "operator")
	d := &Daemon{Backend: mock, Audit: audit, NowFunc: goldenNow} // no Key, no Signer

	body := `{"kind":"sign","request_id":"r_nokey","commands":[{"server":"prod","cmd":"echo hi","ttl_seconds":60}]}`
	conn := &rwBuf{in: bytes.NewReader([]byte(body + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest hard error: %v", err)
	}
	var resp struct{ Status, Error string }
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "error" {
		t.Fatalf("status=%q; want error", resp.Status)
	}
	if !strings.Contains(resp.Error, "sign: no signer configured") {
		t.Errorf("error=%q; want it to contain %q", resp.Error, "sign: no signer configured")
	}
}

// TestCustody_LockUnlock: Lock refuses signing with ErrLocked (carrying the
// reason), Unlock restores it. Exercised at the signBytes level.
func TestCustody_LockUnlock(t *testing.T) {
	t.Parallel()
	priv, _ := goldenSignerKey()
	d := &Daemon{Key: priv}
	op := Operator{ID: "op1", DisplayName: "Op One", AuthnMethod: "totp"}

	if _, err := d.signBytes([]byte("x")); err != nil {
		t.Fatalf("pre-lock sign: %v", err)
	}
	if err := d.Lock("maintenance window", op); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	_, err := d.signBytes([]byte("x"))
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("post-lock sign err=%v; want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), "maintenance window") {
		t.Errorf("lock error dropped the reason: %v", err)
	}
	if err := d.Unlock(op); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := d.signBytes([]byte("x")); err != nil {
		t.Fatalf("post-unlock sign: %v", err)
	}
}

// TestCustody_MidFlightLock drives an APPROVED sign request (via MockBackend)
// into a signer that is Locked before the mint. The verdict has resolved, but
// signBytes reads the lock at mint time → ErrLocked → an "error" sign response
// AND an "error" audit row, per C1. The lifecycle "lock" row is also present.
func TestCustody_MidFlightLock(t *testing.T) {
	t.Parallel()
	priv, _ := goldenSignerKey()
	dir := t.TempDir()
	audit, err := OpenAuditLog(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { audit.Close() })
	mock := NewMockBackend()
	d := &Daemon{Key: priv, Backend: mock, Audit: audit, NowFunc: goldenNow}

	// Verdict resolves (buffered on the mock) but the signer is Locked before the
	// mint runs: the classic "approval meets a locked signer" case.
	mock.Approve("r_mid", "operator")
	if err := d.Lock("scheduled rotation", Operator{ID: "op1", DisplayName: "Op One"}); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	body := `{"kind":"sign","request_id":"r_mid","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60,"host":"` + goldenHostFP + `"}]}`
	conn := &rwBuf{in: bytes.NewReader([]byte(body + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest hard error: %v", err)
	}
	var resp struct{ Status, Error string }
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "error" {
		t.Fatalf("status=%q; want error", resp.Status)
	}
	if !strings.Contains(resp.Error, "sign: signer locked: scheduled rotation") {
		t.Errorf("error=%q; want it to contain %q", resp.Error, "sign: signer locked: scheduled rotation")
	}

	// The audit trail must carry BOTH the lifecycle lock row and the mint-refusal
	// error row for r_mid — no envelope was minted.
	raw, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var sawLock, sawError bool
	for _, ln := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		if len(ln) == 0 {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal(ln, &ev); err != nil {
			t.Fatalf("decode audit line %q: %v", ln, err)
		}
		switch ev.Status {
		case "lock":
			sawLock = true
			if len(ev.Commands) == 0 || !strings.Contains(ev.Commands[0], "scheduled rotation") {
				t.Errorf("lock row missing reason: %+v", ev)
			}
		case "error":
			if ev.RequestID == "r_mid" {
				sawError = true
			}
		case "approved", "approved-undelivered":
			t.Errorf("a signature was minted under Lock: %+v", ev)
		}
	}
	if !sawLock {
		t.Error("no custody lifecycle 'lock' audit row")
	}
	if !sawError {
		t.Error("no 'error' audit row for the lock-refused request r_mid")
	}
}

// TestCustody_RotateTo proves atomic cut-over (C2): after RotateTo(next) every
// signature verifies under next's pubkey and NOT the old one. RotateTo(nil) is
// rejected, and a held Lock is independent of rotation.
func TestCustody_RotateTo(t *testing.T) {
	t.Parallel()
	priv1, pub1 := goldenSignerKey()
	priv2, pub2 := altSignerKey()
	d := &Daemon{Key: priv1}
	msg := []byte("rotate me")

	sig, err := d.signBytes(msg)
	if err != nil {
		t.Fatalf("pre-rotate sign: %v", err)
	}
	if !ed25519.Verify(pub1, msg, sig) {
		t.Fatal("pre-rotate signature does not verify under the original key")
	}
	if ed25519.Verify(pub2, msg, sig) {
		t.Fatal("pre-rotate signature verifies under the rotation target — impossible")
	}

	rotateOp := Operator{ID: "op2", DisplayName: "Op Two", AuthnMethod: "webauthn"}
	if err := d.RotateToWithAudit(priv2, "scheduled key rollover", rotateOp); err != nil {
		t.Fatalf("RotateTo: %v", err)
	}
	sig2, err := d.signBytes(msg)
	if err != nil {
		t.Fatalf("post-rotate sign: %v", err)
	}
	if !ed25519.Verify(pub2, msg, sig2) {
		t.Fatal("post-rotate signature does not verify under the new key")
	}
	if ed25519.Verify(pub1, msg, sig2) {
		t.Fatal("post-rotate signature still verifies under the OLD key — cut-over failed")
	}

	if err := d.RotateTo(nil); err == nil {
		t.Fatal("RotateTo(nil) must error")
	}

	// Lock is independent of rotation: a rotated-then-locked signer refuses.
	if err := d.Lock("x", Operator{}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := d.signBytes(msg); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked-after-rotate: err=%v; want ErrLocked", err)
	}
}

// TestCustody_SignerWinsOverKey pins the C7 precedence: a non-nil Signer wins
// over Key.
func TestCustody_SignerWinsOverKey(t *testing.T) {
	t.Parallel()
	privKey, pubKey := goldenSignerKey()
	privSigner, pubSigner := altSignerKey()
	d := &Daemon{Key: privKey, Signer: privSigner}
	msg := []byte("precedence")

	sig, err := d.signBytes(msg)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	if !ed25519.Verify(pubSigner, msg, sig) {
		t.Fatal("Signer did not win over Key")
	}
	if ed25519.Verify(pubKey, msg, sig) {
		t.Fatal("Key was consulted even though Signer was set")
	}
}

// TestCustody_ConcurrentRotateLockSign is the -race test (C3): many goroutines
// mint through signBytes while one goroutine hammers Lock/Unlock/RotateTo. The
// custody state is guarded by custodyMu, so the race detector must find no data
// race and nothing panics. Signers tolerate ErrLocked (an expected outcome).
func TestCustody_ConcurrentRotateLockSign(t *testing.T) {
	priv1, _ := goldenSignerKey()
	priv2, _ := altSignerKey()
	d := &Daemon{Key: priv1} // nil Audit ⇒ auditLifecycle is a no-op (no file contention)
	msg := []byte("race")

	const signers = 8
	const rounds = 300
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < signers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if _, err := d.signBytes(msg); err != nil && !errors.Is(err, ErrLocked) {
						t.Errorf("unexpected sign error under concurrency: %v", err)
						return
					}
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		op := Operator{ID: "racer"}
		for i := 0; i < rounds; i++ {
			_ = d.Lock("rotating", op)
			_ = d.RotateToWithAudit(priv2, "race to second", op)
			_ = d.Unlock(op)
			_ = d.RotateToWithAudit(priv1, "race to first", op)
		}
		close(stop)
	}()

	wg.Wait()
}

// blockingSigner holds Sign until release is closed, modeling a slow HSM/KMS.
// It lets the tests observe whether custody controls wait for a mint that began
// under the previous state.
type blockingSigner struct {
	key     ed25519.PrivateKey
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingSigner(key ed25519.PrivateKey) *blockingSigner {
	return &blockingSigner{key: key, entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *blockingSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *blockingSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.key.Sign(nil, digest, opts)
}

// TestCustody_LockLinearizesWithInFlightSign proves Lock cannot report success
// while an earlier crypto.Signer.Sign call is still capable of completing. Once
// Lock returns, all prior mints are done and every later mint sees ErrLocked.
func TestCustody_LockLinearizesWithInFlightSign(t *testing.T) {
	priv, _ := goldenSignerKey()
	blocked := newBlockingSigner(priv)
	d := &Daemon{Signer: blocked}

	signDone := make(chan error, 1)
	go func() {
		_, err := d.signBytes([]byte("in flight"))
		signDone <- err
	}()
	<-blocked.entered

	lockDone := make(chan error, 1)
	go func() { lockDone <- d.Lock("incident", Operator{ID: "op-lock"}) }()
	select {
	case err := <-lockDone:
		t.Fatalf("Lock returned before in-flight Sign completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(blocked.release)
	if err := <-signDone; err != nil {
		t.Fatalf("in-flight sign: %v", err)
	}
	if err := <-lockDone; err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := d.signBytes([]byte("after lock")); !errors.Is(err, ErrLocked) {
		t.Fatalf("post-Lock sign err=%v; want ErrLocked", err)
	}
}

// TestCustody_RotateLinearizesWithInFlightSign proves RotateTo waits for an old
// signer invocation to finish. After it returns, every new mint uses next.
func TestCustody_RotateLinearizesWithInFlightSign(t *testing.T) {
	priv1, pub1 := goldenSignerKey()
	priv2, pub2 := altSignerKey()
	blocked := newBlockingSigner(priv1)
	d := &Daemon{Signer: blocked}
	msg := []byte("rotation boundary")

	type signResult struct {
		sig []byte
		err error
	}
	signDone := make(chan signResult, 1)
	go func() {
		sig, err := d.signBytes(msg)
		signDone <- signResult{sig: sig, err: err}
	}()
	<-blocked.entered

	rotateDone := make(chan error, 1)
	op := Operator{ID: "op-rotate", AuthnMethod: "webauthn"}
	go func() { rotateDone <- d.RotateToWithAudit(priv2, "compromise response", op) }()
	select {
	case err := <-rotateDone:
		t.Fatalf("RotateTo returned before old Sign completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(blocked.release)
	old := <-signDone
	if old.err != nil {
		t.Fatalf("old in-flight sign: %v", old.err)
	}
	if !ed25519.Verify(pub1, msg, old.sig) {
		t.Fatal("in-flight signature did not use old signer")
	}
	if err := <-rotateDone; err != nil {
		t.Fatalf("RotateTo: %v", err)
	}
	newSig, err := d.signBytes(msg)
	if err != nil {
		t.Fatalf("post-rotate sign: %v", err)
	}
	if !ed25519.Verify(pub2, msg, newSig) || ed25519.Verify(pub1, msg, newSig) {
		t.Fatal("post-rotate signature did not cut over exclusively to new signer")
	}
}

package signerkit

import (
	"reflect"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

func TestSignAtByteIdentity(t *testing.T) {
	original := randRead
	defer func() { randRead = original }()
	key, _ := goldenSignerKey()
	d := &Daemon{Key: key, NowFunc: goldenNow}
	commands := []signRequestCmd{
		{Cmd: goldenCmd, Host: goldenHostFP, TTLSec: goldenTTL},
		{Cmd: "cat /etc/secret", Host: goldenDestFP, TTLSec: 120, Reveal: true},
		{Cmd: "curl https://example.com", Host: goldenSrcFP, TTLSec: 300, Net: true},
		{Cmd: "curl https://example.org", Host: goldenHostFP, TTLSec: 45, Reveal: true, Net: true},
	}
	randRead = fixedEntropy()
	legacy, err := d.signAll(commands)
	if err != nil {
		t.Fatal(err)
	}
	d.NowFunc = func() time.Time { t.Fatal("signAt read the wall clock"); return time.Time{} }
	// Each command draws exactly one nonce, in order, from the entropy stream.
	randRead = fixedEntropy()
	wantNonces := make([]string, len(commands))
	for i := range wantNonces {
		if wantNonces[i], err = newNonce(); err != nil {
			t.Fatal(err)
		}
	}
	entropy, draws := fixedEntropy(), 0
	randRead = func(b []byte) (int, error) { draws++; return entropy(b) }
	got, err := d.signAt(commands, goldenNowUnix)
	if err != nil {
		t.Fatal(err)
	}
	if draws != len(commands) {
		t.Fatalf("entropy draws = %d, want %d", draws, len(commands))
	}
	if !reflect.DeepEqual(got, legacy) {
		t.Fatalf("signatures differ: got %#v, want %#v", got, legacy)
	}
	if got[0].Sig != wantSignHostGolden {
		t.Fatal("host envelope changed from frozen golden")
	}
	for i, signature := range got {
		_, payload, err := sigwire.DecodeSigned(signature.Sig)
		if err != nil {
			t.Fatal(err)
		}
		if payload.TS != goldenNowUnix || payload.Exp != goldenNowUnix+commands[i].TTLSec {
			t.Fatalf("wrong timestamps: %+v", payload)
		}
		if payload.Nonce != wantNonces[i] {
			t.Fatalf("command %d nonce = %q, want %q", i, payload.Nonce, wantNonces[i])
		}
	}
	randRead = fixedEntropy()
	reveal, err := d.signAt([]signRequestCmd{{Cmd: goldenCmd, Host: goldenHostFP, TTLSec: goldenTTL, Reveal: true}}, goldenNowUnix)
	if err != nil {
		t.Fatal(err)
	}
	if reveal[0].Sig != wantSignRevealGolden {
		t.Fatal("reveal envelope changed from frozen golden")
	}
}

func TestSignTransferLegsAtByteIdentity(t *testing.T) {
	original := randRead
	defer func() { randRead = original }()
	key, _ := goldenSignerKey()
	d := &Daemon{Key: key, NowFunc: goldenNow}
	_, sendPayload, err := sigwire.DecodeSigned(wantXferSendGolden)
	if err != nil {
		t.Fatal(err)
	}
	_, recvPayload, err := sigwire.DecodeSigned(wantXferRecvGolden)
	if err != nil {
		t.Fatal(err)
	}
	// The transfer handler consumes the first entropy draw for the transfer ID.
	randRead = fixedEntropy()
	if _, err := newNonce(); err != nil {
		t.Fatal(err)
	}
	legacySend, legacyRecv, err := d.signTransferLegs(sendPayload.Cmd, goldenSrcFP, recvPayload.Cmd, goldenDestFP, goldenTTL)
	if err != nil {
		t.Fatal(err)
	}
	d.NowFunc = func() time.Time { t.Fatal("signTransferLegsAt read the wall clock"); return time.Time{} }
	randRead = fixedEntropy()
	if _, err := newNonce(); err != nil {
		t.Fatal(err)
	}
	send, recv, err := d.signTransferLegsAt(sendPayload.Cmd, goldenSrcFP, recvPayload.Cmd, goldenDestFP, goldenTTL, goldenNowUnix)
	if err != nil {
		t.Fatal(err)
	}
	if *send != *legacySend || *recv != *legacyRecv {
		t.Fatal("transfer signatures differ from legacy path")
	}
	if send.Sig != wantXferSendGolden || recv.Sig != wantXferRecvGolden {
		t.Fatal("transfer envelopes changed from frozen goldens")
	}
}

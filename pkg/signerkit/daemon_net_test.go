package signerkit

import (
	"encoding/json"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
)

func TestEnvelopeGolden_SignNet(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()
	mock := NewMockBackend()
	d, pub := goldenSignDaemon(t, mock)
	mock.Approve("net", "operator")
	body := `{"kind":"sign","request_id":"net","commands":[{"server":"prod","cmd":"uptime","ttl_seconds":60,"host":"` + goldenHostFP + `","net":true,"reason":"check connectivity"}]}`
	var resp signRespGolden
	if err := json.Unmarshal([]byte(driveGolden(t, d, body)), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "approved" || len(resp.Signatures) != 1 {
		t.Fatalf("response=%+v", resp)
	}
	const want = "SSHGATE_SIG:2vwsPRKcctcnYSTv0viULAa6JYS_lo30eptFgfWtmlBsLaB0PUuXK4wRRHi-zL4IN2wmaVAJwWiPxbq6Du8wAQ:eyJjbWQiOiJ1cHRpbWUiLCJ0cyI6MTAwMCwiZXhwIjoxMDYwLCJub25jZSI6IkJ3b05FQk1XR1J3ZklpVW9LeTR4TkEiLCJob3N0IjoiU0hBMjU2OlptOXZZbUZ5TFdacGVHVmtMV2R2YkdSbGJpMW9iM04wTFdad0xUQXdNREF3TURBeCIsIm5ldCI6dHJ1ZX0"
	if resp.Signatures[0].Sig != want {
		t.Fatalf("network envelope: got %q; want %q", resp.Signatures[0].Sig, want)
	}
	verified, err := gate.Verify(want, pub, goldenNow(), []string{goldenHostFP})
	if err != nil || !verified.Net || verified.Reveal || verified.Cmd != "uptime" {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
}

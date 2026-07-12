package signerkit

import (
	"crypto/ed25519"
	"testing"

	"github.com/karthikeyan5/sshgate/src/xfer"
)

// socketrpc_golden_test.go is a PHASE-0 FREEZE HARNESS (signerkit extraction,
// SPEC §Phase 0(b)). It pins the EXACT byte-for-byte JSON response line the
// daemon writes over the MCP<->signer Unix socket for EVERY response kind
// HandleSignRequest emits — sign (approved/denied/timeout/error/unknown-verb),
// request_grant, revoke_grant, list_grants, transfer, and register_xfer_key,
// each in its approved / non-approved / error shapes. The response structs
// (daemon.go:118-375) are marshalled in struct-field order, so a reordered or
// renamed field, a dropped/added omitempty, or a changed status/error spelling
// flips one of these goldens — the tripwire that keeps the socket-RPC shape
// (ProtoVersion=1) byte-stable across the core's move to pkg/signerkit.
//
// It is in package signer (white-box) so it can reuse the fixed-seed key /
// fixed clock / deterministic randRead seam from envelope_golden_test.go —
// nonces, grant-ids, and xfer-ids are thereby fixed, so lines carrying them are
// reproducible. Like the envelope goldens (and TestSignAll_NonceFailure) these
// tests do NOT call t.Parallel(): they swap the package randRead var (restored
// under defer), and Go completes the non-parallel bodies before any parallel
// signer test resumes.

// assertGolden compares one response line against its frozen golden. The
// name is the golden const's own identifier, so a capture pass can map a drift
// report straight back to the const to update.
func assertGolden(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s golden drift:\n got  %q\n want %q", name, got, want)
	}
}

// goldenBoxIDText returns the fixed box/id PublicText pair used by the register
// and transfer goldens (the same fixed key bytes goldenXferDaemon registers).
func goldenBoxIDText() (boxText, idText string) {
	var boxPub [32]byte
	idPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := 0; i < 32; i++ {
		boxPub[i] = byte(0x40 + i)
		idPub[i] = byte(0x80 + i)
	}
	return xfer.BoxPublicText(&boxPub), xfer.IDPublicText(idPub)
}

// ---- Frozen response-line goldens (see file header). ----

// signResponse (daemon.go:225): approved-with-signatures / denied / timeout /
// error(no commands) / error(unknown verb — request_id echoes the peeked kind).
const wantSignApproved = `{"request_id":"s_ok","status":"approved","auth_mode":"human","signatures":[{"cmd":"systemctl restart nginx","sig":"SSHGATE_SIG:o7XPO8_vMG1BCD6MDyo-1F7baBpr6Pn8Q79fLvhrSGyRATHGJH3agHQLYROmr1go-X8flT-ttto2BIvXvSSgAg:eyJjbWQiOiJzeXN0ZW1jdGwgcmVzdGFydCBuZ2lueCIsInRzIjoxMDAwLCJleHAiOjEwNjAsIm5vbmNlIjoiQndvTkVCTVdHUndmSWlVb0t5NHhOQSIsImhvc3QiOiJTSEEyNTY6Wm05dlltRnlMV1pwZUdWa0xXZHZiR1JsYmkxb2IzTjBMV1p3TFRBd01EQXdNREF4In0"}],"proto_version":1}`
const wantSignDenied = `{"request_id":"s_deny","status":"denied","proto_version":1}`
const wantSignTimeout = `{"request_id":"s_to","status":"timeout","proto_version":1}`
const wantSignErrNoCommands = `{"request_id":"s_nocmd","status":"error","error":"no commands in request","proto_version":1}`
const wantSignErrUnknownKind = `{"request_id":"frobnicate","status":"error","error":"unsupported kind \"frobnicate\"","proto_version":1}`

// grantResponse (daemon.go:310): approved(grant_id+expiry) / denied / error(scope).
const wantGrantApproved = `{"request_id":"g_ok","status":"approved","grant_id":"g_BwoNEBMWGRwfIiUo","expiry_unix":4600,"proto_version":1}`
const wantGrantDenied = `{"request_id":"g_deny","status":"denied","proto_version":1}`
const wantGrantErrScope = `{"request_id":"g_scope","status":"error","error":"invalid scope \"bogus\" (must be \"all\" or \"commands\")","proto_version":1}`

// revokeGrantResponse (daemon.go:333): approved(no-op) / error(missing alias).
const wantRevokeApproved = `{"request_id":"rv_ok","status":"approved","proto_version":1}`
const wantRevokeErrNoAlias = `{"request_id":"rv_x","status":"error","error":"missing alias","proto_version":1}`

// listGrantsResponse (daemon.go:369): ok(empty) / ok(one grant) / error(missing id).
const wantListEmpty = `{"request_id":"l_e","status":"ok","proto_version":1}`
const wantListOne = `{"request_id":"l_one","status":"ok","grants":[{"alias":"prod","scope":"all","grant_id":"g_BwoNEBMWGRwfIiUo","expiry_unix":4600}],"proto_version":1}`
const wantListErrNoID = `{"request_id":"","status":"error","error":"missing request_id","proto_version":1}`

// transferResponse (daemon.go:143): approved(xfer_id+both legs) / denied / error(bad fp).
const wantXferApproved = `{"request_id":"x_ok","status":"approved","auth_mode":"human","xfer_id":"BwoNEBMWGRwfIiUoKy4xNA","send":{"cmd":"SSHGATE_XFER_SEND c3NoZ2F0ZS14ZmVyLWJveC14MjU1MTkgUUVGQ1EwUkZSa2RJU1VwTFRFMU9UMUJSVWxOVVZWWlhXRmxhVzF4ZFhsOD0 QndvTkVCTVdHUndmSWlVb0t5NHhOQQ U0hBMjU2OmRzdC1mcC1nb2xkZW4tYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJi L2V0Yy9zcmMtc2VjcmV0LmVudg","sig":"SSHGATE_SIG:BDyVWL2M2Bt2meUklzN5C-YWvXchZ7pvolHthi6SzV7sf8nY8EQghb-Ro4EXtlx2CMQhvvZKmGSHk61lRbMmAA:eyJjbWQiOiJTU0hHQVRFX1hGRVJfU0VORCBjM05vWjJGMFpTMTRabVZ5TFdKdmVDMTRNalUxTVRrZ1VVVkdRMUV3VWtaU2EyUkpVMVZ3VEZSRk1VOVVNVUpTVld4T1ZWWldXbGhYUm14aFZ6RjRaRmhzT0QwIFFuZHZUa1ZDVFZkSFVuZG1TV2xWYjB0NU5IaE9RUSBVMGhCTWpVMk9tUnpkQzFtY0MxbmIyeGtaVzR0WW1KaVltSmlZbUppWW1KaVltSmlZbUppWW1KaVltSmkgTDJWMFl5OXpjbU10YzJWamNtVjBMbVZ1ZGciLCJ0cyI6MTAwMCwiZXhwIjoxMDYwLCJub25jZSI6IkRoRVVGeG9kSUNNbUtTd3ZNalU0T3ciLCJob3N0IjoiU0hBMjU2OnNyYy1mcC1nb2xkZW4tYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIn0"},"recv":{"cmd":"SSHGATE_XFER_RECV c3NoZ2F0ZS14ZmVyLWlkLWVkMjU1MTkgZ0lHQ2c0U0Zob2VJaVlxTGpJMk9qNUNSa3BPVWxaYVhtSm1hbTV5ZG5wOD0 QndvTkVCTVdHUndmSWlVb0t5NHhOQQ U0hBMjU2OnNyYy1mcC1nb2xkZW4tYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh U0hBMjU2OmRzdC1mcC1nb2xkZW4tYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJi MDYwMA L2V0Yy9kc3Qtc2VjcmV0LmVudg","sig":"SSHGATE_SIG:FtvQ4JET-Q8UmWFdvCvdl91iTQLbHN47CUEccmshLA6R2VVHETCR9rhdOploM8pW7plpzilDdWohJxY20G0pDw:eyJjbWQiOiJTU0hHQVRFX1hGRVJfUkVDViBjM05vWjJGMFpTMTRabVZ5TFdsa0xXVmtNalUxTVRrZ1owbEhRMmMwVTBab2IyVkphVmx4VEdwSk1rOXFOVU5TYTNCUFZXeGFZVmh0U20xaGJUVjVaRzV3T0QwIFFuZHZUa1ZDVFZkSFVuZG1TV2xWYjB0NU5IaE9RUSBVMGhCTWpVMk9uTnlZeTFtY0MxbmIyeGtaVzR0WVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmggVTBoQk1qVTJPbVJ6ZEMxbWNDMW5iMnhrWlc0dFltSmlZbUppWW1KaVltSmlZbUppWW1KaVltSmlZbUppIE1EWXdNQSBMMlYwWXk5a2MzUXRjMlZqY21WMExtVnVkZyIsInRzIjoxMDAwLCJleHAiOjEwNjAsIm5vbmNlIjoiRlJnYkhpRWtKeW90TURNMk9Ud19RZyIsImhvc3QiOiJTSEEyNTY6ZHN0LWZwLWdvbGRlbi1iYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIifQ"},"proto_version":1}`
const wantXferDenied = `{"request_id":"x_deny","status":"denied","proto_version":1}`
const wantXferErrBadFP = `{"request_id":"x_badfp","status":"error","error":"invalid src_fp","proto_version":1}`

// registerXferKeyResponse (daemon.go:171): approved / denied / error(bad host fp).
const wantRegApproved = `{"request_id":"k_ok","status":"approved","proto_version":1}`
const wantRegDenied = `{"request_id":"k_deny","status":"denied","proto_version":1}`
const wantRegErrBadFP = `{"request_id":"k_badfp","status":"error","error":"invalid host_fp","proto_version":1}`

// TestSocketGolden_Sign freezes the signResponse lines.
func TestSocketGolden_Sign(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	// approved: identical inner sig to the envelope host golden (request_id is a
	// socket field, not part of the signed payload).
	mock := NewMockBackend()
	d, _ := goldenSignDaemon(t, mock)
	mock.Approve("s_ok", "operator")
	body := `{"kind":"sign","request_id":"s_ok","commands":[{"server":"prod","cmd":"` +
		goldenCmd + `","ttl_seconds":60,"host":"` + goldenHostFP + `"}]}`
	assertGolden(t, "wantSignApproved", driveGolden(t, d, body), wantSignApproved)

	// denied
	md := NewMockBackend()
	dd, _ := goldenSignDaemon(t, md)
	md.Deny("s_deny")
	assertGolden(t, "wantSignDenied",
		driveGolden(t, dd, `{"kind":"sign","request_id":"s_deny","commands":[{"server":"prod","cmd":"ls","ttl_seconds":60}]}`),
		wantSignDenied)

	// timeout
	mt := NewMockBackend()
	dt, _ := goldenSignDaemon(t, mt)
	mt.Timeout("s_to")
	assertGolden(t, "wantSignTimeout",
		driveGolden(t, dt, `{"kind":"sign","request_id":"s_to","commands":[{"server":"prod","cmd":"ls","ttl_seconds":60}]}`),
		wantSignTimeout)

	// error: empty commands list
	de, _ := goldenSignDaemon(t, NewMockBackend())
	assertGolden(t, "wantSignErrNoCommands",
		driveGolden(t, de, `{"kind":"sign","request_id":"s_nocmd","commands":[]}`),
		wantSignErrNoCommands)

	// error: unknown/unsupported kind — respondError echoes the PEEKED kind as
	// the request_id (daemon.go:434), a behaviour worth freezing.
	du, _ := goldenSignDaemon(t, NewMockBackend())
	assertGolden(t, "wantSignErrUnknownKind",
		driveGolden(t, du, `{"kind":"frobnicate","request_id":"s_x","commands":[]}`),
		wantSignErrUnknownKind)
}

// TestSocketGolden_Grant freezes the grantResponse lines.
func TestSocketGolden_Grant(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	mock := NewMockBackend()
	d, _ := goldenSignDaemon(t, mock)
	mock.Approve("g_ok", "operator")
	assertGolden(t, "wantGrantApproved",
		driveGolden(t, d, `{"kind":"request_grant","request_id":"g_ok","alias":"prod","scope":"all","duration_seconds":3600}`),
		wantGrantApproved)

	md := NewMockBackend()
	dd, _ := goldenSignDaemon(t, md)
	md.Deny("g_deny")
	assertGolden(t, "wantGrantDenied",
		driveGolden(t, dd, `{"kind":"request_grant","request_id":"g_deny","alias":"prod","scope":"all","duration_seconds":3600}`),
		wantGrantDenied)

	de, _ := goldenSignDaemon(t, NewMockBackend())
	assertGolden(t, "wantGrantErrScope",
		driveGolden(t, de, `{"kind":"request_grant","request_id":"g_scope","alias":"prod","scope":"bogus","duration_seconds":3600}`),
		wantGrantErrScope)
}

// TestSocketGolden_RevokeGrant freezes the revokeGrantResponse lines.
func TestSocketGolden_RevokeGrant(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	d, _ := goldenSignDaemon(t, NewMockBackend())
	assertGolden(t, "wantRevokeApproved",
		driveGolden(t, d, `{"kind":"revoke_grant","request_id":"rv_ok","alias":"prod"}`),
		wantRevokeApproved)

	de, _ := goldenSignDaemon(t, NewMockBackend())
	assertGolden(t, "wantRevokeErrNoAlias",
		driveGolden(t, de, `{"kind":"revoke_grant","request_id":"rv_x"}`),
		wantRevokeErrNoAlias)
}

// TestSocketGolden_ListGrants freezes the listGrantsResponse lines.
func TestSocketGolden_ListGrants(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	// empty
	d, _ := goldenSignDaemon(t, NewMockBackend())
	assertGolden(t, "wantListEmpty",
		driveGolden(t, d, `{"kind":"list_grants","request_id":"l_e"}`),
		wantListEmpty)

	// one live grant: mint it (deterministic id via the entropy stub), then list.
	mock := NewMockBackend()
	d1, _ := goldenSignDaemon(t, mock)
	mock.Approve("l_mk", "operator")
	if got := driveGolden(t, d1, `{"kind":"request_grant","request_id":"l_mk","alias":"prod","scope":"all","duration_seconds":3600}`); got == "" {
		t.Fatal("grant mint produced no response")
	}
	assertGolden(t, "wantListOne",
		driveGolden(t, d1, `{"kind":"list_grants","request_id":"l_one"}`),
		wantListOne)

	// error: missing request_id → echoed as ""
	de, _ := goldenSignDaemon(t, NewMockBackend())
	assertGolden(t, "wantListErrNoID",
		driveGolden(t, de, `{"kind":"list_grants","alias":"prod"}`),
		wantListErrNoID)
}

// TestSocketGolden_Transfer freezes the transferResponse lines.
func TestSocketGolden_Transfer(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	mock := NewMockBackend()
	d, _ := goldenXferDaemon(t, mock)
	mock.Approve("x_ok", "operator")
	approvedBody := `{"kind":"transfer","request_id":"x_ok","src_alias":"src","src_fp":"` + goldenSrcFP +
		`","src_path":"` + goldenSrcPath + `","dest_alias":"dest","dest_fp":"` + goldenDestFP +
		`","dest_path":"` + goldenDestPath + `","mode":"` + goldenMode + `","ttl_seconds":60}`
	assertGolden(t, "wantXferApproved", driveGolden(t, d, approvedBody), wantXferApproved)

	// denied (fps registered so it reaches the backend, then denied)
	md := NewMockBackend()
	dd, _ := goldenXferDaemon(t, md)
	md.Deny("x_deny")
	deniedBody := `{"kind":"transfer","request_id":"x_deny","src_alias":"src","src_fp":"` + goldenSrcFP +
		`","src_path":"` + goldenSrcPath + `","dest_alias":"dest","dest_fp":"` + goldenDestFP +
		`","dest_path":"` + goldenDestPath + `","mode":"` + goldenMode + `","ttl_seconds":60}`
	assertGolden(t, "wantXferDenied", driveGolden(t, dd, deniedBody), wantXferDenied)

	// error: invalid src_fp (rejected before any lookup/sign)
	de, _ := goldenXferDaemon(t, NewMockBackend())
	badBody := `{"kind":"transfer","request_id":"x_badfp","src_alias":"src","src_fp":"not-a-fingerprint",` +
		`"src_path":"` + goldenSrcPath + `","dest_alias":"dest","dest_fp":"` + goldenDestFP +
		`","dest_path":"` + goldenDestPath + `","mode":"` + goldenMode + `","ttl_seconds":60}`
	assertGolden(t, "wantXferErrBadFP", driveGolden(t, de, badBody), wantXferErrBadFP)
}

// TestSocketGolden_RegisterKey freezes the registerXferKeyResponse lines.
func TestSocketGolden_RegisterKey(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	boxText, idText := goldenBoxIDText()
	regFP := "SHA256:reg-fp-golden-cccccccccccccccccccccccc"

	// approved
	mock := NewMockBackend()
	d, _ := goldenXferDaemon(t, mock)
	mock.Approve("k_ok", "operator")
	body := `{"kind":"register_xfer_key","request_id":"k_ok","host_fp":"` + regFP +
		`","label":"reg-golden","box_pub":"` + boxText + `","id_pub":"` + idText + `"}`
	assertGolden(t, "wantRegApproved", driveGolden(t, d, body), wantRegApproved)

	// denied
	md := NewMockBackend()
	dd, _ := goldenXferDaemon(t, md)
	md.Deny("k_deny")
	dbody := `{"kind":"register_xfer_key","request_id":"k_deny","host_fp":"` + regFP +
		`","label":"reg-golden","box_pub":"` + boxText + `","id_pub":"` + idText + `"}`
	assertGolden(t, "wantRegDenied", driveGolden(t, dd, dbody), wantRegDenied)

	// error: invalid host_fp
	de, _ := goldenXferDaemon(t, NewMockBackend())
	ebody := `{"kind":"register_xfer_key","request_id":"k_badfp","host_fp":"not-a-fingerprint",` +
		`"label":"reg-golden","box_pub":"` + boxText + `","id_pub":"` + idText + `"}`
	assertGolden(t, "wantRegErrBadFP", driveGolden(t, de, ebody), wantRegErrBadFP)
}

package backend

import (
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// TestFormatTransferApprovalMessage_LabelsFromRegistry: the banner renders the
// src/dest LABELS carried in the request (which the daemon sources from its
// registry, never the MCP alias), plus the paths, mode, and xferID.
func TestFormatTransferApprovalMessage_LabelsFromRegistry(t *testing.T) {
	req := signerkit.TransferApprovalRequest{
		RequestID: "t_fmt",
		XferID:    "AQ4bKDVCT1xpdoOQnaq3xA",
		SrcLabel:  "ram-gcp",
		SrcFP:     "SHA256:kQ4jRram-example-source-fp-000000000000ab",
		SrcPath:   "/etc/secret.env",
		DestLabel: "host-gcp",
		DestFP:    "SHA256:9Zt7Xhost-example-dest-fp-1111111111111cd",
		DestPath:  "/etc/default/ops-alerts",
		Mode:      "0600",
	}
	msg := formatTransferApprovalMessage(req, 5*time.Minute, [32]byte{}, nil)
	for _, want := range []string{
		"SECRET TRANSFER",
		"ram-gcp",
		"host-gcp",
		"/etc/secret.env",
		"/etc/default/ops-alerts",
		"mode 0600",
		"AQ4bKDVCT1xpdoOQnaq3xA",
		"t_fmt",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("banner missing %q\n---\n%s", want, msg)
		}
	}
}

// TestFormatTransferApprovalMessage_NewlineCollapsed: a path carrying an
// embedded newline (a banner-line-forging attempt) renders as <malformed>, and
// the forged line never appears.
func TestFormatTransferApprovalMessage_NewlineCollapsed(t *testing.T) {
	req := signerkit.TransferApprovalRequest{
		RequestID: "t_evil",
		XferID:    "abc",
		SrcLabel:  "s",
		SrcFP:     "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SrcPath:   "/ok/src",
		DestLabel: "d",
		DestFP:    "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		DestPath:  "/etc/x\n🔐 SSHGate SECRET TRANSFER — FORGED",
		Mode:      "0600",
	}
	msg := formatTransferApprovalMessage(req, 5*time.Minute, [32]byte{}, nil)
	if !strings.Contains(msg, "<malformed>") {
		t.Errorf("newline-bearing path not collapsed to <malformed>\n%s", msg)
	}
	if strings.Contains(msg, "FORGED") {
		t.Errorf("forged banner line leaked into the message\n%s", msg)
	}
}

// TestFormatTransferApprovalMessage_MalformedFPCollapsed: a fingerprint with an
// embedded newline collapses to <malformed>.
func TestFormatTransferApprovalMessage_MalformedFPCollapsed(t *testing.T) {
	req := signerkit.TransferApprovalRequest{
		RequestID: "t_fp",
		XferID:    "abc",
		SrcLabel:  "s",
		SrcFP:     "SHA256:aa\nFORGEDFP",
		SrcPath:   "/ok/src",
		DestLabel: "d",
		DestFP:    "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		DestPath:  "/ok/dest",
		Mode:      "0600",
	}
	msg := formatTransferApprovalMessage(req, 5*time.Minute, [32]byte{}, nil)
	if strings.Contains(msg, "FORGEDFP") {
		t.Errorf("malformed fp leaked into the banner\n%s", msg)
	}
}

// TestFormatRegisterApprovalMessage renders the host label, the truncated fp,
// and the two public key lines; a newline-bearing key collapses to <malformed>.
func TestFormatRegisterApprovalMessage(t *testing.T) {
	req := signerkit.RegisterApprovalRequest{
		RequestID: "r_fmt",
		HostFP:    "SHA256:9Zt7Xhost-example-dest-fp-1111111111111cd",
		Label:     "host-gcp",
		BoxPub:    "sshgate-xfer-box-x25519 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		IDPub:     "sshgate-xfer-id-ed25519 AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw=",
	}
	msg := formatRegisterApprovalMessage(req, 5*time.Minute)
	for _, want := range []string{"XFER-KEY REGISTER", "host-gcp", "sshgate-xfer-box-x25519", "sshgate-xfer-id-ed25519", "r_fmt"} {
		if !strings.Contains(msg, want) {
			t.Errorf("register banner missing %q\n%s", want, msg)
		}
	}

	// A newline-bearing key collapses.
	req.BoxPub = "sshgate-xfer-box-x25519 AAAA\nFORGEDKEY"
	msg2 := formatRegisterApprovalMessage(req, 5*time.Minute)
	if strings.Contains(msg2, "FORGEDKEY") {
		t.Errorf("malformed key leaked into the register banner\n%s", msg2)
	}
}

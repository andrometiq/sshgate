package approvalreview

import (
	"fmt"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// validate checks stored display invariants without access to hidden originals.
func (s ReviewSnapshot) validate() error {
	bad := func() error { return fmt.Errorf("approvalreview: invalid snapshot content") }
	if s.Version != SnapshotVersion || (!s.Legacy && !approvalplan.ValidSHA256Hex(s.PlanHash)) || (s.Legacy && s.PlanHash != "") {
		return bad()
	}
	if s.SignDigest != "" && (!s.Legacy || s.Kind != approvalplan.KindCommandJob || !approvalplan.ValidSHA256Hex(s.SignDigest)) {
		return bad()
	}
	switch s.Origin {
	case approvalplan.OriginAgent, approvalplan.OriginTrustedHumanCLI, approvalplan.OriginSynthesizedLegacyV1:
	default:
		return bad()
	}
	payloads := 0
	if len(s.Steps) > 0 {
		payloads++
	}
	if s.Grant != nil {
		payloads++
	}
	if s.Transfer != nil {
		payloads++
	}
	if s.Register != nil {
		payloads++
	}
	if payloads != 1 {
		return bad()
	}
	displays := []Display{s.Reason}
	switch s.Kind {
	case approvalplan.KindCommandJob:
		if len(s.Steps) == 0 {
			return bad()
		}
		for i, st := range s.Steps {
			if st.Net && (!s.Legacy || s.SignDigest == "" || len(s.Steps) != 1 || st.LegacyReason == nil || st.LegacyReason.Bytes == 0 || (st.Route != approvalplan.RouteSignedWrite && st.Route != approvalplan.RouteSignedReveal)) {
				return bad()
			}
			switch st.Route {
			case approvalplan.RouteUnsignedRead, approvalplan.RouteSignedWrite, approvalplan.RouteSignedReveal, approvalplan.RouteSignedAdmin:
			default:
				return bad()
			}
			if st.Ordinal != i+1 || !approvalplan.ValidSHA256Hex(st.Command.SHA256) {
				return bad()
			}
			if st.UpdateSHA256 != "" && (!st.IsUpdate || !approvalplan.ValidSHA256Hex(st.UpdateSHA256)) {
				return bad()
			}
			if st.Target.Port < 0 || st.Target.Port > 65535 {
				return bad()
			}
			displays = append(displays, st.Command)
			if st.LegacyReason != nil {
				displays = append(displays, *st.LegacyReason)
			}
			if st.Build != nil {
				displays = append(displays, st.Build.StagedBasename, st.Build.StagedVersion, st.Build.RunningVersion)
			}
		}
	case approvalplan.KindStandingGrant:
		if s.Grant == nil {
			return bad()
		}
		for _, d := range s.Grant.Commands {
			if !approvalplan.ValidSHA256Hex(d.SHA256) {
				return bad()
			}
			displays = append(displays, d)
		}
	case approvalplan.KindTransfer:
		if s.Transfer == nil {
			return bad()
		}
		tr := s.Transfer
		for _, hash := range []string{tr.SendSHA256, tr.RecvSHA256, tr.Source.PublicKeySHA256, tr.Destination.PublicKeySHA256} {
			if hash != "" && !approvalplan.ValidSHA256Hex(hash) {
				return bad()
			}
		}
		if !s.Legacy && (!approvalplan.ValidSHA256Hex(tr.SendSHA256) || !approvalplan.ValidSHA256Hex(tr.RecvSHA256)) {
			return bad()
		}
		displays = append(displays, tr.Source.Path, tr.Destination.Path)
	case approvalplan.KindRegisterTransferKey:
		if s.Register == nil {
			return bad()
		}
	default:
		return bad()
	}
	for _, d := range displays {
		if d.Bytes < 0 || d.HiddenBytes < 0 || d.HiddenBytes > d.Bytes || d.FullyHidden != (d.Bytes > 0 && d.HiddenBytes == d.Bytes) {
			return bad()
		}
		if d.SHA256 != "" && !approvalplan.ValidSHA256Hex(d.SHA256) {
			return bad()
		}
		total := 0
		for _, seg := range d.Segments {
			if (d.FullyHidden && seg.Text != "") || seg.Hidden < 0 || (seg.Hidden > 0) == (seg.Text != "") || (seg.Hidden == 0 && len(seg.RuleIDs) > 0) {
				return bad()
			}
			if seg.Hidden > d.HiddenBytes-total {
				return bad()
			}
			total += seg.Hidden
			for i, id := range seg.RuleIDs {
				if id == "" || (i > 0 && id <= seg.RuleIDs[i-1]) {
					return bad()
				}
			}
		}
		if total != d.HiddenBytes || (d.Bytes == 0 && len(d.Segments) > 0) || (d.Bytes > 0 && len(d.Segments) == 0) {
			return bad()
		}
	}
	return nil
}

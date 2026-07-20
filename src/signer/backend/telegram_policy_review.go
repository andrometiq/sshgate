package backend

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/redact"
)

const (
	policyTelegramPartBytes       = 3900 // every part must be strictly smaller
	policyTelegramMaxMessages     = 40   // includes the sole decision card
	policyTelegramMaxReviewBytes  = 128 << 10
	policyTelegramPreviewBytes    = 512
	policyTelegramPartBodyBytes   = 3650 // reserves banner + numbering + request/host identity
	policyPermanentAuthorityTitle = "⚠️ PERMANENT REMOTE POLICY AUTHORITY"
	policyReviewMaxChanges        = 32
	policyReviewMaxLiteralBytes   = 24 << 10
	policyReviewMaxLiteral        = 4 << 10
)

const policySourceExactWarning = "WARNING: source-exact is not exact effect; variables, globs, interpreters, cwd/env, and referenced files can change behavior. Dynamic/interpreter commands should not be made permanent."

var policyRedactString = redact.RedactString

type policyRenderedReview struct {
	DetailParts   []string
	DecisionCard  string
	LogicalChange int
}

func renderPolicyReview(req signerkit.BaseManifestApprovalRequest, timeout time.Duration, salt [32]byte, rules []redact.Rule) (policyRenderedReview, error) {
	if req.DecisionHooks == nil {
		return policyRenderedReview{}, errors.New("telegram policy: durable decision hooks are required")
	}
	if len(req.FrozenPublicKey) != ed25519.PublicKeySize {
		return policyRenderedReview{}, errors.New("telegram policy: frozen Ed25519 public key must be exactly 32 bytes")
	}
	publicKey := ed25519.PublicKey(append([]byte(nil), req.FrozenPublicKey...))
	keyID, err := policy.SignerKeyID(publicKey)
	if err != nil || keyID != req.ExpectedSignerKeyID {
		return policyRenderedReview{}, errors.New("telegram policy: frozen public key does not match expected signer key id")
	}
	candidate, err := policy.ParseBaseManifest(req.Payload)
	if err != nil || candidate.Host != req.HostKeyFP {
		return policyRenderedReview{}, errors.New("telegram policy: candidate payload is invalid or host-mismatched")
	}
	payloadSHA, candidateDigest, err := policywire.PayloadDigests(req.Payload)
	if err != nil {
		return policyRenderedReview{}, fmt.Errorf("telegram policy: candidate digests: %w", err)
	}

	var head *policy.BaseManifest
	headDigest := "<none — bootstrap>"
	if req.Bootstrap {
		if req.ExpectedHeadDigest != "" || len(req.TrustedHeadEnvelope) != 0 {
			return policyRenderedReview{}, errors.New("telegram policy: bootstrap carried a predecessor")
		}
		if candidate.Epoch != 1 || candidate.Revision != 1 || len(candidate.Entries) > policyReviewMaxChanges {
			return policyRenderedReview{}, errors.New("telegram policy: bootstrap exceeds version or entry review bounds")
		}
	} else {
		if len(req.TrustedHeadEnvelope) == 0 {
			return policyRenderedReview{}, errors.New("telegram policy: successor is missing signer-owned predecessor")
		}
		verified, verifyErr := policy.VerifyBaseManifest(req.TrustedHeadEnvelope, publicKey)
		if verifyErr != nil || verified.Host != req.HostKeyFP {
			return policyRenderedReview{}, errors.New("telegram policy: signer-owned predecessor verification failed")
		}
		headPayload, _, decodeErr := policy.DecodeBaseManifestEnvelope(req.TrustedHeadEnvelope)
		if decodeErr != nil {
			return policyRenderedReview{}, fmt.Errorf("telegram policy: decode predecessor: %w", decodeErr)
		}
		_, gotHeadDigest, digestErr := policywire.PayloadDigests(headPayload)
		if digestErr != nil || gotHeadDigest != req.ExpectedHeadDigest {
			return policyRenderedReview{}, errors.New("telegram policy: predecessor digest does not match expected head")
		}
		headDigest = gotHeadDigest
		head = &verified
		if candidate.Epoch != head.Epoch || candidate.Revision != head.Revision+1 {
			return policyRenderedReview{}, errors.New("telegram policy: successor is not the exact next revision")
		}
	}
	if err := validatePolicyLiteralReviewBounds(head, candidate); err != nil {
		return policyRenderedReview{}, err
	}

	blocks, logicalChanges, err := buildPolicyChangeBlocks(head, candidate, salt, rules)
	if err != nil {
		return policyRenderedReview{}, err
	}
	if logicalChanges == 0 {
		return policyRenderedReview{}, errors.New("telegram policy: review contains no semantic change")
	}
	if head != nil && logicalChanges > policyReviewMaxChanges {
		return policyRenderedReview{}, errors.New("telegram policy: review exceeds logical-change bound")
	}
	preset := policyPreset(candidate.MissAction, candidate.Growth)
	summary := fmt.Sprintf("DETAIL REVIEW\nRequest ID: %s\nHost fingerprint: %s\nSigner key ID: %s\nPayload SHA-256: %s\nCandidate digest: %s\nSigner-owned head digest: %s\nVersion: epoch %d / revision %d\nAxes: miss_action=%s, growth=%s\nPreset: %s\nEntries: %d\nRevocations: %d\nLogical changes: %d",
		req.RequestID, req.HostKeyFP, req.ExpectedSignerKeyID,
		payloadSHA, candidateDigest, headDigest, candidate.Epoch, candidate.Revision,
		candidate.MissAction, candidate.Growth, preset, len(candidate.Entries), len(candidate.RevokedPermitIDs), logicalChanges)
	allBlocks := make([]string, 0, len(blocks)+1)
	allBlocks = append(allBlocks, summary)
	allBlocks = append(allBlocks, blocks...)
	parts, err := packPolicyDetailParts(req.RequestID, req.HostKeyFP, allBlocks)
	if err != nil {
		return policyRenderedReview{}, err
	}
	decision := fmt.Sprintf("%s\n\nDECISION CARD — review the numbered detail messages before deciding.\nRequest ID: %s\nHost fingerprint: %s\nSigner key ID: %s\nSigner-owned head digest: %s\nCandidate digest: %s\nVersion: epoch %d / revision %d\nAxes: miss_action=%s, growth=%s\nPreset: %s\nLogical changes: %d\nEntries: %d; revocations: %d\nDecision expires in %s",
		policyPermanentAuthorityTitle, req.RequestID, req.HostKeyFP, req.ExpectedSignerKeyID,
		headDigest, candidateDigest, candidate.Epoch, candidate.Revision, candidate.MissAction,
		candidate.Growth, preset, logicalChanges, len(candidate.Entries), len(candidate.RevokedPermitIDs), timeout)
	if len(decision) >= policyTelegramPartBytes {
		return policyRenderedReview{}, errors.New("telegram policy: decision card exceeds Telegram bound")
	}
	if len(parts)+1 > policyTelegramMaxMessages {
		return policyRenderedReview{}, errors.New("telegram policy: review exceeds message-count bound")
	}
	total := len(decision)
	for _, part := range parts {
		total += len(part)
	}
	if total > policyTelegramMaxReviewBytes {
		return policyRenderedReview{}, errors.New("telegram policy: rendered review exceeds aggregate bound")
	}
	return policyRenderedReview{DetailParts: parts, DecisionCard: decision, LogicalChange: logicalChanges}, nil
}

func validatePolicyLiteralReviewBounds(head *policy.BaseManifest, candidate policy.BaseManifest) error {
	existing := make(map[string]struct{})
	revoked := make(map[string]struct{})
	if head != nil {
		for _, entry := range head.Entries {
			existing[entry.ID] = struct{}{}
		}
		for _, id := range head.RevokedPermitIDs {
			revoked[id] = struct{}{}
		}
	}
	newBytes := 0
	for _, entry := range candidate.Entries {
		if head == nil && len(entry.Identity.Literal) > policyReviewMaxLiteral {
			return errors.New("telegram policy: command literal exceeds per-entry review bound")
		}
		if _, ok := existing[entry.ID]; !ok {
			const prefix = "pa_oob_"
			if len(entry.ID) != len(prefix)+32 || !strings.HasPrefix(entry.ID, prefix) || !isLowerHex(entry.ID[len(prefix):]) {
				return errors.New("telegram policy: newly reviewed entry is not a random out-of-band policy id")
			}
			if _, wasRevoked := revoked[entry.ID]; wasRevoked {
				return errors.New("telegram policy: revoked entry id was resurrected")
			}
			newBytes += len(entry.Identity.Literal)
		}
	}
	if newBytes > policyReviewMaxLiteralBytes {
		return errors.New("telegram policy: newly reviewed literals exceed aggregate bound")
	}
	return nil
}

func buildPolicyChangeBlocks(head *policy.BaseManifest, candidate policy.BaseManifest, salt [32]byte, rules []redact.Rule) ([]string, int, error) {
	var blocks []string
	changes := 0
	if head == nil {
		blocks = append(blocks, fmt.Sprintf("BASELINE AXES\nmiss_action=%s\ngrowth=%s", candidate.MissAction, candidate.Growth))
		changes++
		entries := append([]policy.BaseEntry(nil), candidate.Entries...)
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
		for _, entry := range entries {
			blocks = append(blocks, renderPolicyAddedEntry(entry, salt, rules))
			changes++
		}
		revoked := append([]string(nil), candidate.RevokedPermitIDs...)
		sort.Strings(revoked)
		for _, id := range revoked {
			blocks = append(blocks, "REVOKED ID\nID: "+id)
			changes++
		}
		return blocks, changes, nil
	}
	if head.MissAction != candidate.MissAction || head.Growth != candidate.Growth {
		blocks = append(blocks, fmt.Sprintf("AXES CHANGED\nmiss_action: %s -> %s\ngrowth: %s -> %s", head.MissAction, candidate.MissAction, head.Growth, candidate.Growth))
		changes++
	}
	headEntries := make(map[string]policy.BaseEntry, len(head.Entries))
	candidateEntries := make(map[string]policy.BaseEntry, len(candidate.Entries))
	headRevoked := make(map[string]struct{}, len(head.RevokedPermitIDs))
	candidateRevoked := make(map[string]struct{}, len(candidate.RevokedPermitIDs))
	for _, entry := range head.Entries {
		headEntries[entry.ID] = entry
	}
	for _, entry := range candidate.Entries {
		candidateEntries[entry.ID] = entry
	}
	for _, id := range head.RevokedPermitIDs {
		headRevoked[id] = struct{}{}
	}
	for _, id := range candidate.RevokedPermitIDs {
		candidateRevoked[id] = struct{}{}
	}
	for id := range headRevoked {
		if _, ok := candidateRevoked[id]; !ok {
			return nil, 0, fmt.Errorf("telegram policy: prior tombstone %s was deleted", id)
		}
		if _, resurrected := candidateEntries[id]; resurrected {
			return nil, 0, fmt.Errorf("telegram policy: tombstoned id %s was resurrected", id)
		}
	}
	var removed []string
	for id, old := range headEntries {
		if current, ok := candidateEntries[id]; ok {
			if !reflect.DeepEqual(old, current) {
				return nil, 0, fmt.Errorf("telegram policy: retained entry %s changed under immutable id", id)
			}
			continue
		}
		if _, ok := candidateRevoked[id]; !ok {
			return nil, 0, fmt.Errorf("telegram policy: removed entry %s is not tombstoned", id)
		}
		removed = append(removed, id)
	}
	sort.Strings(removed)
	removedSet := make(map[string]struct{}, len(removed))
	for _, id := range removed {
		removedSet[id] = struct{}{}
		blocks = append(blocks, "REMOVED AND REVOKED ENTRY\nID: "+id)
		changes++
	}
	var added []policy.BaseEntry
	for id, entry := range candidateEntries {
		if _, ok := headEntries[id]; !ok {
			if len(id) != len("pa_oob_")+32 || !strings.HasPrefix(id, "pa_oob_") || !isLowerHex(id[len("pa_oob_"):]) {
				return nil, 0, fmt.Errorf("telegram policy: newly added entry %s is not an out-of-band policy id", id)
			}
			added = append(added, entry)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].ID < added[j].ID })
	for _, entry := range added {
		blocks = append(blocks, renderPolicyAddedEntry(entry, salt, rules))
		changes++
	}
	var tombstones []string
	for id := range candidateRevoked {
		if _, old := headRevoked[id]; old {
			continue
		}
		if _, paired := removedSet[id]; paired {
			continue
		}
		tombstones = append(tombstones, id)
	}
	sort.Strings(tombstones)
	for _, id := range tombstones {
		blocks = append(blocks, "NEW CERTIFICATE-ONLY REVOCATION\nID: "+id)
		changes++
	}
	return blocks, changes, nil
}

func renderPolicyAddedEntry(entry policy.BaseEntry, salt [32]byte, rules []redact.Rule) string {
	var b strings.Builder
	b.WriteString("ADDED PERMANENT COMMAND\nID: ")
	b.WriteString(entry.ID)
	b.WriteString("\nIdentity digest: ")
	b.WriteString(hex.EncodeToString(entry.Identity.Digest[:]))
	fmt.Fprintf(&b, "\nLiteral length: %d bytes", len(entry.Identity.Literal))
	if preview, hidden, redacted, ok := policyLiteralPreview(entry.Identity.Literal, salt, rules); ok {
		label := "Preview"
		if redacted {
			label = "Preview (redaction markers are labels)"
		}
		fmt.Fprintf(&b, "\n%s: %s\nHidden original bytes: %d", label, preview, hidden)
	} else {
		fmt.Fprintf(&b, "\nPreview: <omitted — safe bounded source mapping unavailable>\nHidden original bytes: %d", len(entry.Identity.Literal))
	}
	b.WriteString("\n")
	b.WriteString(policySourceExactWarning)
	return b.String()
}

func policyLiteralPreview(literal []byte, salt [32]byte, rules []redact.Rule) (preview string, hidden int, wasRedacted bool, ok bool) {
	if len(literal) == 0 || len(rules) == 0 {
		return "", 0, false, false
	}
	original := string(literal)
	redacted, redactOK := safePolicyRedactString(original, salt, rules)
	if !redactOK {
		return "", 0, false, false
	}
	escaped := escapePolicyBytes([]byte(redacted))
	changed := redacted != original
	if len(escaped) <= policyTelegramPreviewBytes {
		return escaped, 0, changed, true
	}
	if changed {
		// Redaction changed byte cardinality. Without a source map, truncating
		// the redacted result cannot prove an exact original hidden-byte count.
		return "", 0, true, false
	}
	var b strings.Builder
	consumed := 0
	for consumed < len(literal) {
		piece := escapePolicyBytes(literal[consumed : consumed+1])
		if b.Len()+len(piece) > policyTelegramPreviewBytes {
			break
		}
		b.WriteString(piece)
		consumed++
	}
	if consumed == 0 {
		return "", 0, false, false
	}
	return b.String(), len(literal) - consumed, false, true
}

func safePolicyRedactString(value string, salt [32]byte, rules []redact.Rule) (redacted string, ok bool) {
	defer func() {
		if recover() != nil {
			redacted = ""
			ok = false
		}
	}()
	return policyRedactString(value, salt, rules)
}

func escapePolicyBytes(raw []byte) string {
	var b strings.Builder
	for _, c := range raw {
		switch {
		case c >= 0x20 && c <= 0x7e && c != '\\':
			b.WriteByte(c)
		case c == '\\':
			b.WriteString(`\\`)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String()
}

func packPolicyDetailParts(requestID, hostKeyFP string, blocks []string) ([]string, error) {
	var bodies []string
	var current strings.Builder
	flush := func() {
		if current.Len() != 0 {
			bodies = append(bodies, current.String())
			current.Reset()
		}
	}
	for _, block := range blocks {
		if block == "" || len(block) > policyTelegramPartBodyBytes {
			return nil, errors.New("telegram policy: logical review item exceeds one part")
		}
		separator := 0
		if current.Len() != 0 {
			separator = 2
		}
		if current.Len()+separator+len(block) > policyTelegramPartBodyBytes {
			flush()
		}
		if current.Len() != 0 {
			current.WriteString("\n\n")
		}
		current.WriteString(block)
	}
	flush()
	if len(bodies) == 0 || len(bodies)+1 > policyTelegramMaxMessages {
		return nil, errors.New("telegram policy: invalid detail part count")
	}
	parts := make([]string, len(bodies))
	for i, body := range bodies {
		parts[i] = fmt.Sprintf("%s\nPOLICY REVIEW PART %d/%d\nRequest ID: %s\nHost fingerprint: %s\n%s",
			policyPermanentAuthorityTitle, i+1, len(bodies), requestID, hostKeyFP, body)
		if len(parts[i]) >= policyTelegramPartBytes {
			return nil, errors.New("telegram policy: numbered detail part exceeds Telegram bound")
		}
	}
	return parts, nil
}

func policyPreset(miss policy.MissAction, growth policy.Growth) string {
	switch {
	case miss == policy.MissActionClassifier && growth == policy.GrowthNone:
		return "auto"
	case miss == policy.MissActionAsk && growth == policy.GrowthOutOfBand:
		return "strict"
	case miss == policy.MissActionAsk && growth == policy.GrowthSignToAdd:
		return "ask"
	default:
		return "custom"
	}
}

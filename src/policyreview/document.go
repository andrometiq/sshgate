package policyreview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/redact"
)

const (
	RendererVersion  = "sshgate-policy-review-v2"
	MaxDocumentBytes = 128 << 10
	MaxDocumentItems = 40
	MaxPreviewBytes  = 512

	SourceExactWarning = "WARNING: source-exact is not exact effect; variables, globs, interpreters, cwd/env, and referenced files can change behavior. Dynamic/interpreter commands should not be made permanent."
)

var reviewRulesDigest = func() string {
	digest := sha256.Sum256([]byte("sshgate-policy-review-rules-v2\x00"))
	return hex.EncodeToString(digest[:])
}()

// RulesDigest returns the replica-bound v2 review-rules identifier digest.
func RulesDigest() string { return reviewRulesDigest }

// Document is ordered to freeze json.Marshal's compact v2 field order.
type Document struct {
	Contract           string   `json:"contract"`
	Purpose            string   `json:"purpose"`
	Principal          string   `json:"principal"`
	RequestID          string   `json:"request_id"`
	ReviewID           string   `json:"review_id"`
	AuthorityID        string   `json:"authority_id"`
	Host               string   `json:"host"`
	Bootstrap          bool     `json:"bootstrap"`
	Epoch              string   `json:"epoch"`
	Revision           string   `json:"revision"`
	MissAction         string   `json:"miss_action"`
	Growth             string   `json:"growth"`
	EntryCount         string   `json:"entry_count"`
	RevocationCount    string   `json:"revocation_count"`
	LogicalChangeCount string   `json:"logical_change_count"`
	AxesChanged        bool     `json:"axes_changed"`
	Items              []Item   `json:"items"`
	Warnings           []string `json:"warnings"`
}

// Item is the closed union of the four v2 item shapes. Declaration order is
// wire-significant; omitempty keeps non-applicable fields absent, never null.
type Item struct {
	Kind           string   `json:"kind"`
	ID             string   `json:"id,omitempty"`
	IdentityDigest string   `json:"identity_digest,omitempty"`
	LiteralLength  string   `json:"literal_length,omitempty"`
	HiddenBytes    string   `json:"hidden_bytes,omitempty"`
	Preview        *Preview `json:"preview,omitempty"`
}

type Preview struct {
	Text     string `json:"text"`
	Redacted bool   `json:"redacted"`
}

type DocumentInput struct {
	Purpose, Principal, RequestID, ReviewID, AuthorityID string
	Bootstrap                                            bool
	Head                                                 *policy.BaseManifest
	Candidate                                            policy.BaseManifest
	NoOp                                                 bool
	Salt                                                 [32]byte
	Rules                                                []redact.Rule
	RedactString                                         RedactString
}

type RenderedDocument struct {
	JSON      []byte
	ItemCount int
}

// RenderDocument produces the complete compact sshgate-policy-review-v2
// document. It never falls back to an unredacted preview when the bounded
// source mapping is unavailable.
func RenderDocument(input DocumentInput) (RenderedDocument, error) {
	if input.Purpose == "" || input.Principal == "" || input.RequestID == "" || input.ReviewID == "" || input.AuthorityID == "" {
		return RenderedDocument{}, errors.New("policy review: incomplete document identity")
	}
	if err := input.Candidate.Validate(); err != nil {
		return RenderedDocument{}, err
	}
	if input.Bootstrap != (input.Head == nil) || (input.NoOp && input.Head == nil) {
		return RenderedDocument{}, errors.New("policy review: inconsistent predecessor mapping")
	}

	changes := ChangeSet{}
	var err error
	if !input.NoOp {
		changes, err = Changes(input.Head, input.Candidate)
		if err != nil {
			return RenderedDocument{}, err
		}
	}
	items := make([]Item, 0, len(changes.AddedEntries)+len(changes.RemovedIDs)+len(changes.NewRevokedIDs)+1)
	for _, entry := range changes.AddedEntries {
		item := Item{
			Kind: "added", ID: entry.ID, IdentityDigest: hex.EncodeToString(entry.Identity.Digest[:]),
			LiteralLength: strconv.Itoa(len(entry.Identity.Literal)), HiddenBytes: strconv.Itoa(len(entry.Identity.Literal)),
		}
		if text, hidden, redacted, ok := LiteralPreview(entry.Identity.Literal, MaxPreviewBytes, input.Salt, input.Rules, input.RedactString); ok {
			item.HiddenBytes = strconv.Itoa(hidden)
			item.Preview = &Preview{Text: text, Redacted: redacted}
		}
		items = append(items, item)
	}
	for _, id := range changes.RemovedIDs {
		items = append(items, Item{Kind: "removed", ID: id})
	}
	for _, id := range changes.NewRevokedIDs {
		items = append(items, Item{Kind: "revoked", ID: id})
	}
	if changes.AxesChanged {
		items = append(items, Item{Kind: "axes"})
	}
	if len(items) > MaxDocumentItems {
		return RenderedDocument{}, errors.New("policy review: document item bound exceeded")
	}
	warnings := []string{}
	if len(changes.AddedEntries) != 0 {
		warnings = append(warnings, SourceExactWarning)
	}
	document := Document{
		Contract: RendererVersion, Purpose: input.Purpose, Principal: input.Principal,
		RequestID: input.RequestID, ReviewID: input.ReviewID, AuthorityID: input.AuthorityID,
		Host: input.Candidate.Host, Bootstrap: input.Bootstrap,
		Epoch: strconv.FormatUint(input.Candidate.Epoch, 10), Revision: strconv.FormatUint(input.Candidate.Revision, 10),
		MissAction: string(input.Candidate.MissAction), Growth: string(input.Candidate.Growth),
		EntryCount: strconv.Itoa(len(input.Candidate.Entries)), RevocationCount: strconv.Itoa(len(input.Candidate.RevokedPermitIDs)),
		LogicalChangeCount: strconv.Itoa(changes.LogicalChanges), AxesChanged: changes.AxesChanged,
		Items: items, Warnings: warnings,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return RenderedDocument{}, err
	}
	if len(encoded) > MaxDocumentBytes {
		return RenderedDocument{}, errors.New("policy review: rendered document exceeds byte bound")
	}
	return RenderedDocument{JSON: encoded, ItemCount: len(items)}, nil
}

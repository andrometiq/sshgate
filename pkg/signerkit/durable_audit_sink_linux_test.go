//go:build linux

package signerkit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/policy"
	"golang.org/x/sys/unix"
)

func durableAuditTestPath(t testing.TB) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "policy-audit.jsonl")
}

func openDurableAuditForTest(t testing.TB, path string) *DurableFileAuditSink {
	t.Helper()
	sink, err := NewDurableFileAuditSink(path)
	if err != nil {
		t.Fatal(err)
	}
	return sink
}

func TestDurableAuditReadyAppendAndStickyIdentityFailure(t *testing.T) {
	path := durableAuditTestPath(t)
	sink := openDurableAuditForTest(t, path)
	defer sink.Close()
	event := AuditCall{Time: time.Unix(1, 0).UTC(), RequestID: "request", HostKeyFP: "host", Command: "true"}
	if err := sink.Call(context.Background(), event); err == nil {
		t.Fatal("call succeeded before readiness")
	}
	if err := sink.PolicyAuditReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sink.Call(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	want, err := marshalAuditLine(auditLine{Kind: "call", Event: event})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("durable bytes = %q, %v; want %q", got, err, want)
	}

	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	first := sink.Call(context.Background(), event)
	second := sink.PolicyAuditReady(context.Background())
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("identity failure was not sticky: first=%v second=%v", first, second)
	}
}

func TestPolicyAuditEvidenceOrderedCanonicalEncoding(t *testing.T) {
	_, publicKey := goldenSignerKey()
	keyID, err := policy.SignerKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	evidence := PolicyAuditEvidence{
		ExpectedSignerKeyID: keyID, FrozenSignerKeyID: keyID,
		FrozenSignerPublicKeyB64: base64.StdEncoding.EncodeToString(publicKey),
		TrustedEpoch:             "1", TrustedRevision: "2", ClaimedEpoch: "3", ClaimedRevision: "4",
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"expected_signer_key_id":"` + keyID + `","frozen_signer_key_id":"` + keyID + `","frozen_signer_public_key_b64":"` + base64.StdEncoding.EncodeToString(publicKey) + `","trusted_epoch":"1","trusted_revision":"2","claimed_epoch":"3","claimed_revision":"4"}`
	if string(encoded) != want {
		t.Fatalf("evidence bytes = %s; want %s", encoded, want)
	}
	metadata := PolicyAuditMetadata{AuthorityID: "pauth_0123456789abcdef0123456789abcdef", Evidence: &evidence}
	canonical, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicyAuditMetadata
	if err := json.Unmarshal(canonical, &decoded); err != nil || decoded.Evidence == nil || decoded.Evidence.ClaimedRevision != "4" {
		t.Fatalf("strict evidence round trip = %+v, %v", decoded.Evidence, err)
	}

	bad := evidence
	bad.FrozenSignerKeyID = strings.Repeat("0", 64)
	if _, err := json.Marshal(PolicyAuditMetadata{AuthorityID: metadata.AuthorityID, Evidence: &bad}); err == nil {
		t.Fatal("derived frozen key-ID corruption accepted")
	}
	bad = evidence
	bad.TrustedRevision = ""
	if _, err := json.Marshal(PolicyAuditMetadata{AuthorityID: metadata.AuthorityID, Evidence: &bad}); err == nil {
		t.Fatal("partial trusted predecessor evidence accepted")
	}
	bad = evidence
	bad.ClaimedEpoch = "01"
	if _, err := json.Marshal(PolicyAuditMetadata{AuthorityID: metadata.AuthorityID, Evidence: &bad}); err == nil {
		t.Fatal("noncanonical predecessor integer accepted")
	}
}

func TestDurableAuditRejectsUnsafeParentAndFile(t *testing.T) {
	t.Run("parent mode", func(t *testing.T) {
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDurableFileAuditSink(filepath.Join(parent, "audit")); err == nil {
			t.Fatal("unsafe parent mode accepted")
		}
	})
	t.Run("parent symlink", func(t *testing.T) {
		realParent := t.TempDir()
		linkParent := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(realParent, linkParent); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDurableFileAuditSink(filepath.Join(linkParent, "audit")); err == nil {
			t.Fatal("parent symlink accepted")
		}
	})
	t.Run("file symlink", func(t *testing.T) {
		path := durableAuditTestPath(t)
		target := filepath.Join(filepath.Dir(path), "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDurableFileAuditSink(path); err == nil {
			t.Fatal("audit symlink accepted")
		}
	})
}

func TestDurableAuditRecoveryFramingCases(t *testing.T) {
	complete := []byte("{\"legacy\":true}\n")
	cases := []struct {
		name      string
		initial   []byte
		wantEvent bool
		prefix    []byte
	}{
		{name: "empty"},
		{name: "complete final", initial: complete, prefix: complete},
		{name: "no newline", initial: []byte("partial"), wantEvent: true},
		{name: "complete plus partial", initial: append(append([]byte(nil), complete...), []byte("partial")...), wantEvent: true, prefix: complete},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := durableAuditTestPath(t)
			if err := os.WriteFile(path, test.initial, 0o600); err != nil {
				t.Fatal(err)
			}
			sink := openDurableAuditForTest(t, path)
			sink.now = func() time.Time { return time.Unix(100, 0) }
			if err := sink.PolicyAuditReady(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := sink.Close(); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(body, test.prefix) {
				t.Fatalf("acknowledged prefix changed: %q", body)
			}
			remaining := body[len(test.prefix):]
			if test.wantEvent {
				if len(remaining) == 0 || remaining[len(remaining)-1] != '\n' || bytes.Contains(remaining, []byte("partial")) {
					t.Fatalf("recovery event/framing = %q", remaining)
				}
			} else if len(remaining) != 0 {
				t.Fatalf("clean file changed: %q", remaining)
			}
			if _, err := os.Stat(path + durableAuditRecoveryIntentSuffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("intent remains after readiness: %v", err)
			}
		})
	}
}

func TestDurableAuditCrashInjectionMatrix(t *testing.T) {
	prefix := []byte("{\"acknowledged\":true}\n")
	points := []durableAuditFaultPoint{
		durableAuditFaultAfterIntentDurable,
		durableAuditFaultAfterTruncate,
		durableAuditFaultAfterTruncateDurable,
		durableAuditFaultBeforeRecoveryAppend,
		durableAuditFaultAfterRecoveryAppend,
		durableAuditFaultAfterRecoveryDurable,
		durableAuditFaultMidDuplicateAppend,
		durableAuditFaultAfterIntentUnlink,
		durableAuditFaultAfterIntentClearDurable,
	}
	for _, point := range points {
		t.Run(string(point), func(t *testing.T) {
			path := durableAuditTestPath(t)
			if err := os.WriteFile(path, append(append([]byte(nil), prefix...), []byte("torn")...), 0o600); err != nil {
				t.Fatal(err)
			}
			sink := openDurableAuditForTest(t, path)
			sink.now = func() time.Time { return time.Unix(200, 0) }
			sink.faultHook = func(got durableAuditFaultPoint, current *DurableFileAuditSink, record []byte) error {
				if got != point {
					return nil
				}
				if point == durableAuditFaultBeforeRecoveryAppend || point == durableAuditFaultMidDuplicateAppend {
					if _, err := unix.Write(current.fileFD, record[:len(record)/2]); err != nil {
						return err
					}
				}
				return errors.New("injected crash")
			}
			first := sink.PolicyAuditReady(context.Background())
			second := sink.PolicyAuditReady(context.Background())
			if first == nil || second == nil || first.Error() != second.Error() {
				t.Fatalf("fault %s was not sticky: first=%v second=%v", point, first, second)
			}
			_ = sink.Close()

			reopened := openDurableAuditForTest(t, path)
			reopened.now = func() time.Time { return time.Unix(201, 0) }
			if err := reopened.PolicyAuditReady(context.Background()); err != nil {
				t.Fatalf("reopen recovery: %v", err)
			}
			_ = reopened.Close()
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(body, prefix) || bytes.Contains(body[len(prefix):], []byte("torn")) || len(body) == len(prefix) {
				t.Fatalf("recovered bytes lost prefix/event: %q", body)
			}
			if _, err := os.Stat(path + durableAuditRecoveryIntentSuffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recovery still owed: %v", err)
			}
		})
	}
}

func TestDurableAuditRepeatedCrashesAndPartialDuplicateAreIdempotent(t *testing.T) {
	prefix := []byte("{\"acknowledged\":true}\n")
	path := durableAuditTestPath(t)
	if err := os.WriteFile(path, append(append([]byte(nil), prefix...), []byte("torn")...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, point := range []durableAuditFaultPoint{durableAuditFaultAfterIntentDurable, durableAuditFaultAfterTruncate, durableAuditFaultBeforeRecoveryAppend} {
		sink := openDurableAuditForTest(t, path)
		sink.faultHook = func(got durableAuditFaultPoint, current *DurableFileAuditSink, record []byte) error {
			if got != point {
				return nil
			}
			if point == durableAuditFaultBeforeRecoveryAppend {
				_, _ = unix.Write(current.fileFD, record[:len(record)/3])
			}
			return errors.New("repeated crash")
		}
		if err := sink.PolicyAuditReady(context.Background()); err == nil {
			t.Fatalf("fault %s did not fire", point)
		}
		_ = sink.Close()
	}
	sink := openDurableAuditForTest(t, path)
	sink.faultHook = func(point durableAuditFaultPoint, _ *DurableFileAuditSink, _ []byte) error {
		if point == durableAuditFaultAfterRecoveryDurable {
			return errors.New("leave complete recovery event and intent")
		}
		return nil
	}
	if err := sink.PolicyAuditReady(context.Background()); err == nil {
		t.Fatal("post-durability fault did not fire")
	}
	_ = sink.Close()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	completeRecovery := body[len(prefix):]
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(completeRecovery[:len(completeRecovery)/2]); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	reopened := openDurableAuditForTest(t, path)
	if err := reopened.PolicyAuditReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
	final, _ := os.ReadFile(path)
	if !bytes.Equal(final, append(append([]byte(nil), prefix...), completeRecovery...)) {
		t.Fatalf("partial duplicate was not removed exactly:\n got %q\nwant %q", final, append(prefix, completeRecovery...))
	}
}

func TestRecoveryIntentStrictEncodingFailuresAreSticky(t *testing.T) {
	tests := map[string]func(auditRecoveryIntent) []byte{
		"oversize": func(intent auditRecoveryIntent) []byte {
			return append(bytes.Repeat([]byte{'x'}, maxRecoveryIntentBytes), '\n')
		},
		"unknown field": func(intent auditRecoveryIntent) []byte {
			body, _ := json.Marshal(intent)
			return append(append(body[:len(body)-1], []byte(`,"unknown":true}`)...), '\n')
		},
		"missing field": func(intent auditRecoveryIntent) []byte {
			return []byte(fmt.Sprintf(`{"contract":%q,"recovery_id":%q,"audit_dev":%q,"audit_ino":%q,"observed_length":%q}`+"\n", intent.Contract, intent.RecoveryID, intent.AuditDev, intent.AuditIno, intent.ObservedLength))
		},
		"bad id": func(intent auditRecoveryIntent) []byte {
			intent.RecoveryID = "recv_UPPER"
			return mustJSONLine(t, intent)
		},
		"signed numeric": func(intent auditRecoveryIntent) []byte { intent.AuditDev = "+1"; return mustJSONLine(t, intent) },
		"padded numeric": func(intent auditRecoveryIntent) []byte { intent.AuditIno = "01"; return mustJSONLine(t, intent) },
		"overflow numeric": func(intent auditRecoveryIntent) []byte {
			intent.ObservedLength = "18446744073709551616"
			return mustJSONLine(t, intent)
		},
		"offset beyond length": func(intent auditRecoveryIntent) []byte {
			intent.LastCompleteOffset = "999"
			return mustJSONLine(t, intent)
		},
		"remarshal inequality": func(intent auditRecoveryIntent) []byte { return append([]byte(" "), mustJSONLine(t, intent)...) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			path := durableAuditTestPath(t)
			if err := os.WriteFile(path, []byte("complete\ntorn"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stat unix.Stat_t
			if err := unix.Stat(path, &stat); err != nil {
				t.Fatal(err)
			}
			intent := auditRecoveryIntent{
				Contract:   durableAuditRecoveryIntentContract,
				RecoveryID: "recv_0123456789abcdef0123456789abcdef",
				AuditDev:   strconv.FormatUint(uint64(stat.Dev), 10), AuditIno: strconv.FormatUint(stat.Ino, 10),
				ObservedLength: strconv.FormatInt(stat.Size, 10), LastCompleteOffset: strconv.Itoa(len("complete\n")),
			}
			if err := os.WriteFile(path+durableAuditRecoveryIntentSuffix, mutate(intent), 0o600); err != nil {
				t.Fatal(err)
			}
			sink := openDurableAuditForTest(t, path)
			defer sink.Close()
			first := sink.PolicyAuditReady(context.Background())
			second := sink.PolicyAuditReady(context.Background())
			if first == nil || second == nil || first.Error() != second.Error() {
				t.Fatalf("malformed intent not sticky: first=%v second=%v", first, second)
			}
		})
	}
}

func TestRecoveryEventStrictEncodingFailuresAreSticky(t *testing.T) {
	tests := map[string]func(AuditCall) (string, AuditCall){
		"wrong kind":      func(event AuditCall) (string, AuditCall) { return "call", event },
		"wrong lifecycle": func(event AuditCall) (string, AuditCall) { event.Lifecycle = "rotate"; return "lifecycle", event },
		"nil recovery":    func(event AuditCall) (string, AuditCall) { event.Recovery = nil; return "lifecycle", event },
		"mismatched id": func(event AuditCall) (string, AuditCall) {
			event.Recovery.RecoveryID = "recv_ffffffffffffffffffffffffffffffff"
			return "lifecycle", event
		},
		"signed before": func(event AuditCall) (string, AuditCall) {
			event.Recovery.BeforeLength = "+9"
			return "lifecycle", event
		},
		"padded after": func(event AuditCall) (string, AuditCall) {
			event.Recovery.AfterLength = "09"
			return "lifecycle", event
		},
		"unrelated field": func(event AuditCall) (string, AuditCall) { event.Reason = "unexpected"; return "lifecycle", event },
		"nil time":        func(event AuditCall) (string, AuditCall) { event.Time = time.Time{}; return "lifecycle", event },
		"policy field": func(event AuditCall) (string, AuditCall) {
			event.Policy = &PolicyAuditMetadata{ErrorCode: "policy_not_supported"}
			return "lifecycle", event
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			path := durableAuditTestPath(t)
			prefix := []byte("complete\n")
			if err := os.WriteFile(path, prefix, 0o600); err != nil {
				t.Fatal(err)
			}
			var stat unix.Stat_t
			if err := unix.Stat(path, &stat); err != nil {
				t.Fatal(err)
			}
			intent := auditRecoveryIntent{
				Contract:   durableAuditRecoveryIntentContract,
				RecoveryID: "recv_0123456789abcdef0123456789abcdef",
				AuditDev:   strconv.FormatUint(uint64(stat.Dev), 10), AuditIno: strconv.FormatUint(stat.Ino, 10),
				ObservedLength: strconv.Itoa(len(prefix)), LastCompleteOffset: strconv.Itoa(len(prefix)),
			}
			event := AuditCall{Time: time.Unix(1, 0).UTC(), Lifecycle: recoveryLifecycle, Recovery: &AuditRecoveryMetadata{
				RecoveryID: intent.RecoveryID, BeforeLength: intent.ObservedLength, AfterLength: intent.LastCompleteOffset,
			}}
			kind, event := mutate(event)
			line, err := marshalAuditLine(auditLine{Kind: kind, Event: event})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(prefix, line...), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+durableAuditRecoveryIntentSuffix, mustJSONLine(t, intent), 0o600); err != nil {
				t.Fatal(err)
			}
			sink := openDurableAuditForTest(t, path)
			defer sink.Close()
			if err := sink.PolicyAuditReady(context.Background()); err == nil {
				t.Fatal("malformed recovery event accepted")
			}
		})
	}
}

func mustJSONLine(t testing.TB, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(body, '\n')
}

func TestRecoveryFieldIsByteInvisibleWhenAbsent(t *testing.T) {
	type legacyAuditCall struct {
		Time           time.Time            `json:"time"`
		RequestID      string               `json:"request_id,omitempty"`
		HostKeyFP      string               `json:"host_key_fp,omitempty"`
		Command        string               `json:"command,omitempty"`
		CommandSHA256  string               `json:"command_sha256,omitempty"`
		CommandsSHA256 string               `json:"commands_sha256,omitempty"`
		CommandCount   int                  `json:"command_count,omitempty"`
		HostKeyFPs     []string             `json:"host_key_fps,omitempty"`
		Phase          string               `json:"phase,omitempty"`
		Lifecycle      string               `json:"lifecycle,omitempty"`
		Reason         string               `json:"reason,omitempty"`
		Operator       *Operator            `json:"operator,omitempty"`
		Policy         *PolicyAuditMetadata `json:"policy,omitempty"`
	}
	type legacyLine struct {
		Kind  string          `json:"kind"`
		Event legacyAuditCall `json:"event"`
	}
	cases := []AuditCall{
		{Time: time.Unix(1, 0).UTC(), RequestID: "ordinary", Command: "true"},
		{Time: time.Unix(2, 0).UTC(), Lifecycle: "rotate", Reason: "owner", Operator: &Operator{ID: "op"}},
		{Time: time.Unix(3, 0).UTC(), Policy: &PolicyAuditMetadata{AuthorityID: "pauth_0123456789abcdef0123456789abcdef"}},
	}
	for _, event := range cases {
		got, err := marshalAuditLine(auditLine{Kind: "call", Event: event})
		if err != nil {
			t.Fatal(err)
		}
		legacy := legacyAuditCall{
			Time: event.Time, RequestID: event.RequestID, HostKeyFP: event.HostKeyFP, Command: event.Command,
			CommandSHA256: event.CommandSHA256, CommandsSHA256: event.CommandsSHA256, CommandCount: event.CommandCount,
			HostKeyFPs: event.HostKeyFPs, Phase: event.Phase, Lifecycle: event.Lifecycle, Reason: event.Reason,
			Operator: event.Operator, Policy: event.Policy,
		}
		want, err := json.Marshal(legacyLine{Kind: "call", Event: legacy})
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, '\n')
		if !bytes.Equal(got, want) || bytes.Contains(got, []byte(`"recovery"`)) {
			t.Fatalf("Recovery changed legacy encoding:\n got %q\nwant %q", got, want)
		}
	}
}

func TestPolicyAuditMetadataAuthorityBiconditionalCodec(t *testing.T) {
	authority := "pauth_0123456789abcdef0123456789abcdef"
	valid := PolicyAuditMetadata{AuthorityID: authority}
	body, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicyAuditMetadata
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.AuthorityID != authority {
		t.Fatalf("valid authority round trip = %#v, %v", decoded, err)
	}
	if _, err := json.Marshal(PolicyAuditMetadata{}); err == nil {
		t.Fatal("missing authority on ordinary metadata accepted")
	}
	refusal := PolicyAuditMetadata{ErrorCode: "policy_not_supported"}
	body, err = json.Marshal(refusal)
	if err != nil || bytes.Contains(body, []byte("authority_id")) {
		t.Fatalf("compatibility refusal encoding = %q, %v", body, err)
	}
	refusal.AuthorityID = authority
	if _, err := json.Marshal(refusal); err == nil {
		t.Fatal("policy_not_supported metadata carrying authority accepted")
	}
	missing := strings.Replace(string(body), `"error_code":"policy_not_supported"`, `"error_code":"signer_key_changed"`, 1)
	if err := json.Unmarshal([]byte(missing), &decoded); err == nil {
		t.Fatal("decoded non-refusal metadata without authority")
	}
}

var _ DurableAuditSink = (*DurableFileAuditSink)(nil)

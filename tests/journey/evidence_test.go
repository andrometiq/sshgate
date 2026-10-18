//go:build journey

package journey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

const journeyEvidenceLimit = 8 << 20

type journeyEvidence struct {
	mu         sync.Mutex
	directory  string
	transcript []json.RawMessage
	size       int
}

// Decode first so escaped strings and nested protocol results use the same scrubber.
func scrubJourneyEvidence(value any) (any, bool) {
	switch value := value.(type) {
	case string:
		if containsSecret([]byte(value)) {
			return "[synthetic plaintext withheld]", true
		}
		clean, ok := redact.RedactString(value, [32]byte{}, rules.Combined())
		if !ok {
			return "[evidence withheld]", true
		}
		return clean, false
	case []any:
		leaked := false
		for i := range value {
			clean, found := scrubJourneyEvidence(value[i])
			value[i] = clean
			leaked = leaked || found
		}
		return value, leaked
	case map[string]any:
		clean := make(map[string]any, len(value))
		leaked := false
		for key, item := range value {
			cleanKey, keyLeak := scrubJourneyEvidence(key)
			cleanItem, itemLeak := scrubJourneyEvidence(item)
			clean[cleanKey.(string)] = cleanItem
			leaked = leaked || keyLeak || itemLeak
		}
		return clean, leaked
	default:
		return value, false
	}
}

func (e *journeyEvidence) append(scenario string, value any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	data, err := json.Marshal(map[string]any{"at": time.Now().UTC(), "scenario": scenario, "value": value})
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("evidence item exceeds 1 MiB")
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	clean, leaked := scrubJourneyEvidence(decoded)
	data, err = json.Marshal(clean)
	if err != nil {
		return err
	}
	// Include separators and the final summary's brackets in the same bound.
	if e.size+len(data)+1 > journeyEvidenceLimit-2 {
		return errors.New("evidence exceeds 8 MiB")
	}
	if e.directory != "" {
		if err := os.MkdirAll(e.directory, 0700); err != nil {
			return err
		}
		file, err := os.OpenFile(filepath.Join(e.directory, "main-evidence.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err == nil && info.Size()+int64(len(data)+1) > journeyEvidenceLimit {
			err = errors.New("incremental evidence exceeds 8 MiB")
		}
		if err == nil {
			_, err = file.Write(append(data, '\n'))
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	e.transcript = append(e.transcript, data)
	e.size += len(data) + 1
	if leaked {
		return errors.New("synthetic plaintext leaked; evidence scrubbed")
	}
	return nil
}

func (e *journeyEvidence) record(t *testing.T, value any) {
	t.Helper()
	if err := e.append(t.Name(), value); err != nil {
		t.Fatal(err)
	}
}

func (e *journeyEvidence) summary(t *testing.T) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t.Helper()
	if e.directory == "" {
		return
	}
	// append stores only scrubbed records, including when a leak fails the test.
	data, err := json.Marshal(e.transcript)
	if err == nil {
		err = os.WriteFile(filepath.Join(e.directory, "main-evidence.json"), data, 0600)
	}
	if err != nil {
		t.Error(err)
	}
}

func TestJourneyIncrementalEvidence(t *testing.T) {
	e := &journeyEvidence{directory: t.TempDir()}
	secret := "unit-password-value"
	if err := e.append("test", map[string]any{"nested": []any{"PASSWORD=" + secret}}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{journeySentinel, base64.StdEncoding.EncodeToString([]byte(journeySentinel))} {
		if err := e.append("test", value); err == nil {
			t.Fatal("leak did not fail")
		}
	}
	path := filepath.Join(e.directory, "main-evidence.jsonl")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if containsSecret(before) || strings.Contains(string(before), secret) {
		t.Fatal("secret persisted")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(before)), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatal("invalid JSON line")
		}
	}
	e.size = journeyEvidenceLimit - 2
	if err := e.append("test", "over cap"); err == nil {
		t.Fatal("cap not enforced")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("cap changed persisted evidence")
	}
	// A new collector must also honor bytes already on disk.
	if err := os.Truncate(path, journeyEvidenceLimit); err != nil {
		t.Fatal(err)
	}
	fresh := &journeyEvidence{directory: e.directory}
	if err := fresh.append("test", "over disk cap"); err == nil {
		t.Fatal("disk cap not enforced")
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != journeyEvidenceLimit {
		t.Fatal("disk cap changed file size")
	}
	if err := e.append("test", strings.Repeat("x", (1<<20)+1)); err == nil {
		t.Fatal("item cap not enforced")
	}
	e.summary(t)
	summary, err := os.ReadFile(filepath.Join(e.directory, "main-evidence.json"))
	if err != nil || containsSecret(summary) || strings.Contains(string(summary), secret) {
		t.Fatal("unsafe summary")
	}
}

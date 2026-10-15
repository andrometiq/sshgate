//go:build linux

package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"golang.org/x/sys/unix"
)

func storeJob(t *testing.T, n int, large bool) ap.R2 {
	t.Helper()
	specs := []st.StepSpec{st.Write("touch /tmp/job", 60)}
	if large {
		specs = nil
		for i := 0; i < 32; i++ {
			specs = append(specs, st.Write(strings.Repeat("<", ap.MaxTotalBytes/32), 60))
		}
	}
	d := st.JobDraft(st.ID(n), ap.CoordinatorExecutor, st.T0, specs...)
	if large {
		d.Rationale = strings.Repeat("<", ap.MaxRationaleBytes)
		d.CommandJob.MaxOutputBytes = ap.MaxStreamOutputBytes
	}
	hash, err := ap.DraftHash(d)
	if err != nil {
		t.Fatal(err)
	}
	token := st.Token(d.RequestID)
	job := ap.R2{Version: ap.R2Version, RequestID: d.RequestID, InputHash: hash, Draft: d, DraftHash: hash, CreatedAt: st.T0, Reservation: int64(ap.R2Reservation(d, ap.PermittedOutputBytes(d))), ClaimToken: hex.EncodeToString(token[:])}
	for i := range specs {
		job.Steps = append(job.Steps, ap.JobStep{Ordinal: i + 1})
	}
	return job
}

func jobStore(t *testing.T) (*Local, *JobStore, string) {
	t.Helper()
	runtime, config := roots(t)
	local := openLocal(t, runtime, config)
	s, err := local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return local, s, filepath.Join(config, "executor")
}

func TestJobStoreRoundTrip(t *testing.T) {
	local, s, dir := jobStore(t)
	job := storeJob(t, 1, false)
	if err := s.Commit(job); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ap.JobKey(job.RequestID))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	loaded, err := s.Load(job.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Draft.CommandJob.Steps[0].ExactCommand = "mutated"
	loaded, err = s.Load(job.RequestID)
	if err != nil || loaded.Draft.CommandJob.Steps[0].ExactCommand != job.Draft.CommandJob.Steps[0].ExactCommand {
		t.Fatal("load leaked mutable state", err)
	}
	s.update = func(func(*securestate.Transaction) error) error { t.Fatal("read attempted mutation"); return nil }
	if _, err = s.List(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("read changed file")
	}
	s.Close()
	s, err = local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	files, listErr := s.List()
	if listErr != nil || len(files) != 1 || files[0].RequestID != job.RequestID {
		t.Fatal("restart lost job index", files, listErr)
	}
	loaded, err = s.Load(files[0].RequestID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := ap.EncodeR2(loaded)
	if !bytes.Equal(encoded, original) {
		t.Fatal("restart changed record")
	}
	if err = s.Remove(job.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file not removed", err)
	}
	if _, err = s.Load(job.RequestID); !errors.Is(err, securestate.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestJobQuarantine(t *testing.T) {
	for _, kind := range []string{"json", "noncanonical", "version", "wrong-key", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			local, s, dir := jobStore(t)
			job := storeJob(t, 1, false)
			body, err := ap.EncodeR2(job)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "json":
				body = []byte("{")
			case "noncanonical":
				body = append(body, '\n')
			case "version":
				body = bytes.Replace(body, []byte(`"version":1`), []byte(`"version":9`), 1)
			case "wrong-key":
				other := storeJob(t, 2, false)
				body, _ = ap.EncodeR2(other)
			case "oversize":
				body = bytes.Repeat([]byte("x"), ap.R2Max+1)
			}
			path := filepath.Join(dir, ap.JobKey(job.RequestID))
			s.Close()
			if err = os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				s, err = local.OpenJobStore()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.Load(job.RequestID); !errors.Is(err, ErrReportAuthLost) {
					t.Fatal("quarantine load", err)
				}
				files, err := s.List()
				if err != nil || len(files) != 1 || !files[0].Quarantined || files[0].RequestID != "" || files[0].EncodedBytes != int64(len(body)) {
					t.Fatal("quarantine metadata", files, err)
				}
				if err = s.Commit(job); !errors.Is(err, ErrReportAuthLost) {
					t.Fatal("quarantine overwritten", err)
				}
				if err = s.Remove(job.RequestID); !errors.Is(err, ErrReportAuthLost) {
					t.Fatal("quarantine removed", err)
				}
				s.Close()
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, after) {
				t.Fatal("quarantine changed", err)
			}
		})
	}
}

func TestJobStoreHygiene(t *testing.T) {
	for _, kind := range []string{"unknown-name", "bad-padding", "short-key", "uppercase-key", "symlink", "directory", "fifo", "mode", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			local, s, dir := jobStore(t)
			s.Close()
			name := ap.JobKey(st.ID(1))
			switch kind {
			case "unknown-name":
				name = "unexpected"
			case "bad-padding":
				name = name[:len(name)-1] + "b"
			case "short-key":
				name = name[:len(name)-1]
			case "uppercase-key":
				name = strings.ToUpper(name)
			}
			path := filepath.Join(dir, name)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("/dev/null", path)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			default:
				err = os.WriteFile(path, []byte("{}"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "mode" {
				if err = os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "hardlink" {
				if err = os.Link(path, filepath.Join(dir, ap.JobKey(st.ID(2)))); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := local.OpenJobStore()
			if err == nil {
				opened.Close()
				t.Fatal("unsafe store opened")
			}
		})
	}
}

func TestJobOrphanTemps(t *testing.T) {
	local, s, dir := jobStore(t)
	s.Close()
	path := filepath.Join(dir, ".tmp-"+strings.Repeat("a", 24))
	child := exec.Command(os.Args[0], "-test.run=^TestJobOrphanChild$")
	child.Env = append(os.Environ(), "EXECUTOR_ORPHAN_PATH="+path)
	if err := child.Run(); err == nil {
		t.Fatal("child did not die")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("child left no temp", err)
	}
	s, err := local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temp survived", err)
	}
	files, err := s.List()
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
}

func TestJobCommitRefusalAndUncertainty(t *testing.T) {
	for _, kind := range []string{"refused", "uncertain-absent", "uncertain-landed", "remove-uncertain"} {
		t.Run(kind, func(t *testing.T) {
			local, s, _ := jobStore(t)
			job := storeJob(t, 1, false)
			if err := s.Commit(job); err != nil {
				t.Fatal(err)
			}
			next, answer := ap.ApplyJob(job, ap.SetOutcome{Outcome: ap.JobOutcome{Kind: ap.OutcomeDenied}}, ap.Now{Wall: st.T0}, st.Epoch(1))
			if !answer.Changed {
				t.Fatal(answer)
			}
			s.update = func(fn func(*securestate.Transaction) error) error {
				if kind == "uncertain-landed" || kind == "remove-uncertain" {
					if err := s.disk.Update(fn); err != nil {
						return err
					}
				}
				if kind == "refused" {
					return errors.New("injected refusal")
				}
				return securestate.ErrCommitUncertain
			}
			var err error
			if kind == "remove-uncertain" {
				err = s.Remove(job.RequestID)
			} else {
				err = s.Commit(next)
			}
			if err == nil {
				t.Fatal("injection not returned")
			}
			if kind == "refused" {
				got, err := s.Load(job.RequestID)
				if err != nil || got.Outcome != nil {
					t.Fatal("refusal changed snapshot", err)
				}
				return
			}
			if _, err = s.Load(job.RequestID); !errors.Is(err, securestate.ErrCommitUncertain) {
				t.Fatal("poisoned load", err)
			}
			if _, err = s.List(); !errors.Is(err, securestate.ErrCommitUncertain) {
				t.Fatal("poisoned list", err)
			}
			if err = s.Commit(job); !errors.Is(err, securestate.ErrCommitUncertain) {
				t.Fatal("poisoned commit", err)
			}
			if err = s.Remove(job.RequestID); !errors.Is(err, securestate.ErrCommitUncertain) {
				t.Fatal("poisoned remove", err)
			}
			s.Close()
			s, err = local.OpenJobStore()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, err := s.Load(job.RequestID)
			if kind == "remove-uncertain" {
				if !errors.Is(err, securestate.ErrNotFound) {
					t.Fatal(err)
				}
				return
			}
			if err != nil || (got.Outcome != nil) != (kind == "uncertain-landed") {
				t.Fatal("restart did not use disk", err)
			}
		})
	}
}

func TestJobStoreMaximumBodies(t *testing.T) {
	local, s, _ := jobStore(t)
	job := storeJob(t, 1, true)
	body := bytes.Repeat([]byte{0xff, '<', 0xfe, '>', '&', 0, 0xc3, 0x80}, ap.MaxJobOutputBytes/64/8)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	exit := 0
	for i := range job.Steps {
		var answer ap.JobAnswer
		job, answer = ap.ApplyJob(job, ap.RecordResult{Ordinal: i + 1, Result: ap.StepResult{Status: ap.StepSucceeded, ExitCode: &exit, StdoutBytes: int64(len(body)), StderrBytes: int64(len(body)), StdoutSHA256: digest, StderrSHA256: digest, Stdout: body, Stderr: body}}, ap.Now{Wall: st.T0}, st.Epoch(1))
		if !answer.Changed {
			t.Fatal(answer)
		}
	}
	if err := s.Commit(job); err != nil {
		t.Fatal(err)
	}
	files, err := s.List()
	if err != nil || files[0].EncodedBytes > job.Reservation || files[0].EncodedBytes > ap.R2Max {
		t.Fatal("encoded bound", files, err)
	}
	s.Close()
	s, err = local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Load(job.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range got.Steps {
		if !bytes.Equal(step.Result.Stdout, body) || !bytes.Equal(step.Result.Stderr, body) {
			t.Fatal("output bytes changed")
		}
	}
	invalid := got
	invalid.Reservation = 1
	if err = s.Commit(invalid); err == nil {
		t.Fatal("invalid record committed")
	}
}

func TestJobStoreBodyRemoval(t *testing.T) {
	_, s, _ := jobStore(t)
	job := storeJob(t, 1, false)
	body := bytes.Repeat([]byte("output"), 1024)
	sum := sha256.Sum256(body)
	empty := sha256.Sum256(nil)
	exit := 0
	job, answer := ap.ApplyJob(job, ap.RecordResult{Ordinal: 1, Result: ap.StepResult{Status: ap.StepSucceeded, ExitCode: &exit, StdoutBytes: int64(len(body)), Stdout: body, StdoutSHA256: hex.EncodeToString(sum[:]), StderrSHA256: hex.EncodeToString(empty[:])}}, ap.Now{Wall: st.T0}, st.Epoch(1))
	if !answer.Changed {
		t.Fatal(answer)
	}
	if err := s.Commit(job); err != nil {
		t.Fatal(err)
	}
	before, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	job, answer = ap.ApplyJob(job, ap.RemoveBodies{Cause: ap.BodiesRemovedAge}, ap.Now{Wall: st.T0.Add(ap.BodyRetention)}, st.Epoch(1))
	if !answer.Changed {
		t.Fatal(answer)
	}
	if err := s.Commit(job); err != nil {
		t.Fatal(err)
	}
	after, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := ap.EncodeR2(job)
	if err != nil || after[0].EncodedBytes != int64(len(encoded)) {
		t.Fatal("stale encoded size", err)
	}
	got, err := s.Load(job.RequestID)
	if err != nil || len(got.Steps[0].Result.Stdout) != 0 || got.Steps[0].Result.StdoutSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("body removal changed digest or kept body", err)
	}
	if after[0].EncodedBytes >= before[0].EncodedBytes {
		t.Fatal("body removal did not release encoded bytes")
	}
}

func TestJobOrphanChild(t *testing.T) {
	path := os.Getenv("EXECUTOR_ORPHAN_PATH")
	if path == "" {
		return
	}
	if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Kill(os.Getpid(), unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
}

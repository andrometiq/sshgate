//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type m2CoreRecord struct {
	PID    int    `json:"pid"`
	Signal int    `json:"signal"`
	Bytes  int64  `json:"bytes"`
	Error  string `json:"error,omitempty"`
}

type m2CoreObserver struct {
	directory, pattern, records, output string
	kernelPattern                       string
	target, sentinel                    int
	sealed                              bool
	snapshot                            ObservationRecords
	mark                                ObserverMark
	err                                 error
	restore                             func() error
}

func (o *m2CoreObserver) install(t *testing.T) {
	t.Helper()
	directory, err := os.MkdirTemp("/var/tmp", "sshgate-core-")
	mutationSetup(t, err)
	t.Cleanup(func() { mutationSetup(t, os.RemoveAll(directory)) })
	helper := filepath.Join(directory, "collector")
	command := exec.Command("go", "build", "-o", helper, "./testdata/corecollector")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("SETUP: core helper build: %v: %s", err, output)
	}
	o.records = filepath.Join(directory, "records")
	mutationSetup(t, os.WriteFile(o.records, nil, 0600))
	mutationSetup(t, os.WriteFile(filepath.Join(directory, "failed"), make([]byte, 4096), 0600))
	previousPattern, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	mutationSetup(t, err)
	previousLimit, err := os.ReadFile("/proc/sys/kernel/core_pipe_limit")
	mutationSetup(t, err)
	restored := false
	o.restore = func() error {
		if restored {
			return nil
		}
		patternErr := os.WriteFile("/proc/sys/kernel/core_pattern", previousPattern, 0600)
		limitErr := os.WriteFile("/proc/sys/kernel/core_pipe_limit", previousLimit, 0600)
		if patternErr != nil || limitErr != nil {
			return fmt.Errorf("restore core sysctls: pattern=%v limit=%v", patternErr, limitErr)
		}
		restored = true
		return nil
	}
	t.Cleanup(func() { mutationSetup(t, o.restore()) })
	mutationSetup(t, os.WriteFile("/proc/sys/kernel/core_pipe_limit", []byte("16\n"), 0600))
	o.pattern = "|" + helper + " %P %s"
	mutationSetup(t, os.WriteFile("/proc/sys/kernel/core_pattern", []byte(o.pattern+"\n"), 0600))
}
func (o *m2CoreObserver) Start(t *testing.T) {
	t.Helper()
	if o.records == "" {
		if o.pattern == "" || filepath.IsAbs(o.pattern) || strings.Contains(o.pattern, "/") {
			t.Fatalf("SETUP: file core_pattern outside owned fixture: %q", o.pattern)
		}
		usesPID, err := os.ReadFile("/proc/sys/kernel/core_uses_pid")
		mutationSetup(t, err)
		if strings.TrimSpace(string(usesPID)) == "1" && !strings.Contains(o.pattern, "%p") {
			o.pattern += ".%p"
		}
	}
	pattern, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	mutationSetup(t, err)
	o.kernelPattern = strings.TrimSpace(string(pattern))
	if o.records == "" {
		paths, err := filepath.Glob(crashFileGlob(o.pattern, o.directory))
		mutationSetup(t, err)
		if len(paths) != 0 {
			t.Fatal("SETUP: core fixture must start empty")
		}
	}
	mutationSetup(t, o.Healthy())
}
func (o *m2CoreObserver) Mark() ObserverMark {
	o.sealed = false
	o.snapshot = ObservationRecords{}
	o.mark = 0
	o.target = 0
	o.sentinel = 0

	if o.records == "" {
		return 0
	}
	data, err := os.ReadFile(o.records)
	if err != nil {
		o.err = err
	}
	o.mark = ObserverMark(len(data))
	return o.mark
}
func (o *m2CoreObserver) Healthy() error {
	if o.err != nil {
		return o.err
	}
	if o.kernelPattern != "" {
		pattern, err := os.ReadFile("/proc/sys/kernel/core_pattern")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(pattern)) != o.kernelPattern {
			return fmt.Errorf("core_pattern ownership lost")
		}
	}
	if o.records != "" {
		pattern, err := os.ReadFile("/proc/sys/kernel/core_pattern")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(pattern)) != o.pattern {
			return fmt.Errorf("core_pattern ownership lost")
		}
		limit, err := os.ReadFile("/proc/sys/kernel/core_pipe_limit")
		if err != nil {
			return err
		}
		value, err := strconv.Atoi(strings.TrimSpace(string(limit)))
		if err != nil || value <= 0 {
			return fmt.Errorf("core_pipe_limit no longer synchronous")
		}
		latch, err := os.ReadFile(filepath.Join(filepath.Dir(o.records), "failed"))
		if err != nil {
			return err
		}
		if len(latch) != 4096 || !bytes.Equal(latch, make([]byte, 4096)) {
			return fmt.Errorf("core collector failure latched")
		}
		entries, err := os.ReadDir(filepath.Dir(o.records))
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "inflight-") {
				return fmt.Errorf("unfinished core collector invocation: %s", entry.Name())
			}
		}
		data, err := os.ReadFile(o.records)
		if err != nil {
			return err
		}
		_, err = m2CoreRecords(data, 0, 0)
		return err
	}
	_, err := os.ReadDir(o.directory)
	return err
}
func (o *m2CoreObserver) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "worker-reaped" || o.target <= 0 {
		return fmt.Errorf("core observation requires reaped worker")
	}
	if err := o.Healthy(); err != nil {
		o.err = err
		return err
	}
	o.sealed = true
	o.snapshot = o.readWindow(o.mark)
	return o.snapshot.Err
}
func m2CoreRecords(data []byte, target, sentinel int) ([]string, error) {
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("incomplete core record")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	seen := map[int]bool{}
	found := false
	sentinelFound := sentinel == 0
	for {
		var item m2CoreRecord
		if err := decoder.Decode(&item); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if item.PID <= 0 || item.Signal <= 0 || item.Bytes <= 0 || item.Error != "" || seen[item.PID] {
			return nil, fmt.Errorf("invalid or failed core record: %+v", item)
		}
		seen[item.PID] = true
		if item.PID == target {
			if item.Signal != 11 {
				return nil, fmt.Errorf("target signal mismatch")
			}
			found = true
		}
		if item.PID == sentinel {
			if item.Signal != 11 {
				return nil, fmt.Errorf("sentinel signal mismatch")
			}
			sentinelFound = true
			break
		}
	}
	if !sentinelFound {
		return nil, fmt.Errorf("sentinel core missing")
	}
	if found {
		return []string{fmt.Sprintf("pid=%d", target)}, nil
	}
	return nil, nil
}
func (o *m2CoreObserver) Since(mark ObserverMark) ObservationRecords {
	if !o.sealed || mark != 0 && mark != o.mark {
		return ObservationRecords{Err: fmt.Errorf("invalid or unsealed core window")}
	}
	result := o.snapshot
	result.Records = append([]string(nil), result.Records...)
	return result
}
func (o *m2CoreObserver) readWindow(mark ObserverMark) ObservationRecords {
	result := ObservationRecords{Sealed: o.sealed}
	if !o.sealed {
		result.Err = fmt.Errorf("unsealed core observation")
		return result
	}
	if o.records != "" {
		data, err := os.ReadFile(o.records)
		if err == nil && (mark < 0 || int64(mark) > int64(len(data))) {
			err = fmt.Errorf("invalid core mark")
		}
		if err == nil {
			result.Records, err = m2CoreRecords(data[int(mark):], o.target, o.sentinel)
		}
		result.Err = err
	} else {
		pattern := crashPIDFileGlob(o.pattern, o.directory, o.output, o.target)
		paths, err := filepath.Glob(pattern)
		for _, path := range paths {
			if err != nil {
				break
			}
			var data []byte
			file, openErr := os.Open(path)
			err = openErr
			if err == nil {
				data = make([]byte, 18)
				_, err = io.ReadFull(file, data)
				closeErr := file.Close()
				if err == nil {
					err = closeErr
				}
			}
			if err == nil {
				if len(data) < 18 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) || data[16] != 4 || data[17] != 0 {
					err = fmt.Errorf("invalid core file %s", path)
				} else {
					result.Records = append(result.Records, path)
				}
			}
		}
		result.Err = err
	}
	result.Conclusive = result.Err == nil
	if result.Err != nil {
		o.err = result.Err
	}
	return result
}
func (o *m2CoreObserver) Stop() error {
	err := o.Healthy()
	if o.restore != nil {
		if restoreErr := o.restore(); restoreErr != nil {
			return restoreErr
		}
	}
	return err
}

func m2CrashControlStatus(state *os.ProcessState, signal syscall.Signal) error {
	if state == nil {
		return fmt.Errorf("crash control failed to start")
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != signal {
		return fmt.Errorf("control did not die of signal %d: %v", signal, state)
	}
	return nil
}

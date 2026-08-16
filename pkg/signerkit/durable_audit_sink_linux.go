//go:build linux

package signerkit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	durableAuditRecoveryIntentContract = "sshgate-policy-audit-recovery-intent-v1"
	durableAuditRecoveryIntentSuffix   = ".sshgate-audit-recovery-intent"
	maxRecoveryIntentBytes             = 512
	maxRecoveryEventLineBytes          = 512
	recoveryLifecycle                  = "audit_log_recovered"
)

type durableAuditFaultPoint string

const (
	durableAuditFaultAfterIntentDurable      durableAuditFaultPoint = "after-intent-durable"
	durableAuditFaultAfterTruncate           durableAuditFaultPoint = "after-truncate"
	durableAuditFaultAfterTruncateDurable    durableAuditFaultPoint = "after-truncate-durable"
	durableAuditFaultBeforeRecoveryAppend    durableAuditFaultPoint = "before-recovery-append"
	durableAuditFaultAfterRecoveryAppend     durableAuditFaultPoint = "after-recovery-append"
	durableAuditFaultAfterRecoveryDurable    durableAuditFaultPoint = "after-recovery-durable"
	durableAuditFaultMidDuplicateAppend      durableAuditFaultPoint = "mid-duplicate-append"
	durableAuditFaultAfterIntentUnlink       durableAuditFaultPoint = "after-intent-unlink"
	durableAuditFaultAfterIntentClearDurable durableAuditFaultPoint = "after-intent-clear-durable"
)

type durableAuditFaultHook func(point durableAuditFaultPoint, sink *DurableFileAuditSink, record []byte) error

// DurableFileAuditSink is the held-parent, fsync-per-event reference
// implementation of DurableAuditSink.
type DurableFileAuditSink struct {
	mu sync.Mutex

	parentFD   int
	fileFD     int
	basename   string
	intentName string
	ready      bool
	closed     bool
	stickyErr  error

	now       func() time.Time
	random    io.Reader
	faultHook durableAuditFaultHook
}

type auditRecoveryIntent struct {
	Contract           string `json:"contract"`
	RecoveryID         string `json:"recovery_id"`
	AuditDev           string `json:"audit_dev"`
	AuditIno           string `json:"audit_ino"`
	ObservedLength     string `json:"observed_length"`
	LastCompleteOffset string `json:"last_complete_offset"`
}

type parsedAuditRecoveryIntent struct {
	wire               auditRecoveryIntent
	auditDev           uint64
	auditIno           uint64
	observedLength     uint64
	lastCompleteOffset uint64
	fileDev            uint64
	fileIno            uint64
}

type auditRecoveryLine struct {
	Kind  string    `json:"kind"`
	Event AuditCall `json:"event"`
}

func NewDurableFileAuditSink(path string) (*DurableFileAuditSink, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("durable audit path must be absolute")
	}
	clean := filepath.Clean(path)
	basename := filepath.Base(clean)
	if clean == string(filepath.Separator) || basename == "." || basename == string(filepath.Separator) {
		return nil, errors.New("durable audit path has no file basename")
	}
	parentPath := filepath.Dir(clean)
	parentFD, err := openDirectoryPathNoSymlinks(parentPath)
	if err != nil {
		return nil, fmt.Errorf("open durable audit parent: %w", err)
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = unix.Close(parentFD)
		}
	}()
	if err := validateOwnedNode(parentFD, unix.S_IFDIR, 0o700, false); err != nil {
		return nil, fmt.Errorf("validate durable audit parent: %w", err)
	}

	flags := unix.O_RDWR | unix.O_APPEND | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fileFD, err := unix.Openat(parentFD, basename, flags|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fileFD, err = unix.Openat(parentFD, basename, flags, 0o600)
	}
	if err != nil {
		return nil, fmt.Errorf("open durable audit file: %w", err)
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = unix.Close(fileFD)
		}
	}()
	if err := validateOwnedNode(fileFD, unix.S_IFREG, 0o600, false); err != nil {
		return nil, fmt.Errorf("validate durable audit file: %w", err)
	}
	sink := &DurableFileAuditSink{
		parentFD: parentFD, fileFD: fileFD, basename: basename,
		intentName: basename + durableAuditRecoveryIntentSuffix,
		now:        time.Now, random: rand.Reader,
	}
	if err := sink.validateFileIdentityLocked(); err != nil {
		return nil, err
	}
	if created {
		if err := unix.Fsync(parentFD); err != nil {
			return nil, fmt.Errorf("fsync durable audit parent after create: %w", err)
		}
	}
	closeParent = false
	closeFile = false
	return sink, nil
}

func (sink *DurableFileAuditSink) Call(ctx context.Context, event AuditCall) error {
	kind := "call"
	if event.Lifecycle != "" {
		kind = "lifecycle"
	}
	record, err := marshalAuditLine(auditLine{Kind: kind, Event: event})
	if err != nil {
		return err
	}
	return sink.appendReady(ctx, record)
}

func (sink *DurableFileAuditSink) Verdict(ctx context.Context, event AuditVerdict) error {
	record, err := marshalAuditLine(auditLine{Kind: "verdict", Event: event})
	if err != nil {
		return err
	}
	return sink.appendReady(ctx, record)
}

func (sink *DurableFileAuditSink) PolicyAuditReady(ctx context.Context) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if err := sink.usableLocked(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if sink.ready {
		if err := sink.validateFileIdentityLocked(); err != nil {
			return sink.stickLocked(err)
		}
		return nil
	}
	if err := sink.recoverLocked(ctx); err != nil {
		return sink.stickLocked(err)
	}
	sink.ready = true
	return nil
}

func (sink *DurableFileAuditSink) Close() error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.closed {
		return nil
	}
	sink.closed = true
	sink.ready = false
	fileErr := unix.Close(sink.fileFD)
	parentErr := unix.Close(sink.parentFD)
	if fileErr != nil {
		return fmt.Errorf("close durable audit file: %w", fileErr)
	}
	if parentErr != nil {
		return fmt.Errorf("close durable audit parent: %w", parentErr)
	}
	return nil
}

func (sink *DurableFileAuditSink) appendReady(ctx context.Context, record []byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if err := sink.usableLocked(); err != nil {
		return err
	}
	if !sink.ready {
		return errors.New("durable audit sink is not ready")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sink.appendDurableLocked(record); err != nil {
		sink.ready = false
		return sink.stickLocked(err)
	}
	return nil
}

func (sink *DurableFileAuditSink) recoverLocked(ctx context.Context) error {
	intentExists, err := sink.intentExistsLocked()
	if err != nil {
		return err
	}
	if !intentExists {
		fileStat, err := sink.fileStatLocked()
		if err != nil {
			return err
		}
		if fileStat.Size < 0 {
			return errors.New("durable audit file has negative length")
		}
		observed := uint64(fileStat.Size)
		if observed == 0 {
			return sink.validateFileIdentityLocked()
		}
		last := []byte{0}
		if _, err := unix.Pread(sink.fileFD, last, fileStat.Size-1); err != nil {
			return fmt.Errorf("read durable audit tail: %w", err)
		}
		if last[0] == '\n' {
			return sink.validateFileIdentityLocked()
		}
		offset, err := sink.lastCompleteOffsetLocked(fileStat.Size)
		if err != nil {
			return err
		}
		intent, err := sink.newRecoveryIntentLocked(fileStat, observed, uint64(offset))
		if err != nil {
			return err
		}
		if err := sink.publishIntentLocked(intent.wire); err != nil {
			return err
		}
		if err := sink.injectLocked(durableAuditFaultAfterIntentDurable, nil); err != nil {
			return err
		}
	}

	intent, err := sink.readIntentLocked()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lastRecoveryEnd, recoveryCount, fragment, err := sink.scanRecoveryRegionLocked(intent)
	if err != nil {
		return err
	}
	truncateTo := int64(intent.lastCompleteOffset)
	if recoveryCount > 0 {
		truncateTo = lastRecoveryEnd
	}
	fileStat, err := sink.fileStatLocked()
	if err != nil {
		return err
	}
	if fragment || fileStat.Size != truncateTo {
		if err := unix.Ftruncate(sink.fileFD, truncateTo); err != nil {
			return fmt.Errorf("truncate durable audit fragment: %w", err)
		}
		if err := sink.injectLocked(durableAuditFaultAfterTruncate, nil); err != nil {
			return err
		}
		if err := unix.Fsync(sink.fileFD); err != nil {
			return fmt.Errorf("fsync durable audit truncation: %w", err)
		}
		if err := sink.validateFileIdentityLocked(); err != nil {
			return err
		}
		if err := sink.injectLocked(durableAuditFaultAfterTruncateDurable, nil); err != nil {
			return err
		}
	}
	if recoveryCount == 0 {
		record, err := sink.recoveryEventRecordLocked(intent)
		if err != nil {
			return err
		}
		if err := sink.injectLocked(durableAuditFaultBeforeRecoveryAppend, record); err != nil {
			return err
		}
		if err := sink.appendRecoveryDurableLocked(record); err != nil {
			return err
		}
		if err := sink.injectLocked(durableAuditFaultAfterRecoveryDurable, record); err != nil {
			return err
		}
		if err := sink.injectLocked(durableAuditFaultMidDuplicateAppend, record); err != nil {
			return err
		}
	} else {
		if err := unix.Fsync(sink.fileFD); err != nil {
			return fmt.Errorf("fsync existing audit recovery event: %w", err)
		}
		if err := sink.validateFileIdentityLocked(); err != nil {
			return err
		}
	}
	if err := sink.revalidateIntentIdentityLocked(intent); err != nil {
		return err
	}
	if err := unix.Unlinkat(sink.parentFD, sink.intentName, 0); err != nil {
		return fmt.Errorf("unlink durable audit recovery intent: %w", err)
	}
	if err := sink.injectLocked(durableAuditFaultAfterIntentUnlink, nil); err != nil {
		return err
	}
	if err := unix.Fsync(sink.parentFD); err != nil {
		return fmt.Errorf("fsync durable audit intent clear: %w", err)
	}
	if err := sink.injectLocked(durableAuditFaultAfterIntentClearDurable, nil); err != nil {
		return err
	}
	return sink.validateFileIdentityLocked()
}

func (sink *DurableFileAuditSink) appendDurableLocked(record []byte) error {
	written, err := unix.Write(sink.fileFD, record)
	if err != nil {
		return fmt.Errorf("append durable audit record: %w", err)
	}
	if written != len(record) {
		return io.ErrShortWrite
	}
	if err := unix.Fsync(sink.fileFD); err != nil {
		return fmt.Errorf("fsync durable audit record: %w", err)
	}
	return sink.validateFileIdentityLocked()
}

func (sink *DurableFileAuditSink) appendRecoveryDurableLocked(record []byte) error {
	written, err := unix.Write(sink.fileFD, record)
	if err != nil {
		return fmt.Errorf("append audit recovery event: %w", err)
	}
	if written != len(record) {
		return io.ErrShortWrite
	}
	if err := sink.injectLocked(durableAuditFaultAfterRecoveryAppend, record); err != nil {
		return err
	}
	if err := unix.Fsync(sink.fileFD); err != nil {
		return fmt.Errorf("fsync audit recovery event: %w", err)
	}
	return sink.validateFileIdentityLocked()
}

func (sink *DurableFileAuditSink) newRecoveryIntentLocked(stat unix.Stat_t, observed, offset uint64) (parsedAuditRecoveryIntent, error) {
	random := make([]byte, 16)
	if _, err := io.ReadFull(sink.random, random); err != nil {
		return parsedAuditRecoveryIntent{}, fmt.Errorf("generate audit recovery id: %w", err)
	}
	wire := auditRecoveryIntent{
		Contract:           durableAuditRecoveryIntentContract,
		RecoveryID:         "recv_" + hex.EncodeToString(random),
		AuditDev:           strconv.FormatUint(uint64(stat.Dev), 10),
		AuditIno:           strconv.FormatUint(stat.Ino, 10),
		ObservedLength:     strconv.FormatUint(observed, 10),
		LastCompleteOffset: strconv.FormatUint(offset, 10),
	}
	return parseRecoveryIntent(wire)
}

func (sink *DurableFileAuditSink) publishIntentLocked(intent auditRecoveryIntent) error {
	record, err := json.Marshal(intent)
	if err != nil {
		return fmt.Errorf("marshal audit recovery intent: %w", err)
	}
	record = append(record, '\n')
	if len(record) > maxRecoveryIntentBytes {
		return errors.New("audit recovery intent exceeds 512 bytes")
	}
	tempName := "." + sink.intentName + ".tmp." + strings.TrimPrefix(intent.RecoveryID, "recv_")
	tempFD, err := unix.Openat(sink.parentFD, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create audit recovery intent temp: %w", err)
	}
	tempOpen := true
	defer func() {
		if tempOpen {
			_ = unix.Close(tempFD)
		}
		_ = unix.Unlinkat(sink.parentFD, tempName, 0)
	}()
	if err := validateOwnedNode(tempFD, unix.S_IFREG, 0o600, true); err != nil {
		return fmt.Errorf("validate audit recovery intent temp: %w", err)
	}
	written, err := unix.Write(tempFD, record)
	if err != nil {
		return fmt.Errorf("write audit recovery intent: %w", err)
	}
	if written != len(record) {
		return io.ErrShortWrite
	}
	if err := unix.Fsync(tempFD); err != nil {
		return fmt.Errorf("fsync audit recovery intent: %w", err)
	}
	if err := unix.Close(tempFD); err != nil {
		return fmt.Errorf("close audit recovery intent temp: %w", err)
	}
	tempOpen = false
	if err := unix.Renameat2(sink.parentFD, tempName, sink.parentFD, sink.intentName, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			_, readErr := sink.readIntentLocked()
			return readErr
		}
		return fmt.Errorf("publish audit recovery intent: %w", err)
	}
	if err := unix.Fsync(sink.parentFD); err != nil {
		return fmt.Errorf("fsync audit recovery intent parent: %w", err)
	}
	return nil
}

func (sink *DurableFileAuditSink) readIntentLocked() (parsedAuditRecoveryIntent, error) {
	fd, err := unix.Openat(sink.parentFD, sink.intentName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return parsedAuditRecoveryIntent{}, fmt.Errorf("open audit recovery intent: %w", err)
	}
	file := os.NewFile(uintptr(fd), sink.intentName)
	if file == nil {
		_ = unix.Close(fd)
		return parsedAuditRecoveryIntent{}, errors.New("open audit recovery intent file handle")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return parsedAuditRecoveryIntent{}, fmt.Errorf("stat audit recovery intent: %w", err)
	}
	if err := validateStat(stat, unix.S_IFREG, 0o600, true); err != nil {
		return parsedAuditRecoveryIntent{}, fmt.Errorf("validate audit recovery intent: %w", err)
	}
	if stat.Size <= 0 || stat.Size > maxRecoveryIntentBytes {
		return parsedAuditRecoveryIntent{}, fmt.Errorf("audit recovery intent length %d is outside 1..%d", stat.Size, maxRecoveryIntentBytes)
	}
	body, err := io.ReadAll(io.LimitReader(file, maxRecoveryIntentBytes+1))
	if err != nil {
		return parsedAuditRecoveryIntent{}, fmt.Errorf("read audit recovery intent: %w", err)
	}
	if int64(len(body)) != stat.Size || len(body) > maxRecoveryIntentBytes || body[len(body)-1] != '\n' {
		return parsedAuditRecoveryIntent{}, errors.New("audit recovery intent is not one bounded newline-terminated record")
	}
	var wire auditRecoveryIntent
	if err := decodeStrictCanonical(body[:len(body)-1], &wire); err != nil {
		return parsedAuditRecoveryIntent{}, fmt.Errorf("decode audit recovery intent: %w", err)
	}
	intent, err := parseRecoveryIntent(wire)
	if err != nil {
		return parsedAuditRecoveryIntent{}, err
	}
	intent.fileDev = uint64(stat.Dev)
	intent.fileIno = stat.Ino
	var namedIntent unix.Stat_t
	if err := unix.Fstatat(sink.parentFD, sink.intentName, &namedIntent, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return parsedAuditRecoveryIntent{}, fmt.Errorf("revalidate audit recovery intent name: %w", err)
	}
	if uint64(namedIntent.Dev) != intent.fileDev || namedIntent.Ino != intent.fileIno {
		return parsedAuditRecoveryIntent{}, errors.New("audit recovery intent pathname identity changed during read")
	}
	fileStat, err := sink.fileStatLocked()
	if err != nil {
		return parsedAuditRecoveryIntent{}, err
	}
	if intent.auditDev != uint64(fileStat.Dev) || intent.auditIno != fileStat.Ino {
		return parsedAuditRecoveryIntent{}, errors.New("audit recovery intent names a different audit file")
	}
	if intent.lastCompleteOffset > 0 {
		boundary := []byte{0}
		if _, err := unix.Pread(sink.fileFD, boundary, int64(intent.lastCompleteOffset)-1); err != nil {
			return parsedAuditRecoveryIntent{}, fmt.Errorf("read audit recovery offset boundary: %w", err)
		}
		if boundary[0] != '\n' {
			return parsedAuditRecoveryIntent{}, errors.New("audit recovery intent offset is not a complete-record boundary")
		}
	}
	return intent, nil
}

func parseRecoveryIntent(wire auditRecoveryIntent) (parsedAuditRecoveryIntent, error) {
	if wire.Contract != durableAuditRecoveryIntentContract {
		return parsedAuditRecoveryIntent{}, errors.New("audit recovery intent contract mismatch")
	}
	if !validRecoveryID(wire.RecoveryID) {
		return parsedAuditRecoveryIntent{}, errors.New("audit recovery intent has invalid recovery_id")
	}
	values := []*string{&wire.AuditDev, &wire.AuditIno, &wire.ObservedLength, &wire.LastCompleteOffset}
	parsed := make([]uint64, len(values))
	for index, value := range values {
		var err error
		parsed[index], err = parseDecimalUint64(*value)
		if err != nil {
			return parsedAuditRecoveryIntent{}, fmt.Errorf("audit recovery intent numeric field: %w", err)
		}
	}
	if parsed[3] > parsed[2] {
		return parsedAuditRecoveryIntent{}, errors.New("audit recovery intent offset exceeds observed length")
	}
	return parsedAuditRecoveryIntent{
		wire: wire, auditDev: parsed[0], auditIno: parsed[1],
		observedLength: parsed[2], lastCompleteOffset: parsed[3],
	}, nil
}

func (sink *DurableFileAuditSink) scanRecoveryRegionLocked(intent parsedAuditRecoveryIntent) (lastEnd int64, count int, fragment bool, err error) {
	stat, err := sink.fileStatLocked()
	if err != nil {
		return 0, 0, false, err
	}
	if stat.Size < 0 || uint64(stat.Size) < intent.lastCompleteOffset {
		return 0, 0, false, errors.New("durable audit file is shorter than recovery offset")
	}
	offset := int64(intent.lastCompleteOffset)
	lastEnd = offset
	line := make([]byte, 0, maxRecoveryEventLineBytes)
	oversized := false
	buffer := make([]byte, 32<<10)
	for offset < stat.Size {
		readSize := int64(len(buffer))
		if remaining := stat.Size - offset; remaining < readSize {
			readSize = remaining
		}
		n, readErr := unix.Pread(sink.fileFD, buffer[:readSize], offset)
		if readErr != nil {
			return 0, 0, false, fmt.Errorf("read durable audit recovery region: %w", readErr)
		}
		if n == 0 {
			return 0, 0, false, io.ErrUnexpectedEOF
		}
		for _, value := range buffer[:n] {
			offset++
			if value == '\n' {
				if oversized {
					return 0, 0, false, errors.New("complete audit recovery event exceeds bound")
				}
				candidate := append(append([]byte(nil), line...), '\n')
				if err := validateRecoveryEventLine(candidate, intent); err != nil {
					return 0, 0, false, err
				}
				count++
				lastEnd = offset
				line = line[:0]
				oversized = false
				continue
			}
			if !oversized {
				if len(line) == maxRecoveryEventLineBytes-1 {
					oversized = true
					line = line[:0]
				} else {
					line = append(line, value)
				}
			}
		}
	}
	fragment = oversized || len(line) != 0
	return lastEnd, count, fragment, nil
}

func validateRecoveryEventLine(line []byte, intent parsedAuditRecoveryIntent) error {
	if len(line) == 0 || len(line) > maxRecoveryEventLineBytes || line[len(line)-1] != '\n' {
		return errors.New("invalid audit recovery event framing")
	}
	var decoded auditRecoveryLine
	if err := decodeStrictCanonical(line[:len(line)-1], &decoded); err != nil {
		return fmt.Errorf("decode audit recovery event: %w", err)
	}
	event := decoded.Event
	if decoded.Kind != "lifecycle" || event.Lifecycle != recoveryLifecycle || event.Time.IsZero() || event.Recovery == nil {
		return errors.New("invalid audit recovery lifecycle event")
	}
	if event.Recovery.RecoveryID != intent.wire.RecoveryID ||
		event.Recovery.BeforeLength != intent.wire.ObservedLength ||
		event.Recovery.AfterLength != intent.wire.LastCompleteOffset {
		return errors.New("audit recovery metadata does not match intent")
	}
	if _, err := parseDecimalUint64(event.Recovery.BeforeLength); err != nil {
		return fmt.Errorf("audit recovery before_length: %w", err)
	}
	if _, err := parseDecimalUint64(event.Recovery.AfterLength); err != nil {
		return fmt.Errorf("audit recovery after_length: %w", err)
	}
	withoutRecovery := event
	withoutRecovery.Time = time.Time{}
	withoutRecovery.Lifecycle = ""
	withoutRecovery.Recovery = nil
	if !reflect.DeepEqual(withoutRecovery, AuditCall{}) {
		return errors.New("audit recovery event carries unrelated fields")
	}
	return nil
}

func (sink *DurableFileAuditSink) recoveryEventRecordLocked(intent parsedAuditRecoveryIntent) ([]byte, error) {
	event := AuditCall{
		Time: sink.now().UTC(), Lifecycle: recoveryLifecycle,
		Recovery: &AuditRecoveryMetadata{
			RecoveryID:   intent.wire.RecoveryID,
			BeforeLength: intent.wire.ObservedLength,
			AfterLength:  intent.wire.LastCompleteOffset,
		},
	}
	record, err := marshalAuditLine(auditLine{Kind: "lifecycle", Event: event})
	if err != nil {
		return nil, err
	}
	if len(record) > maxRecoveryEventLineBytes {
		return nil, errors.New("audit recovery event exceeds bound")
	}
	if err := validateRecoveryEventLine(record, intent); err != nil {
		return nil, fmt.Errorf("validate generated audit recovery event: %w", err)
	}
	return record, nil
}

func (sink *DurableFileAuditSink) lastCompleteOffsetLocked(length int64) (int64, error) {
	buffer := make([]byte, 32<<10)
	for end := length; end > 0; {
		start := end - int64(len(buffer))
		if start < 0 {
			start = 0
		}
		n, err := unix.Pread(sink.fileFD, buffer[:end-start], start)
		if err != nil {
			return 0, fmt.Errorf("scan durable audit tail: %w", err)
		}
		if n != int(end-start) {
			return 0, io.ErrUnexpectedEOF
		}
		if index := bytes.LastIndexByte(buffer[:n], '\n'); index >= 0 {
			return start + int64(index) + 1, nil
		}
		end = start
	}
	return 0, nil
}

func (sink *DurableFileAuditSink) intentExistsLocked() (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(sink.parentFD, sink.intentName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat audit recovery intent: %w", err)
	}
	if err := validateStat(stat, unix.S_IFREG, 0o600, true); err != nil {
		return false, fmt.Errorf("validate audit recovery intent name: %w", err)
	}
	return true, nil
}

func (sink *DurableFileAuditSink) revalidateIntentIdentityLocked(intent parsedAuditRecoveryIntent) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(sink.parentFD, sink.intentName, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("revalidate audit recovery intent: %w", err)
	}
	if err := validateStat(stat, unix.S_IFREG, 0o600, true); err != nil {
		return err
	}
	if uint64(stat.Dev) != intent.fileDev || stat.Ino != intent.fileIno {
		return errors.New("audit recovery intent pathname identity changed")
	}
	return nil
}

func (sink *DurableFileAuditSink) validateFileIdentityLocked() error {
	held, err := sink.fileStatLocked()
	if err != nil {
		return err
	}
	if err := validateStat(held, unix.S_IFREG, 0o600, false); err != nil {
		return fmt.Errorf("validate held durable audit file: %w", err)
	}
	var named unix.Stat_t
	if err := unix.Fstatat(sink.parentFD, sink.basename, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat durable audit pathname: %w", err)
	}
	if named.Mode&unix.S_IFMT != unix.S_IFREG || uint64(named.Dev) != uint64(held.Dev) || named.Ino != held.Ino {
		return errors.New("durable audit pathname identity changed")
	}
	return nil
}

func (sink *DurableFileAuditSink) fileStatLocked() (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(sink.fileFD, &stat); err != nil {
		return unix.Stat_t{}, fmt.Errorf("stat durable audit file: %w", err)
	}
	return stat, nil
}

func validateOwnedNode(fd int, kind uint32, mode uint32, singleLink bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	return validateStat(stat, kind, mode, singleLink)
}

func validateStat(stat unix.Stat_t, kind uint32, mode uint32, singleLink bool) error {
	if stat.Mode&unix.S_IFMT != kind {
		return errors.New("unexpected inode type")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("inode is not owned by process uid")
	}
	if stat.Mode&0o7777 != mode {
		return fmt.Errorf("inode mode is %#o; want %#o", stat.Mode&0o7777, mode)
	}
	if singleLink {
		if stat.Nlink != 1 {
			return errors.New("inode must have exactly one link")
		}
	} else if stat.Nlink < 1 {
		return errors.New("inode is unlinked")
	}
	return nil
}

func decodeStrictCanonical(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(body, canonical) {
		return errors.New("JSON is not the canonical typed encoding")
	}
	return nil
}

func validRecoveryID(recoveryID string) bool {
	const prefix = "recv_"
	if len(recoveryID) != len(prefix)+32 || !strings.HasPrefix(recoveryID, prefix) {
		return false
	}
	_, err := hex.DecodeString(recoveryID[len(prefix):])
	return err == nil && strings.ToLower(recoveryID) == recoveryID
}

func parseDecimalUint64(value string) (uint64, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, errors.New("not a canonical decimal uint64")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("not a canonical decimal uint64")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("not a canonical decimal uint64")
	}
	return parsed, nil
}

func (sink *DurableFileAuditSink) usableLocked() error {
	if sink.closed {
		return errors.New("durable audit sink is closed")
	}
	if sink.stickyErr != nil {
		return sink.stickyErr
	}
	return nil
}

func (sink *DurableFileAuditSink) stickLocked(err error) error {
	if sink.stickyErr == nil {
		sink.stickyErr = fmt.Errorf("durable audit sink failed: %w", err)
	}
	return sink.stickyErr
}

func (sink *DurableFileAuditSink) injectLocked(point durableAuditFaultPoint, record []byte) error {
	if sink.faultHook == nil {
		return nil
	}
	return sink.faultHook(point, sink, record)
}

var (
	_ DurableAuditSink = (*DurableFileAuditSink)(nil)
	_ io.Closer        = (*DurableFileAuditSink)(nil)
)

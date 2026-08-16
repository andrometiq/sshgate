package policyarchive

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// BindingFilename is the frozen archive-root binding record name.
	BindingFilename       = ".sshgate-policy-archive-binding-v1"
	maintenanceLockSuffix = ".policy-maintenance.lock"
	temporaryObjectPrefix = ".pja-tmp-"
	objectSuffix          = ".pja"
	maxObjectBytes        = int64(256 << 20)
)

var bindingMagic = []byte("sshgate-policy-archive-binding-v1\x00")

// ObjectRef identifies a complete, content-addressed archive record.
// It is intentionally byte-oriented; the policy-store codec owns v3 records.
type ObjectRef struct {
	SHA256 string
	Bytes  int64
}

// EncodeBinding returns the frozen binding-record bytes.
func EncodeBinding(archiveID, authorityID string) ([]byte, error) {
	if !validIdentifier(archiveID, "parch_") {
		return nil, errors.New("policy archive: archive ID must be parch_ plus 32 lowercase hexadecimal characters")
	}
	if !validIdentifier(authorityID, "pauth_") {
		return nil, errors.New("policy archive: authority ID must be pauth_ plus 32 lowercase hexadecimal characters")
	}

	record := make([]byte, 0, len(bindingMagic)+4+5+len(archiveID)+5+len(authorityID))
	record = append(record, bindingMagic...)
	record = binary.BigEndian.AppendUint32(record, 2)
	record = appendTextField(record, archiveID)
	record = appendTextField(record, authorityID)
	return record, nil
}

func appendTextField(destination []byte, value string) []byte {
	destination = append(destination, 0x01)
	destination = binary.BigEndian.AppendUint32(destination, uint32(len(value)))
	return append(destination, value...)
}

func validIdentifier(value, prefix string) bool {
	if len(value) != len(prefix)+32 || !strings.HasPrefix(value, prefix) {
		return false
	}
	return validLowerHex(value[len(prefix):], 32)
}

func validLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range value {
		if !((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')) {
			return false
		}
	}
	return true
}

func objectReference(record []byte) (ObjectRef, error) {
	if len(record) == 0 || int64(len(record)) > maxObjectBytes {
		return ObjectRef{}, fmt.Errorf("policy archive: record length %d is outside 1..%d", len(record), maxObjectBytes)
	}
	digest := sha256.Sum256(record)
	return ObjectRef{SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(record))}, nil
}

func validateObjectReference(reference ObjectRef) error {
	if !validLowerHex(reference.SHA256, sha256.Size*2) {
		return errors.New("policy archive: object SHA-256 must be 64 lowercase hexadecimal characters")
	}
	if reference.Bytes <= 0 || reference.Bytes > maxObjectBytes {
		return fmt.Errorf("policy archive: object length %d is outside 1..%d", reference.Bytes, maxObjectBytes)
	}
	return nil
}

func objectName(reference ObjectRef) string {
	return reference.SHA256 + objectSuffix
}

func validTemporaryObjectName(name string) bool {
	return strings.HasPrefix(name, temporaryObjectPrefix) && validLowerHex(name[len(temporaryObjectPrefix):], 32)
}

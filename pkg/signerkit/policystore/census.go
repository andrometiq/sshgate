package policystore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

type ColumnKind uint8

const (
	ColumnText ColumnKind = iota + 1
	ColumnBlob
	ColumnInteger
)

type Column struct {
	Name string
	Kind ColumnKind
}

const (
	MetaColumnCount    = 28
	RequestColumnCount = 83
	VoteColumnCount    = 15
	HeadColumnCount    = 13
)

var MetaColumns = [...]Column{
	{"singleton", ColumnInteger}, {"authority_id", ColumnText}, {"accounting_version", ColumnText},
	{"archive_id", ColumnText}, {"max_heads", ColumnInteger}, {"max_requests", ColumnInteger},
	{"max_logical_bytes", ColumnInteger}, {"max_active_global", ColumnInteger},
	{"max_active_per_principal", ColumnInteger}, {"max_votes_per_request", ColumnInteger},
	{"max_rejection_reserved_bytes_per_principal", ColumnInteger}, {"config_digest", ColumnText},
	{"requester_operator_id", ColumnText}, {"required_approvals", ColumnInteger},
	{"deny_veto", ColumnInteger}, {"allow_self_approve", ColumnInteger},
	{"policy_voter_role", ColumnText}, {"voter_eligibility_version", ColumnText},
	{"vote_step_up_required", ColumnInteger}, {"vote_auth_methods_json", ColumnText},
	{"review_renderer_version", ColumnText}, {"review_rules_digest", ColumnText},
	{"logical_used_bytes", ColumnInteger}, {"logical_reserved_bytes", ColumnInteger},
	{"full_request_count", ColumnInteger}, {"head_count", ColumnInteger},
	{"active_count", ColumnInteger}, {"created_at", ColumnInteger},
}

var RequestColumns = [...]Column{
	{"principal", ColumnText}, {"request_id", ColumnText}, {"review_id", ColumnText},
	{"authority_singleton", ColumnInteger}, {"authority_id", ColumnText}, {"storage_kind", ColumnText},
	{"purpose", ColumnText}, {"canonical_request", ColumnBlob}, {"payload", ColumnBlob},
	{"tuple_digest", ColumnText}, {"payload_sha256", ColumnText}, {"base_digest", ColumnText},
	{"host_key_fp", ColumnText}, {"expected_head_digest", ColumnText}, {"expected_signer_key_id", ColumnText},
	{"bootstrap", ColumnInteger}, {"trusted_head_envelope", ColumnBlob}, {"trusted_head_digest", ColumnText},
	{"trusted_head_key_id", ColumnText}, {"trusted_head_public_key", ColumnBlob},
	{"trusted_head_epoch_be", ColumnBlob}, {"trusted_head_revision_be", ColumnBlob},
	{"trusted_head_row_version", ColumnInteger}, {"claimed_head_envelope", ColumnBlob},
	{"claimed_head_digest", ColumnText}, {"claimed_head_key_id", ColumnText},
	{"claimed_head_public_key", ColumnBlob}, {"claimed_head_epoch_be", ColumnBlob},
	{"claimed_head_revision_be", ColumnBlob}, {"claimed_head_row_version", ColumnInteger},
	{"frozen_signer_key_id", ColumnText}, {"frozen_signer_public_key", ColumnBlob},
	{"epoch_be", ColumnBlob}, {"revision_be", ColumnBlob}, {"miss_action", ColumnText},
	{"growth", ColumnText}, {"entry_count", ColumnInteger}, {"revocation_count", ColumnInteger},
	{"logical_change_count", ColumnInteger}, {"review_json", ColumnBlob}, {"review_sha256", ColumnText},
	{"review_rendered_bytes", ColumnInteger}, {"review_item_count", ColumnInteger},
	{"review_renderer_version", ColumnText}, {"review_rules_digest", ColumnText},
	{"eligible_voters_json", ColumnBlob}, {"eligible_voters_sha256", ColumnText},
	{"eligible_voter_count", ColumnInteger}, {"vote_step_up_required", ColumnInteger},
	{"vote_auth_methods_json", ColumnBlob}, {"vote_auth_methods_sha256", ColumnText},
	{"required_approvals", ColumnInteger}, {"deny_veto", ColumnInteger},
	{"allow_self_approve", ColumnInteger}, {"requester_principal", ColumnText},
	{"state", ColumnText}, {"state_version", ColumnInteger}, {"submission_audited", ColumnInteger},
	{"pre_mint_audited", ColumnInteger}, {"result_audited", ColumnInteger},
	{"terminal_audited", ColumnInteger}, {"no_op", ColumnInteger}, {"error_family", ColumnText},
	{"failure_code", ColumnText}, {"result_envelope", ColumnBlob}, {"result_sha256", ColumnText},
	{"pending_response", ColumnBlob}, {"terminal_response", ColumnBlob},
	{"terminal_http_status", ColumnInteger}, {"reserved_bytes", ColumnInteger},
	{"recovery_lease_owner", ColumnText}, {"recovery_lease_until", ColumnInteger},
	{"recovery_lease_generation", ColumnInteger}, {"archive_id", ColumnText},
	{"archive_object_sha256", ColumnText}, {"archive_record_bytes", ColumnInteger},
	{"terminal_response_sha256", ColumnText}, {"terminal_response_bytes", ColumnInteger},
	{"compaction_delete_guard", ColumnInteger}, {"logical_bytes", ColumnInteger},
	{"created_at", ColumnInteger}, {"updated_at", ColumnInteger}, {"resolved_at", ColumnInteger},
}

var VoteColumns = [...]Column{
	{"principal", ColumnText}, {"request_id", ColumnText}, {"operator", ColumnText},
	{"decision", ColumnText}, {"authn_method", ColumnText}, {"ts", ColumnInteger},
	{"audited", ColumnInteger}, {"audit_state_version", ColumnInteger}, {"tuple_digest", ColumnText},
	{"purpose", ColumnText}, {"payload_sha256", ColumnText}, {"candidate_digest", ColumnText},
	{"head_digest", ColumnText}, {"signer_key_id", ColumnText}, {"logical_bytes", ColumnInteger},
}

var HeadColumns = [...]Column{
	{"authority_singleton", ColumnInteger}, {"authority_id", ColumnText}, {"host_key_fp", ColumnText},
	{"manifest_envelope", ColumnBlob}, {"payload_sha256", ColumnText}, {"base_digest", ColumnText},
	{"epoch_be", ColumnBlob}, {"revision_be", ColumnBlob}, {"signer_key_id", ColumnText},
	{"signer_public_key", ColumnBlob}, {"row_version", ColumnInteger},
	{"logical_bytes", ColumnInteger}, {"updated_at", ColumnInteger},
}

type Field struct {
	Null bool
	raw  []byte
}

func NullField() Field             { return Field{Null: true} }
func TextField(value string) Field { return Field{raw: []byte(value)} }
func BlobField(value []byte) Field { return Field{raw: cloneBytes(value)} }
func IntegerField(value int64) Field {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(value))
	return Field{raw: raw[:]}
}

func (field Field) Bytes() []byte { return cloneBytes(field.raw) }
func (field Field) Text() (string, error) {
	if field.Null {
		return "", errors.New("policy store: NULL field")
	}
	if !utf8.Valid(field.raw) {
		return "", errors.New("policy store: invalid UTF-8 field")
	}
	return string(field.raw), nil
}
func (field Field) Integer() (int64, error) {
	if field.Null || len(field.raw) != 8 {
		return 0, errors.New("policy store: invalid integer field")
	}
	return int64(binary.BigEndian.Uint64(field.raw)), nil
}

func validateField(column Column, field Field) error {
	if field.Null {
		if len(field.raw) != 0 {
			return errors.New("NULL field carries bytes")
		}
		return nil
	}
	switch column.Kind {
	case ColumnText:
		if !utf8.Valid(field.raw) {
			return errors.New("invalid UTF-8 TEXT")
		}
	case ColumnBlob:
	case ColumnInteger:
		if len(field.raw) != 8 {
			return fmt.Errorf("INTEGER is %d bytes", len(field.raw))
		}
	default:
		return errors.New("unknown column kind")
	}
	return nil
}

func LogicalRowCharge(columns []Column, fields []Field) (uint64, error) {
	if len(columns) != len(fields) {
		return 0, fmt.Errorf("policy store: census has %d columns and %d fields", len(columns), len(fields))
	}
	total := uint64(8) // row frame
	for index, column := range columns {
		field := fields[index]
		if err := validateField(column, field); err != nil {
			return 0, fmt.Errorf("policy store: %s: %w", column.Name, err)
		}
		if field.Null {
			continue
		}
		var charge uint64
		if column.Kind == ColumnInteger {
			charge = 8
		} else {
			charge = uint64(len(field.raw))
		}
		if math.MaxUint64-total < charge {
			return 0, errors.New("policy store: logical byte overflow")
		}
		total += charge
	}
	return total, nil
}

func RequestLogicalCharge(fields []Field) (uint64, error) {
	return LogicalRowCharge(RequestColumns[:], fields)
}
func VoteLogicalCharge(fields []Field) (uint64, error) {
	return LogicalRowCharge(VoteColumns[:], fields)
}
func HeadLogicalCharge(fields []Field) (uint64, error) {
	return LogicalRowCharge(HeadColumns[:], fields)
}

func checkedAdd(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if math.MaxUint64-total < value {
			return 0, errors.New("policy store: byte count overflow")
		}
		total += value
	}
	return total, nil
}

func checkedMultiply(left, right uint64) (uint64, error) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, errors.New("policy store: byte count overflow")
	}
	return left * right, nil
}

func cloneBytes(value []byte) []byte {
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}

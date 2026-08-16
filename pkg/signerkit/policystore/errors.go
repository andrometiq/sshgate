package policystore

import (
	"fmt"

	"github.com/karthikeyan5/sshgate/src/policywire"
)

type ErrorProducer string

const (
	ProducerBeginRejection     ErrorProducer = "begin_rejection"
	ProducerIntakeKey          ErrorProducer = "intake_key"
	ProducerMaterialization    ErrorProducer = "materialization"
	ProducerQuorumUnattainable ErrorProducer = "quorum_unattainable"
	ProducerNoOpPublication    ErrorProducer = "no_op_publication"
	ProducerResultPublication  ErrorProducer = "result_publication"
)

func ValidateStoredError(producer ErrorProducer, family ErrorFamily, code policywire.ErrorCode) error {
	allowed := false
	switch producer {
	case ProducerBeginRejection:
		allowed = family == ErrorFamilySemantic && oneOfError(code,
			policywire.ErrorInvalidPolicyRequest, policywire.ErrorPolicyRequestInProgress,
			policywire.ErrorSignerKeyChanged, policywire.ErrorStalePolicyHead,
			policywire.ErrorPolicyKeyTransitionRequired)
	case ProducerIntakeKey:
		allowed = family == ErrorFamilyProcessing && code == policywire.ErrorSignerKeyChanged
	case ProducerMaterialization:
		allowed = family == ErrorFamilyProcessing && oneOfError(code,
			policywire.ErrorSignerKeyChanged, policywire.ErrorStalePolicyHead,
			policywire.ErrorPolicyMaterializationFailed)
	case ProducerQuorumUnattainable:
		allowed = family == ErrorFamilySemantic && code == policywire.ErrorQuorumUnattainable
	case ProducerNoOpPublication, ProducerResultPublication:
		allowed = family == ErrorFamilyPublication && oneOfError(code,
			policywire.ErrorSignerKeyChanged, policywire.ErrorStalePolicyHead)
	}
	if !allowed {
		return fmt.Errorf("policy store: producer %q cannot store %q/%q", producer, family, code)
	}
	return nil
}

// ValidateErrorFamilyCode checks the persisted family/code closure when the
// producing command is no longer available, as on startup and archive reads.
func ValidateErrorFamilyCode(family ErrorFamily, code policywire.ErrorCode) error {
	allowed := false
	switch family {
	case ErrorFamilySemantic:
		allowed = validMatrix2AError(code) || code == policywire.ErrorQuorumUnattainable
	case ErrorFamilyProcessing:
		allowed = oneOfError(code, policywire.ErrorSignerKeyChanged,
			policywire.ErrorStalePolicyHead, policywire.ErrorPolicyMaterializationFailed)
	case ErrorFamilyPublication:
		allowed = oneOfError(code, policywire.ErrorSignerKeyChanged, policywire.ErrorStalePolicyHead)
	}
	if !allowed {
		return fmt.Errorf("policy store: invalid stored error %q/%q", family, code)
	}
	return nil
}

func HTTPStatusForError(code policywire.ErrorCode) (int, error) {
	switch code {
	case policywire.ErrorInvalidPolicyRequest:
		return 400, nil
	case policywire.ErrorIdempotencyConflict, policywire.ErrorPolicyRequestInProgress,
		policywire.ErrorSignerKeyChanged, policywire.ErrorStalePolicyHead,
		policywire.ErrorPolicyKeyTransitionRequired, policywire.ErrorQuorumUnattainable:
		return 409, nil
	case policywire.ErrorPolicyJournalFull:
		return 429, nil
	case policywire.ErrorPolicyNotificationFailed, policywire.ErrorPolicyMaterializationFailed:
		return 500, nil
	case policywire.ErrorPolicyNotSupported:
		return 501, nil
	default:
		return 0, fmt.Errorf("policy store: unknown error code %q", code)
	}
}

func oneOfError(value policywire.ErrorCode, allowed ...policywire.ErrorCode) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validMatrix2AError(code policywire.ErrorCode) bool {
	return oneOfError(code, policywire.ErrorInvalidPolicyRequest,
		policywire.ErrorPolicyRequestInProgress, policywire.ErrorSignerKeyChanged,
		policywire.ErrorStalePolicyHead, policywire.ErrorPolicyKeyTransitionRequired)
}

package policystore

import (
	"testing"

	"github.com/karthikeyan5/sshgate/src/policywire"
)

func TestStoredErrorAllowlistAndHTTPStatus(t *testing.T) {
	t.Parallel()
	allowed := []struct {
		producer ErrorProducer
		family   ErrorFamily
		code     policywire.ErrorCode
		status   int
	}{
		{ProducerBeginRejection, ErrorFamilySemantic, policywire.ErrorInvalidPolicyRequest, 400},
		{ProducerIntakeKey, ErrorFamilyProcessing, policywire.ErrorSignerKeyChanged, 409},
		{ProducerMaterialization, ErrorFamilyProcessing, policywire.ErrorPolicyMaterializationFailed, 500},
		{ProducerQuorumUnattainable, ErrorFamilySemantic, policywire.ErrorQuorumUnattainable, 409},
		{ProducerNoOpPublication, ErrorFamilyPublication, policywire.ErrorStalePolicyHead, 409},
	}
	for _, test := range allowed {
		if err := ValidateStoredError(test.producer, test.family, test.code); err != nil {
			t.Errorf("%+v: %v", test, err)
		}
		if status, err := HTTPStatusForError(test.code); err != nil || status != test.status {
			t.Errorf("%s status=%d, %v", test.code, status, err)
		}
	}
	if err := ValidateStoredError(ProducerQuorumUnattainable, ErrorFamilyProcessing, policywire.ErrorQuorumUnattainable); err == nil {
		t.Fatal("cross-family quorum error accepted")
	}
	if err := ValidateStoredError(ProducerResultPublication, ErrorFamilyPublication, policywire.ErrorPolicyMaterializationFailed); err == nil {
		t.Fatal("publication producer accepted materialization code")
	}
	if err := ValidateErrorFamilyCode(ErrorFamilyProcessing, policywire.ErrorPolicyMaterializationFailed); err != nil {
		t.Fatal(err)
	}
	if err := ValidateErrorFamilyCode(ErrorFamilySemantic, policywire.ErrorPolicyMaterializationFailed); err == nil {
		t.Fatal("semantic family accepted materialization code")
	}
}

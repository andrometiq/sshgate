package gate

import "github.com/karthikeyan5/sshgate/src/gate/confine"

// TransportMetadata separates delivery and cleanup from the command's outcome.
type TransportMetadata struct {
	Abandoned         bool                 `json:"abandoned"`
	DroppedBytes      int64                `json:"dropped_bytes"`
	SourceTruncated   string               `json:"source_truncated"`
	SourceBytesRead   int64                `json:"source_bytes_read"`
	DeliveryError     string               `json:"delivery_error"`
	OutputDestination string               `json:"output_destination"`
	CleanupError      string               `json:"cleanup_error"`
	WorkerStatus      confine.WorkerStatus `json:"worker_status"`
}

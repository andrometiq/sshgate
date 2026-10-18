package lifecycle

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// LegacyDestination includes the optional Telegram topic (zero means none).
type LegacyDestination struct{ ChatID, TopicID int64 }

// LegacyRenderContext freezes all non-snapshot rendering inputs. Metadata is
// adapter-encoded canonical metadata; lifecycle deliberately does not render it.
type LegacyRenderContext struct {
	Metadata          []byte
	Assist            assist.Snapshot
	Destination       LegacyDestination
	Handle, Challenge string
}

// LegacyMessage is one rendered message. Only the last has decision labels;
// the adapter derives callback data from the frozen handle and challenge.
type LegacyMessage struct {
	Bytes                   []byte
	ApproveLabel, DenyLabel string
}

// LegacyPreparedData is the constructor/getter value, never retained by reference.
// Inputs and SignDigest are empty for the non-sign legacy kinds.
type LegacyPreparedData struct {
	Instance   string
	Inputs     []ap.LegacySignInput
	SignDigest string
	Snapshot   []byte
	Context    LegacyRenderContext
	Payload    []LegacyMessage
}

// PreparedLegacyApproval owns the exact signing, display and delivery material.
// It is immutable, including through constructor arguments and getter results.
type PreparedLegacyApproval struct{ data LegacyPreparedData }

func NewPreparedLegacyApproval(data LegacyPreparedData) (*PreparedLegacyApproval, error) {
	if !ap.ValidEpoch(data.Instance) || len(data.Snapshot) == 0 || !ap.ValidCardHandle(data.Context.Handle) || !ap.ValidChallenge(data.Context.Challenge) || data.Context.Destination.ChatID == 0 || data.Context.Destination.TopicID < 0 || len(data.Payload) == 0 || !terminalLegacyAssist(data.Context.Assist) {
		return nil, errors.New("lifecycle: invalid prepared legacy approval")
	}
	if len(data.Inputs) > 0 {
		digest, ok := ap.LegacySignDigest(data.Instance, data.Inputs)
		if !ok || digest != data.SignDigest {
			return nil, errors.New("lifecycle: invalid legacy sign digest")
		}
	} else if data.SignDigest != "" {
		return nil, errors.New("lifecycle: legacy sign digest without inputs")
	}
	for i, message := range data.Payload {
		last := i == len(data.Payload)-1
		if len(message.Bytes) == 0 || (last && (message.ApproveLabel == "" || message.DenyLabel == "")) || (!last && (message.ApproveLabel != "" || message.DenyLabel != "")) {
			return nil, errors.New("lifecycle: invalid legacy payload")
		}
	}
	return &PreparedLegacyApproval{data: cloneLegacyData(data)}, nil
}

func (p *PreparedLegacyApproval) Data() LegacyPreparedData { return cloneLegacyData(p.data) }

func terminalLegacyAssist(s assist.Snapshot) bool {
	switch s.State {
	case ap.AssistReady:
		return s.Reason == "" && s.Result != nil && s.Result.Alignment == ap.AlignmentNotAssessed && ap.ValidateAssist(*s.Result) == nil
	case ap.AssistUnavailable:
		return s.Result == nil && (s.Reason == assist.ReasonBusy || s.Reason == assist.ReasonDeadline || s.Reason == assist.ReasonFailed || s.Reason == assist.ReasonRedaction || s.Reason == assist.ReasonCanceled)
	}
	return false
}

func cloneLegacyContext(c LegacyRenderContext) LegacyRenderContext {
	c.Metadata = bytes.Clone(c.Metadata)
	c.Handle = strings.Clone(c.Handle)
	c.Challenge = strings.Clone(c.Challenge)
	c.Assist.Reason = strings.Clone(c.Assist.Reason)
	if c.Assist.Result != nil {
		result := *c.Assist.Result
		result.Effects = slices.Clone(result.Effects)
		result.Concerns = slices.Clone(result.Concerns)
		result.Summary = strings.Clone(result.Summary)
		result.Model = strings.Clone(result.Model)
		result.PromptVersion = strings.Clone(result.PromptVersion)
		result.InputDigest = strings.Clone(result.InputDigest)
		for i := range result.Effects {
			result.Effects[i] = strings.Clone(result.Effects[i])
		}
		for i := range result.Concerns {
			result.Concerns[i].Text = strings.Clone(result.Concerns[i].Text)
		}
		c.Assist.Result = &result
	}
	return c
}

func cloneLegacyData(d LegacyPreparedData) LegacyPreparedData {
	d.Instance = strings.Clone(d.Instance)
	d.SignDigest = strings.Clone(d.SignDigest)
	d.Inputs = slices.Clone(d.Inputs)
	for i := range d.Inputs {
		in := &d.Inputs[i]
		in.Server = strings.Clone(in.Server)
		in.HostFingerprint = strings.Clone(in.HostFingerprint)
		in.Command = strings.Clone(in.Command)
		in.CommandSHA256 = strings.Clone(in.CommandSHA256)
		in.Reason = strings.Clone(in.Reason)
	}
	d.Snapshot = bytes.Clone(d.Snapshot)
	d.Context = cloneLegacyContext(d.Context)
	d.Payload = slices.Clone(d.Payload)
	for i := range d.Payload {
		d.Payload[i].Bytes = bytes.Clone(d.Payload[i].Bytes)
		d.Payload[i].ApproveLabel = strings.Clone(d.Payload[i].ApproveLabel)
		d.Payload[i].DenyLabel = strings.Clone(d.Payload[i].DenyLabel)
	}
	return d
}

func sameLegacyPrepared(a, b *PreparedLegacyApproval) bool {
	return a != nil && b != nil && reflect.DeepEqual(a.data, b.data)
}

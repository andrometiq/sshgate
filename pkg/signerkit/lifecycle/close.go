package lifecycle

import (
	"errors"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

func unavailable() error { return &ap.CodeError{Code: ap.CodeLifecycleUnavailable} }

// stop establishes the commit cut before canceling any owned effect.
func (e *Engine) stop() {
	e.mu.Lock()
	e.stopping = true
	e.cancelEffects()
	e.mu.Unlock()
}

// Close stops admission and joins all engine work. The configured assist pool
// belongs to this engine. Close must not be called by an engine adapter.
func (e *Engine) Close() error {
	e.stop()
	e.mu.Lock()
	done := e.runDone
	e.mu.Unlock()
	if e.config.AssistPool != nil {
		e.config.AssistPool.Close()
	}
	if done != nil {
		<-done
	}
	e.waitJoined.Wait()
	return nil
}

// Availability reports the permanent stop cause for this generation.
func (e *Engine) Availability() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.availabilityLocked()
}

func (e *Engine) checkAvailable() error { return e.Availability() }

func (e *Engine) availabilityLocked() error {
	if e.stopCause != nil {
		return e.stopCause
	}
	if e.stopping {
		return unavailable()
	}
	return nil
}

func (e *Engine) storageErrorLocked(err error) error {
	var coded *ap.CodeError
	if errors.As(err, &coded) && coded.Code == ap.CodeStorageUncertain {
		e.stopCause = err
		e.stopping = true
		e.cancelEffects()
	}
	return err
}

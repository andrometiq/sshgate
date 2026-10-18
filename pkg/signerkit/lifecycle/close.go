package lifecycle

import ap "github.com/karthikeyan5/sshgate/src/approvalplan"

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
	e.legacyClosed = true
	e.cancelLegacy()
	for _, r := range e.legacy.requests {
		e.resolveLegacyLocked(r, LegacyResult{Status: "timeout"})
	}
	done := e.runDone
	e.mu.Unlock()
	if e.config.AssistPool != nil {
		e.config.AssistPool.Close()
	}
	if done != nil {
		<-done
	}
	e.waitJoined.Wait()
	e.legacyJoined.Wait()
	return nil
}

func (e *Engine) checkAvailable() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return unavailable()
	}
	return nil
}

package lifecycle

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Each actor owns its raw edit challenge and retry timer. The engine mutex
// serializes nudges and commits; transport calls never hold it.
type notifyActor struct {
	engine *Engine
	key    string
	nudge  chan struct{}
	edit   Notification
	delay  time.Duration
}

func (e *Engine) nudgeNotifyLocked(key string) {
	if e.config.Notifier == nil || e.notifyContext == nil || e.notifyContext.Err() != nil {
		return
	}
	a := e.notifyActors[key]
	if a == nil {
		if e.projections.work[key].Notify.Kind == ap.NotifyNone {
			return
		}
		a = &notifyActor{engine: e, key: key, nudge: make(chan struct{}, 1)}
		e.notifyActors[key] = a
		e.startNotifyLocked(a)
	}
	select {
	case a.nudge <- struct{}{}:
	default:
	}
}

func (e *Engine) startNotifyLocked(a *notifyActor) {
	e.notifyJoined.Add(1)
	ctx := e.notifyContext
	go func() {
		defer e.notifyJoined.Done()
		if err := a.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			select {
			case e.effectErrors <- err:
			default:
			}
		}
	}()
}

func (a *notifyActor) read(ctx context.Context) (*ap.R1, ap.NotifyStep, error) {
	e := a.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, ap.NotifyStep{}, err
	}
	rec, err := e.load(a.key)
	if err != nil || rec == nil {
		return rec, ap.NotifyStep{}, err
	}
	now := e.now()
	if ap.Next(*rec, now, e.epoch, e.config.Settings, e.projections.grants[a.key] != nil).Clock {
		after, answer, err := e.commitLocked(a.key, rec, ap.Tick{}, now, ap.Inputs{})
		if err != nil {
			return nil, ap.NotifyStep{}, err
		}
		if err := answerError(answer); err != nil {
			return nil, ap.NotifyStep{}, err
		}
		rec = &after
	}
	return rec, ap.NotifyNext(*rec, now, e.epoch, e.config.Settings), nil
}

func (a *notifyActor) commit(ctx context.Context, cmd ap.Command) (ap.R1, ap.Answer, error) {
	e := a.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ap.R1{}, ap.Answer{}, err
	}
	rec, err := e.load(a.key)
	if err != nil {
		return ap.R1{}, ap.Answer{}, err
	}
	if rec == nil {
		return ap.R1{}, ap.Answer{}, keyError()
	}
	after, answer, err := e.commitLocked(a.key, rec, cmd, e.now(), ap.Inputs{})
	if err == nil {
		err = answerError(answer)
	}
	return after, answer, err
}

func notification(rec ap.R1) Notification {
	n := Notification{Snapshot: rec.Payload.ReviewSnapshot, Assist: rec.Payload.AssistResult, AssistState: ap.AssistPreparing}
	if rec.Header.Assist != nil {
		n.AssistState, n.Revision = rec.Header.Assist.State, 1
	}
	if bursts := rec.Payload.Bursts; len(bursts) != 0 {
		n.PartMessageIDs = bursts[len(bursts)-1].PartMsgIDs
	}
	return n
}

func (a *notifyActor) run(ctx context.Context) error {
	var timer *time.Timer
	var retry <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		_, step, err := a.read(ctx)
		if err != nil {
			return err
		}
		if step.Kind != ap.NotifyEditRetry || step.Handle != a.edit.Handle {
			if timer != nil {
				timer.Stop()
			}
			retry, a.delay = nil, 0
		}
		switch step.Kind {
		case ap.NotifyBurst, ap.NotifyCard:
			if err := a.engine.config.Notifier.Burst(ctx, func(session BurstSession) error {
				return a.burst(ctx, session)
			}); err != nil {
				return err
			}
		case ap.NotifyEdit, ap.NotifyEditRetry:
			if step.Kind == ap.NotifyEditRetry && retry != nil {
				break
			}
			if step.Kind == ap.NotifyEdit {
				_, n, ok, err := a.startCard(ctx, true)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
				a.edit = n
			}
			_, next, err := a.read(ctx)
			if err != nil {
				return err
			}
			if next.Kind != ap.NotifyEditRetry {
				continue
			}
			if a.edit.Challenge == "" || next.Handle != a.edit.Handle {
				return errors.New("lifecycle: missing edit challenge")
			}
			outcome, _ := a.engine.config.Notifier.EditCard(ctx, next.MsgID, a.edit)
			if err := ctx.Err(); err != nil {
				return err
			}
			if outcome == EditPossible {
				if a.delay == 0 {
					a.delay = time.Second
				} else {
					a.delay = min(a.delay*2, 30*time.Second)
				}
				timer = newEditRetryTimer(a.delay)
				retry = timer.C
			} else {
				if _, _, err := a.commit(ctx, ap.EditDone{Handle: a.edit.Handle, Failed: outcome != EditConfirmed}); err != nil {
					return err
				}
			}
		case ap.NotifyStatus:
			_ = a.engine.config.Notifier.EditStatus(ctx, step.MsgID, step.State)
			if _, _, err := a.commit(ctx, ap.StatusEdited{State: step.State}); err != nil {
				return err
			}
		}
		if step.Kind == ap.NotifyNone || retry != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-a.nudge:
			case <-retry:
				retry = nil
			}
		}
	}
}

// The timer wakes the actor only; its timestamp is never a lifecycle fact.
func newEditRetryTimer(delay time.Duration) *time.Timer { return time.NewTimer(delay) }

func (a *notifyActor) startCard(ctx context.Context, edit bool) (ap.R1, Notification, bool, error) {
	handle, err := ap.NewCardHandle(rand.Reader)
	if err != nil {
		return ap.R1{}, Notification{}, false, err
	}
	challenge, err := ap.NewChallenge(rand.Reader)
	if err != nil {
		return ap.R1{}, Notification{}, false, err
	}
	var cmd ap.Command = ap.CardStart{Handle: handle, ChalHash: ap.ChallengeHash(challenge)}
	if edit {
		cmd = ap.EditStart{Handle: handle, ChalHash: ap.ChallengeHash(challenge)}
	}
	rec, answer, err := a.commit(ctx, cmd)
	if err != nil || answer.Reason != "" {
		return rec, Notification{}, false, err
	}
	n := notification(rec)
	n.Handle, n.Challenge = handle, challenge
	return rec, n, true, nil
}

func (a *notifyActor) burst(ctx context.Context, session BurstSession) error {
	for {
		rec, step, err := a.read(ctx)
		if err != nil {
			return err
		}
		switch step.Kind {
		case ap.NotifyBurst:
			_, answer, err := a.commit(ctx, ap.BurstStart{})
			if err != nil {
				return err
			}
			if answer.Reason != "" {
				continue
			}
			rec, _, err = a.read(ctx)
			if err != nil {
				return err
			}
			if rec.Header.Decision != nil {
				return nil
			}
			ids, sendErr := session.SendParts(ctx, notification(*rec))
			if _, _, err := a.commit(ctx, ap.BurstDone{PartMsgIDs: ids, Failed: sendErr != nil}); err != nil {
				return err
			}
			if sendErr != nil {
				return a.incomplete(ctx, ids)
			}
		case ap.NotifyCard:
			_, n, ok, err := a.startCard(ctx, false)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			rec, _, err = a.read(ctx)
			if err != nil {
				return err
			}
			if rec.Header.Decision != nil {
				return nil
			}
			id, sendErr := session.SendCard(ctx, n)
			if id <= 0 && sendErr == nil {
				sendErr = errors.New("lifecycle: invalid card message ID")
			}
			if _, _, err := a.commit(ctx, ap.CardDone{Handle: n.Handle, MsgID: id, Failed: sendErr != nil}); err != nil {
				return err
			}
			if sendErr != nil {
				return a.incomplete(ctx, n.PartMessageIDs)
			}
			return nil
		default:
			return nil
		}
	}
}

func (a *notifyActor) incomplete(ctx context.Context, ids []int64) error {
	for _, id := range ids {
		if _, _, err := a.read(ctx); err != nil {
			return err
		}
		_ = a.engine.config.Notifier.MarkIncomplete(ctx, id)
	}
	return ctx.Err()
}

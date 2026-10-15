package statetest

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Clock is the harness's two-reading clock fake: the wall clock, and an
// elapsed clock that never steps and counts suspend (CLOCK_BOOTTIME).
type Clock struct {
	Wall    time.Time
	Elapsed time.Duration
}

// Now is the current reading pair.
func (c *Clock) Now() ap.Now { return ap.Now{Wall: c.Wall, Elapsed: c.Elapsed} }

// Advance lets d of real time pass; Suspend is the same on CLOCK_BOOTTIME.
func (c *Clock) Advance(d time.Duration) { c.Wall, c.Elapsed = c.Wall.Add(d), c.Elapsed+d }

// StepWall moves only the wall clock, by d of either sign.
func (c *Clock) StepWall(d time.Duration) { c.Wall = c.Wall.Add(d) }

// crash is the panic a commit raises at an injected crash point.
type crash struct{ owner string }

// Sink is the fake audit sink. It records each event key it took.
type Sink struct {
	Fail bool
	Keys map[string]int
}

// Telegram is the fake Bot API. It counts every send per burst and per card
// handle, so a resend is visible.
type Telegram struct {
	Fail       bool
	BurstSends map[string]int
	CardSends  map[string]int
	Edits      int
	msg        int64
}

func (t *Telegram) next() int64 { t.msg++; return t.msg }

// Signer is the model local signer: a durable store of R1 records, the
// projections a real engine keeps in memory, and the effect drivers, all
// running through approvalplan's pure core. Every commit is checked with
// CheckTransition, and a commit can be made a crash point, landed or not.
type Signer struct {
	Oracle     bool
	authorized map[string]authorization
	LiveCap    int
	FlushOrder []string
	Settings   ap.Settings
	Flags      ap.VoteFlags
	Validity   time.Duration
	Clock      *Clock
	Store      map[string]ap.R1
	Epoch      string
	Sink       *Sink
	TG         *Telegram
	// Released is the one signature set that left per record.
	Released map[string][]string
	// CrashAt makes commit number CrashAt a crash point; CrashLanded says
	// whether that commit reached the store.
	CrashAt     int
	CrashLanded bool
	Commits     int
	Err         error
	// Reserved is each record's R1Reservation at freeze.
	Reserved map[string]int

	rnd       *rand.Rand
	epochs    int
	nonce     int
	grants    map[string]*grantHold
	newest    map[string]string
	challenge map[string]string
}

type grantHold struct {
	held ap.Held
	dead bool
}

// NewSigner starts a model signer at clock with a fresh epoch.
func NewSigner(clock *Clock, seed uint64) *Signer {
	s := &Signer{
		Settings: ap.LocalSettings, Flags: ap.LocalVoteFlags, Validity: ap.ValidityMin, Clock: clock,
		Store: map[string]ap.R1{}, Sink: &Sink{Keys: map[string]int{}},
		TG:       &Telegram{BurstSends: map[string]int{}, CardSends: map[string]int{}},
		Released: map[string][]string{}, Reserved: map[string]int{}, rnd: rand.New(rand.NewPCG(seed, 1)),
	}
	s.authorized = map[string]authorization{}
	s.Restart()
	return s
}

func (s *Signer) fail(err error) {
	if s.Err == nil {
		s.Err = err
	}
}

// Restart is Startup after a crash or stop: all memory is discarded, a new
// epoch is minted (so every grant dies), and the reconciler runs on every
// record (SA-8).
func (s *Signer) Restart() {
	s.NewEpoch()
	for _, key := range s.keys() {
		s.Reconcile(key)
	}
}

// NewEpoch is the crash cut alone: memory discarded and a new epoch, before
// Startup's reconciler runs.
func (s *Signer) NewEpoch() {
	s.epochs++
	s.Epoch = Epoch(s.epochs)
	s.grants, s.newest, s.challenge = map[string]*grantHold{}, map[string]string{}, map[string]string{}
}

func (s *Signer) keys() []string {
	keys := make([]string, 0, len(s.Store))
	for k := range s.Store {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// grantLive is the projection's verdict: newest for its alias, and its held
// pair latched dead at the first finding on either clock.
func (s *Signer) grantLive(key string) bool {
	g, ok := s.grants[key]
	rec := s.Store[key]
	if !ok || g.dead {
		return false
	}
	if g.held.Passed(s.Clock.Now()) {
		g.dead = true
		return false
	}
	return s.newest[rec.Header.Principal+"\x00"+rec.Header.GrantAlias] == key && ap.GrantLive(rec, s.Clock.Now(), s.Epoch, true)
}

func (s *Signer) inputs(key string) ap.Inputs {
	return ap.Inputs{Epoch: s.Epoch, Settings: s.Settings, GrantLive: s.grantLive(key)}
}

// apply runs one command through Apply and commits its record.
func (s *Signer) apply(key string, cmd ap.Command, in ap.Inputs) ap.Answer {
	now := s.Clock.Now()
	var cur *ap.R1
	if rec, ok := s.Store[key]; ok {
		cur = &rec
	}
	after, ans := ap.Apply(cur, cmd, now, in)
	if ans.Removed {
		delete(s.Store, key)
		return ans
	}
	if err := CheckRecordAnswer(after, ans, now); err != nil {
		s.fail(fmt.Errorf("%T: %w", cmd, err))
	}
	if ans.Changed {
		if err := s.checkVote(cur, after, cmd, ans); err != nil {
			s.fail(err)
		}
		s.commit(key, cur, after, now, cmd, in)
	}
	return ans
}

// checkVote: a vote's decision is Decide under the record's effective
// policy, and a refused or duplicate vote is exactly one noise event (or one
// fold).
func (s *Signer) checkVote(before *ap.R1, after ap.R1, cmd ap.Command, ans ap.Answer) error {
	v, ok := cmd.(ap.CastVote)
	if !ok || before == nil {
		return nil
	}
	b, a := before.Header, after.Header
	if ans.Noise {
		noise := 0
		for _, e := range a.Outbox {
			if e.Seq > b.OutboxSeq && e.Replay {
				noise++
			}
		}
		if noise+int(a.NoiseDropped-b.NoiseDropped) != 1 || len(a.Votes) != len(b.Votes) {
			return fmt.Errorf("a refused or duplicate vote changed more than one noise event")
		}
		return nil
	}
	if a.Decision != nil && b.Decision == nil && len(a.Votes) > len(b.Votes) {
		if got := ap.Decide(ap.EffectivePolicy(after, v.Flags), a.Votes); got != a.Decision.Status {
			return fmt.Errorf("a vote decided %s where Decide says %s", a.Decision.Status, got)
		}
	}
	return nil
}

func (s *Signer) commit(key string, before *ap.R1, after ap.R1, now ap.Now, cmd ap.Command, in ap.Inputs) {
	if err := CheckTransition(before, after, now); err != nil {
		s.fail(fmt.Errorf("commit %d on %s: %w", s.Commits+1, key, err))
	}
	s.Commits++
	crashing := s.Commits == s.CrashAt
	if !crashing || s.CrashLanded {
		s.checkAuthorization(key, before, after, cmd, in)
		if before == nil {
			s.Reserved[key] = ap.R1Reservation(after)
		}
		s.Store[key] = after
		s.project(key, before, after, now)
	}
	if crashing {
		panic(crash{owner: "signer"})
	}
}

// project updates the grant projection after a confirmed commit: a grant
// approved in this epoch is acquired on two clocks and raises the
// newest-grant mark; a revoke latches it dead.
func (s *Signer) project(key string, before *ap.R1, after ap.R1, now ap.Now) {
	h := after.Header
	if h.Kind != ap.KindStandingGrant {
		return
	}
	if (before == nil || before.Header.Decision == nil) && h.Decision != nil && h.Decision.Status == ap.ApprovalApproved {
		s.grants[key] = &grantHold{held: ap.AcquireGrant(after, now)}
		s.newest[h.Principal+"\x00"+h.GrantAlias] = key
	}
	if h.RevokedAt != nil {
		if g := s.grants[key]; g != nil {
			g.dead = true
		}
	}
}

// Submit submits d for principal: grant matching over the principal's live
// grants, then the freeze.
func (s *Signer) Submit(principal string, d ap.ApprovalDraft) ap.Answer {
	key := ap.RecordKey(principal, d.RequestID)
	now := s.Clock.Now()
	cmd := SubmitOf(d, principal, now.Wall, s.Validity)
	in := s.inputs(key)
	if _, exists := s.Store[key]; !exists {
		probe, ans := ap.Apply(nil, cmd, now, in)
		if ans.Code != "" {
			return ans
		}
		if s.LiveCap > 0 {
			for _, k := range s.keys() {
				s.apply(k, ap.Tick{}, s.inputs(k))
			}
			live := 0
			for _, k := range s.keys() {
				if ap.Class(s.Store[k], now, s.Settings, s.grantLive(k)) == ap.ClassLive {
					live++
				}
			}
			if live >= s.LiveCap {
				return ap.Answer{Code: ap.CodeQueueFull}
			}
		}
		for _, gk := range s.keys() {
			if s.grantLive(gk) && ap.GrantCovers(s.Store[gk], probe) {
				in.Grant = &ap.GrantRef{Record: s.Store[gk], Live: true}
				break
			}
		}
	}
	return s.apply(key, cmd, in)
}

// Get is a read: it must never change the record.
func (s *Signer) Get(key string) (ap.Summary, bool) {
	rec, ok := s.Store[key]
	if !ok {
		return ap.Summary{}, false
	}
	before := enc(rec)
	sum := ap.View(rec, s.Clock.Now(), s.Epoch, s.Settings, s.grantLive(key))
	ap.Next(rec, s.Clock.Now(), s.Epoch, s.Settings, s.grantLive(key))
	if enc(rec) != before || enc(s.Store[key]) != before {
		s.fail(fmt.Errorf("a view wrote to %s", key))
	}
	return sum, true
}

// Claim claims a record, supplying the mint inputs when the core asks.
func (s *Signer) Claim(key string, token [32]byte) ap.Answer {
	rec, ok := s.Store[key]
	cmd := ap.Claim{Token: token}
	if ok {
		cmd.PlanHash = rec.Header.PlanHash
	}
	in := s.inputs(key)
	ans := s.apply(key, cmd, in)
	if ans.MintRequired {
		in.Minted = s.mint(rec)
		if d := rec.Header.Decision; d != nil && strings.HasPrefix(d.DecidedBy, ap.GrantDecidedPrefix) {
			gk := ap.RecordKey(rec.Header.Principal, strings.TrimPrefix(d.DecidedBy, ap.GrantDecidedPrefix))
			in.Grant = &ap.GrantRef{Record: s.Store[gk], Live: s.grantLive(gk)}
		}
		ans = s.apply(key, cmd, in)
	}
	if len(ans.Signatures) > 0 {
		s.checkReleaseAuthority(key)
		if prev, ok := s.Released[key]; ok && !slices.Equal(prev, ans.Signatures) {
			s.fail(fmt.Errorf("a second signature set left for %s", key))
		}
		s.Released[key] = ans.Signatures
	}
	return ans
}

// mint is the fake minter: every call is fresh bytes, as a real nonce makes.
func (s *Signer) mint(rec ap.R1) []string {
	s.nonce++
	var sigs []string
	for i, st := range rec.Payload.Plan.CommandJob.Steps {
		if st.Route.Signed() {
			sigs = append(sigs, Sig(rec.Header.RequestID, i, s.nonce))
		}
	}
	return sigs
}

// Report sends a final report.
func (s *Signer) Report(key string, token [32]byte, body ap.FinalReport) ap.Answer {
	cmd := ap.Report{Token: token, Body: body}
	if rec, ok := s.Store[key]; ok {
		cmd.PlanHash = rec.Header.PlanHash
	}
	return s.apply(key, cmd, s.inputs(key))
}

// Tap votes on the record's latest card entry, with its real challenge when
// valid, else with a stale one.
func (s *Signer) Tap(key, decision, operator string, valid bool) ap.Answer {
	rec, ok := s.Store[key]
	tap := &ap.CardTap{Handle: "aaaaaaaaaaaa", Challenge: "0000000000000000", MsgID: 1}
	if ok && rec.Payload != nil {
		for i := len(rec.Payload.CardEntries) - 1; i >= 0; i-- {
			if e := rec.Payload.CardEntries[i]; valid && e.MsgID != nil {
				tap = &ap.CardTap{Handle: e.Handle, Challenge: s.challenge[e.Handle], MsgID: *e.MsgID}
				break
			}
		}
	}
	return s.apply(key, ap.CastVote{Operator: operator, Decision: decision, Authn: "telegram", Flags: s.Flags, Card: tap}, s.inputs(key))
}

// Cancel is an admin cancel of the record's current plan.
func (s *Signer) Cancel(key string) ap.Answer {
	return s.apply(key, ap.AdminCancel{PlanHash: s.Store[key].Header.PlanHash, Admin: Admin}, s.inputs(key))
}

// Renotify is /renotify.
func (s *Signer) Renotify(key string) ap.Answer { return s.apply(key, ap.Renotify{}, s.inputs(key)) }

// RevokeAlias revokes every live grant for alias, whatever its principal.
func (s *Signer) RevokeAlias(alias string) {
	for _, key := range s.keys() {
		if rec := s.Store[key]; rec.Header.GrantAlias == alias && s.grantLive(key) {
			s.apply(key, ap.Revoke{}, s.inputs(key))
		}
	}
}

// AssistArrives commits the one assist attempt's result for a record.
func (s *Signer) AssistArrives(key string, unavailable bool) {
	cmd := ap.AssistDone{Unavailable: "assist busy"}
	if !unavailable {
		r := Assist(s.Clock.Wall)
		cmd = ap.AssistDone{Result: &r}
	}
	if _, ok := s.Store[key]; ok {
		s.apply(key, cmd, s.inputs(key))
	}
}

// Tick is the per-second reconciler pass over every record, then one flush
// pass.
func (s *Signer) Tick() {
	for _, key := range s.keys() {
		s.Reconcile(key)
	}
	s.FlushPass()
}

// Reconcile runs Next's work for one record: Clock, the notify steps, and
// Shed or Delete by age.
func (s *Signer) Reconcile(key string) {
	for range 8 {
		rec, ok := s.Store[key]
		if !ok {
			return
		}
		w := ap.Next(rec, s.Clock.Now(), s.Epoch, s.Settings, s.grantLive(key))
		switch {
		case w.Clock:
			s.apply(key, ap.Tick{}, s.inputs(key))
		case w.Notify.Kind != ap.NotifyNone:
			if !s.notify(key, w.Notify) {
				return
			}
		case w.Delete:
			s.apply(key, ap.Delete{}, s.inputs(key))
		case w.Shed:
			s.apply(key, ap.ShedRecord{}, s.inputs(key))
		default:
			return
		}
	}
}

func (s *Signer) handle() (string, string) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, ap.CardHandleLen)
	for i := range b {
		b[i] = alphabet[s.rnd.IntN(len(alphabet))]
	}
	return string(b), fmt.Sprintf("%016x", s.rnd.Uint64())
}

// notify runs one notify step as the record's actor: the write-ahead
// commit, the fake Bot API call, and the outcome commit. It reports whether
// the step made progress.
func (s *Signer) notify(key string, step ap.NotifyStep) bool {
	in := s.inputs(key)
	switch step.Kind {
	case ap.NotifyBurst:
		if ans := s.apply(key, ap.BurstStart{}, in); !ans.Changed {
			return false
		}
		gen := s.Store[key].Header.RenotifyGen
		s.TG.BurstSends[fmt.Sprintf("%s/%d", key, gen)]++
		s.apply(key, ap.BurstDone{PartMsgIDs: []int64{s.TG.next()}, Failed: s.TG.Fail}, in)
	case ap.NotifyCard:
		h, chal := s.handle()
		if ans := s.apply(key, ap.CardStart{Handle: h, ChalHash: ap.ChallengeHash(chal)}, in); !ans.Changed || ans.Reason != "" {
			return ans.Changed
		}
		s.challenge[h] = chal
		s.TG.CardSends[h]++
		s.apply(key, ap.CardDone{Handle: h, MsgID: s.TG.next(), Failed: s.TG.Fail}, in)
	case ap.NotifyEdit:
		h, chal := s.handle()
		if ans := s.apply(key, ap.EditStart{Handle: h, ChalHash: ap.ChallengeHash(chal)}, in); !ans.Changed || ans.Reason != "" {
			return ans.Changed
		}
		s.challenge[h] = chal
		s.TG.Edits++
		s.apply(key, ap.EditDone{Handle: h, Failed: s.TG.Fail}, in)
	case ap.NotifyEditRetry:
		if _, ok := s.challenge[step.Handle]; !ok {
			s.fail(fmt.Errorf("edit retry for %s without its challenge in memory", key))
			return false
		}
		s.TG.Edits++
		s.apply(key, ap.EditDone{Handle: step.Handle, Failed: s.TG.Fail}, in)
	case ap.NotifyStatus:
		s.TG.Edits++
		return s.apply(key, ap.StatusEdited{State: step.State}, in).Changed
	}
	return true
}

// FlushPass is the flusher's retry pass: every unflushed record, stopping at
// the first sink failure.
func (s *Signer) FlushPass() {
	keys := s.keys()
	slices.SortStableFunc(keys, func(a, b string) int {
		x, y := ap.NextDueAt(s.Store[a], s.Clock.Now(), s.Settings), ap.NextDueAt(s.Store[b], s.Clock.Now(), s.Settings)
		if x.IsZero() {
			if y.IsZero() {
				return 0
			}
			return 1
		}
		if y.IsZero() {
			return -1
		}
		return x.Compare(y)
	})
	count := 0
	for _, key := range keys {
		if count >= ap.FlushBatch {
			return
		}
		rec := s.Store[key]
		if !ap.Unflushed(rec) {
			continue
		}
		if s.Sink.Fail {
			return
		}
		count++
		s.FlushOrder = append(s.FlushOrder, key)
		for _, e := range rec.Header.Outbox {
			s.Sink.Keys[ap.EventKey(key, e.Seq)]++
		}
		s.apply(key, ap.Flush{Through: rec.Header.OutboxSeq}, s.inputs(key))
	}
}

// TapEntry votes on one card entry with the challenge the actor minted for
// it, so a test can press a superseded card.
func (s *Signer) TapEntry(key string, entry ap.CardEntry, decision, operator string) ap.Answer {
	var msg int64
	if entry.MsgID != nil {
		msg = *entry.MsgID
	}
	tap := &ap.CardTap{Handle: entry.Handle, Challenge: s.challenge[entry.Handle], MsgID: msg}
	return s.apply(key, ap.CastVote{Operator: operator, Decision: decision, Authn: "telegram", Flags: s.Flags, Card: tap}, s.inputs(key))
}

// Do applies one command to a record with the signer's current inputs,
// checked and committed like every other.
func (s *Signer) Do(key string, cmd ap.Command) ap.Answer { return s.apply(key, cmd, s.inputs(key)) }

// NewCard mints a card handle and challenge the way the actor does and
// remembers the challenge.
func (s *Signer) NewCard() (handle, chalHash string) {
	h, chal := s.handle()
	s.challenge[h] = chal
	return h, ap.ChallengeHash(chal)
}

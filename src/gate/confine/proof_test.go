package confine

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

type Case = harness.Case

type jailResult struct {
	exit           int
	stdout, stderr string
	setupErr       error
}
type JailedResult struct {
	ShimExit  int
	Cancelled bool
	jailResult
	Facts     Facts
	Worker    WorkerStatus
	validated bool
	owner     *proof
	token     *bool
	mode      string
}
type ControlResult struct {
	Valid  bool
	Detail string
	Jailed *JailedResult
}
type Observation struct {
	Conclusive, Sealed, Valid bool
	Detail                    string
}
type ObserverMark int64
type ObservationRecords struct {
	Records            []string
	Sealed, Conclusive bool
	Err                error
}
type ProducerSync struct {
	Complete bool
	Kind     string
}
type Observer interface {
	Start(*testing.T)
	Mark() ObserverMark
	Since(ObserverMark) ObservationRecords
	Healthy() error
	Seal(ProducerSync) error
	Stop() error
}
type proof struct {
	t          *testing.T
	caseDef    harness.Case
	abi        string
	done       map[string]bool
	markers    map[string]bool
	observers  map[string]Observer
	finished   bool
	executions []*bool
}

var activeProofs sync.Map // keyed by testing.T, never by leg name (ABIs may run concurrently)

func newProof(t *testing.T, leg string) *proof {
	t.Helper()
	var found *harness.Case
	for i := range legCases {
		if legCases[i].Name == leg {
			found = &legCases[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("SETUP: undeclared proof %s", leg)
	}
	return beginProof(t, *found)
}
func beginProof(t *testing.T, c harness.Case) *proof {
	t.Helper()
	if err := harness.ValidateCases([]harness.Case{c}); err != nil {
		t.Fatalf("SETUP: invalid proof declaration: %v", err)
	}
	abi := "native"
	for _, part := range strings.Split(t.Name(), "/") {
		if part == "abi1" {
			abi = "abi1"
		}
	}
	p := &proof{t: t, caseDef: c, abi: abi, done: map[string]bool{}, markers: map[string]bool{}, observers: map[string]Observer{}}
	if _, loaded := activeProofs.LoadOrStore(t, p); loaded {
		t.Fatal("SETUP: duplicate active proof")
	}
	t.Cleanup(func() {
		activeProofs.Delete(t)
		if !p.finished {
			t.Error("SETUP: proof not finished")
			p.stopObservers()
		}
	})
	return p
}
func RunCase(t *testing.T, c Case, body func(*proof)) {
	t.Helper()
	p := newProof(t, c.Name)
	body(p)
	if !p.finished {
		p.Finish()
	}
}
func (p *proof) complete(key string) {
	p.t.Helper()
	if p.finished {
		p.t.Fatal("SETUP: obligation after finalization")
	}
	allowed := false
	for _, want := range p.caseDef.Obligations {
		if want == key {
			allowed = true
		}
	}
	if !allowed || p.done[key] {
		p.t.Fatalf("SETUP: undeclared or duplicate obligation %s", key)
	}
	p.done[key] = true
}
func (p *proof) Control(name string, result ControlResult) {
	p.t.Helper()
	if !result.Valid {
		p.t.Fatalf("SETUP: control %s: %s", name, result.Detail)
	}
	if result.Jailed != nil {
		p.consume(*result.Jailed)
	}
	p.complete("control:" + name)
}
func (p *proof) consume(result JailedResult) {
	p.t.Helper()
	if !result.validated || result.owner != p || result.token == nil || *result.token {
		p.t.Fatal("SETUP: jailed evidence unvalidated, foreign or reused")
	}
	*result.token = true
}
func (p *proof) Jailed(name string, results ...JailedResult) {
	p.t.Helper()
	if len(results) == 0 {
		p.t.Fatal("SETUP: empty jailed evidence")
	}
	for _, result := range results {
		p.consume(result)
	}
	p.complete("jailed:" + name)
}
func (p *proof) Observed(name string, value Observation) {
	p.t.Helper()
	for observerName, observer := range p.observers {
		records := observer.Since(0)
		if err := observer.Healthy(); err != nil || records.Err != nil || !records.Sealed || !records.Conclusive {
			p.t.Fatalf("SETUP: inconclusive or invalid observation %s from %s: %v %v", name, observerName, err, records.Err)
		}
	}
	if !value.Conclusive || !value.Sealed || !value.Valid {
		p.t.Fatalf("SETUP: inconclusive or invalid observation %s: %s", name, value.Detail)
	}
	p.complete("observe:" + name)
}
func (p *proof) ObserveWith(name string, observer Observer) {
	p.t.Helper()
	if p.finished || observer == nil || p.observers[name] != nil {
		p.t.Fatal("SETUP: invalid observer registration")
	}
	p.observers[name] = observer
	observer.Start(p.t)
	p.healthy()
}
func (p *proof) healthy() {
	p.t.Helper()
	for name, obs := range p.observers {
		if err := obs.Healthy(); err != nil {
			p.t.Fatalf("SETUP: observer %s: %v", name, err)
		}
	}
}
func (p *proof) stopObservers() {
	for name, obs := range p.observers {
		if err := obs.Healthy(); err != nil {
			p.t.Errorf("SETUP: observer %s: %v", name, err)
		}
		if err := obs.Stop(); err != nil {
			p.t.Errorf("SETUP: observer %s stop: %v", name, err)
		}
		delete(p.observers, name)
	}
}
func (p *proof) record(kind, leg, marker string) {
	p.t.Helper()
	if p.finished || leg != p.caseDef.Name {
		p.t.Fatalf("SETUP: marker outside proof %s", leg)
	}
	key := kind + ":" + marker
	for _, allowed := range p.caseDef.Markers {
		if key == allowed {
			if p.markers[key] {
				p.t.Fatalf("SETUP: duplicate marker %s", key)
			}
			p.markers[key] = true
			return
		}
	}
	p.t.Fatalf("SETUP: undeclared marker %s", key)
}
func (p *proof) Finish() {
	p.t.Helper()
	if p.finished {
		p.t.Fatal("SETUP: duplicate proof finalization")
	}
	for _, key := range p.caseDef.Obligations {
		if !p.done[key] {
			p.t.Fatalf("SETUP: unfinished obligation %s", key)
		}
	}
	for _, consumed := range p.executions {
		if !*consumed {
			p.t.Fatal("SETUP: unconsumed jailed evidence")
		}
	}
	p.stopObservers()
	if p.t.Failed() {
		return
	}
	markers := make([]string, 0, len(p.markers))
	for marker := range p.markers {
		markers = append(markers, marker)
	}
	sort.Strings(markers)
	p.finished = true
	if p.caseDef.CharacterisationOutcome != "" {
		p.t.Logf("CHARACTERISATION %s", p.caseDef.CharacterisationOutcome)
	}
	p.t.Logf("PROOF-COMPLETE %s %s markers=%s", p.caseDef.Name, p.abi, strings.Join(markers, ","))
	if !proofMutationBuild && len(markers) > 0 {
		p.t.Errorf("protection effects observed: %v", markers)
	}
}
func (p *proof) Omit(code string) {
	p.t.Helper()
	if p.finished || len(p.markers) > 0 {
		p.t.Fatal("SETUP: omission after markers or finalization")
	}
	allowed := false
	for _, item := range p.caseDef.Omissions {
		if item == code {
			allowed = true
		}
	}
	if !allowed {
		p.t.Fatalf("SETUP: undeclared omission %s", code)
	}
	if code == "root-only" && (!p.caseDef.Root || os.Geteuid() == 0) || code == "ci-only" && (!p.caseDef.CIOnly || os.Getenv("SSHGATE_JAIL_CI") == "1") {
		p.t.Fatalf("SETUP: invalid lane omission %s", code)
	}
	if os.Getenv("SSHGATE_JAIL_CI") == "1" && code != "root-only" {
		p.t.Fatalf("SETUP: CI omission %s", code)
	}
	p.stopObservers()
	if p.t.Failed() {
		return
	}
	p.finished = true
	p.t.Logf("PROOF-OMITTED %s %s %s", p.caseDef.Name, p.abi, code)
}
func (p *proof) Residual(code string) {
	p.t.Helper()
	if p.finished || p.caseDef.Kind != "Residual" || len(p.markers) > 0 {
		p.t.Fatal("SETUP: invalid residual")
	}
	allowed := false
	for _, item := range p.caseDef.Residuals {
		if item == code {
			allowed = true
		}
	}
	if !allowed || code != "R-NUMA-EFFECT" {
		p.t.Fatalf("SETUP: undeclared residual %s", code)
	}
	p.stopObservers()
	if p.t.Failed() {
		return
	}
	p.finished = true
	p.t.Logf("PROOF-RESIDUAL %s %s %s", p.caseDef.Name, p.abi, code)
}
func proofFor(t *testing.T) *proof {
	t.Helper()
	value, ok := activeProofs.Load(t)
	if !ok {
		t.Fatalf("SETUP: marker without active proof in %s", t.Name())
	}
	return value.(*proof)
}
func proofError(format string, args ...any) error { return fmt.Errorf(format, args...) }

package lifecycle

import (
	"container/heap"
	"time"
)

type reclamationCandidate struct {
	key string
	at  time.Time
}

func (c reclamationCandidate) before(other reclamationCandidate) bool {
	if order := c.at.Compare(other.at); order != 0 {
		return order < 0
	}
	return c.key < other.key
}

// reclamationQueue orders committed decisions without sorting retained history
// at admission. Positions permit replacement and removal in logarithmic time.
type reclamationQueue struct {
	candidates []reclamationCandidate
	positions  map[string]int
}

func (q reclamationQueue) Len() int           { return len(q.candidates) }
func (q reclamationQueue) Less(i, j int) bool { return q.candidates[i].before(q.candidates[j]) }
func (q reclamationQueue) Swap(i, j int) {
	q.candidates[i], q.candidates[j] = q.candidates[j], q.candidates[i]
	q.positions[q.candidates[i].key], q.positions[q.candidates[j].key] = i, j
}
func (q *reclamationQueue) Push(value any) {
	candidate := value.(reclamationCandidate)
	if q.positions == nil {
		q.positions = make(map[string]int)
	}
	q.positions[candidate.key] = len(q.candidates)
	q.candidates = append(q.candidates, candidate)
}
func (q *reclamationQueue) Pop() any {
	last := len(q.candidates) - 1
	candidate := q.candidates[last]
	q.candidates[last] = reclamationCandidate{}
	q.candidates = q.candidates[:last]
	delete(q.positions, candidate.key)
	return candidate
}
func (q *reclamationQueue) remove(key string) {
	if position, ok := q.positions[key]; ok {
		heap.Remove(q, position)
	}
}
func (q *reclamationQueue) add(candidate reclamationCandidate) {
	if position, ok := q.positions[candidate.key]; ok {
		q.candidates[position] = candidate
		heap.Fix(q, position)
		return
	}
	heap.Push(q, candidate)
}

func (p *projections) indexReclamation(key string) {
	charge, ok := p.records[key]
	if !ok || charge.decidedAt.IsZero() {
		return
	}
	candidate := reclamationCandidate{key: key, at: charge.decidedAt}
	p.deleteCandidates.add(candidate)
	if charge.full {
		p.shedCandidates.add(candidate)
	}
}

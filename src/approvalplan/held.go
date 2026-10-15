package approvalplan

import "time"

// Held is a deadline held in memory on two clocks (SA-1 rule 3.4): a v2
// grant, a claimed step's signature window, or the sync wait budget. It ends
// at the first of its wall end and its elapsed end, so neither a wall step
// back nor a suspend extends it. The holder latches the first Passed finding.
type Held struct {
	WallEnd    time.Time
	ElapsedEnd time.Duration
}

// K16Margin is the margin K16 keeps on both clocks before a signed step
// is dispatched (E10).
const K16Margin = 2 * time.Second

// Acquire fixes a held deadline once, at acquisition: W = wallEnd, and
// elapsed_end = E_acq + max(0, min(nominal, W − wall_acq)). The elapsed half
// is capped at the nominal span, so a wall reading that is behind at
// acquisition cannot stretch it (R-4).
func Acquire(now Now, wallEnd time.Time, nominal time.Duration) Held {
	span := min(nominal, wallEnd.Sub(now.Wall))
	return Held{WallEnd: wallEnd, ElapsedEnd: now.Elapsed + max(0, span)}
}

// Passed reports whether either end has been reached.
func (h Held) Passed(now Now) bool {
	return !now.Wall.Before(h.WallEnd) || now.Elapsed >= h.ElapsedEnd
}

// PassesK16 is K16 on the held pair: wall + 2 s < W and E + 2 s < elapsed_end.
func (h Held) PassesK16(now Now) bool {
	return now.Wall.Add(K16Margin).Before(h.WallEnd) && now.Elapsed+K16Margin < h.ElapsedEnd
}

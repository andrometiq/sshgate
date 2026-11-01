package approvalplan

import "testing"

func TestCardHandleForGolden(t *testing.T) {
	for gen, want := range map[int]string{0: "5uke25hbtcyj", 1: "uu2yfwtysdfw", 12: "2zyqsfmgcfou"} {
		got := CardHandleFor("r-example", gen)
		if got != want || !ValidCardHandle(got) {
			t.Fatalf("gen %d: %q, want %q", gen, got, want)
		}
		if got == RecordHandle("r-example")[:CardHandleLen] || got == CardHandleFor("r-other", gen) {
			t.Fatal("handle domains collided")
		}
	}
}

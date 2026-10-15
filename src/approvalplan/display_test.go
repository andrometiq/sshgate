package approvalplan

import "testing"

func TestHiddenMarker(t *testing.T) {
	cases := []struct {
		n     int
		rules []string
		want  string
	}{
		{12, nil, "⟦hidden 12 bytes⟧"},
		{40, []string{"aws-access-token"}, "⟦hidden 40 bytes · aws-access-token⟧"},
		{7, []string{"password", "generic-api-key", "password"}, "⟦hidden 7 bytes · generic-api-key,password⟧"},
	}
	for _, c := range cases {
		if got := HiddenMarker(c.n, c.rules); got != c.want {
			t.Errorf("HiddenMarker(%d, %v) = %q, want %q", c.n, c.rules, got, c.want)
		}
	}
	rules := []string{"b", "a"}
	HiddenMarker(1, rules)
	if rules[0] != "b" {
		t.Fatal("HiddenMarker reordered its argument")
	}
}

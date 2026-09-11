package apk

import "testing"

func TestCompare(t *testing.T) {
	less := [][2]string{
		{"1.10.8-r0", "1.10.9-r0"},
		{"2.1-r2", "2.4-r0"},
		{"0.26.0-r0", "0.26.0-r1"},
		{"1.2.3", "1.2.4"},
	}

	for _, tt := range less {
		if !LessThan(tt[0], tt[1]) {
			t.Errorf("LessThan(%q, %q) = false, want true", tt[0], tt[1])
		}
		if LessThan(tt[1], tt[0]) {
			t.Errorf("LessThan(%q, %q) = true, want false", tt[1], tt[0])
		}
	}

	if got := Compare("1.10.11-r0", "1.10.11-r0"); got != 0 {
		t.Errorf("Compare of equal versions = %d, want 0", got)
	}
}

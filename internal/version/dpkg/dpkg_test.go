package dpkg

import "testing"

func TestCompare(t *testing.T) {
	less := [][2]string{
		{"1.0", "1.1"},
		{"1.0~rc1", "1.0"},
		{"1:1.0", "1:1.1"},
		{"2.0", "1:1.0"}, // a higher epoch always wins, regardless of upstream
		{"1.0-1", "1.0-2"},
		{"1.0", "1.0-1"}, // missing revision compares as "0"
		{"7.81.0-1ubuntu1.15", "7.81.0-1ubuntu1.16"},
		{"7.68.0-1ubuntu2.18", "7.81.0-1ubuntu1.15"},
	}

	for _, tt := range less {
		if !LessThan(tt[0], tt[1]) {
			t.Errorf("LessThan(%q, %q) = false, want true", tt[0], tt[1])
		}
		if LessThan(tt[1], tt[0]) {
			t.Errorf("LessThan(%q, %q) = true, want false", tt[1], tt[0])
		}
	}

	equal := [][2]string{
		{"1.0", "1.0"},
		{"1.0-0", "1.0"},
		{"0:1.0", "1.0"},
	}
	for _, tt := range equal {
		if got := Compare(tt[0], tt[1]); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", tt[0], tt[1], got)
		}
	}
}

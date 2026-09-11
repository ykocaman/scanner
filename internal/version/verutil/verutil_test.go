package verutil

import "testing"

func TestCompareSegment(t *testing.T) {
	tests := []struct{ a, b string }{
		{"1.0", "1.1"},
		{"1.0~rc1", "1.0"},
		{"1.0", "1.0+dfsg"},
		{"1.0-1", "1.0-2"},
		{"9", "10"},
		{"1.0-1ubuntu1.15", "1.0-1ubuntu1.16"},
	}

	for _, tt := range tests {
		if got := CompareSegment(tt.a, tt.b); got >= 0 {
			t.Errorf("CompareSegment(%q, %q) = %d, want < 0", tt.a, tt.b, got)
		}
		if got := CompareSegment(tt.b, tt.a); got <= 0 {
			t.Errorf("CompareSegment(%q, %q) = %d, want > 0", tt.b, tt.a, got)
		}
	}

	equal := []struct{ a, b string }{
		{"1.0", "1.0"},
		{"", ""},
	}
	for _, tt := range equal {
		if got := CompareSegment(tt.a, tt.b); got != 0 {
			t.Errorf("CompareSegment(%q, %q) = %d, want 0", tt.a, tt.b, got)
		}
	}
}

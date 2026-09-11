package rpm

import (
	"testing"

	"github.com/ykocaman/scanner/internal/models"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want models.Component
		ok   bool
	}{
		{
			name: "empty line is skipped",
			line: "",
			ok:   false,
		},
		{
			name: "malformed line is skipped",
			line: "curl\t7.81.0-1.el9",
			ok:   false,
		},
		{
			name: "well-formed entry",
			line: "curl\t7.81.0-1.el9\tx86_64",
			want: models.Component{Name: "curl", Version: "7.81.0-1.el9", RawVersion: "7.81.0-1.el9", Arch: "x86_64"},
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("parseLine(%q) ok = %v, want %v", tt.line, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("parseLine(%q) = %+v, want %+v", tt.line, got, tt.want)
			}
		})
	}
}

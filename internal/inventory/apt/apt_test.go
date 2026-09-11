package apt

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
			name: "header line is skipped",
			line: "Listing...",
			ok:   false,
		},
		{
			name: "empty line is skipped",
			line: "",
			ok:   false,
		},
		{
			name: "malformed line is skipped",
			line: "curl 7.81.0",
			ok:   false,
		},
		{
			name: "well-formed entry",
			line: "curl/jammy-updates,now 7.81.0-1ubuntu1.15 amd64 [installed]",
			want: models.Component{
				Name:       "curl",
				Repo:       "jammy-updates,now",
				Version:    "7.81.0",
				RawVersion: "7.81.0-1ubuntu1.15",
				Arch:       "amd64",
			},
			ok: true,
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

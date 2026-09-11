package apk

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
			name: "simple name and version",
			line: "curl-8.9.1-r2",
			want: models.Component{Name: "curl", Version: "8.9.1-r2", RawVersion: "8.9.1-r2", Arch: "x86_64"},
			ok:   true,
		},
		{
			name: "hyphenated package name",
			line: "ca-certificates-20240705-r0",
			want: models.Component{Name: "ca-certificates", Version: "20240705-r0", RawVersion: "20240705-r0", Arch: "x86_64"},
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseLine(tt.line, "x86_64")
			if ok != tt.ok {
				t.Fatalf("parseLine(%q) ok = %v, want %v", tt.line, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("parseLine(%q) = %+v, want %+v", tt.line, got, tt.want)
			}
		})
	}
}

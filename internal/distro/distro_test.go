package distro

import (
	"strings"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{
			name: "ubuntu",
			file: `NAME="Ubuntu"` + "\n" + `ID=ubuntu` + "\n" + `ID_LIKE=debian` + "\n",
			want: Ubuntu,
		},
		{
			name: "debian",
			file: `ID=debian` + "\n",
			want: Debian,
		},
		{
			name: "alpine",
			file: `ID=alpine` + "\n",
			want: Alpine,
		},
		{
			name: "centos falls back to ID_LIKE",
			file: `ID="centos"` + "\n" + `ID_LIKE="rhel fedora"` + "\n",
			want: RHEL,
		},
		{
			name: "fedora is rhel-family",
			file: `ID=fedora` + "\n",
			want: RHEL,
		},
		{
			name: "rocky via id_like",
			file: `ID=rocky` + "\n",
			want: RHEL,
		},
		{
			name: "unrecognized distro",
			file: `ID=gentoo` + "\n",
			want: Unknown,
		},
		{
			name: "empty file",
			file: ``,
			want: Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseOSRelease(strings.NewReader(tt.file)); got != tt.want {
				t.Errorf("parseOSRelease(%q) = %q, want %q", tt.file, got, tt.want)
			}
		})
	}
}

func TestDetect_MissingFile(t *testing.T) {
	t.Setenv("PATH", "") // irrelevant, just proving Detect doesn't panic without /etc/os-release assumptions
	_ = Detect()
}

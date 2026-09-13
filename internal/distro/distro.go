// Package distro identifies the Linux distribution the scanner is
// running on, so the right CVE source can be picked automatically
// instead of making the user choose one by hand.
package distro

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// Values Detect can return.
const (
	Ubuntu  = "ubuntu"
	Debian  = "debian"
	RHEL    = "rhel" // RHEL, CentOS, Fedora, Rocky, AlmaLinux, Oracle Linux, ...
	Alpine  = "alpine"
	Unknown = ""
)

// rhelLike are /etc/os-release ID / ID_LIKE values naming an RPM-based,
// Red Hat-family distribution.
var rhelLike = map[string]bool{
	"rhel": true, "centos": true, "fedora": true,
	"rocky": true, "almalinux": true, "ol": true,
}

// Detect reads /etc/os-release and returns Ubuntu, Debian, RHEL, or
// Alpine, or Unknown if the file is missing or names something else.
func Detect() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return Unknown
	}
	defer func() { _ = f.Close() }()

	return parseOSRelease(f)
}

func parseOSRelease(r io.Reader) string {
	values := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(value, `"`)
	}
	_ = scanner.Err() // best-effort: a partial read still yields a usable ID

	return identify(values["ID"], values["ID_LIKE"])
}

func identify(id, idLike string) string {
	switch id {
	case Ubuntu, Debian, Alpine:
		return id
	}
	if rhelLike[id] {
		return RHEL
	}

	for like := range strings.FieldsSeq(idLike) {
		switch {
		case like == Debian:
			return Debian
		case rhelLike[like]:
			return RHEL
		}
	}
	return Unknown
}

// Package apk inventories software installed on the local host via
// Alpine's apk package manager.
package apk

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ykocaman/scanner/internal/models"
)

// nameVersion splits an apk "name-version-rN" string into name and
// version at the last hyphen that begins a version (a digit) — apk
// package names may themselves contain hyphens, so a plain
// last-hyphen split isn't reliable.
var nameVersion = regexp.MustCompile(`^(.+)-([0-9][^-]*(?:-r[0-9]+)?)$`)

// List returns every package currently installed on the host, as
// reported by `apk info -v`. It requires Alpine Linux with apk on PATH.
func List(ctx context.Context) ([]models.Component, error) {
	arch := printArch(ctx)

	out, err := exec.CommandContext(ctx, "apk", "info", "-v").Output()
	if err != nil {
		return nil, fmt.Errorf("running apk info -v: %w", err)
	}

	var components []models.Component
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if c, ok := parseLine(scanner.Text(), arch); ok {
			components = append(components, c)
		}
	}
	return components, scanner.Err()
}

// parseLine parses one line of `apk info -v` output, e.g.
// "ca-certificates-20240705-r0".
func parseLine(line, arch string) (models.Component, bool) {
	line = strings.TrimSpace(line)
	m := nameVersion.FindStringSubmatch(line)
	if m == nil {
		return models.Component{}, false
	}

	return models.Component{
		Name:       m[1],
		Version:    m[2],
		RawVersion: m[2],
		Arch:       arch,
	}, true
}

// printArch returns the host's apk architecture (e.g. "x86_64"), or ""
// if it can't be determined.
func printArch(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "apk", "--print-arch").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

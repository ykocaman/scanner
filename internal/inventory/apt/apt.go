// Package apt inventories software installed on the local host via
// Debian/Ubuntu's apt package manager.
package apt

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

// versionPattern pulls the leading numeric version out of an apt version
// string such as "1.2.3-4ubuntu5", discarding distro/build suffixes.
var versionPattern = regexp.MustCompile(`(\d+\.)(\d+\.)(\d+)|(\d+\.)(\d+)|(\d+)\d`)

// List returns every package currently installed on the host, as reported
// by `apt list --installed`. It requires a Debian/Ubuntu-based system with
// apt on PATH.
func List(ctx context.Context) ([]models.Component, error) {
	out, err := exec.CommandContext(ctx, "apt", "list", "--installed").Output()
	if err != nil {
		return nil, fmt.Errorf("running apt list --installed: %w", err)
	}

	var components []models.Component

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if component, ok := parseLine(scanner.Text()); ok {
			components = append(components, component)
		}
	}

	return components, scanner.Err()
}

// parseLine parses one line of `apt list --installed` output, e.g.:
//
//	curl/jammy-updates,now 7.81.0-1ubuntu1.15 amd64 [installed]
func parseLine(line string) (models.Component, bool) {
	if line == "" || strings.HasPrefix(line, "Listing...") {
		return models.Component{}, false
	}

	fields := strings.Split(line, " ")
	if len(fields) < 3 {
		return models.Component{}, false
	}

	identity := strings.SplitN(fields[0], "/", 2)
	if len(identity) != 2 {
		return models.Component{}, false
	}

	return models.Component{
		Name:       identity[0],
		Repo:       identity[1],
		Version:    versionPattern.FindString(fields[1]),
		RawVersion: fields[1],
		Arch:       fields[2],
	}, true
}

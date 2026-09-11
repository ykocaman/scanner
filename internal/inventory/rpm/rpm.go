// Package rpm inventories software installed on the local host via the
// RPM database. yum (RHEL/CentOS) and dnf (Fedora, and newer RHEL/CentOS)
// are both just front-ends over that same database, so one
// implementation querying rpm directly covers hosts managed by either,
// rather than parsing each front-end's own (and less stable) "list
// installed" text output.
package rpm

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ykocaman/scanner/internal/models"
)

const queryFormat = `%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n`

// List returns every package currently installed on the host, as
// reported by `rpm -qa`. It requires an RPM-based system (RHEL, CentOS,
// Fedora, ...) with rpm on PATH.
func List(ctx context.Context) ([]models.Component, error) {
	out, err := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", queryFormat).Output()
	if err != nil {
		return nil, fmt.Errorf("running rpm -qa: %w", err)
	}

	var components []models.Component
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if c, ok := parseLine(scanner.Text()); ok {
			components = append(components, c)
		}
	}
	return components, scanner.Err()
}

// parseLine parses one line of the --queryformat output above, e.g.:
//
//	curl	7.81.0-1.el9	x86_64
func parseLine(line string) (models.Component, bool) {
	fields := strings.Split(line, "\t")
	if len(fields) != 3 {
		return models.Component{}, false
	}

	return models.Component{
		Name:       fields[0],
		Version:    fields[1],
		RawVersion: fields[1],
		Arch:       fields[2],
	}, true
}

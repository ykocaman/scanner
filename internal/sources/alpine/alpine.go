// Package alpine fetches, indexes, and matches vulnerability data from
// Alpine's secdb feeds.
//
// On an Alpine host (where internal/inventory/apk supplies the
// installed-package list), matching uses a best-effort apk version
// comparator — see internal/version/apk for what it does and doesn't
// handle. On an apt- or rpm-based host this source is effectively a
// no-op: Alpine's package universe doesn't overlap with theirs, so it
// only ever matches by coincidence of name and version.
package alpine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ykocaman/scanner/internal/config"
	"github.com/ykocaman/scanner/internal/models"
	"github.com/ykocaman/scanner/internal/version/apk"
)

type secdb struct {
	Packages []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

// fix is one Alpine package version that resolved a set of CVEs.
type fix struct {
	Version string
	CVEs    []string
}

// Scan fetches an Alpine secdb feed and returns every Finding it
// produces against components.
func Scan(ctx context.Context, client *http.Client, cfg config.Config, components []models.Component) ([]models.Finding, error) {
	data, err := Fetch(ctx, client, cfg.Alpine.URL)
	if err != nil {
		return nil, fmt.Errorf("alpine: %w", err)
	}

	var findings []models.Finding
	for _, c := range components {
		if fixes, ok := data[c.Name]; ok {
			findings = append(findings, match(c, fixes)...)
		}
	}
	return findings, nil
}

// Fetch downloads and decodes a single Alpine secdb feed (e.g. one
// release's "community.json"), indexed by package name.
func Fetch(ctx context.Context, client *http.Client, url string) (map[string][]fix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building secdb request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching secdb: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching secdb: unexpected status %s", res.Status)
	}

	var db secdb
	if err := json.NewDecoder(res.Body).Decode(&db); err != nil {
		return nil, fmt.Errorf("decoding secdb: %w", err)
	}

	result := make(map[string][]fix, len(db.Packages))
	for _, p := range db.Packages {
		for version, cves := range p.Pkg.Secfixes {
			// secdb uses "0" as a placeholder meaning "no real fix
			// version" rather than an actual package version.
			if version == "0" || len(cves) == 0 {
				continue
			}
			result[p.Pkg.Name] = append(result[p.Pkg.Name], fix{Version: version, CVEs: cves})
		}
	}
	return result, nil
}

// match flags component as vulnerable to every fix whose version the
// installed version hasn't reached yet.
func match(component models.Component, fixes []fix) []models.Finding {
	var findings []models.Finding
	for _, f := range fixes {
		if !apk.LessThan(component.RawVersion, f.Version) {
			continue
		}
		for _, cve := range f.CVEs {
			findings = append(findings, models.Finding{
				Source:      "alpine",
				Code:        cve,
				Description: fmt.Sprintf("fixed in %s %s", component.Name, f.Version),
				URL:         fmt.Sprintf("https://security.alpinelinux.org/vuln/%s", cve),
				Component:   component,
			})
		}
	}
	return findings
}

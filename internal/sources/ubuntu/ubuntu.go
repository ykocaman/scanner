// Package ubuntu fetches, indexes, and matches vulnerability data from
// Ubuntu's USN (Ubuntu Security Notices) database.
package ubuntu

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ykocaman/scanner/internal/config"
	"github.com/ykocaman/scanner/internal/models"
	"github.com/ykocaman/scanner/internal/version/dpkg"
)

type usnEntry struct {
	CVEs            []string                         `json:"cves"`
	Description     string                           `json:"description"`
	ReleasePackages map[string]map[string]usnPackage `json:"release_packages"`
}

type usnPackage struct {
	Version string `json:"version"`
}

// Match is one USN's fixed-package entry for a package present in
// wanted, tagged with the release (suite) it applies to.
type Match struct {
	USNID        string
	Release      string
	CVEs         []string
	Description  string
	FixedVersion string
}

// Scan fetches the USN database and returns every Finding it produces
// against components. The USN feed is a very large (hundreds of MB)
// single JSON document; only entries mentioning a package present in
// components are kept.
func Scan(ctx context.Context, client *http.Client, cfg config.Config, components []models.Component) ([]models.Finding, error) {
	wanted := make(map[string]bool, len(components))
	for _, c := range components {
		wanted[c.Name] = true
	}

	data, err := Fetch(ctx, client, cfg.Ubuntu.URL, wanted)
	if err != nil {
		return nil, fmt.Errorf("ubuntu: %w", err)
	}

	var findings []models.Finding
	for _, c := range components {
		if matches, ok := data[c.Name]; ok {
			findings = append(findings, matchComponent(c, matches)...)
		}
	}
	return findings, nil
}

// Fetch streams the USN database (a single JSON object keyed by USN
// ID) and keeps only the release/package entries named in wanted,
// decoding one USN at a time rather than holding the whole feed in
// memory at once.
func Fetch(ctx context.Context, client *http.Client, url string, wanted map[string]bool) (map[string][]Match, error) {
	dec, closeBody, err := openUSNStream(ctx, client, url)
	if err != nil {
		return nil, err
	}
	defer closeBody()

	result := make(map[string][]Match, len(wanted))
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("decoding USN database: %w", err)
		}
		usnID, _ := keyTok.(string)

		var entry usnEntry
		if err := dec.Decode(&entry); err != nil {
			return nil, fmt.Errorf("decoding USN database entry %s: %w", usnID, err)
		}

		collectMatches(result, usnID, entry, wanted)
	}

	return result, nil
}

// openUSNStream issues the request and returns a decoder positioned
// just inside the feed's top-level JSON object, ready for token-by-token
// streaming.
func openUSNStream(ctx context.Context, client *http.Client, url string) (*json.Decoder, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("building USN database request: %w", err)
	}

	res, err := client.Do(req) //nolint:bodyclose // closed via the returned close func; the linter can't see through it
	if err != nil {
		return nil, nil, fmt.Errorf("fetching USN database: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		return nil, nil, fmt.Errorf("fetching USN database: unexpected status %s", res.Status)
	}

	dec := json.NewDecoder(res.Body)
	if _, err := dec.Token(); err != nil { // consume the opening '{'
		_ = res.Body.Close()
		return nil, nil, fmt.Errorf("decoding USN database: %w", err)
	}

	return dec, func() { _ = res.Body.Close() }, nil
}

// collectMatches appends a Match to result for every release/package in
// entry that names a package in wanted.
func collectMatches(result map[string][]Match, usnID string, entry usnEntry, wanted map[string]bool) {
	for release, packages := range entry.ReleasePackages {
		for name, pkg := range packages {
			if !wanted[name] {
				continue
			}
			result[name] = append(result[name], Match{
				USNID:        usnID,
				Release:      release,
				CVEs:         entry.CVEs,
				Description:  entry.Description,
				FixedVersion: pkg.Version,
			})
		}
	}
}

// matchComponent flags component as vulnerable to every USN match whose
// release matches its apt repo and whose fixed version the installed
// version hasn't reached yet, producing one Finding per CVE the USN lists.
func matchComponent(component models.Component, matches []Match) []models.Finding {
	release := releaseCodename(component.Repo)

	var findings []models.Finding
	for _, m := range matches {
		if m.Release != release {
			continue
		}
		if m.FixedVersion != "" && !dpkg.LessThan(component.RawVersion, m.FixedVersion) {
			continue
		}

		for _, cve := range m.CVEs {
			findings = append(findings, models.Finding{
				Source:      "ubuntu",
				Code:        cve,
				Description: m.Description,
				URL:         fmt.Sprintf("https://ubuntu.com/security/notices/%s", m.USNID),
				Component:   component,
			})
		}
	}
	return findings
}

// releaseCodename extracts the release codename apt embeds in a
// package's repo field, e.g. "jammy-updates,now" -> "jammy".
func releaseCodename(repo string) string {
	if i := strings.IndexByte(repo, ','); i >= 0 {
		repo = repo[:i]
	}
	if i := strings.IndexByte(repo, '-'); i >= 0 {
		repo = repo[:i]
	}
	return repo
}

// Package debian fetches, indexes, and matches vulnerability data from
// the Debian Security Tracker.
package debian

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

// Entry is one CVE's tracker data for a single source package.
type Entry struct {
	Description string             `json:"description"`
	Releases    map[string]Release `json:"releases"`
}

// Release describes a CVE's status in a single Debian release (suite).
type Release struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
}

// Scan fetches the Debian tracker feed and returns every Finding it
// produces against components. Only the package names present in
// components are decoded out of the (tens-of-MB) feed.
func Scan(ctx context.Context, client *http.Client, cfg config.Config, components []models.Component) ([]models.Finding, error) {
	wanted := make(map[string]bool, len(components))
	for _, c := range components {
		wanted[c.Name] = true
	}

	data, err := Fetch(ctx, client, cfg.Debian.URL, wanted)
	if err != nil {
		return nil, fmt.Errorf("debian: %w", err)
	}

	var findings []models.Finding
	for _, c := range components {
		if pkg, ok := data[c.Name]; ok {
			findings = append(findings, Match(c, pkg)...)
		}
	}
	return findings, nil
}

// Fetch streams the tracker feed (a single JSON object keyed by source
// package name) and decodes only the packages named in wanted, so a
// single lookup doesn't have to hold the entire feed in memory.
func Fetch(ctx context.Context, client *http.Client, url string, wanted map[string]bool) (map[string]map[string]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building tracker request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching tracker data: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching tracker data: unexpected status %s", res.Status)
	}

	dec := json.NewDecoder(res.Body)
	if _, err := dec.Token(); err != nil { // consume the opening '{'
		return nil, fmt.Errorf("decoding tracker data: %w", err)
	}

	result := make(map[string]map[string]Entry, len(wanted))
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("decoding tracker data: %w", err)
		}
		name, _ := keyTok.(string)

		if !wanted[name] {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, fmt.Errorf("decoding tracker data: %w", err)
			}
			continue
		}

		var pkg map[string]Entry
		if err := dec.Decode(&pkg); err != nil {
			return nil, fmt.Errorf("decoding tracker data for %s: %w", name, err)
		}
		result[name] = pkg
	}

	return result, nil
}

// Match checks component against every CVE tracked for a package with
// its name, using the release matching component's apt repo (e.g.
// "jammy-updates,now" -> "jammy"). A component is flagged when its
// release is marked "open"/"undetermined" (no fix yet), or "resolved"
// with a fixed_version the installed version hasn't reached yet.
// Releases the CVE doesn't mention at all are skipped rather than
// guessed at, to avoid flagging an unrelated Debian/Ubuntu suite.
func Match(component models.Component, cves map[string]Entry) []models.Finding {
	release := releaseCodename(component.Repo)

	var findings []models.Finding
	for code, entry := range cves {
		rel, ok := entry.Releases[release]
		if !ok {
			continue
		}

		switch {
		case rel.Status == "resolved" && rel.FixedVersion != "" && rel.FixedVersion != "0":
			if !dpkg.LessThan(component.RawVersion, rel.FixedVersion) {
				continue
			}
		case rel.Status == "open" || rel.Status == "undetermined":
			// no fix yet (or status unclear): flag it.
		default:
			continue
		}

		findings = append(findings, models.Finding{
			Source:      "debian",
			Code:        code,
			Description: entry.Description,
			Severity:    rel.Urgency,
			URL:         fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", code),
			Component:   component,
		})
	}
	return findings
}

// releaseCodename extracts the release codename apt embeds in a
// package's repo field, e.g. "jammy-updates,now" -> "jammy" and
// "bookworm,now" -> "bookworm".
func releaseCodename(repo string) string {
	if i := strings.IndexByte(repo, ','); i >= 0 {
		repo = repo[:i]
	}
	if i := strings.IndexByte(repo, '-'); i >= 0 {
		repo = repo[:i]
	}
	return repo
}

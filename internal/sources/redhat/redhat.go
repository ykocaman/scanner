// Package redhat fetches, indexes, and matches vulnerability data from
// Red Hat's public security data feed.
package redhat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/ykocaman/scanner/internal/config"
	"github.com/ykocaman/scanner/internal/models"
)

// packageReleaseSuffix strips the "-<epoch>:<version>-<release>" tail Red
// Hat appends to package names in AffectedPackages, leaving the bare name.
var packageReleaseSuffix = regexp.MustCompile(`-[0-9]+:.*`)

// Scan fetches the Red Hat CVE feed and returns every Finding it
// produces against components.
func Scan(ctx context.Context, client *http.Client, cfg config.Config, components []models.Component) ([]models.Finding, error) {
	cves, err := FetchAll(ctx, client, cfg.Redhat.URL, cfg.RedhatPerPage)
	if err != nil {
		return nil, fmt.Errorf("redhat: %w", err)
	}

	index := Index(cves)

	var findings []models.Finding
	for _, component := range components {
		findings = append(findings, match(component, index[component.Name])...)
	}

	return findings, nil
}

// match checks component against every CVE known to affect a package
// with its name, returning one Finding per CVE whose affected-package
// list contains the installed version.
//
// Red Hat's feed lists exact package-release strings rather than
// version ranges, so matching is a substring check against
// component.Version. This is a coarse heuristic: it can miss version
// schemes that don't line up character-for-character, and it doesn't
// reason about "fixed in" ranges.
func match(component models.Component, candidates map[string]models.RedhatCVE) []models.Finding {
	var findings []models.Finding

	for _, cve := range candidates {
		for _, affected := range cve.AffectedPackages {
			if strings.Contains(affected, component.Version) {
				findings = append(findings, models.Finding{
					Source:      "redhat",
					Code:        cve.Code,
					Description: cve.Description,
					Severity:    cve.Severity,
					PublicDate:  cve.PublicDate,
					Score:       cve.Score,
					URL:         cve.URL,
					Component:   component,
				})
				break
			}
		}
	}

	return findings
}

// FetchAll downloads the full CVE feed at url, paging through it
// perPage entries at a time rather than requesting everything in one
// oversized request.
func FetchAll(ctx context.Context, client *http.Client, url string, perPage int) ([]models.RedhatCVE, error) {
	var all []models.RedhatCVE

	for page := 1; ; page++ {
		cves, err := fetchPage(ctx, client, url, perPage, page)
		if err != nil {
			return nil, err
		}

		all = append(all, cves...)
		if len(cves) < perPage {
			return all, nil
		}
	}
}

func fetchPage(ctx context.Context, client *http.Client, feedURL string, perPage, page int) ([]models.RedhatCVE, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building CVE feed request: %w", err)
	}

	q := req.URL.Query()
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("page", strconv.Itoa(page))
	req.URL.RawQuery = q.Encode()

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching CVE feed: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching CVE feed: unexpected status %s", res.Status)
	}

	var cves []models.RedhatCVE
	if err := json.NewDecoder(res.Body).Decode(&cves); err != nil {
		return nil, fmt.Errorf("decoding CVE feed: %w", err)
	}

	for i, cve := range cves {
		cves[i].Description = strings.ReplaceAll(cve.Description, cve.Code+" ", "")
		cves[i].URL = fmt.Sprintf("https://access.redhat.com/security/cve/%s", cve.Code)
	}

	return cves, nil
}

// Index groups CVEs by base package name, so callers can look up every
// CVE that mentions a given package in O(1).
func Index(cves []models.RedhatCVE) map[string]map[string]models.RedhatCVE {
	index := make(map[string]map[string]models.RedhatCVE, len(cves))

	for _, cve := range cves {
		for _, pkg := range cve.AffectedPackages {
			name := packageReleaseSuffix.ReplaceAllString(pkg, "")
			if index[name] == nil {
				index[name] = make(map[string]models.RedhatCVE)
			}
			index[name][cve.Code] = cve
		}
	}

	return index
}

package models

// RedhatCVE is a single vulnerability entry from Red Hat's security data feed.
type RedhatCVE struct {
	Code             string   `json:"CVE"`
	Description      string   `json:"bugzilla_description"`
	URL              string   `json:"bugzilla"`
	Severity         string   `json:"severity"`
	PublicDate       string   `json:"public_date"`
	AffectedPackages []string `json:"affected_packages"`
	Score            string   `json:"cvss3_score"`
}

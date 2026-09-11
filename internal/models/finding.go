package models

// Finding is a single vulnerability confirmed to affect an installed
// component, normalized across every source (Red Hat, Debian, Ubuntu,
// Alpine) so the reporting layer can treat them uniformly.
type Finding struct {
	Source      string
	Code        string
	Description string
	Severity    string
	PublicDate  string
	Score       string
	URL         string
	Component   Component
}

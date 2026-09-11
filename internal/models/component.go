// Package models holds the data types shared across the scanner.
package models

// Component is a package installed on the scanned host.
type Component struct {
	Name       string
	Version    string
	RawVersion string
	Repo       string
	Arch       string
}

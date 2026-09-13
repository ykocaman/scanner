// Package config loads scanner settings from the environment.
package config

import (
	"os"
	"time"

	"github.com/ykocaman/scanner/internal/distro"
)

const (
	defaultRedhatCVEURL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"

	defaultDebianTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
	defaultAlpineSecdbURL   = "https://secdb.alpinelinux.org/v3.24/main.json,https://secdb.alpinelinux.org/v3.24/community.json"

	defaultCachePath    = "/tmp/scanner-cache"
	defaultHTTPTimeout  = 5 * time.Minute
	defaultElasticIndex = "scanner"
)

// Source holds the settings for a single vulnerability feed.
type Source struct {
	Enabled bool
	URL     string
}

// Config holds every runtime setting the scanner needs, loaded once at startup.
type Config struct {
	HTTPTimeout time.Duration

	Redhat Source
	Debian Source
	Ubuntu Source
	Alpine Source

	CachePath string

	MailServerHost string
	MailServerPort string
	MailUsername   string
	MailPassword   string
	MailTo         string

	ElasticHost  string
	ElasticIndex string
}

// MailEnabled reports whether email reporting is configured: there's no
// separate on/off switch, sending is enabled by setting a recipient.
func (c Config) MailEnabled() bool {
	return c.MailTo != ""
}

// ElasticEnabled reports whether Elasticsearch indexing is configured:
// there's no separate on/off switch, indexing is enabled by pointing at
// a cluster.
func (c Config) ElasticEnabled() bool {
	return c.ElasticHost != ""
}

// Load reads Config from environment variables, applying defaults for
// anything unset. Call godotenv.Load beforehand to pull values from a
// .env file into the environment first.
//
// Every optional feature here is enabled by the presence of the setting
// it actually needs, rather than a separate boolean living next to it:
//   - Which CVE source(s) run is auto-detected from the host's
//     distribution (see internal/distro and sourceDefaults).
//   - Ubuntu's own USN feed (hundreds of MB, never auto-enabled) turns
//     on when UBUNTU_USN_URL is set.
//   - Email sends when MAIL_TO is set.
//   - Elasticsearch indexing runs when ELASTIC_HOST is set.
//   - The "already reported?" cache is always on; CACHE_PATH only
//     changes where it's stored.
func Load() Config {
	redhat, debian, alpine := sourceDefaults(distro.Detect())
	ubuntuURL := os.Getenv("UBUNTU_USN_URL")

	return Config{
		HTTPTimeout: getDuration("HTTP_TIMEOUT", defaultHTTPTimeout),

		Redhat: Source{
			Enabled: redhat,
			URL:     getString("REDHAT_CVE_URL", defaultRedhatCVEURL),
		},
		Debian: Source{
			Enabled: debian,
			URL:     getString("DEBIAN_TRACKER_URL", defaultDebianTrackerURL),
		},
		Ubuntu: Source{
			Enabled: ubuntuURL != "",
			URL:     ubuntuURL,
		},
		Alpine: Source{
			Enabled: alpine,
			URL:     getString("ALPINE_SECDB_URL", defaultAlpineSecdbURL),
		},

		CachePath: getString("CACHE_PATH", defaultCachePath),

		MailServerHost: os.Getenv("MAIL_SERVER_HOST"),
		MailServerPort: os.Getenv("MAIL_SERVER_PORT"),
		MailUsername:   os.Getenv("MAIL_USERNAME"),
		MailPassword:   os.Getenv("MAIL_PASSWORD"),
		MailTo:         os.Getenv("MAIL_TO"),

		ElasticHost:  os.Getenv("ELASTIC_HOST"),
		ElasticIndex: getString("ELASTIC_INDEX", defaultElasticIndex),
	}
}

// sourceDefaults picks which CVE source is enabled by default, based on
// the host's detected distribution id (see internal/distro). Ubuntu
// isn't decided here: see the comment on Load.
func sourceDefaults(id string) (redhat, debian, alpine bool) {
	switch id {
	case distro.Debian:
		return true, true, false
	case distro.Alpine:
		return false, false, true
	default: // distro.Ubuntu, distro.RHEL, or undetected
		return true, false, false
	}
}

func getString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v, err := time.ParseDuration(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return v
}

// Package config loads scanner settings from the environment.
package config

import (
	"os"
	"strconv"
	"time"
)

const (
	defaultRedhatCVEURL  = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
	defaultRedhatPerPage = 1000

	defaultDebianTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
	defaultUbuntuUSNURL     = "https://usn.ubuntu.com/usn-db/database-all.json"
	defaultAlpineSecdbURL   = "https://secdb.alpinelinux.org/v3.24/main.json,https://secdb.alpinelinux.org/v3.24/community.json"

	defaultCachePath    = "/tmp/scanner-cache"
	defaultHTTPTimeout  = 5 * time.Minute
	defaultElasticHost  = "http://127.0.0.1:9200"
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

	Redhat        Source
	RedhatPerPage int
	Debian        Source
	Ubuntu        Source
	Alpine        Source

	UseCaching bool
	CachePath  string

	SendMail       bool
	MailServerHost string
	MailServerPort string
	MailUsername   string
	MailPassword   string
	MailTo         string

	UseElastic   bool
	ElasticHost  string
	ElasticIndex string
}

// Load reads Config from environment variables, applying defaults for
// anything unset. Call godotenv.Load beforehand to pull values from a
// .env file into the environment first.
//
// Debian and Ubuntu are disabled by default because their feeds are
// large (tens to hundreds of MB); Alpine is disabled by default because
// it only produces real matches on an Alpine (apk) host. Note that
// ALPINE_SECDB_URL points at a specific Alpine release (repo files
// aren't versioned by a stable alias) - update it when you upgrade the
// host's Alpine version. See the README before enabling any of these.
func Load() Config {
	return Config{
		HTTPTimeout: getDuration("HTTP_TIMEOUT", defaultHTTPTimeout),

		Redhat: Source{
			Enabled: getBool("USE_REDHAT", true),
			URL:     getString("REDHAT_CVE_URL", defaultRedhatCVEURL),
		},
		RedhatPerPage: getInt("REDHAT_PER_PAGE", defaultRedhatPerPage),
		Debian: Source{
			Enabled: getBool("USE_DEBIAN", false),
			URL:     getString("DEBIAN_TRACKER_URL", defaultDebianTrackerURL),
		},
		Ubuntu: Source{
			Enabled: getBool("USE_UBUNTU", false),
			URL:     getString("UBUNTU_USN_URL", defaultUbuntuUSNURL),
		},
		Alpine: Source{
			Enabled: getBool("USE_ALPINE", false),
			URL:     getString("ALPINE_SECDB_URL", defaultAlpineSecdbURL),
		},

		UseCaching: getBool("USE_CACHING", false),
		CachePath:  getString("CACHE_PATH", defaultCachePath),

		SendMail:       getBool("SEND_MAIL", false),
		MailServerHost: os.Getenv("MAIL_SERVER_HOST"),
		MailServerPort: os.Getenv("MAIL_SERVER_PORT"),
		MailUsername:   os.Getenv("MAIL_USERNAME"),
		MailPassword:   os.Getenv("MAIL_PASSWORD"),
		MailTo:         os.Getenv("MAIL_TO"),

		UseElastic:   getBool("USE_ELASTIC", false),
		ElasticHost:  getString("ELASTIC_HOST", defaultElasticHost),
		ElasticIndex: getString("ELASTIC_INDEX", defaultElasticIndex),
	}
}

func getString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getBool(key string, fallback bool) bool {
	v, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return v
}

func getInt(key string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return v
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v, err := time.ParseDuration(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return v
}

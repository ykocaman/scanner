package config

import (
	"testing"

	"github.com/ykocaman/scanner/internal/distro"
)

func TestSourceDefaults(t *testing.T) {
	tests := []struct {
		id                     string
		redhat, debian, alpine bool
		wantEnabled            int
	}{
		{distro.Ubuntu, true, false, false, 1},
		{distro.Debian, true, true, false, 2},
		{distro.Alpine, false, false, true, 1},
		{distro.RHEL, true, false, false, 1},
		{distro.Unknown, true, false, false, 1},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			redhat, debian, alpine := sourceDefaults(tt.id)
			if redhat != tt.redhat || debian != tt.debian || alpine != tt.alpine {
				t.Errorf("sourceDefaults(%q) = (%v,%v,%v), want (%v,%v,%v)",
					tt.id, redhat, debian, alpine, tt.redhat, tt.debian, tt.alpine)
			}

			enabledCount := 0
			for _, e := range []bool{redhat, debian, alpine} {
				if e {
					enabledCount++
				}
			}
			if enabledCount != tt.wantEnabled {
				t.Errorf("sourceDefaults(%q) enabled %d sources, want %d", tt.id, enabledCount, tt.wantEnabled)
			}
		})
	}
}

func TestLoad_PresenceEnablesOptionalFeatures(t *testing.T) {
	t.Run("ubuntu source follows UBUNTU_USN_URL", func(t *testing.T) {
		if Load().Ubuntu.Enabled {
			t.Fatal("Ubuntu.Enabled = true with UBUNTU_USN_URL unset, want false")
		}

		t.Setenv("UBUNTU_USN_URL", "https://example.invalid/usn.json")
		cfg := Load()
		if !cfg.Ubuntu.Enabled {
			t.Error("Ubuntu.Enabled = false with UBUNTU_USN_URL set, want true")
		}
		if cfg.Ubuntu.URL != "https://example.invalid/usn.json" {
			t.Errorf("Ubuntu.URL = %q, want the value from UBUNTU_USN_URL", cfg.Ubuntu.URL)
		}
	})

	t.Run("mail follows MAIL_TO", func(t *testing.T) {
		if Load().MailEnabled() {
			t.Fatal("MailEnabled() = true with MAIL_TO unset, want false")
		}
		t.Setenv("MAIL_TO", "ops@example.invalid")
		if !Load().MailEnabled() {
			t.Error("MailEnabled() = false with MAIL_TO set, want true")
		}
	})

	t.Run("elastic follows ELASTIC_HOST", func(t *testing.T) {
		if Load().ElasticEnabled() {
			t.Fatal("ElasticEnabled() = true with ELASTIC_HOST unset, want false")
		}
		t.Setenv("ELASTIC_HOST", "http://es.example.invalid:9200")
		if !Load().ElasticEnabled() {
			t.Error("ElasticEnabled() = false with ELASTIC_HOST set, want true")
		}
	})
}

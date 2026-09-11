package debian

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykocaman/scanner/internal/models"
)

const sampleFeed = `{
	"curl": {
		"CVE-2024-0001": {
			"description": "something bad in curl",
			"releases": {
				"jammy": {"status": "resolved", "fixed_version": "7.81.0-1ubuntu1.16", "urgency": "medium"},
				"bookworm": {"status": "open", "urgency": "high"}
			}
		}
	},
	"openssl": {
		"CVE-2024-0002": {
			"description": "unrelated package, should be skipped",
			"releases": {"jammy": {"status": "open"}}
		}
	}
}`

func TestFetch_FiltersByWantedPackage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleFeed))
	}))
	defer server.Close()

	data, err := Fetch(context.Background(), server.Client(), server.URL, map[string]bool{"curl": true})
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	if _, ok := data["curl"]; !ok {
		t.Fatal("data missing curl, the only wanted package")
	}
	if _, ok := data["openssl"]; ok {
		t.Error("data contains openssl, which wasn't in the wanted set")
	}
}

func TestMatch(t *testing.T) {
	entries := map[string]Entry{
		"CVE-2024-0001": {
			Description: "something bad",
			Releases: map[string]Release{
				"jammy":    {Status: "resolved", FixedVersion: "7.81.0-1ubuntu1.16", Urgency: "medium"},
				"bookworm": {Status: "open", Urgency: "high"},
			},
		},
		"CVE-2024-9999": {
			Releases: map[string]Release{
				"focal": {Status: "open"}, // release the component isn't on
			},
		},
	}

	vulnerable := models.Component{Name: "curl", Repo: "jammy-updates,now", RawVersion: "7.81.0-1ubuntu1.15"}
	findings := Match(vulnerable, entries)
	if len(findings) != 1 || findings[0].Code != "CVE-2024-0001" {
		t.Fatalf("Match(vulnerable) = %+v, want exactly CVE-2024-0001", findings)
	}

	patched := models.Component{Name: "curl", Repo: "jammy-updates,now", RawVersion: "7.81.0-1ubuntu1.16"}
	if findings := Match(patched, entries); len(findings) != 0 {
		t.Fatalf("Match(patched) = %+v, want none (fixed_version already reached)", findings)
	}

	openStatus := models.Component{Name: "curl", Repo: "bookworm,now", RawVersion: "7.81.0-1"}
	if findings := Match(openStatus, entries); len(findings) != 1 {
		t.Fatalf("Match(openStatus) = %+v, want 1 (status=open has no fix yet)", findings)
	}
}

func TestReleaseCodename(t *testing.T) {
	tests := map[string]string{
		"jammy-updates,now":     "jammy",
		"bookworm,now":          "bookworm",
		"bookworm-security,now": "bookworm",
	}
	for repo, want := range tests {
		if got := releaseCodename(repo); got != want {
			t.Errorf("releaseCodename(%q) = %q, want %q", repo, got, want)
		}
	}
}

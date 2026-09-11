package ubuntu

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykocaman/scanner/internal/models"
)

const sampleUSNDB = `{
	"USN-6738-1": {
		"cves": ["CVE-2024-0001"],
		"description": "curl vulnerabilities",
		"release_packages": {
			"jammy": {"curl": {"version": "7.81.0-1ubuntu1.16"}},
			"focal": {"curl": {"version": "7.68.0-1ubuntu2.19"}}
		}
	},
	"USN-6700-1": {
		"cves": ["CVE-2024-9999"],
		"description": "unrelated package",
		"release_packages": {
			"jammy": {"openssl": {"version": "3.0.2-0ubuntu1.11"}}
		}
	}
}`

func TestFetch_FiltersByWantedPackage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleUSNDB))
	}))
	defer server.Close()

	data, err := Fetch(context.Background(), server.Client(), server.URL, map[string]bool{"curl": true})
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	if len(data["curl"]) != 2 {
		t.Fatalf("got %d curl matches, want 2 (jammy and focal)", len(data["curl"]))
	}
	if _, ok := data["openssl"]; ok {
		t.Error("data contains openssl, which wasn't in the wanted set")
	}
}

func TestMatchComponent(t *testing.T) {
	matches := []Match{
		{USNID: "USN-6738-1", Release: "jammy", CVEs: []string{"CVE-2024-0001"}, FixedVersion: "7.81.0-1ubuntu1.16"},
		{USNID: "USN-6738-1", Release: "focal", CVEs: []string{"CVE-2024-0001"}, FixedVersion: "7.68.0-1ubuntu2.19"},
	}

	vulnerable := models.Component{Name: "curl", Repo: "jammy-updates,now", RawVersion: "7.81.0-1ubuntu1.15"}
	findings := matchComponent(vulnerable, matches)
	if len(findings) != 1 || findings[0].Code != "CVE-2024-0001" {
		t.Fatalf("matchComponent(vulnerable) = %+v, want exactly CVE-2024-0001", findings)
	}

	patched := models.Component{Name: "curl", Repo: "jammy-updates,now", RawVersion: "7.81.0-1ubuntu1.16"}
	if findings := matchComponent(patched, matches); len(findings) != 0 {
		t.Fatalf("matchComponent(patched) = %+v, want none", findings)
	}

	otherRelease := models.Component{Name: "curl", Repo: "noble,now", RawVersion: "7.1.0-1"}
	if findings := matchComponent(otherRelease, matches); len(findings) != 0 {
		t.Fatalf("matchComponent(otherRelease) = %+v, want none (no jammy/focal match)", findings)
	}
}

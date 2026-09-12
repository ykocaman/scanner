package alpine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykocaman/scanner/internal/models"
)

const sampleSecdb = `{
	"packages": [
		{"pkg": {"name": "curl", "secfixes": {"7.81.0-r1": ["CVE-2024-0001"], "0": ["CVE-2019-0001"]}}},
		{"pkg": {"name": "openssl", "secfixes": {"3.0.2-r1": ["CVE-2024-0002"]}}}
	]
}`

func TestFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleSecdb))
	}))
	defer server.Close()

	data, err := Fetch(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	fixes := data["curl"]
	if len(fixes) != 1 {
		t.Fatalf("got %d fixes for curl, want 1 (the \"0\" placeholder should be skipped)", len(fixes))
	}
	if fixes[0].Version != "7.81.0-r1" {
		t.Errorf("fix version = %q, want 7.81.0-r1", fixes[0].Version)
	}
}

func TestFetchAll_MergesRepos(t *testing.T) {
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"packages": [{"pkg": {"name": "musl", "secfixes": {"1.2.5-r0": ["CVE-2024-9999"]}}}]}`))
	}))
	defer main.Close()

	community := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleSecdb))
	}))
	defer community.Close()

	data, err := FetchAll(context.Background(), community.Client(), []string{main.URL, community.URL})
	if err != nil {
		t.Fatalf("FetchAll returned error: %v", err)
	}

	if len(data["musl"]) != 1 {
		t.Errorf("got %d fixes for musl (from the \"main\" feed), want 1", len(data["musl"]))
	}
	if len(data["curl"]) != 1 {
		t.Errorf("got %d fixes for curl (from the \"community\" feed), want 1", len(data["curl"]))
	}
}

func TestMatch(t *testing.T) {
	fixes := []fix{{Version: "7.81.0-r1", CVEs: []string{"CVE-2024-0001"}}}

	vulnerable := models.Component{Name: "curl", RawVersion: "7.81.0-r0"}
	findings := match(vulnerable, fixes)
	if len(findings) != 1 || findings[0].Code != "CVE-2024-0001" {
		t.Fatalf("match(vulnerable) = %+v, want exactly CVE-2024-0001", findings)
	}

	patched := models.Component{Name: "curl", RawVersion: "7.81.0-r1"}
	if findings := match(patched, fixes); len(findings) != 0 {
		t.Fatalf("match(patched) = %+v, want none", findings)
	}
}

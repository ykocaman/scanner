package redhat

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ykocaman/scanner/internal/models"
)

func TestFetchAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"CVE":"CVE-2024-0001","bugzilla_description":"CVE-2024-0001 something bad","severity":"important","affected_packages":["curl-0:7.81.0-1ubuntu1.15"]}]`))
	}))
	defer server.Close()

	cves, err := FetchAll(context.Background(), server.Client(), server.URL, 10)
	if err != nil {
		t.Fatalf("FetchAll returned error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1", len(cves))
	}

	got := cves[0]
	if got.Description != "something bad" {
		t.Errorf("Description = %q, want CVE code prefix stripped", got.Description)
	}
	want := "https://access.redhat.com/security/cve/CVE-2024-0001"
	if got.URL != want {
		t.Errorf("URL = %q, want %q", got.URL, want)
	}
}

func TestFetchAll_Paginates(t *testing.T) {
	const perPage = 2
	requests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		page := r.URL.Query().Get("page")

		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "1":
			_, _ = fmt.Fprint(w, `[{"CVE":"CVE-2024-0001"},{"CVE":"CVE-2024-0002"}]`)
		case "2":
			_, _ = fmt.Fprint(w, `[{"CVE":"CVE-2024-0003"}]`)
		default:
			t.Errorf("unexpected page %q requested", page)
		}
	}))
	defer server.Close()

	cves, err := FetchAll(context.Background(), server.Client(), server.URL, perPage)
	if err != nil {
		t.Fatalf("FetchAll returned error: %v", err)
	}
	if requests != 2 {
		t.Errorf("made %d requests, want 2 (should stop once a page is short)", requests)
	}
	if len(cves) != 3 {
		t.Fatalf("got %d CVEs across pages, want 3", len(cves))
	}
}

func TestFetchAll_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	if _, err := FetchAll(context.Background(), server.Client(), server.URL, 10); err == nil {
		t.Fatal("FetchAll returned nil error for a 500 response")
	}
}

func TestMatch(t *testing.T) {
	candidates := map[string]models.RedhatCVE{
		"CVE-2024-0001": {Code: "CVE-2024-0001", AffectedPackages: []string{"curl-0:7.81.0-1ubuntu1.15"}},
		"CVE-2024-0002": {Code: "CVE-2024-0002", AffectedPackages: []string{"curl-0:7.68.0-1ubuntu2.18"}},
	}

	installed := models.Component{Name: "curl", Version: "7.81.0", RawVersion: "7.81.0-1ubuntu1.15"}

	findings := match(installed, candidates)
	if len(findings) != 1 || findings[0].Code != "CVE-2024-0001" {
		t.Fatalf("match(installed) = %+v, want exactly CVE-2024-0001", findings)
	}
	if findings[0].Source != "redhat" {
		t.Errorf("Source = %q, want %q", findings[0].Source, "redhat")
	}

	clean := models.Component{Name: "curl", Version: "9.9.9"}
	if findings := match(clean, candidates); len(findings) != 0 {
		t.Fatalf("match(clean) = %+v, want none", findings)
	}
}

func TestIndex(t *testing.T) {
	cves := []models.RedhatCVE{
		{Code: "CVE-2024-0001", AffectedPackages: []string{"curl-0:7.81.0-1ubuntu1.15", "openssl-0:3.0.2-0ubuntu1.10"}},
		{Code: "CVE-2024-0002", AffectedPackages: []string{"curl-0:7.68.0-1ubuntu2.18"}},
	}

	index := Index(cves)

	if got := len(index["curl"]); got != 2 {
		t.Fatalf("len(index[curl]) = %d, want 2", got)
	}
	if _, ok := index["curl"]["CVE-2024-0001"]; !ok {
		t.Error("index[curl] missing CVE-2024-0001")
	}
	if got := len(index["openssl"]); got != 1 {
		t.Fatalf("len(index[openssl]) = %d, want 1", got)
	}
}

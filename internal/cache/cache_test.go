package cache

import (
	"path/filepath"
	"testing"
)

func TestCache_MissingFileIsEmpty(t *testing.T) {
	c, err := Open(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("Open returned error for a missing file: %v", err)
	}
	if c.Seen("CVE-2024-0001") {
		t.Error("Seen returned true for an empty cache")
	}
}

func TestCache_MarkAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache")

	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := c.Mark("CVE-2024-0001"); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	if !c.Seen("CVE-2024-0001") {
		t.Error("Seen returned false right after Mark")
	}

	reloaded, err := Open(path)
	if err != nil {
		t.Fatalf("Open (reload): %v", err)
	}
	if !reloaded.Seen("CVE-2024-0001") {
		t.Error("Seen returned false after reloading the cache from disk")
	}
	if reloaded.Seen("CVE-2024-9999") {
		t.Error("Seen returned true for a key that was never marked")
	}
}

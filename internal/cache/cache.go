// Package cache tracks which findings have already been reported, so
// recurring runs (e.g. from cron) only surface new ones.
package cache

import (
	"bufio"
	"errors"
	"os"
)

// Cache tracks which keys have already been recorded by a previous run.
type Cache struct {
	path string
	seen map[string]bool
}

// Open loads the set of previously seen keys from path. A missing file
// is treated as an empty cache rather than an error.
func Open(path string) (*Cache, error) {
	c := &Cache{path: path, seen: make(map[string]bool)}

	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		c.seen[scanner.Text()] = true
	}
	return c, scanner.Err()
}

// Seen reports whether key was recorded by a previous run.
func (c *Cache) Seen(key string) bool {
	return c.seen[key]
}

// Mark records key as seen and appends it to the on-disk cache.
func (c *Cache) Mark(key string) error {
	if c.seen[key] {
		return nil
	}
	c.seen[key] = true

	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	_, writeErr := f.WriteString(key + "\n")
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

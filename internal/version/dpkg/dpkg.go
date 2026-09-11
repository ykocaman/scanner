// Package dpkg compares Debian/Ubuntu package version strings using
// the algorithm from Debian Policy §5.6.12 — the same one dpkg itself
// uses, and the one behind the version strings `apt list --installed`
// reports.
package dpkg

import (
	"strconv"
	"strings"

	"github.com/ykocaman/scanner/internal/version/verutil"
)

// LessThan reports whether a is an earlier version than b.
func LessThan(a, b string) bool {
	return Compare(a, b) < 0
}

// Compare returns a negative number if a < b, zero if a == b, and a
// positive number if a > b.
func Compare(a, b string) int {
	ea, ua, ra := split(a)
	eb, ub, rb := split(b)

	if c := ea - eb; c != 0 {
		return c
	}
	if c := verutil.CompareSegment(ua, ub); c != 0 {
		return c
	}
	return verutil.CompareSegment(ra, rb)
}

// split breaks a version into its epoch (0 if absent), upstream_version,
// and debian_revision ("" if absent, which compares equal to "0").
func split(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, _ = strconv.Atoi(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

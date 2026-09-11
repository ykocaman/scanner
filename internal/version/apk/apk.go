// Package apk compares Alpine (apk) package version strings.
//
// It handles the common "<version>-r<revision>" shape (e.g.
// "1.10.11-r0") using the same digit/non-digit run comparison dpkg
// uses. It does not implement apk's full suffix grammar
// (_alpha/_beta/_pre/_rc/_cvs/_git/... have a specific relative
// ordering in real apk-tools that this package treats as plain,
// lexically-compared text instead). That covers the vast majority of
// entries in Alpine's secdb feeds but is not a complete apk version
// comparator.
package apk

import (
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
	va, ra := splitRevision(a)
	vb, rb := splitRevision(b)

	if c := verutil.CompareSegment(va, vb); c != 0 {
		return c
	}
	return verutil.CompareSegment(ra, rb)
}

// splitRevision separates apk's "-r<N>" package revision suffix from
// the rest of the version, if present.
func splitRevision(v string) (version, revision string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 && strings.HasPrefix(v[i+1:], "r") {
		return v[:i], v[i+2:]
	}
	return v, ""
}

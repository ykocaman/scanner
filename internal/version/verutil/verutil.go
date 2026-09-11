// Package verutil provides the generic version-string comparison
// primitive shared by the dpkg (Debian/Ubuntu) and apk (Alpine) version
// comparators.
package verutil

import "strconv"

// CompareSegment compares two version-like strings by splitting them
// into alternating non-digit and digit runs: non-digit runs are
// compared byte-by-byte (with '~' sorting before everything, including
// the end of the string, and letters sorting before non-letters), and
// digit runs are compared numerically. This is the core algorithm
// dpkg uses to compare a version's upstream and revision parts
// (Debian Policy §5.6.12); apk's version scheme follows the same shape
// closely enough to reuse it.
func CompareSegment(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		na, nb := nonDigitRun(a), nonDigitRun(b)
		if c := compareNonDigit(na, nb); c != 0 {
			return c
		}
		a, b = a[len(na):], b[len(nb):]

		da, db := digitRun(a), digitRun(b)
		if c := compareDigits(da, db); c != 0 {
			return c
		}
		a, b = a[len(da):], b[len(db):]
	}
	return 0
}

func nonDigitRun(s string) string {
	i := 0
	for i < len(s) && (s[i] < '0' || s[i] > '9') {
		i++
	}
	return s[:i]
}

func digitRun(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

func compareDigits(a, b string) int {
	na, nb := parseDigits(a), parseDigits(b)
	switch {
	case na < nb:
		return -1
	case na > nb:
		return 1
	default:
		return 0
	}
}

func parseDigits(s string) int {
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func compareNonDigit(a, b string) int {
	n := max(len(b), len(a))
	for i := range n {
		var ca, cb byte
		if i < len(a) {
			ca = a[i]
		}
		if i < len(b) {
			cb = b[i]
		}
		if ca == cb {
			continue
		}
		if c := order(ca) - order(cb); c != 0 {
			return c
		}
	}
	return 0
}

// order gives each byte dpkg's comparison weight: '~' sorts before
// everything (even the implicit end-of-string, weight 0), letters sort
// by their ASCII value, and everything else sorts after all letters.
func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0:
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

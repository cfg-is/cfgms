// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrUnparseableVersion is returned when a version string cannot be ordered
// (empty, or a Debian epoch that is not a number). Callers treat it as "do not
// downgrade" and keep the plain install behaviour.
var ErrUnparseableVersion = errors.New("unparseable package version")

// compareDebianVersions orders two Debian package versions
// ([epoch:]upstream[-revision]) the way dpkg does: epoch numerically, then
// upstream and revision with the dpkg character order, where '~' sorts before
// everything including the end of the string. It returns -1, 0 or 1.
func compareDebianVersions(a, b string) (int, error) {
	ea, ua, ra, err := splitDebianVersion(a)
	if err != nil {
		return 0, err
	}
	eb, ub, rb, err := splitDebianVersion(b)
	if err != nil {
		return 0, err
	}
	if ea != eb {
		if ea < eb {
			return -1, nil
		}
		return 1, nil
	}
	if c := debianVerRevCmp(ua, ub); c != 0 {
		return c, nil
	}
	return debianVerRevCmp(ra, rb), nil
}

// splitDebianVersion splits a version into epoch, upstream and revision. A
// missing epoch is 0; a missing revision is the empty string (equal to "0").
func splitDebianVersion(v string) (epoch uint64, upstream, revision string, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, "", "", fmt.Errorf("%w: empty version", ErrUnparseableVersion)
	}
	rest := v
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, err = strconv.ParseUint(v[:i], 10, 32)
		if err != nil {
			return 0, "", "", fmt.Errorf("%w: invalid epoch in %q", ErrUnparseableVersion, v)
		}
		rest = v[i+1:]
	}
	upstream = rest
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		upstream, revision = rest[:i], rest[i+1:]
	}
	if upstream == "" {
		return 0, "", "", fmt.Errorf("%w: empty upstream version in %q", ErrUnparseableVersion, v)
	}
	return epoch, upstream, revision, nil
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func isASCIIAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// byteAt returns s[i], or 0 past the end of s.
func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// debianOrder is dpkg's per-character weight for the non-digit parts of a
// version: digits and the end of the string weigh 0, letters their own value,
// '~' sorts below everything, and other characters sort after letters.
func debianOrder(c byte) int {
	switch {
	case c == 0 || isASCIIDigit(c):
		return 0
	case isASCIIAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// debianVerRevCmp compares one upstream or revision component (dpkg verrevcmp)
// by alternating a non-digit run comparison with a digit run comparison.
func debianVerRevCmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		var c int
		if c, i, j = debianNonDigitCmp(a, b, i, j); c != 0 {
			return c
		}
		if c, i, j = debianDigitCmp(a, b, i, j); c != 0 {
			return c
		}
	}
	return 0
}

// debianNonDigitCmp compares the non-digit runs of a and b starting at i and j
// using the dpkg character order. It returns the ordering (0 when the runs are
// equal) and the positions after the runs.
func debianNonDigitCmp(a, b string, i, j int) (int, int, int) {
	for (i < len(a) && !isASCIIDigit(a[i])) || (j < len(b) && !isASCIIDigit(b[j])) {
		if c := cmp.Compare(debianOrder(byteAt(a, i)), debianOrder(byteAt(b, j))); c != 0 {
			return c, i, j
		}
		i++
		j++
	}
	return 0, i, j
}

// debianDigitCmp compares the digit runs of a and b starting at i and j as
// numbers: leading zeros are skipped, a longer run is larger, and equal-length
// runs order by their first differing digit. It returns the ordering and the
// positions after the runs.
func debianDigitCmp(a, b string, i, j int) (int, int, int) {
	i, j = skipWhile(a, i, isZeroByte), skipWhile(b, j, isZeroByte)
	firstDiff := 0
	for isASCIIDigit(byteAt(a, i)) && isASCIIDigit(byteAt(b, j)) {
		if firstDiff == 0 {
			firstDiff = int(a[i]) - int(b[j])
		}
		i++
		j++
	}
	if isASCIIDigit(byteAt(a, i)) {
		return 1, i, j
	}
	if isASCIIDigit(byteAt(b, j)) {
		return -1, i, j
	}
	return cmp.Compare(firstDiff, 0), i, j
}

func isZeroByte(c byte) bool { return c == '0' }

// skipWhile returns the first index at or after i whose byte in s does not
// satisfy pred (len(s) when all do).
func skipWhile(s string, i int, pred func(byte) bool) int {
	for i < len(s) && pred(s[i]) {
		i++
	}
	return i
}

// compareRPMVersions orders two rpm version strings with rpmvercmp: runs of
// digits compare numerically, runs of letters lexically, a numeric run is newer
// than an alphabetic one, '~' sorts before everything (including the end) and
// '^' sorts after the end but before any other continuation. It returns -1, 0
// or 1. Only %{VERSION} is meant to be passed; epoch and release are not
// handled here.
func compareRPMVersions(a, b string) (int, error) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return 0, fmt.Errorf("%w: empty version", ErrUnparseableVersion)
	}
	if a == b {
		return 0, nil
	}
	r := &rpmCursor{a: a, b: b}
	for r.i < len(a) || r.j < len(b) {
		if c, stop := r.step(); stop {
			return c, nil
		}
	}
	return r.tail(), nil
}

// rpmCursor walks two rpm version strings in lockstep.
type rpmCursor struct {
	a, b string
	i, j int
}

// rpmStep is the outcome of one rpmvercmp rule.
type rpmStep int

const (
	rpmNext     rpmStep = iota // rule does not apply; try the next rule
	rpmContinue                // equal markers consumed; compare the next segment
	rpmDecided                 // the ordering is known
)

func isRPMSignificant(c byte) bool { return isRPMSegmentByte(c) || c == '~' || c == '^' }

func (r *rpmCursor) cur() (byte, byte) { return byteAt(r.a, r.i), byteAt(r.b, r.j) }

// step compares the next segment. It reports stop=true with the final
// ordering once that is known, and stop=false to keep walking.
func (r *rpmCursor) step() (int, bool) {
	r.i = skipWhile(r.a, r.i, func(c byte) bool { return !isRPMSignificant(c) })
	r.j = skipWhile(r.b, r.j, func(c byte) bool { return !isRPMSignificant(c) })
	for _, rule := range [...]func() (int, rpmStep){r.tildeStep, r.caretStep} {
		c, st := rule()
		switch st {
		case rpmDecided:
			return c, true
		case rpmContinue:
			return 0, false
		}
	}
	if ca, cb := r.cur(); ca == 0 || cb == 0 {
		return r.tail(), true
	}
	if c := r.segmentCmp(); c != 0 {
		return c, true
	}
	return 0, false
}

// tildeStep applies the '~' rule: it sorts before everything, even the end.
func (r *rpmCursor) tildeStep() (int, rpmStep) {
	ca, cb := r.cur()
	switch {
	case ca != '~' && cb != '~':
		return 0, rpmNext
	case ca != '~':
		return 1, rpmDecided
	case cb != '~':
		return -1, rpmDecided
	}
	r.i++
	r.j++
	return 0, rpmContinue
}

// caretStep applies the '^' rule: it sorts after the end of the string but
// before any other continuation.
func (r *rpmCursor) caretStep() (int, rpmStep) {
	ca, cb := r.cur()
	switch {
	case ca != '^' && cb != '^':
		return 0, rpmNext
	case ca == 0:
		return -1, rpmDecided
	case cb == 0:
		return 1, rpmDecided
	case ca != '^':
		return 1, rpmDecided
	case cb != '^':
		return -1, rpmDecided
	}
	r.i++
	r.j++
	return 0, rpmContinue
}

// segmentCmp compares the digit or letter run at the cursor in both strings.
func (r *rpmCursor) segmentCmp() int {
	numeric := isASCIIDigit(byteAt(r.a, r.i))
	pred := isASCIIAlpha
	if numeric {
		pred = isASCIIDigit
	}
	si, sj := r.i, r.j
	r.i, r.j = skipWhile(r.a, r.i, pred), skipWhile(r.b, r.j, pred)
	segA, segB := r.a[si:r.i], r.b[sj:r.j]
	if segB == "" {
		// Segments of different kinds: numeric is newer than alphabetic.
		if numeric {
			return 1
		}
		return -1
	}
	if numeric {
		segA, segB = strings.TrimLeft(segA, "0"), strings.TrimLeft(segB, "0")
		if len(segA) != len(segB) {
			return cmp.Compare(len(segA), len(segB))
		}
	}
	return strings.Compare(segA, segB)
}

// tail orders the strings once one of them is exhausted: the one with input
// left over is newer.
func (r *rpmCursor) tail() int {
	switch {
	case r.i >= len(r.a) && r.j >= len(r.b):
		return 0
	case r.i < len(r.a):
		return 1
	default:
		return -1
	}
}

func isRPMSegmentByte(c byte) bool { return isASCIIDigit(c) || isASCIIAlpha(c) }

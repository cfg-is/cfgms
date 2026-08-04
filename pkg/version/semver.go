// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package version

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	semanticVersionRE = regexp.MustCompile(
		`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`,
	)
	numericIdentifierRE = regexp.MustCompile(`^[0-9]+$`)
)

// ErrInvalidSemanticVersion marks a version that is not a complete SemVer 2.0
// value. A single leading "v" is accepted because release tags use that form.
var ErrInvalidSemanticVersion = errors.New("invalid semantic version")

type semanticVersion struct {
	core       [3]string
	prerelease []string
}

// CompareSemantic compares two SemVer 2.0 versions. It returns -1 when a is
// older than b, 0 when they have equal precedence, and 1 when a is newer.
// Build metadata is intentionally ignored as required by SemVer.
func CompareSemantic(a, b string) (int, error) {
	av, err := parseSemantic(a)
	if err != nil {
		return 0, fmt.Errorf("%w %q", ErrInvalidSemanticVersion, a)
	}
	bv, err := parseSemantic(b)
	if err != nil {
		return 0, fmt.Errorf("%w %q", ErrInvalidSemanticVersion, b)
	}

	for i := range av.core {
		if cmp := compareNumericIdentifier(av.core[i], bv.core[i]); cmp != 0 {
			return cmp, nil
		}
	}

	switch {
	case len(av.prerelease) == 0 && len(bv.prerelease) == 0:
		return 0, nil
	case len(av.prerelease) == 0:
		return 1, nil
	case len(bv.prerelease) == 0:
		return -1, nil
	}

	common := min(len(av.prerelease), len(bv.prerelease))
	for i := 0; i < common; i++ {
		ai := av.prerelease[i]
		bi := bv.prerelease[i]
		an := numericIdentifierRE.MatchString(ai)
		bn := numericIdentifierRE.MatchString(bi)
		switch {
		case an && bn:
			if cmp := compareNumericIdentifier(ai, bi); cmp != 0 {
				return cmp, nil
			}
		case an:
			return -1, nil
		case bn:
			return 1, nil
		case ai < bi:
			return -1, nil
		case ai > bi:
			return 1, nil
		}
	}

	switch {
	case len(av.prerelease) < len(bv.prerelease):
		return -1, nil
	case len(av.prerelease) > len(bv.prerelease):
		return 1, nil
	default:
		return 0, nil
	}
}

// IsSemantic reports whether v is a complete semantic version accepted by
// CompareSemantic.
func IsSemantic(v string) bool {
	_, err := parseSemantic(v)
	return err == nil
}

func parseSemantic(v string) (semanticVersion, error) {
	match := semanticVersionRE.FindStringSubmatch(v)
	if match == nil {
		return semanticVersion{}, ErrInvalidSemanticVersion
	}
	out := semanticVersion{core: [3]string{match[1], match[2], match[3]}}
	if match[4] == "" {
		return out, nil
	}
	out.prerelease = strings.Split(match[4], ".")
	for _, identifier := range out.prerelease {
		if numericIdentifierRE.MatchString(identifier) &&
			len(identifier) > 1 && identifier[0] == '0' {
			return semanticVersion{}, ErrInvalidSemanticVersion
		}
	}
	return out, nil
}

// compareNumericIdentifier compares non-negative base-10 integers without
// converting to a fixed-width type, so arbitrarily large SemVer components
// cannot overflow.
func compareNumericIdentifier(a, b string) int {
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package modules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SemanticVersion represents a semantic version (MAJOR.MINOR.PATCH)
type SemanticVersion struct {
	Major      int    `json:"major"`
	Minor      int    `json:"minor"`
	Patch      int    `json:"patch"`
	PreRelease string `json:"pre_release,omitempty"`
	Build      string `json:"build,omitempty"`
}

// ParseVersion parses a semantic version string
func ParseVersion(version string) (*SemanticVersion, error) {
	if version == "" {
		return nil, fmt.Errorf("version string cannot be empty")
	}

	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")

	// Regular expression for semantic versioning
	// Matches: MAJOR.MINOR.PATCH[-prerelease][+build]
	re := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z\-\.]+))?(?:\+([0-9A-Za-z\-\.]+))?$`)

	matches := re.FindStringSubmatch(version)
	if matches == nil {
		return nil, fmt.Errorf("invalid semantic version format: %s", version)
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", matches[1])
	}

	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", matches[2])
	}

	patch, err := strconv.Atoi(matches[3])
	if err != nil {
		return nil, fmt.Errorf("invalid patch version: %s", matches[3])
	}

	return &SemanticVersion{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		PreRelease: matches[4],
		Build:      matches[5],
	}, nil
}

// String returns the string representation of the version
func (v *SemanticVersion) String() string {
	version := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)

	if v.PreRelease != "" {
		version += "-" + v.PreRelease
	}

	if v.Build != "" {
		version += "+" + v.Build
	}

	return version
}

// Compare compares two semantic versions
// Returns: -1 if v < other, 0 if v == other, 1 if v > other
func (v *SemanticVersion) Compare(other *SemanticVersion) int {
	if v.Major != other.Major {
		if v.Major > other.Major {
			return 1
		}
		return -1
	}

	if v.Minor != other.Minor {
		if v.Minor > other.Minor {
			return 1
		}
		return -1
	}

	if v.Patch != other.Patch {
		if v.Patch > other.Patch {
			return 1
		}
		return -1
	}

	// Handle pre-release versions
	// A pre-release version has lower precedence than a normal version
	if v.PreRelease == "" && other.PreRelease != "" {
		return 1
	}
	if v.PreRelease != "" && other.PreRelease == "" {
		return -1
	}

	// Both have pre-release, compare lexically
	if v.PreRelease != "" && other.PreRelease != "" {
		if v.PreRelease > other.PreRelease {
			return 1
		}
		if v.PreRelease < other.PreRelease {
			return -1
		}
	}

	return 0
}

// IsVersionCompatible checks if a version satisfies a constraint
// Supported constraints:
// - "1.2.3" (exact version)
// - ">=1.2.0" (greater than or equal)
// - ">1.2.0" (greater than)
// - "<=1.2.0" (less than or equal)
// - "<1.2.0" (less than)
// - "~1.2.0" (compatible within minor version, allows patch-level changes)
// - "^1.2.0" (compatible within major version, allows minor and patch changes)
// - "*" (any version)
func IsVersionCompatible(version, constraint string) (bool, error) {
	if constraint == "" || constraint == "*" {
		return true, nil
	}

	actualVersion, err := ParseVersion(version)
	if err != nil {
		return false, fmt.Errorf("invalid actual version: %v", err)
	}

	// Handle tilde constraint (~1.2.0)
	if strings.HasPrefix(constraint, "~") {
		return checkTildeConstraint(actualVersion, constraint[1:])
	}

	// Handle caret constraint (^1.2.0)
	if strings.HasPrefix(constraint, "^") {
		return checkCaretConstraint(actualVersion, constraint[1:])
	}

	// Handle comparison operators
	if strings.HasPrefix(constraint, ">=") {
		return checkComparisonConstraint(actualVersion, constraint[2:], ">=")
	}
	if strings.HasPrefix(constraint, "<=") {
		return checkComparisonConstraint(actualVersion, constraint[2:], "<=")
	}
	if strings.HasPrefix(constraint, ">") {
		return checkComparisonConstraint(actualVersion, constraint[1:], ">")
	}
	if strings.HasPrefix(constraint, "<") {
		return checkComparisonConstraint(actualVersion, constraint[1:], "<")
	}

	// Exact version match
	constraintVersion, err := ParseVersion(constraint)
	if err != nil {
		return false, fmt.Errorf("invalid constraint version: %v", err)
	}

	return actualVersion.Compare(constraintVersion) == 0, nil
}

// checkTildeConstraint handles ~1.2.0 (compatible within minor version)
// ~1.2.0 := >=1.2.0 <1.(2+1).0 := >=1.2.0 <1.3.0
func checkTildeConstraint(actual *SemanticVersion, constraint string) (bool, error) {
	constraintVersion, err := ParseVersion(constraint)
	if err != nil {
		return false, fmt.Errorf("invalid tilde constraint version: %v", err)
	}

	// Must be >= constraint version
	if actual.Compare(constraintVersion) < 0 {
		return false, nil
	}

	// Must be within the same major.minor
	if actual.Major != constraintVersion.Major || actual.Minor != constraintVersion.Minor {
		return false, nil
	}

	return true, nil
}

// checkCaretConstraint handles ^1.2.0 (compatible within major version)
// ^1.2.0 := >=1.2.0 <2.0.0
func checkCaretConstraint(actual *SemanticVersion, constraint string) (bool, error) {
	constraintVersion, err := ParseVersion(constraint)
	if err != nil {
		return false, fmt.Errorf("invalid caret constraint version: %v", err)
	}

	// Must be >= constraint version
	if actual.Compare(constraintVersion) < 0 {
		return false, nil
	}

	// Must be within the same major version
	if actual.Major != constraintVersion.Major {
		return false, nil
	}

	return true, nil
}

// checkComparisonConstraint handles >, >=, <, <= operators
func checkComparisonConstraint(actual *SemanticVersion, constraint, operator string) (bool, error) {
	constraintVersion, err := ParseVersion(constraint)
	if err != nil {
		return false, fmt.Errorf("invalid comparison constraint version: %v", err)
	}

	comparison := actual.Compare(constraintVersion)

	switch operator {
	case ">":
		return comparison > 0, nil
	case ">=":
		return comparison >= 0, nil
	case "<":
		return comparison < 0, nil
	case "<=":
		return comparison <= 0, nil
	default:
		return false, fmt.Errorf("unsupported comparison operator: %s", operator)
	}
}

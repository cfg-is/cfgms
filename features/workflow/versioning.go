// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package workflow

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SemanticVersion represents a semantic version following semver.org specification
type SemanticVersion struct {
	Major      int    `yaml:"major" json:"major"`
	Minor      int    `yaml:"minor" json:"minor"`
	Patch      int    `yaml:"patch" json:"patch"`
	PreRelease string `yaml:"pre_release,omitempty" json:"pre_release,omitempty"`
	BuildMeta  string `yaml:"build_meta,omitempty" json:"build_meta,omitempty"`
}

// String returns the string representation of the semantic version
func (sv SemanticVersion) String() string {
	version := fmt.Sprintf("%d.%d.%d", sv.Major, sv.Minor, sv.Patch)
	if sv.PreRelease != "" {
		version += "-" + sv.PreRelease
	}
	if sv.BuildMeta != "" {
		version += "+" + sv.BuildMeta
	}
	return version
}

// ParseSemanticVersion parses a semantic version string
func ParseSemanticVersion(version string) (*SemanticVersion, error) {
	// Regular expression for semantic versioning (simplified)
	semverRegex := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z\-\.]+))?(?:\+([0-9A-Za-z\-\.]+))?$`)

	matches := semverRegex.FindStringSubmatch(version)
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

	sv := &SemanticVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
	}

	if len(matches) > 4 && matches[4] != "" {
		sv.PreRelease = matches[4]
	}

	if len(matches) > 5 && matches[5] != "" {
		sv.BuildMeta = matches[5]
	}

	return sv, nil
}

// Compare compares two semantic versions
// Returns: -1 if sv < other, 0 if equal, 1 if sv > other
func (sv SemanticVersion) Compare(other SemanticVersion) int {
	// Compare major, minor, patch
	if sv.Major != other.Major {
		if sv.Major < other.Major {
			return -1
		}
		return 1
	}

	if sv.Minor != other.Minor {
		if sv.Minor < other.Minor {
			return -1
		}
		return 1
	}

	if sv.Patch != other.Patch {
		if sv.Patch < other.Patch {
			return -1
		}
		return 1
	}

	// Compare pre-release versions
	if sv.PreRelease == "" && other.PreRelease != "" {
		return 1 // Normal version has higher precedence than pre-release
	}
	if sv.PreRelease != "" && other.PreRelease == "" {
		return -1
	}
	if sv.PreRelease != "" && other.PreRelease != "" {
		return strings.Compare(sv.PreRelease, other.PreRelease)
	}

	return 0
}

// IsCompatible checks if this version is compatible with another version
// Compatible means same major version and this version >= other version
func (sv SemanticVersion) IsCompatible(other SemanticVersion) bool {
	if sv.Major != other.Major {
		return false
	}
	return sv.Compare(other) >= 0
}

// NextMajor returns the next major version (e.g., 1.2.3 -> 2.0.0)
func (sv SemanticVersion) NextMajor() SemanticVersion {
	return SemanticVersion{
		Major: sv.Major + 1,
		Minor: 0,
		Patch: 0,
	}
}

// NextMinor returns the next minor version (e.g., 1.2.3 -> 1.3.0)
func (sv SemanticVersion) NextMinor() SemanticVersion {
	return SemanticVersion{
		Major: sv.Major,
		Minor: sv.Minor + 1,
		Patch: 0,
	}
}

// NextPatch returns the next patch version (e.g., 1.2.3 -> 1.2.4)
func (sv SemanticVersion) NextPatch() SemanticVersion {
	return SemanticVersion{
		Major: sv.Major,
		Minor: sv.Minor,
		Patch: sv.Patch + 1,
	}
}

// VersionedWorkflow represents a workflow with semantic versioning
type VersionedWorkflow struct {
	Workflow
	SemanticVersion SemanticVersion  `yaml:"semantic_version" json:"semantic_version"`
	VersionTags     []string         `yaml:"version_tags,omitempty" json:"version_tags,omitempty"`
	Deprecated      bool             `yaml:"deprecated,omitempty" json:"deprecated,omitempty"`
	DeprecationNote string           `yaml:"deprecation_note,omitempty" json:"deprecation_note,omitempty"`
	Changelog       []ChangelogEntry `yaml:"changelog,omitempty" json:"changelog,omitempty"`
}

// ChangelogEntry represents a single changelog entry
type ChangelogEntry struct {
	Version     SemanticVersion `yaml:"version" json:"version"`
	Date        string          `yaml:"date" json:"date"`
	Description string          `yaml:"description" json:"description"`
	Changes     []Change        `yaml:"changes" json:"changes"`
	Author      string          `yaml:"author,omitempty" json:"author,omitempty"`
}

// Change represents a single change in a version
type Change struct {
	Type        ChangeType `yaml:"type" json:"type"`
	Description string     `yaml:"description" json:"description"`
	Breaking    bool       `yaml:"breaking,omitempty" json:"breaking,omitempty"`
}

// ChangeType defines the type of change
type ChangeType string

const (
	ChangeTypeAdded      ChangeType = "added"      // New features
	ChangeTypeChanged    ChangeType = "changed"    // Changes in existing functionality
	ChangeTypeDeprecated ChangeType = "deprecated" // Soon-to-be removed features
	ChangeTypeRemoved    ChangeType = "removed"    // Removed features
	ChangeTypeFixed      ChangeType = "fixed"      // Bug fixes
	ChangeTypeSecurity   ChangeType = "security"   // Security fixes
)

// VersionRange represents a version constraint (e.g., ">=1.0.0,<2.0.0")
type VersionRange struct {
	Min        *SemanticVersion `yaml:"min,omitempty" json:"min,omitempty"`
	Max        *SemanticVersion `yaml:"max,omitempty" json:"max,omitempty"`
	IncludeMin bool             `yaml:"include_min" json:"include_min"`
	IncludeMax bool             `yaml:"include_max" json:"include_max"`
	Exact      *SemanticVersion `yaml:"exact,omitempty" json:"exact,omitempty"`
}

// ParseVersionRange parses a version range string
func ParseVersionRange(rangeStr string) (*VersionRange, error) {
	// Handle exact version (e.g., "1.2.3")
	if !strings.ContainsAny(rangeStr, "<>=,") {
		version, err := ParseSemanticVersion(rangeStr)
		if err != nil {
			return nil, err
		}
		return &VersionRange{Exact: version}, nil
	}

	// Handle range constraints (simplified implementation)
	// This could be extended to support more complex range syntax
	vr := &VersionRange{
		IncludeMin: true,
		IncludeMax: false,
	}

	// Split by comma for multiple constraints
	constraints := strings.Split(rangeStr, ",")
	for _, constraint := range constraints {
		constraint = strings.TrimSpace(constraint)

		if strings.HasPrefix(constraint, ">=") {
			version, err := ParseSemanticVersion(strings.TrimSpace(constraint[2:]))
			if err != nil {
				return nil, err
			}
			vr.Min = version
			vr.IncludeMin = true
		} else if strings.HasPrefix(constraint, ">") {
			version, err := ParseSemanticVersion(strings.TrimSpace(constraint[1:]))
			if err != nil {
				return nil, err
			}
			vr.Min = version
			vr.IncludeMin = false
		} else if strings.HasPrefix(constraint, "<=") {
			version, err := ParseSemanticVersion(strings.TrimSpace(constraint[2:]))
			if err != nil {
				return nil, err
			}
			vr.Max = version
			vr.IncludeMax = true
		} else if strings.HasPrefix(constraint, "<") {
			version, err := ParseSemanticVersion(strings.TrimSpace(constraint[1:]))
			if err != nil {
				return nil, err
			}
			vr.Max = version
			vr.IncludeMax = false
		}
	}

	return vr, nil
}

// Satisfies checks if a version satisfies this range
func (vr *VersionRange) Satisfies(version SemanticVersion) bool {
	// Exact version match
	if vr.Exact != nil {
		return version.Compare(*vr.Exact) == 0
	}

	// Check minimum version
	if vr.Min != nil {
		comparison := version.Compare(*vr.Min)
		if comparison < 0 || (!vr.IncludeMin && comparison == 0) {
			return false
		}
	}

	// Check maximum version
	if vr.Max != nil {
		comparison := version.Compare(*vr.Max)
		if comparison > 0 || (!vr.IncludeMax && comparison == 0) {
			return false
		}
	}

	return true
}

// String returns the string representation of the version range
func (vr *VersionRange) String() string {
	if vr.Exact != nil {
		return vr.Exact.String()
	}

	var parts []string
	if vr.Min != nil {
		if vr.IncludeMin {
			parts = append(parts, ">="+vr.Min.String())
		} else {
			parts = append(parts, ">"+vr.Min.String())
		}
	}
	if vr.Max != nil {
		if vr.IncludeMax {
			parts = append(parts, "<="+vr.Max.String())
		} else {
			parts = append(parts, "<"+vr.Max.String())
		}
	}

	return strings.Join(parts, ",")
}

// ValidateVersionUpgrade validates that a version upgrade is valid
func ValidateVersionUpgrade(from, to SemanticVersion) error {
	comparison := to.Compare(from)
	if comparison <= 0 {
		return errors.New("new version must be greater than current version")
	}

	// Check for valid semantic version upgrades
	if to.Major > from.Major {
		// Major version upgrade - any change is allowed
		return nil
	}

	if to.Major == from.Major && to.Minor > from.Minor {
		// Minor version upgrade - patch should be 0 for clean minor upgrade
		if to.Patch != 0 {
			return fmt.Errorf("minor version upgrade should reset patch to 0, got %d", to.Patch)
		}
		return nil
	}

	if to.Major == from.Major && to.Minor == from.Minor && to.Patch > from.Patch {
		// Patch version upgrade - valid
		return nil
	}

	return errors.New("invalid version upgrade sequence")
}

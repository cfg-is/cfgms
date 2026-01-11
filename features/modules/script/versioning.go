// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Version represents a semantic version for scripts
type Version struct {
	Major      int    `json:"major" yaml:"major"`
	Minor      int    `json:"minor" yaml:"minor"`
	Patch      int    `json:"patch" yaml:"patch"`
	Prerelease string `json:"prerelease,omitempty" yaml:"prerelease,omitempty"`
	BuildMeta  string `json:"build_meta,omitempty" yaml:"build_meta,omitempty"`
}

// String returns the string representation of the version (e.g., "1.2.3")
func (v *Version) String() string {
	version := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		version += "-" + v.Prerelease
	}
	if v.BuildMeta != "" {
		version += "+" + v.BuildMeta
	}
	return version
}

// ParseVersion parses a semantic version string
func ParseVersion(version string) (*Version, error) {
	// Semantic versioning regex pattern
	pattern := `^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`
	re := regexp.MustCompile(pattern)

	matches := re.FindStringSubmatch(version)
	if matches == nil {
		return nil, fmt.Errorf("invalid version format: %s (expected semver format like 1.2.3)", version)
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])

	return &Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: matches[4],
		BuildMeta:  matches[5],
	}, nil
}

// Compare compares two versions (-1 if v < other, 0 if equal, 1 if v > other)
func (v *Version) Compare(other *Version) int {
	if v.Major != other.Major {
		return compareInt(v.Major, other.Major)
	}
	if v.Minor != other.Minor {
		return compareInt(v.Minor, other.Minor)
	}
	if v.Patch != other.Patch {
		return compareInt(v.Patch, other.Patch)
	}

	// Handle prerelease comparison
	if v.Prerelease == "" && other.Prerelease != "" {
		return 1 // Release version > prerelease
	}
	if v.Prerelease != "" && other.Prerelease == "" {
		return -1 // Prerelease < release version
	}
	if v.Prerelease != other.Prerelease {
		return strings.Compare(v.Prerelease, other.Prerelease)
	}

	return 0
}

func compareInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// IsCompatibleWith checks if this version is compatible with the required version
// Compatible means same major version and greater than or equal to required version
func (v *Version) IsCompatibleWith(required *Version) bool {
	if v.Major != required.Major {
		return false
	}
	return v.Compare(required) >= 0
}

// ScriptMetadata contains metadata about a versioned script
type ScriptMetadata struct {
	ID          string            `json:"id" yaml:"id"`                                     // Unique script ID
	Name        string            `json:"name" yaml:"name"`                                 // Human-readable name
	Description string            `json:"description" yaml:"description"`                   // Script description
	Version     *Version          `json:"version" yaml:"version"`                           // Current version
	Author      string            `json:"author" yaml:"author"`                             // Script author
	Tags        []string          `json:"tags,omitempty" yaml:"tags,omitempty"`             // Classification tags
	Category    string            `json:"category,omitempty" yaml:"category,omitempty"`     // Script category
	Platform    []string          `json:"platform" yaml:"platform"`                         // Supported platforms (windows, linux, darwin)
	Shell       ShellType         `json:"shell" yaml:"shell"`                               // Required shell
	Parameters  []ScriptParameter `json:"parameters,omitempty" yaml:"parameters,omitempty"` // Script parameters
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`                     // Creation timestamp
	UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at"`                     // Last update timestamp
}

// ScriptParameter defines a parameter that can be passed to the script
type ScriptParameter struct {
	Name          string      `json:"name" yaml:"name"`                                         // Parameter name
	Description   string      `json:"description,omitempty" yaml:"description,omitempty"`       // Parameter description
	Type          string      `json:"type" yaml:"type"`                                         // Data type (string, int, bool, etc.)
	Required      bool        `json:"required" yaml:"required"`                                 // Whether parameter is required
	Default       interface{} `json:"default,omitempty" yaml:"default,omitempty"`               // Default value
	AllowedValues []string    `json:"allowed_values,omitempty" yaml:"allowed_values,omitempty"` // Enum values
	DNAPath       string      `json:"dna_path,omitempty" yaml:"dna_path,omitempty"`             // Auto-inject from DNA (e.g., "OS.Version")
}

// VersionedScript represents a complete versioned script
type VersionedScript struct {
	Metadata *ScriptMetadata `json:"metadata" yaml:"metadata"` // Script metadata
	Content  string          `json:"content" yaml:"content"`   // Script content
	Hash     string          `json:"hash" yaml:"hash"`         // Content hash for integrity
}

// ScriptRepository defines the interface for script storage and versioning
type ScriptRepository interface {
	// Create creates a new script with initial version
	Create(script *VersionedScript) error

	// Get retrieves a script by ID and version (empty version = latest)
	Get(id string, version string) (*VersionedScript, error)

	// List lists all scripts with optional filtering
	List(filter *ScriptFilter) ([]*ScriptMetadata, error)

	// Update creates a new version of an existing script
	Update(script *VersionedScript) error

	// Delete removes a script (all versions or specific version)
	Delete(id string, version string) error

	// ListVersions lists all versions of a script
	ListVersions(id string) ([]*Version, error)

	// GetLatestVersion returns the latest version of a script
	GetLatestVersion(id string) (*Version, error)

	// Rollback rolls back a script to a previous version
	Rollback(id string, version string) error
}

// ScriptFilter defines filtering options for listing scripts
type ScriptFilter struct {
	Category string   `json:"category,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Platform string   `json:"platform,omitempty"`
	Shell    string   `json:"shell,omitempty"`
	Author   string   `json:"author,omitempty"`
}

// Validate validates the script metadata
func (m *ScriptMetadata) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("script ID cannot be empty")
	}
	if m.Name == "" {
		return fmt.Errorf("script name cannot be empty")
	}
	if m.Version == nil {
		return fmt.Errorf("script version cannot be nil")
	}
	if m.Shell == "" {
		return fmt.Errorf("shell type is required")
	}
	if len(m.Platform) == 0 {
		return fmt.Errorf("at least one platform must be specified")
	}

	// Validate platforms
	validPlatforms := map[string]bool{"windows": true, "linux": true, "darwin": true}
	for _, platform := range m.Platform {
		if !validPlatforms[platform] {
			return fmt.Errorf("invalid platform: %s (must be windows, linux, or darwin)", platform)
		}
	}

	// Validate parameters
	for i, param := range m.Parameters {
		if param.Name == "" {
			return fmt.Errorf("parameter %d: name cannot be empty", i)
		}
		if param.Type == "" {
			return fmt.Errorf("parameter %s: type cannot be empty", param.Name)
		}
	}

	return nil
}

// Clone creates a deep copy of the metadata with a new version
func (m *ScriptMetadata) Clone(newVersion *Version) *ScriptMetadata {
	clone := &ScriptMetadata{
		ID:          m.ID,
		Name:        m.Name,
		Description: m.Description,
		Version:     newVersion,
		Author:      m.Author,
		Category:    m.Category,
		Platform:    make([]string, len(m.Platform)),
		Shell:       m.Shell,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   time.Now(),
	}

	copy(clone.Platform, m.Platform)

	if len(m.Tags) > 0 {
		clone.Tags = make([]string, len(m.Tags))
		copy(clone.Tags, m.Tags)
	}

	if len(m.Parameters) > 0 {
		clone.Parameters = make([]ScriptParameter, len(m.Parameters))
		copy(clone.Parameters, m.Parameters)
	}

	return clone
}

// Package version provides build-time version information for CFGMS components.
//
// Version information can be injected at build time using ldflags:
//   go build -ldflags "-X github.com/cfgis/cfgms/pkg/version.Version=v0.5.0"
package version

import "fmt"

// Version information set at build time via ldflags.
// Default values are used when not overridden during build.
var (
	// Version is the semantic version (e.g., "0.5.0", "1.2.3-beta")
	Version = "0.5.0-dev"

	// GitCommit is the git commit SHA (e.g., "a1b2c3d")
	GitCommit = "unknown"

	// BuildDate is the build timestamp (e.g., "2025-01-15T10:30:00Z")
	BuildDate = "unknown"

	// GoVersion is the Go version used for build (e.g., "go1.23.5")
	GoVersion = "unknown"
)

// Info returns formatted version information.
func Info() string {
	return fmt.Sprintf("Version: %s, Commit: %s, Built: %s, Go: %s",
		Version, GitCommit, BuildDate, GoVersion)
}

// Short returns the version string (e.g., "v0.5.0").
func Short() string {
	if Version[0] != 'v' {
		return "v" + Version
	}
	return Version
}

// ShortWithoutPrefix returns the version without the 'v' prefix (e.g., "0.5.0").
func ShortWithoutPrefix() string {
	if len(Version) > 0 && Version[0] == 'v' {
		return Version[1:]
	}
	return Version
}

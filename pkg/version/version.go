// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package version provides build-time version information for CFGMS components.
//
// Version information can be injected at build time using ldflags:
//
//	go build -ldflags "-X github.com/cfgis/cfgms/pkg/version.Version=v0.5.0"
package version

import (
	"fmt"
	"runtime/debug"
)

// EnvStewardLauncherManaged is the environment variable the steward launcher
// (cmd/cfgms-steward-launcher) sets on its steward child process. When its value
// is "1" the steward is being supervised by a launcher that will re-exec the
// staged binary after a graceful exit, so a pushed-upgrade self-exit is safe and
// expected. When the steward runs bare/standalone (no launcher: dev, fleet-e2e,
// systemd without launcher) the variable is absent and the steward must NOT
// self-exit after staging an upgrade — doing so would only cause downtime or a
// crash loop, since nothing would re-exec the staged binary. Defined here in
// pkg/version (a leaf utility importing only fmt) so BOTH the launcher and the
// steward client can reference one constant without an import cycle. (Issue #2003)
const EnvStewardLauncherManaged = "CFGMS_STEWARD_LAUNCHER_MANAGED"

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

// readBuildInfo is the build-info reader Revision consults; tests replace it.
var readBuildInfo = debug.ReadBuildInfo

// Revision returns the build's source revision. The ldflags GitCommit wins when
// set (scripts/release/build-binaries.sh stamps it for deploy builds). Otherwise
// it falls back to the toolchain's vcs.revision build setting, suffixed with
// "-dirty" when vcs.modified is "true", which serves Makefile dev builds. It
// returns "unknown" when neither is available.
func Revision() string {
	if GitCommit != "" && GitCommit != "unknown" {
		return GitCommit
	}
	info, ok := readBuildInfo()
	if !ok || info == nil {
		return "unknown"
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return "unknown"
	}
	if modified == "true" {
		return revision + "-dirty"
	}
	return revision
}

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

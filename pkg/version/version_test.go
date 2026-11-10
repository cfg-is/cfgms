// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShort_PrependV(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "0.5.0-dev"

	assert.Equal(t, "v0.5.0-dev", Short())
}

func TestShort_NoPrependWhenVPresent(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "v1.0.0"

	assert.Equal(t, "v1.0.0", Short())
}

func TestShortWithoutPrefix_StripsV(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "v1.0.0"

	assert.Equal(t, "1.0.0", ShortWithoutPrefix())
}

func TestShortWithoutPrefix_NoPrefix(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "1.0.0"

	assert.Equal(t, "1.0.0", ShortWithoutPrefix())
}

// withBuildInfo swaps the build-info reader and the ldflags GitCommit for one test.
func withBuildInfo(t *testing.T, commit string, info *debug.BuildInfo, ok bool) {
	t.Helper()
	origCommit, origReader := GitCommit, readBuildInfo
	t.Cleanup(func() { GitCommit, readBuildInfo = origCommit, origReader })
	GitCommit = commit
	readBuildInfo = func() (*debug.BuildInfo, bool) { return info, ok }
}

func vcsInfo(revision, modified string) *debug.BuildInfo {
	settings := []debug.BuildSetting{{Key: "vcs", Value: "git"}}
	if revision != "" {
		settings = append(settings, debug.BuildSetting{Key: "vcs.revision", Value: revision})
	}
	if modified != "" {
		settings = append(settings, debug.BuildSetting{Key: "vcs.modified", Value: modified})
	}
	return &debug.BuildInfo{Settings: settings}
}

func TestRevisionPrefersLdflags(t *testing.T) {
	withBuildInfo(t, "a1b2c3d", vcsInfo("ffffffffffffffffffffffffffffffffffffffff", "true"), true)

	assert.Equal(t, "a1b2c3d", Revision())
}

func TestRevisionFallsBackToBuildInfo(t *testing.T) {
	const rev = "0123456789abcdef0123456789abcdef01234567"

	t.Run("clean tree", func(t *testing.T) {
		withBuildInfo(t, "unknown", vcsInfo(rev, "false"), true)
		assert.Equal(t, rev, Revision())
	})

	t.Run("modified tree is marked dirty", func(t *testing.T) {
		withBuildInfo(t, "unknown", vcsInfo(rev, "true"), true)
		assert.Equal(t, rev+"-dirty", Revision())
	})

	t.Run("empty ldflags value is treated as unset", func(t *testing.T) {
		withBuildInfo(t, "", vcsInfo(rev, ""), true)
		assert.Equal(t, rev, Revision())
	})
}

func TestRevisionUnknown(t *testing.T) {
	t.Run("build info unavailable", func(t *testing.T) {
		withBuildInfo(t, "unknown", nil, false)
		assert.Equal(t, "unknown", Revision())
	})

	t.Run("nil build info", func(t *testing.T) {
		withBuildInfo(t, "unknown", nil, true)
		assert.Equal(t, "unknown", Revision())
	})

	t.Run("no vcs revision setting", func(t *testing.T) {
		withBuildInfo(t, "unknown", vcsInfo("", ""), true)
		assert.Equal(t, "unknown", Revision())
	})

	t.Run("modified without a revision stays unknown", func(t *testing.T) {
		withBuildInfo(t, "unknown", vcsInfo("", "true"), true)
		assert.Equal(t, "unknown", Revision())
	})
}

func TestInfoUnchangedByRevision(t *testing.T) {
	withBuildInfo(t, "unknown", vcsInfo("0123456789abcdef", "true"), true)
	origV, origB, origG := Version, BuildDate, GoVersion
	t.Cleanup(func() { Version, BuildDate, GoVersion = origV, origB, origG })
	Version, BuildDate, GoVersion = "1.2.3", "2025-01-15T10:30:00Z", "go1.23.5"

	assert.Equal(t, "Version: 1.2.3, Commit: unknown, Built: 2025-01-15T10:30:00Z, Go: go1.23.5", Info())
	assert.Equal(t, "v1.2.3", Short())
	assert.Equal(t, "1.2.3", ShortWithoutPrefix())
}

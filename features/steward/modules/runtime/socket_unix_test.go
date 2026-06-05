// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package runtime

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMakeSocketPathShortRuntimeDirUsesNaturalPath verifies that when the
// natural path fits the sun_path limit, it is used unchanged.
func TestMakeSocketPathShortRuntimeDirUsesNaturalPath(t *testing.T) {
	path := makeSocketPath("/tmp/cfg", "echo", 1)
	assert.Equal(t, "/tmp/cfg/cfgms-module-echo-1.sock", path)
}

// TestMakeSocketPathLongRuntimeDirFallsBackToTmp verifies that when the natural
// path would exceed the macOS sun_path limit (104 bytes), makeSocketPath falls
// back to a hashed short path under /tmp. This is the regression test for the
// macOS test failures where t.TempDir() returns paths under /var/folders/...
// that exceed 104 bytes when combined with the socket filename.
func TestMakeSocketPathLongRuntimeDirFallsBackToTmp(t *testing.T) {
	// Simulate the macOS t.TempDir() path that overflowed in CI.
	longDir := "/var/folders/8d/778wjbv96mq1760tv6gk374m0000gn/T/TestEchoModuleLifecycle1001087929/001"
	path := makeSocketPath(longDir, "echo", 1)

	assert.LessOrEqualf(t, len(path), unixSocketPathMax,
		"fallback path %q (%d bytes) must fit Unix sun_path limit", path, len(path))
	assert.Truef(t, strings.HasPrefix(path, "/tmp/cfgms-"),
		"fallback path %q must live under /tmp", path)
	assert.Truef(t, strings.HasSuffix(path, ".sock"),
		"fallback path %q must end with .sock", path)
}

// TestMakeSocketPathFallbackIsUnique verifies that distinct natural paths
// produce distinct fallback paths (so two concurrent modules do not collide).
func TestMakeSocketPathFallbackIsUnique(t *testing.T) {
	longDir := "/var/folders/8d/778wjbv96mq1760tv6gk374m0000gn/T/long-runtime-dir-with-extra-padding"
	p1 := makeSocketPath(longDir, "echo", 1)
	p2 := makeSocketPath(longDir, "echo", 2)
	p3 := makeSocketPath(longDir, "other", 1)

	assert.NotEqual(t, p1, p2, "different ids must produce different fallback paths")
	assert.NotEqual(t, p1, p3, "different module names must produce different fallback paths")
}

// TestMakeSocketPathBoundary verifies behavior right at the path-length
// threshold: paths of exactly unixSocketPathMax bytes are kept as-is, paths
// one byte over fall back to /tmp.
func TestMakeSocketPathBoundary(t *testing.T) {
	// Build a runtime dir such that the natural path is exactly the max length.
	// natural = "/x/<padding>/cfgms-module-echo-1.sock"
	// 24 chars for "cfgms-module-echo-1.sock" + 1 separator + N for runtimeDir.
	const socketName = "cfgms-module-echo-1.sock"
	roomForDir := unixSocketPathMax - len(socketName) - 1 // 1 for the joining /
	dirAtMax := "/" + strings.Repeat("a", roomForDir-1)   // leading / counts
	pathAtMax := makeSocketPath(dirAtMax, "echo", 1)
	assert.Equal(t, unixSocketPathMax, len(pathAtMax),
		"natural path at exactly the limit must be kept as-is")

	dirOverMax := dirAtMax + "a"
	pathOver := makeSocketPath(dirOverMax, "echo", 1)
	assert.LessOrEqual(t, len(pathOver), unixSocketPathMax)
	assert.Truef(t, strings.HasPrefix(pathOver, "/tmp/cfgms-"),
		"path one byte over the limit must fall back to /tmp, got %q", pathOver)
}

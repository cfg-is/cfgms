// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shortBaseDir creates a temp dir under /tmp with a predictably short path
// (~28 chars on all platforms) so tests that need an exact runtimeDir length
// can always reach their target without conditional skipping.
// /tmp on macOS is a symlink to /private/tmp but Go's os.MkdirTemp resolves
// to the /tmp/* path, keeping the returned string short.
func shortBaseDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "cfgms-sock-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

// buildLongDir returns a runtimeDir padded to exactly targetLen characters.
// Uses shortBaseDir to guarantee a short-enough base on every platform.
func buildLongDir(t *testing.T, targetLen int) string {
	t.Helper()
	base := shortBaseDir(t)
	if len(base) >= targetLen {
		t.Fatalf("short base dir %q (%d bytes) is already >= target %d — increase targetLen or use a shorter prefix",
			base, len(base), targetLen)
	}
	paddingLen := targetLen - len(base) - 1 // -1 for the filepath separator
	return filepath.Join(base, strings.Repeat("a", paddingLen))
}

// TestMakeSocketPathShortRuntimeDirUsesNaturalPath verifies that when the
// natural path fits the sun_path limit, it is used unchanged (under the
// private sockets subdir).
func TestMakeSocketPathShortRuntimeDirUsesNaturalPath(t *testing.T) {
	dir := t.TempDir()
	path, err := makeSocketPath(dir, "echo", 1)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "sockets", "cfgms-module-echo-1.sock"), path)
}

// TestMakeSocketPathHashFallback verifies that when the natural path would
// exceed the macOS sun_path limit (104 bytes), makeSocketPath falls back to a
// hashed short path inside the private sockets directory — never under an
// independent /tmp path. runtimeDir of exactly 71 chars is chosen because it
// is the minimum that triggers the fallback (natural = 71+33 = 104 > 103)
// while the hash path still fits (hash = 71+32 = 103 ≤ 103).
func TestMakeSocketPathHashFallback(t *testing.T) {
	longDir := buildLongDir(t, 71)

	path, err := makeSocketPath(longDir, "echo", 1)
	require.NoError(t, err)

	sockDir := filepath.Join(longDir, "sockets")
	assert.LessOrEqualf(t, len(path), unixSocketPathMax,
		"fallback path %q (%d bytes) must fit Unix sun_path limit", path, len(path))
	assert.Truef(t, strings.HasPrefix(path, sockDir),
		"fallback path %q must live under private socket dir %q", path, sockDir)
	assert.Truef(t, strings.HasSuffix(path, ".sock"),
		"fallback path %q must end with .sock", path)
}

// TestMakeSocketPathFallbackIsUnique verifies that distinct natural paths
// produce distinct fallback paths (so two concurrent modules do not collide).
func TestMakeSocketPathFallbackIsUnique(t *testing.T) {
	longDir := buildLongDir(t, 71)

	p1, err := makeSocketPath(longDir, "echo", 1)
	require.NoError(t, err)
	p2, err := makeSocketPath(longDir, "echo", 2)
	require.NoError(t, err)
	p3, err := makeSocketPath(longDir, "other", 1)
	require.NoError(t, err)

	assert.NotEqual(t, p1, p2, "different ids must produce different fallback paths")
	assert.NotEqual(t, p1, p3, "different module names must produce different fallback paths")
}

// TestMakeSocketPathBoundary verifies behaviour right at the path-length
// threshold: a path of exactly unixSocketPathMax bytes is kept as-is; one byte
// over triggers the hashed fallback (which stays in the private socket dir).
//
// Path layout:  runtimeDir + "/sockets/" + socketName
// Lengths:      runtimeDir(70) + 9 + 24 = 103 (exact fit)
//
//	runtimeDir(71) + 9 + 24 = 104 (one over, fallback triggers)
//	runtimeDir(71) + 9 + 23 = 103 (hash, still fits)
func TestMakeSocketPathBoundary(t *testing.T) {
	// For the natural path to be exactly unixSocketPathMax (103):
	//   len(runtimeDir) + 1 + len("sockets") + 1 + len(socketName) = 103
	//   len(runtimeDir) + 9 + 24 = 103  →  len(runtimeDir) = 70
	const socketName = "cfgms-module-echo-1.sock"
	const runtimeDirMaxLen = unixSocketPathMax - len(socketName) - 1 - len("sockets") - 1 // 70

	// Build runtimeDir at exactly runtimeDirMaxLen using a short base so no
	// platform-conditional skip is needed.
	dirAtMax := buildLongDir(t, runtimeDirMaxLen)

	pathAtMax, err := makeSocketPath(dirAtMax, "echo", 1)
	require.NoError(t, err)
	assert.Equal(t, unixSocketPathMax, len(pathAtMax),
		"natural path at exactly the limit must be kept as-is")

	// One byte longer runtimeDir pushes natural path 1 byte over the limit.
	dirOverMax := dirAtMax + "a"
	pathOver, err := makeSocketPath(dirOverMax, "echo", 1)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(pathOver), unixSocketPathMax)
	sockDirOver := filepath.Join(dirOverMax, "sockets")
	assert.Truef(t, strings.HasPrefix(pathOver, sockDirOver),
		"path one byte over limit must be in private socket dir, got %q", pathOver)
}

// TestMakeSocketPath_ParentDirIsOwnerOnly asserts that makeSocketPath creates
// a sockets directory with mode 0700, owned by the current process uid.
func TestMakeSocketPath_ParentDirIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	_, err := makeSocketPath(dir, "echo", 1)
	require.NoError(t, err)

	sockDir := filepath.Join(dir, "sockets")
	info, statErr := os.Stat(sockDir)
	require.NoError(t, statErr)

	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"socket dir must be mode 0700")

	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "expected *syscall.Stat_t from os.Stat on Unix")
	assert.Equal(t, uint32(os.Getuid()), stat.Uid,
		"socket dir must be owned by the current uid")
}

// TestMakeSocketPath_ParentDirModeReasserted verifies that if the socket dir
// already exists with looser permissions (0o755), makeSocketPath re-asserts
// mode 0700 on every call.
func TestMakeSocketPath_ParentDirModeReasserted(t *testing.T) {
	dir := t.TempDir()
	sockDir := filepath.Join(dir, "sockets")
	require.NoError(t, os.MkdirAll(sockDir, 0o755)) // pre-create with loose mode

	_, err := makeSocketPath(dir, "echo", 1)
	require.NoError(t, err)

	info, statErr := os.Stat(sockDir)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"makeSocketPath must tighten a pre-existing looser socket dir to 0700")
}

// TestMakeSocketPath_NoTmpFallback asserts that when the natural path is too
// long, the fallback hashes within the steward-private socket dir — never to an
// independent /tmp path. Uses buildLongDir with a /tmp-based short base so the
// test is not skipped on macOS, which is precisely the platform where the old
// vulnerable /tmp fallback was observed in CI (PR #1897).
func TestMakeSocketPath_NoTmpFallback(t *testing.T) {
	// runtimeDir = 71 chars: natural = 71+33 = 104 > 103 (triggers fallback),
	// hash = 71+32 = 103 ≤ 103 (fits within the private dir).
	longDir := buildLongDir(t, 71)

	path, err := makeSocketPath(longDir, "echo", 1)
	require.NoError(t, err)

	assert.LessOrEqualf(t, len(path), unixSocketPathMax,
		"fallback path must fit Unix sun_path limit")

	// The path must stay within the steward-private socket dir, not jump to an
	// independent /tmp location (the old vulnerable fallback pattern).
	sockDir := filepath.Join(longDir, "sockets")
	assert.Truef(t, strings.HasPrefix(path, sockDir),
		"path must be inside private socket dir %q; got %q (must not be an independent /tmp fallback)",
		sockDir, path)
}

// TestMakeSocketPath_ErrorWhenPathTooLong verifies that makeSocketPath returns
// an error — rather than silently falling back to /tmp — when even the hashed
// filename in sockDir would exceed the sun_path limit. This happens when
// len(runtimeDir) > 71 (hash path = runtimeDir + 32 > 103).
func TestMakeSocketPath_ErrorWhenPathTooLong(t *testing.T) {
	// runtimeDir = 100 chars: hash path = 100+32 = 132 >> 103.
	tooLongDir := buildLongDir(t, 100)

	_, err := makeSocketPath(tooLongDir, "echo", 1)
	require.Error(t, err, "must return error when no valid path fits within sun_path limit")
	assert.Contains(t, err.Error(), "exceeds sun_path limit",
		"error must describe the path length constraint")
}

// TestMakeSocketPath_MkdirAllFailure verifies that makeSocketPath returns a
// descriptive error when the socket directory cannot be created (e.g., because
// a regular file already occupies the path).
func TestMakeSocketPath_MkdirAllFailure(t *testing.T) {
	dir := t.TempDir()
	// Block socket dir creation by placing a regular file at the target path.
	sockDirPath := filepath.Join(dir, "sockets")
	require.NoError(t, os.WriteFile(sockDirPath, []byte("block"), 0o600))

	_, err := makeSocketPath(dir, "echo", 1)
	require.Error(t, err, "must return error when socket dir cannot be created")
	assert.Contains(t, err.Error(), "create module socket dir",
		"error must identify the socket dir creation failure")
}

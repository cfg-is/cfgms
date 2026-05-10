// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package initialization

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundleMarkerPath(t *testing.T) {
	cases := []struct {
		bundlePath string
		wantSuffix string
	}{
		{"/etc/cfgms/admin.bundle.yaml", ".admin-bundle-issued"},
		{"/tmp/test/admin.bundle.yaml", ".admin-bundle-issued"},
	}
	for _, tc := range cases {
		got := bundleMarkerPath(tc.bundlePath)
		assert.Equal(t, filepath.Join(filepath.Dir(tc.bundlePath), tc.wantSuffix), got)
	}
}

func TestIsBundleMarkerPresent_False(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "admin.bundle.yaml")
	assert.False(t, isBundleMarkerPresent(bundlePath))
}

func TestIsBundleMarkerPresent_True(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "admin.bundle.yaml")
	markerPath := bundleMarkerPath(bundlePath)
	require.NoError(t, os.WriteFile(markerPath, []byte("serial=test\n"), 0600))
	assert.True(t, isBundleMarkerPresent(bundlePath))
}

func TestBundleMarker_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "admin.bundle.yaml")

	now := time.Now().UTC().Truncate(time.Second)
	original := &BundleMarker{
		Serial:      "123456789012345678901234567890",
		Fingerprint: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		IssuedAt:    now,
		BundlePath:  bundlePath,
	}

	require.NoError(t, writeBundleMarker(bundlePath, original))
	got, err := readBundleMarker(bundlePath)
	require.NoError(t, err)

	assert.Equal(t, original.Serial, got.Serial)
	assert.Equal(t, original.Fingerprint, got.Fingerprint)
	assert.Equal(t, original.BundlePath, got.BundlePath)
	assert.Equal(t, now, got.IssuedAt)
}

func TestBundleMarker_MalformedLines_Skipped(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "admin.bundle.yaml")
	markerPath := bundleMarkerPath(bundlePath)

	// Lines without '=' are silently skipped
	content := "not-a-key-value-line\nserial=abc123\n=no-key\n"
	require.NoError(t, os.WriteFile(markerPath, []byte(content), 0600))

	got, err := readBundleMarker(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, "abc123", got.Serial)
}

func TestBundleMarker_BadTimestamp_ZeroTime(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "admin.bundle.yaml")
	markerPath := bundleMarkerPath(bundlePath)

	content := "serial=abc\nfingerprint=def\nissued_at=not-a-timestamp\nbundle_path=/tmp/x\n"
	require.NoError(t, os.WriteFile(markerPath, []byte(content), 0600))

	got, err := readBundleMarker(bundlePath)
	require.NoError(t, err)
	assert.True(t, got.IssuedAt.IsZero(), "unparseable timestamp must result in zero time")
}

func TestBundleMarker_MissingFile_Error(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "admin.bundle.yaml")
	_, err := readBundleMarker(bundlePath)
	assert.Error(t, err)
}

func TestWriteBundleMarker_FileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits not enforced on Windows")
	}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "admin.bundle.yaml")
	marker := &BundleMarker{
		Serial:      "test",
		Fingerprint: "fp",
		IssuedAt:    time.Now().UTC(),
		BundlePath:  bundlePath,
	}
	require.NoError(t, writeBundleMarker(bundlePath, marker))

	info, err := os.Stat(bundleMarkerPath(bundlePath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "bundle marker must be mode 0600")
}

func TestDefaultAdminBundlePath(t *testing.T) {
	got := defaultAdminBundlePath()
	assert.NotEmpty(t, got)
	if runtime.GOOS == "windows" {
		assert.Contains(t, got, "cfgms")
		assert.Contains(t, got, "admin.bundle.yaml")
	} else {
		assert.Equal(t, "/etc/cfgms/admin.bundle.yaml", got)
	}
}

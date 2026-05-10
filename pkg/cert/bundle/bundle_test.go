// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package bundle

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundle_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.bundle.yaml")

	original := &Bundle{
		CertPEM:         "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----\n",
		KeyPEM:          "-----BEGIN RSA PRIVATE KEY-----\nkeydata\n-----END RSA PRIVATE KEY-----\n",
		CAPEM:           "-----BEGIN CERTIFICATE-----\ncadata\n-----END CERTIFICATE-----\n",
		ControllerURL:   "https://controller.example.com:9080",
		AuditSubject:    "admin:cfgms-admin",
		CertSerial:      "12345678901234567890",
		CertFingerprint: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	}

	require.NoError(t, Write(path, original))

	got, err := Read(path)
	require.NoError(t, err)

	assert.Equal(t, original.CertPEM, got.CertPEM)
	assert.Equal(t, original.KeyPEM, got.KeyPEM)
	assert.Equal(t, original.CAPEM, got.CAPEM)
	assert.Equal(t, original.ControllerURL, got.ControllerURL)
	assert.Equal(t, original.AuditSubject, got.AuditSubject)
	assert.Equal(t, original.CertSerial, got.CertSerial)
	assert.Equal(t, original.CertFingerprint, got.CertFingerprint)
}

func TestBundle_FileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits not enforced on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "admin.bundle.yaml")

	require.NoError(t, Write(path, &Bundle{AuditSubject: "admin:cfgms-admin"}))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "bundle file must be mode 0600")
}

func TestBundle_Write_CreatesParentDirectory(t *testing.T) {
	// Verify Write creates intermediate directories that do not yet exist.
	// This is the regression test for the CI failure where /etc/cfgms/ was absent.
	path := filepath.Join(t.TempDir(), "nested", "subdir", "admin.bundle.yaml")

	require.NoError(t, Write(path, &Bundle{AuditSubject: "admin:cfgms-admin"}))

	_, err := os.Stat(path)
	require.NoError(t, err, "bundle file must exist after Write to nested path")
}

func TestBundle_Write_InvalidDirectory_Error(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.MkdirAll path-as-file behavior differs on Windows")
	}
	// Create a regular file and then try to use it as a directory component.
	// MkdirAll fails with ENOTDIR, which Write must surface.
	dir := t.TempDir()
	blockingFile := filepath.Join(dir, "notadir")
	require.NoError(t, os.WriteFile(blockingFile, []byte("x"), 0600))

	path := filepath.Join(blockingFile, "admin.bundle.yaml")
	err := Write(path, &Bundle{AuditSubject: "admin:cfgms-admin"})
	assert.Error(t, err, "Write must return error when parent directory cannot be created")
}

func TestBundle_Read_MissingFile(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	assert.Error(t, err)
}

func TestBundle_Read_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("not: valid: yaml: [\n"), 0600))

	_, err := Read(path)
	assert.Error(t, err)
}

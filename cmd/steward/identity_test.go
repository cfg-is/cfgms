// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadIdentity_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	id := StewardIdentity{
		StewardID:        "steward-abc123",
		TenantID:         "tenant-xyz",
		TransportAddress: "controller:4433",
		CACertPEM:        "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----",
		ServerCertPEM:    "-----BEGIN CERTIFICATE-----\nfake-server\n-----END CERTIFICATE-----",
		SigningCertPEM:   "-----BEGIN CERTIFICATE-----\nfake-signing\n-----END CERTIFICATE-----",
	}

	require.NoError(t, saveIdentity(dir, id))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, id.StewardID, got.StewardID)
	assert.Equal(t, id.TenantID, got.TenantID)
	assert.Equal(t, id.TransportAddress, got.TransportAddress)
	assert.Equal(t, id.CACertPEM, got.CACertPEM)
	assert.Equal(t, id.ServerCertPEM, got.ServerCertPEM)
	assert.Equal(t, id.SigningCertPEM, got.SigningCertPEM)
}

// TestSaveAndLoadIdentity_PersistsServerCert proves the controller's server
// certificate survives a save/load cycle. Without it the reconnect path cannot
// verify signed sync_config commands and the steward silently stops applying
// configuration after a restart.
func TestSaveAndLoadIdentity_PersistsServerCert(t *testing.T) {
	dir := t.TempDir()
	id := StewardIdentity{
		StewardID:        "steward-server-cert",
		TransportAddress: "controller:4433",
		ServerCertPEM:    "-----BEGIN CERTIFICATE-----\nserver-only\n-----END CERTIFICATE-----",
	}

	require.NoError(t, saveIdentity(dir, id))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, id.ServerCertPEM, got.ServerCertPEM)
	assert.Empty(t, got.SigningCertPEM, "signing cert is optional and was not set")
}

func TestLoadIdentity_MissingFile_ReturnsNilNoError(t *testing.T) {
	dir := t.TempDir()
	got, err := loadIdentity(dir)
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestLoadIdentity_CorruptJSON_ReturnsNilError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, identityFileName)
	require.NoError(t, os.WriteFile(path, []byte("{not valid json"), 0600))

	got, err := loadIdentity(dir)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "corrupt")
}

func TestLoadIdentity_MissingStewardID_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, identityFileName)
	require.NoError(t, os.WriteFile(path, []byte(`{"tenant_id":"t1","transport_address":"ctrl:4433"}`), 0600))

	got, err := loadIdentity(dir)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "missing required fields")
}

func TestLoadIdentity_MissingTransportAddress_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, identityFileName)
	require.NoError(t, os.WriteFile(path, []byte(`{"steward_id":"s1","tenant_id":"t1"}`), 0600))

	got, err := loadIdentity(dir)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "missing required fields")
}

func TestSaveIdentity_FileMode_IsOwnerReadWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission check not applicable on Windows")
	}
	dir := t.TempDir()
	id := StewardIdentity{
		StewardID:        "steward-abc123",
		TransportAddress: "controller:4433",
	}
	require.NoError(t, saveIdentity(dir, id))

	info, err := os.Stat(filepath.Join(dir, identityFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestSaveIdentity_CreatesDirectoryIfAbsent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "subdir")
	id := StewardIdentity{
		StewardID:        "steward-abc123",
		TransportAddress: "controller:4433",
	}
	require.NoError(t, saveIdentity(dir, id))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "steward-abc123", got.StewardID)
}

func TestSaveIdentity_OverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	first := StewardIdentity{StewardID: "first", TransportAddress: "ctrl:4433"}
	second := StewardIdentity{StewardID: "second", TransportAddress: "ctrl:4433"}

	require.NoError(t, saveIdentity(dir, first))
	require.NoError(t, saveIdentity(dir, second))

	got, err := loadIdentity(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "second", got.StewardID)
}

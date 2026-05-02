// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalCert returns a Certificate suitable for FileStore tests. The PEM
// fields contain placeholder bytes; FileStore stores and returns them verbatim
// without parsing, so real crypto material is not required here.
func minimalCert(serial string, certType CertificateType, expiresAt time.Time) *Certificate {
	now := time.Now()
	return &Certificate{
		Type:           certType,
		CommonName:     "test-" + serial,
		SerialNumber:   serial,
		CreatedAt:      now.Add(-time.Hour),
		ExpiresAt:      expiresAt,
		IsValid:        true, // stored value — must not be trusted on read
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"),
		PrivateKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"),
		Fingerprint:    "AA:BB:CC",
		Issuer:         "Test CA",
		ClientID:       "",
	}
}

// patchMetadataExpiry overwrites the ExpiresAt field inside the on-disk
// metadata.json for the given serial number, simulating a cert that has
// aged past its expiry since it was originally stored.
func patchMetadataExpiry(t *testing.T, basePath, serial string, expiresAt time.Time) {
	t.Helper()
	metaPath := filepath.Join(basePath, serial, "metadata.json")
	// #nosec G304 — test helper reads controlled path
	raw, err := os.ReadFile(metaPath)
	require.NoError(t, err)

	var meta CertificateInfo
	require.NoError(t, json.Unmarshal(raw, &meta))

	meta.ExpiresAt = expiresAt
	// Also keep IsValid as true in the file to confirm the read path overrides it.
	meta.IsValid = true
	meta.DaysUntilExpiration = 999
	meta.NeedsRenewal = false

	updated, err := json.MarshalIndent(meta, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(metaPath, updated, 0600))
}

// --- GetCertificate tests ---

func TestGetCertificate_RecomputesIsValidForExpiredCert(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	serial := "serial-expired-001"
	cert := minimalCert(serial, CertificateTypeServer, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	// Simulate the cert aging past expiry by patching the on-disk metadata.
	expired := time.Now().Add(-24 * time.Hour)
	patchMetadataExpiry(t, dir, serial, expired)

	got, err := store.GetCertificate(serial)
	require.NoError(t, err)

	assert.False(t, got.IsValid, "GetCertificate must recompute IsValid from ExpiresAt; expired cert must return false")
}

func TestGetCertificate_ValidCertRemainsValid(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	serial := "serial-valid-001"
	cert := minimalCert(serial, CertificateTypeServer, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	got, err := store.GetCertificate(serial)
	require.NoError(t, err)

	assert.True(t, got.IsValid, "valid cert must still be reported as valid")
}

func TestGetCertificate_NotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	_, err = store.GetCertificate("does-not-exist")
	assert.Error(t, err)
}

func TestGetCertificate_EmptySerial(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	_, err = store.GetCertificate("")
	assert.Error(t, err)
}

// --- GetCertificatesByType tests ---

func TestGetCertificatesByType_RecomputesIsValidForExpiredCert(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	serial := "serial-type-expired-001"
	cert := minimalCert(serial, CertificateTypeClient, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	expired := time.Now().Add(-24 * time.Hour)
	patchMetadataExpiry(t, dir, serial, expired)

	// Reload so the in-memory cache picks up the patched metadata.
	freshStore, err := NewFileStore(dir)
	require.NoError(t, err)

	results, err := freshStore.GetCertificatesByType(CertificateTypeClient)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].IsValid,
		"GetCertificatesByType must recompute IsValid; expired cert must return false")
	assert.Less(t, results[0].DaysUntilExpiration, 0,
		"DaysUntilExpiration must be negative for expired cert")
	assert.True(t, results[0].NeedsRenewal,
		"NeedsRenewal must be true for expired cert")
}

func TestGetCertificatesByType_ValidCertRemainsValid(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	serial := "serial-type-valid-001"
	cert := minimalCert(serial, CertificateTypeServer, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	results, err := store.GetCertificatesByType(CertificateTypeServer)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.True(t, results[0].IsValid)
	assert.False(t, results[0].NeedsRenewal)
}

// --- loadCertificates / cache tests ---

func TestLoadCertificates_RecomputesDynamicFieldsInCache(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	serial := "serial-cache-001"
	cert := minimalCert(serial, CertificateTypeServer, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	// Patch metadata with stale values before reloading.
	expired := time.Now().Add(-24 * time.Hour)
	patchMetadataExpiry(t, dir, serial, expired)

	// Fresh store loads from disk — cache must reflect recomputed values.
	freshStore, err := NewFileStore(dir)
	require.NoError(t, err)

	results, err := freshStore.ListCertificates()
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].IsValid,
		"cache populated by loadCertificates must reflect recomputed IsValid")
}

// --- GetCertificatesByType DaysUntilExpiration positive case ---

func TestGetCertificatesByType_DaysUntilExpirationPositiveForValidCert(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	serial := "serial-days-positive-001"
	cert := minimalCert(serial, CertificateTypeServer, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	results, err := store.GetCertificatesByType(CertificateTypeServer)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.GreaterOrEqual(t, results[0].DaysUntilExpiration, 364,
		"DaysUntilExpiration must be positive for a cert expiring in 365 days")
}

// --- GetCertificateByCommonName tests ---

func TestGetCertificateByCommonName_RecomputesIsValidForExpiredCert(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	serial := "serial-cn-expired-001"
	cert := minimalCert(serial, CertificateTypeServer, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	expired := time.Now().Add(-24 * time.Hour)
	patchMetadataExpiry(t, dir, serial, expired)

	// Reload so the in-memory cache picks up the patched metadata.
	freshStore, err := NewFileStore(dir)
	require.NoError(t, err)

	results, err := freshStore.GetCertificateByCommonName("test-" + serial)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].IsValid,
		"GetCertificateByCommonName must recompute IsValid; expired cert must return false")
	assert.Less(t, results[0].DaysUntilExpiration, 0,
		"DaysUntilExpiration must be negative for expired cert")
	assert.True(t, results[0].NeedsRenewal,
		"NeedsRenewal must be true for expired cert")
}

func TestGetCertificateByCommonName_ValidCertRemainsValid(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	serial := "serial-cn-valid-001"
	cert := minimalCert(serial, CertificateTypeServer, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	results, err := store.GetCertificateByCommonName("test-" + serial)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.True(t, results[0].IsValid)
	assert.False(t, results[0].NeedsRenewal)
	assert.GreaterOrEqual(t, results[0].DaysUntilExpiration, 364)
}

func TestGetCertificateByCommonName_EmptyCommonName(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	_, err = store.GetCertificateByCommonName("")
	assert.Error(t, err)
}

// --- NewFileStore error path ---

func TestNewFileStore_EmptyBasePath(t *testing.T) {
	_, err := NewFileStore("")
	assert.Error(t, err)
}

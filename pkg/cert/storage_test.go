// SPDX-License-Identifier: AGPL-3.0-only
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
	cert := minimalCert(serial, CertificateTypePublicAPI, time.Now().Add(365*24*time.Hour))
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
	cert := minimalCert(serial, CertificateTypePublicAPI, time.Now().Add(365*24*time.Hour))
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

	results, err := freshStore.getCertificatesByType(CertificateTypeClient)
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
	cert := minimalCert(serial, CertificateTypePublicAPI, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	results, err := store.getCertificatesByType(CertificateTypePublicAPI)
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
	cert := minimalCert(serial, CertificateTypePublicAPI, time.Now().Add(365*24*time.Hour))
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
	cert := minimalCert(serial, CertificateTypePublicAPI, time.Now().Add(365*24*time.Hour))
	require.NoError(t, store.StoreCertificate(cert))

	results, err := store.getCertificatesByType(CertificateTypePublicAPI)
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
	cert := minimalCert(serial, CertificateTypePublicAPI, time.Now().Add(365*24*time.Hour))
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
	cert := minimalCert(serial, CertificateTypePublicAPI, time.Now().Add(365*24*time.Hour))
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

// --- Path traversal / serial validation tests (Issue #4348) ---

// TestGetCertificate_RejectsPathTraversalSerial verifies that GetCertificate
// refuses a serial number containing path traversal sequences before it is
// ever joined into a filesystem path, and does not read a file outside the
// certificate store root.
func TestGetCertificate_RejectsPathTraversalSerial(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	// Plant a secret file outside the store root that a successful traversal
	// would read.
	outsideDir := t.TempDir()
	secretPath := filepath.Join(outsideDir, "secret.pem")
	require.NoError(t, os.WriteFile(secretPath, []byte("top-secret-key-material"), 0600))

	for _, malicious := range []string{
		"../" + filepath.Base(outsideDir) + "/secret",
		"..%2f..%2fetc%2fpasswd",
		"../../etc/passwd",
		"foo/../../bar",
		"a/b",
	} {
		_, err := store.GetCertificate(malicious)
		assert.Error(t, err, "GetCertificate must reject traversal serial %q", malicious)
	}
}

// TestDeleteCertificate_RejectsPathTraversalSerial verifies that
// DeleteCertificate refuses a serial number containing path traversal
// sequences, so it can never be used to remove a directory outside the
// certificate store root.
func TestDeleteCertificate_RejectsPathTraversalSerial(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	// A directory outside the store root that a successful traversal delete
	// would remove.
	outsideDir := t.TempDir()
	canary := filepath.Join(outsideDir, "canary.txt")
	require.NoError(t, os.WriteFile(canary, []byte("must survive"), 0600))

	for _, malicious := range []string{
		"../" + filepath.Base(outsideDir),
		"../../etc",
		"foo/../../bar",
	} {
		err := store.DeleteCertificate(malicious)
		assert.Error(t, err, "DeleteCertificate must reject traversal serial %q", malicious)
	}

	_, statErr := os.Stat(canary)
	assert.NoError(t, statErr, "file outside the store root must survive a rejected DeleteCertificate")
}

// TestGetCertificate_RejectsSymlinkEscape verifies that GetCertificate
// refuses to follow a symlink planted inside the store root that points
// outside of it — filepath.Clean alone would not catch this, since the
// symlink target is only known after resolving it on disk.
func TestGetCertificate_RejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	outsideDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "cert.pem"), []byte("outside-cert"), 0600))

	// A serial number that passes format validation but resolves (via a
	// symlink planted directly inside the store root) to a directory outside
	// the store root.
	linkName := "esc0001"
	require.NoError(t, os.Symlink(outsideDir, filepath.Join(dir, linkName)))

	_, err = store.GetCertificate(linkName)
	assert.Error(t, err, "GetCertificate must reject a serial resolving via symlink outside the store root")
}

// TestStoreCertificate_RejectsInvalidSerial is a regression test
// (security-review finding, Issue #4348): StoreCertificate must validate the
// serial through the same resolveCertDir path as GetCertificate/
// DeleteCertificate. Before this, a serial StoreCertificate accepted (e.g. a
// leading '-', which (*x509.Certificate).SerialNumber.String() can produce
// for a DER-encoded serial with its high bit set) could be written
// successfully and then never be readable or deletable again, since
// serialNumberPattern rejects a leading hyphen.
func TestStoreCertificate_RejectsInvalidSerial(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	cert := minimalCert("-123", CertificateTypePublicAPI, time.Now().Add(365*24*time.Hour))
	err = store.StoreCertificate(cert)
	assert.Error(t, err, "StoreCertificate must reject a serial number that GetCertificate/DeleteCertificate could never resolve")

	// Nothing must have been written to disk.
	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "a rejected StoreCertificate must not leave a partial directory on disk")
}

// --- NewFileStore error path ---

func TestNewFileStore_EmptyBasePath(t *testing.T) {
	_, err := NewFileStore("")
	assert.Error(t, err)
}

func TestFileStore_RemoveSigningKeyFile(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	require.NoError(t, err)
	ca := newTestCAForSigning(t)
	c, err := ca.GenerateSigningCertificate(&SigningCertConfig{KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, fs.StoreCertificate(c))

	require.NoError(t, fs.RemoveSigningKeyFile(c.SerialNumber))
	_, statErr := os.Stat(filepath.Join(dir, c.SerialNumber, "key.pem"))
	assert.True(t, os.IsNotExist(statErr))
	got, err := fs.GetCertificate(c.SerialNumber)
	require.NoError(t, err)
	assert.Empty(t, got.PrivateKeyPEM)
	assert.Equal(t, c.CertificatePEM, got.CertificatePEM)

	assert.NoError(t, fs.RemoveSigningKeyFile(c.SerialNumber), "removing an absent key is not an error")
	assert.Error(t, fs.RemoveSigningKeyFile("../escape"))
	assert.Error(t, fs.RemoveSigningKeyFile(""))
}

// TestFileStore_RejectsLinkedSerialDirectory verifies a serial directory that is
// a symlink to another certificate's directory inside the base is refused by
// every operation and leaves the target's files intact.
func TestFileStore_RejectsLinkedSerialDirectory(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	exp := time.Now().Add(365 * 24 * time.Hour)
	require.NoError(t, store.StoreCertificate(minimalCert("serial-b", CertificateTypeInternalServer, exp)))
	require.NoError(t, os.Symlink(filepath.Join(dir, "serial-b"), filepath.Join(dir, "serial-a")))

	assert.Error(t, store.StoreCertificate(minimalCert("serial-a", CertificateTypeInternalServer, exp)))
	_, err = store.GetCertificate("serial-a")
	assert.Error(t, err)
	assert.Error(t, store.DeleteCertificate("serial-a"))

	b, err := store.GetCertificate("serial-b")
	require.NoError(t, err)
	assert.Equal(t, "serial-b", b.SerialNumber)
	assert.Contains(t, string(b.CertificatePEM), "BEGIN CERTIFICATE")
	assert.Equal(t, "test-serial-b", b.CommonName)

	// Reloading skips the linked directory instead of reading through it.
	reloaded, err := NewFileStore(dir)
	require.NoError(t, err)
	_, ok := reloaded.certs["serial-a"]
	assert.False(t, ok)
}

// TestStoreCertificate_RefusesLinkedLeafFiles verifies a link planted at any
// per-certificate file is refused and its in-base target is never written.
func TestStoreCertificate_RefusesLinkedLeafFiles(t *testing.T) {
	exp := time.Now().Add(365 * 24 * time.Hour)
	for _, name := range []string{"key.pem", "cert.pem", "chain.pem", "metadata.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := NewFileStore(dir)
			require.NoError(t, err)
			certDir := filepath.Join(dir, "serial-c")
			require.NoError(t, os.MkdirAll(certDir, 0750))
			sentinel := filepath.Join(dir, "sentinel.txt")
			require.NoError(t, os.WriteFile(sentinel, []byte("sentinel"), 0600))
			require.NoError(t, os.Symlink(sentinel, filepath.Join(certDir, name)))

			c := minimalCert("serial-c", CertificateTypeInternalServer, exp)
			c.IssuerChainPEM = []byte("chain")
			assert.Error(t, store.StoreCertificate(c))

			got, err := os.ReadFile(sentinel)
			require.NoError(t, err)
			assert.Equal(t, "sentinel", string(got))
		})
	}
}

// TestGetCertificate_RefusesLinkedLeafFiles verifies a cert.pem or metadata.json
// symlink makes GetCertificate fail, and a normal round trip still works.
func TestGetCertificate_RefusesLinkedLeafFiles(t *testing.T) {
	exp := time.Now().Add(365 * 24 * time.Hour)
	for _, name := range []string{"cert.pem", "metadata.json", "key.pem"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := NewFileStore(dir)
			require.NoError(t, err)
			require.NoError(t, store.StoreCertificate(minimalCert("serial-d", CertificateTypeInternalServer, exp)))

			leaf := filepath.Join(dir, "serial-d", name)
			copyPath := filepath.Join(dir, "copy-of-"+name)
			require.NoError(t, os.Rename(leaf, copyPath))
			require.NoError(t, os.Symlink(copyPath, leaf))

			_, err = store.GetCertificate("serial-d")
			assert.Error(t, err)
		})
	}
}

func TestFileStore_RoundTripStillWorks(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)
	c := minimalCert("serial-e", CertificateTypeInternalServer, time.Now().Add(time.Hour*24*365))
	c.IssuerChainPEM = []byte("chain")
	require.NoError(t, store.StoreCertificate(c))
	require.NoError(t, store.StoreCertificate(c), "overwrite of regular files is allowed")
	got, err := store.GetCertificate("serial-e")
	require.NoError(t, err)
	assert.Equal(t, c.PrivateKeyPEM, got.PrivateKeyPEM)
	assert.Equal(t, c.IssuerChainPEM, got.IssuerChainPEM)
	require.NoError(t, store.DeleteCertificate("serial-e"))
	_, err = store.GetCertificate("serial-e")
	assert.Error(t, err)
}

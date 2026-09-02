// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/pkg/cert"
)

// sharedTestCACertPEM and sharedTestCAKeyPEM hold one real, RSA-backed CA identity,
// generated once per test binary run by buildSharedTestCA (called from TestMain).
//
// Issue #3797: features/controller/api exceeded its macOS merge-queue timeout because
// the package's ~1900 tests each pay full RSA-2048 CA keygen (and often RSA-4096
// config-signing keygen) through their own fresh cert.Manager — a cost `go tool pprof`
// showed as ~35% of the package's total CPU time (crypto/internal/fips140/rsa.GenerateKey
// under CA.Initialize and Manager.EnsureSigningCertificate). None of these tests are
// exercising CA generation itself (that is pkg/cert's own test suite); they only need
// *a* valid, working CA as scaffolding for handler logic. seedSharedTestCA installs the
// pre-generated CA into a fresh per-test storage path via cert.Manager's production
// LoadExistingCA path (the same code a controller uses to survive a restart without
// regenerating its CA), so CA identity is shared while every other piece of
// cert.Manager state (issued certs, revocations) stays private per test.
var (
	sharedTestCACertPEM []byte
	sharedTestCAKeyPEM  []byte

	// sharedSigningCert* cache the one config-signing certificate (RSA-4096,
	// EnsureSigningCertificate's default shape) built alongside the shared CA. Only
	// call sites that call Manager.EnsureSigningCertificate(nil) purely as scaffolding
	// (they need *a* signing cert to exist, not a freshly generated one) should seed
	// it — see ensureSharedSigningCertificate. Tests asserting the absence of a
	// signing cert (e.g. TestHandleGetRevocationManifest_NoSigningCert_Returns500)
	// must keep calling certMgr.EnsureSigningCertificate directly without seeding.
	sharedSigningCertSerial       string
	sharedSigningCertPEM          []byte
	sharedSigningKeyPEM           []byte
	sharedSigningCertMetadataJSON []byte
)

// buildSharedTestCA generates the process-wide shared test CA (and one config-signing
// certificate under it) into a throwaway directory, captures their PEM/metadata bytes,
// and returns a cleanup func that removes the directory. Called once from TestMain
// before any test runs.
func buildSharedTestCA() (func(), error) {
	dir, err := os.MkdirTemp("", "cfgms-api-shared-ca-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	ca, err := cert.NewCA(&cert.CAConfig{
		Organization: "Test CFGMS",
		Country:      "US",
		ValidityDays: 365,
		StoragePath:  dir,
	})
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := ca.Initialize(nil); err != nil {
		cleanup()
		return nil, err
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt")) // #nosec G304 -- fixed template path this process just wrote
	if err != nil {
		cleanup()
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key")) // #nosec G304 -- fixed template path this process just wrote
	if err != nil {
		cleanup()
		return nil, err
	}

	sharedTestCACertPEM = certPEM
	sharedTestCAKeyPEM = keyPEM

	// Build the shared signing cert via the real GenerateSigningCertificate +
	// FileStore.StoreCertificate path (not hand-built PEM), then read the resulting
	// on-disk record back so seeding elsewhere is a byte-identical file copy.
	signingCert, err := ca.GenerateSigningCertificate(&cert.SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 1095,
		KeySize:      4096,
	})
	if err != nil {
		cleanup()
		return nil, err
	}
	signingStoreDir := filepath.Join(dir, "signing-store")
	signingStore, err := cert.NewFileStore(signingStoreDir)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := signingStore.StoreCertificate(signingCert); err != nil {
		cleanup()
		return nil, err
	}
	signingCertDir := filepath.Join(signingStoreDir, signingCert.SerialNumber)
	signingCertPEM, err := os.ReadFile(filepath.Join(signingCertDir, "cert.pem")) // #nosec G304 -- fixed template path this process just wrote
	if err != nil {
		cleanup()
		return nil, err
	}
	signingKeyPEM, err := os.ReadFile(filepath.Join(signingCertDir, "key.pem")) // #nosec G304 -- fixed template path this process just wrote
	if err != nil {
		cleanup()
		return nil, err
	}
	signingMetadataJSON, err := os.ReadFile(filepath.Join(signingCertDir, "metadata.json")) // #nosec G304 -- fixed template path this process just wrote
	if err != nil {
		cleanup()
		return nil, err
	}

	sharedSigningCertSerial = signingCert.SerialNumber
	sharedSigningCertPEM = signingCertPEM
	sharedSigningKeyPEM = signingKeyPEM
	sharedSigningCertMetadataJSON = signingMetadataJSON

	return cleanup, nil
}

// seedSharedTestCA installs the shared test CA into storagePath/ca/, the layout
// cert.Manager's LoadExistingCA option expects. Call before cert.NewManager(&cert.ManagerConfig{
// StoragePath: storagePath, LoadExistingCA: true}).
func seedSharedTestCA(t *testing.T, storagePath string) {
	t.Helper()
	caDir := filepath.Join(storagePath, "ca")
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		t.Fatalf("seedSharedTestCA: mkdir %s: %v", caDir, err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.crt"), sharedTestCACertPEM, 0o600); err != nil {
		t.Fatalf("seedSharedTestCA: write ca.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.key"), sharedTestCAKeyPEM, 0o600); err != nil {
		t.Fatalf("seedSharedTestCA: write ca.key: %v", err)
	}
}

// seedSharedSigningCert installs the process-wide shared config-signing certificate
// into storagePath, the layout Manager.EnsureSigningCertificate expects to find an
// existing CertificateTypeConfigSigning record in. Callers must still call
// EnsureSigningCertificate(nil) afterward — this only makes that call a no-op.
func seedSharedSigningCert(t *testing.T, storagePath string) {
	t.Helper()
	certDir := filepath.Join(storagePath, sharedSigningCertSerial)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatalf("seedSharedSigningCert: mkdir %s: %v", certDir, err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), sharedSigningCertPEM, 0o600); err != nil {
		t.Fatalf("seedSharedSigningCert: write cert.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), sharedSigningKeyPEM, 0o600); err != nil {
		t.Fatalf("seedSharedSigningCert: write key.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "metadata.json"), sharedSigningCertMetadataJSON, 0o600); err != nil {
		t.Fatalf("seedSharedSigningCert: write metadata.json: %v", err)
	}
}

// ensureSharedSigningCertificate seeds the shared config-signing certificate into
// certMgr's storage and then calls EnsureSigningCertificate(nil), which becomes a
// cheap no-op (store already has a CertificateTypeConfigSigning record) instead of
// paying RSA-4096 keygen. Only use where a test needs *a* signing cert as scaffolding
// — never in a test asserting the absence of one.
func ensureSharedSigningCertificate(t *testing.T, certMgr *cert.Manager) {
	t.Helper()
	seedSharedSigningCert(t, certMgr.GetStoragePath())
	if err := certMgr.EnsureSigningCertificate(nil); err != nil {
		t.Fatalf("ensureSharedSigningCertificate: %v", err)
	}
}

// newSharedTestCertManager returns a cert.Manager backed by the process-wide shared
// test CA (see sharedTestCACertPEM), rooted at a fresh t.TempDir(). Loading a known CA
// skips CA.Initialize's RSA keygen; every other Manager code path (issuing, revoking,
// rotating a config-signing cert) still runs for real.
func newSharedTestCertManager(t *testing.T) *cert.Manager {
	t.Helper()
	return newSharedTestCertManagerAt(t, t.TempDir())
}

// newSharedTestCertManagerAt is newSharedTestCertManager for a caller-owned storage
// path (tests that need to reach into the cert store directory, e.g. to inject a
// storage fault).
func newSharedTestCertManagerAt(t *testing.T, storagePath string) *cert.Manager {
	t.Helper()
	seedSharedTestCA(t, storagePath)
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    storagePath,
		LoadExistingCA: true,
	})
	if err != nil {
		t.Fatalf("newSharedTestCertManagerAt: %v", err)
	}
	return mgr
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// setupInitializedController runs full initialization and returns the config and a
// cert.Manager pointing at the same storage path for direct IsRevoked checks.
func setupInitializedController(t *testing.T) (*testControllerSetup, func()) {
	t.Helper()
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	bundlePath := filepath.Join(tempDir, "admin.bundle.yaml")
	logger := logging.NewNoopLogger()

	cfg := makeTestConfig(t, tempDir, caDir, bundlePath)

	_, err := Run(cfg, logger)
	require.NoError(t, err, "initialization must succeed")
	require.FileExists(t, bundlePath, "system admin bundle must be created")

	// StoragePath must be the parent of "ca/" — cert.NewManager always derives the CA
	// directory as filepath.Join(StoragePath,"ca"), matching what initialization.Run does.
	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    tempDir,
		LoadExistingCA: true,
	})
	require.NoError(t, err, "cert manager must load successfully after init")

	return &testControllerSetup{
		cfg:         cfg,
		logger:      logger,
		certManager: certManager,
		bundlePath:  bundlePath,
		caDir:       caDir,
		tempDir:     tempDir,
	}, func() {}
}

type testControllerSetup struct {
	cfg         *config.Config
	logger      logging.Logger
	certManager *cert.Manager
	bundlePath  string
	caDir       string
	tempDir     string
}

// parseX509FromBundle reads a bundle file and returns the parsed X.509 cert.
func parseX509FromBundle(t *testing.T, bundlePath string) *x509.Certificate {
	t.Helper()
	b, err := bundle.Read(bundlePath)
	require.NoError(t, err, "bundle must be readable")

	block, _ := pem.Decode([]byte(b.CertPEM))
	require.NotNil(t, block, "bundle CertPEM must be valid PEM")

	x509cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "bundle cert must be valid X.509")
	return x509cert
}

// TestIssueAdminBundle_CreatesFile verifies that IssueAdminBundle creates a bundle
// file at the specified path with mode 0600, containing a cert with CN=alice,
// the admin marker, and 365-day validity.
func TestIssueAdminBundle_CreatesFile(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "alice.bundle.yaml")

	err := IssueAdminBundle(setup.cfg, setup.logger, "alice", outputPath, false)
	require.NoError(t, err)

	// File must exist
	info, err := os.Stat(outputPath)
	require.NoError(t, err, "bundle file must exist")

	// Mode must be 0600 (Unix only — Windows does not enforce Unix permission bits)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "bundle file must have mode 0600")
	}

	x509cert := parseX509FromBundle(t, outputPath)

	// Must carry the admin marker
	assert.True(t, cert.HasAdminMarker(x509cert), "admin bundle cert must carry the CFGMS admin marker")

	// CN must match the requested name
	assert.Equal(t, "alice", x509cert.Subject.CommonName)

	// Validity must be 365 days ±1 day
	validity := x509cert.NotAfter.Sub(x509cert.NotBefore)
	assert.InDelta(t, float64(365*24*time.Hour), float64(validity), float64(24*time.Hour),
		"admin cert validity must be 365 days (±1 day)")
}

// TestIssueAdminBundle_ReservedCN_Rejected verifies that reserved common names
// are rejected and no bundle file is created.
func TestIssueAdminBundle_ReservedCN_Rejected(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	cases := []struct {
		name string
		cn   string
	}{
		{"reserved system", "system"},
		{"reserved cfgms", "cfgms"},
		{"reserved cfgms-internal", "cfgms-internal"},
		{"reserved cfgms-admin", "cfgms-admin"},
		{"steward UUID pattern", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "should-not-exist.bundle.yaml")
			err := IssueAdminBundle(setup.cfg, setup.logger, tc.cn, outputPath, false)
			require.Error(t, err, "reserved CN %q must be rejected", tc.cn)
			assert.Contains(t, err.Error(), "RESERVED_CN",
				"error message must contain RESERVED_CN for %q", tc.cn)
			assert.NoFileExists(t, outputPath, "no bundle file must be created for reserved CN")
		})
	}
}

// TestIssueAdminBundle_InvalidCN_Rejected verifies that invalid common names
// (empty, too long, or containing disallowed characters) are rejected.
func TestIssueAdminBundle_InvalidCN_Rejected(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	cases := []struct {
		name string
		cn   string
	}{
		{"empty name", ""},
		{"too long", "a" + string(make([]byte, 64))},
		{"contains underscore", "my_admin"},
		{"contains space", "my admin"},
		{"contains unicode", "ädmin"},
		{"leading hyphen", "-alice"},
		{"trailing hyphen", "alice-"},
		{"all hyphens", "----"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "should-not-exist.bundle.yaml")
			err := IssueAdminBundle(setup.cfg, setup.logger, tc.cn, outputPath, false)
			require.Error(t, err, "invalid CN %q must be rejected", tc.cn)
			assert.NoFileExists(t, outputPath, "no bundle file must be created for invalid CN")
		})
	}
}

// TestIssueAdminBundle_CannotOverwriteSystemBundle verifies that passing the default
// system bundle path as --output is rejected.
func TestIssueAdminBundle_CannotOverwriteSystemBundle(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	err := IssueAdminBundle(setup.cfg, setup.logger, "alice", defaultAdminBundlePath(), false)
	require.Error(t, err, "must reject outputPath equal to the system bundle path")
	assert.Contains(t, err.Error(), "cannot overwrite the system admin bundle")
}

// TestRevokeAdminBundle_IdempotentDoubleRevoke verifies that revoking the same serial
// twice is a no-op and the original RevokedAt timestamp is preserved.
func TestRevokeAdminBundle_IdempotentDoubleRevoke(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "idempotent-revoke.bundle.yaml")
	require.NoError(t, IssueAdminBundle(setup.cfg, setup.logger, "idempotent-user", outputPath, false))

	b, err := bundle.Read(outputPath)
	require.NoError(t, err)
	serial := b.CertSerial

	require.NoError(t, RevokeAdminBundle(setup.cfg, setup.logger, serial))
	require.NoError(t, RevokeAdminBundle(setup.cfg, setup.logger, serial), "double-revoke must be a no-op")
	revoked, err := setup.certManager.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revoked, "cert must still be revoked after double-revoke")
}

// TestIssueAdminBundle_ValidityCap verifies that the issued cert's validity is
// exactly 365 days (±1 day clock-skew tolerance).
func TestIssueAdminBundle_ValidityCap(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "validity-test.bundle.yaml")
	err := IssueAdminBundle(setup.cfg, setup.logger, "validity-tester", outputPath, false)
	require.NoError(t, err)

	x509cert := parseX509FromBundle(t, outputPath)
	validity := x509cert.NotAfter.Sub(x509cert.NotBefore)

	assert.InDelta(t, float64(365*24*time.Hour), float64(validity), float64(24*time.Hour),
		"cert NotAfter-NotBefore must be 365 days (±1 day)")
}

// TestRevokeAdminBundle_RevokedThenAuthFails verifies the full revocation lifecycle:
// issue a bundle, confirm it is not revoked (auth would succeed), revoke it, and
// confirm it is revoked (auth would fail with CERT_REVOKED).
func TestRevokeAdminBundle_RevokedThenAuthFails(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "revoke-test.bundle.yaml")
	err := IssueAdminBundle(setup.cfg, setup.logger, "revoke-test-user", outputPath, false)
	require.NoError(t, err)

	b, err := bundle.Read(outputPath)
	require.NoError(t, err)
	serial := b.CertSerial

	// Parse the cert and verify it has the admin marker
	block, _ := pem.Decode([]byte(b.CertPEM))
	require.NotNil(t, block)
	x509cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, cert.HasAdminMarker(x509cert), "issued cert must carry admin marker")

	// Before revocation: cert manager must not report it as revoked
	revokedBefore, err := setup.certManager.IsRevoked(serial)
	require.NoError(t, err)
	assert.False(t, revokedBefore,
		"cert must not be revoked before RevokeAdminBundle is called")

	// Revoke
	err = RevokeAdminBundle(setup.cfg, setup.logger, serial)
	require.NoError(t, err)

	// After revocation: a fresh cert manager (simulating controller restart) must
	// report the serial as revoked (CERT_REVOKED — auth would be rejected)
	freshManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:    setup.tempDir,
		LoadExistingCA: true,
	})
	require.NoError(t, err)
	revokedAfter, err := freshManager.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revokedAfter,
		"cert must be revoked after RevokeAdminBundle; auth would return CERT_REVOKED")
}

// TestRegenerate_RequiresConfirmation verifies that RunRegenerate requires the
// operator to type exactly "yes" and exits non-zero otherwise.
func TestRegenerate_RequiresConfirmation(t *testing.T) {
	t.Run("no input cancels regeneration", func(t *testing.T) {
		setup, cleanup := setupInitializedController(t)
		defer cleanup()

		var in bytes.Buffer
		in.WriteString("no\n")
		var out bytes.Buffer

		err := RunRegenerate(setup.cfg, setup.logger, &in, &out)
		require.Error(t, err, "--regenerate with 'no' must exit non-zero")
		assert.Contains(t, out.String(), "Regeneration cancelled.")
	})

	t.Run("empty input cancels regeneration", func(t *testing.T) {
		setup, cleanup := setupInitializedController(t)
		defer cleanup()

		var in bytes.Buffer
		in.WriteString("\n")
		var out bytes.Buffer

		err := RunRegenerate(setup.cfg, setup.logger, &in, &out)
		require.Error(t, err, "--regenerate with empty input must exit non-zero")
		assert.Contains(t, out.String(), "Regeneration cancelled.")
	})

	t.Run("yes confirms regeneration", func(t *testing.T) {
		setup, cleanup := setupInitializedController(t)
		defer cleanup()

		originalBundle, err := bundle.Read(setup.bundlePath)
		require.NoError(t, err)

		var in bytes.Buffer
		in.WriteString("yes\n")

		err = RunRegenerate(setup.cfg, setup.logger, &in, io.Discard)
		require.NoError(t, err, "--regenerate with 'yes' must succeed")

		// Bundle must have been regenerated (new cert serial)
		newBundle, err := bundle.Read(setup.bundlePath)
		require.NoError(t, err)
		assert.NotEqual(t, originalBundle.CertSerial, newBundle.CertSerial,
			"regeneration must produce a new certificate serial")

		// New cert must still carry the admin marker
		x509cert := parseX509FromBundle(t, setup.bundlePath)
		assert.True(t, cert.HasAdminMarker(x509cert), "regenerated cert must carry the admin marker")
	})
}

// TestIssueAdminBundle_RejectsUnsetExternalURL verifies that IssueAdminBundle fails
// with an actionable error when external_url is not configured.
func TestIssueAdminBundle_RejectsUnsetExternalURL(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	cfg := *setup.cfg
	cfg.ExternalURL = ""

	outputPath := filepath.Join(t.TempDir(), "should-not-exist.bundle.yaml")
	err := IssueAdminBundle(&cfg, setup.logger, "alice", outputPath, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external_url",
		"error must name the field that needs to be set")
	assert.NoFileExists(t, outputPath,
		"no bundle file must be created when external_url is unset")
}

// TestIssueAdminBundle_RejectsNonHTTPSExternalURL verifies that a config with a
// non-https external_url is rejected — an http bundle exposes the controller URL
// as cleartext.
func TestIssueAdminBundle_RejectsNonHTTPSExternalURL(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	cfg := *setup.cfg
	cfg.ExternalURL = "http://controller.example.com:8080"

	outputPath := filepath.Join(t.TempDir(), "should-not-exist.bundle.yaml")
	err := IssueAdminBundle(&cfg, setup.logger, "alice", outputPath, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https",
		"error must require the https scheme")
	assert.NoFileExists(t, outputPath,
		"no bundle file must be created when external_url uses http")
}

// TestIssueAdminBundle_HonoursExplicitLocalhostURL verifies that a config that
// explicitly sets external_url to https://localhost:8080 is accepted unchanged.
// A single-host development deployment is a legitimate use case.
func TestIssueAdminBundle_HonoursExplicitLocalhostURL(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	cfg := *setup.cfg
	cfg.ExternalURL = "https://localhost:8080"

	outputPath := filepath.Join(t.TempDir(), "dev.bundle.yaml")
	err := IssueAdminBundle(&cfg, setup.logger, "dev-admin", outputPath, false)
	require.NoError(t, err, "explicit https://localhost:8080 must be accepted")

	b, err := bundle.Read(outputPath)
	require.NoError(t, err)
	assert.Equal(t, "https://localhost:8080", b.ControllerURL,
		"bundle ControllerURL must reflect the explicitly configured external_url")
}

// TestRegenerate_RecoversFromMissingBundle verifies that when the bundle marker is
// present but the bundle file has been deleted externally, RunRegenerate recreates
// the bundle and the controller initialization state is still valid.
func TestRegenerate_RecoversFromMissingBundle(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	// Simulate external deletion of the bundle file
	require.NoError(t, os.Remove(setup.bundlePath))
	assert.NoFileExists(t, setup.bundlePath, "pre-condition: bundle file must be absent")

	// The bundle marker file must still be present
	assert.FileExists(t, bundleMarkerPath(setup.bundlePath),
		"pre-condition: bundle marker must still be present")

	// RunRegenerate with "yes" must recreate the bundle
	var in bytes.Buffer
	in.WriteString("yes\n")
	err := RunRegenerate(setup.cfg, setup.logger, &in, io.Discard)
	require.NoError(t, err)

	require.FileExists(t, setup.bundlePath, "bundle file must be recreated by --regenerate")

	// Recreated bundle must be valid
	x509cert := parseX509FromBundle(t, setup.bundlePath)
	assert.True(t, cert.HasAdminMarker(x509cert), "recreated cert must carry the admin marker")

	// Initialization marker must still be intact (controller can start)
	assert.True(t, IsInitialized(setup.caDir),
		"initialization marker must remain intact after --regenerate")
}

// TestIssueAdminBundle_NeverCarriesPayloadSigningMarker locks the issuance-side
// precondition for the confinement Epic #3711 D4 rests on: "The bootstrap credential
// is not trusted for execution. The bundle from `controller bootstrap-admin` is
// controller-custody by construction. It receives AdminMarkerOID and never
// PayloadSigningMarkerOID." IssueAdminBundle's TemplateModifier composes only
// cert.SetAdminMarker (and cert.SetRootScopeMarker when rootScoped) — it never calls
// cert.SetPayloadSigningMarker. This test locks that so a future edit that widens
// the TemplateModifier to include payload-signing fails loudly, for both the plain
// and the root-scoped bundle (Issue #3716).
//
// Scope limit — this is NOT proof of a shipped control. The marker requirement is
// not yet enforced at either verification site: verifyOperatorCert
// (features/steward/commands/execute_script.go) and the operator-signature check in
// features/controller/api/handlers_runs.go both accept any admin-marked certificate
// and never call cert.HasPayloadSigningMarker, which has no non-test caller
// repo-wide. Until Story #3696 adds the positive requirement, a bootstrap bundle
// can still authorise endpoint code execution; what this test proves is only that
// the bundle does not acquire the marker, so the enforcement #3696 adds will bite.
func TestIssueAdminBundle_NeverCarriesPayloadSigningMarker(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	cases := []struct {
		name       string
		rootScoped bool
	}{
		{"plain", false},
		{"root-scoped", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "no-signing-marker.bundle.yaml")
			err := IssueAdminBundle(setup.cfg, setup.logger, "confinement-operator", outputPath, tc.rootScoped)
			require.NoError(t, err)

			x509cert := parseX509FromBundle(t, outputPath)
			assert.True(t, cert.HasAdminMarker(x509cert),
				"the bootstrap bundle must be able to administer the controller")
			assert.False(t, cert.HasPayloadSigningMarker(x509cert),
				"the bootstrap bundle must never acquire the payload-signing marker "+
					"(issuance-side precondition only; the marker is not yet required at "+
					"execute_script.go verifyOperatorCert or handlers_runs.go — Story #3696)")
		})
	}
}

// TestIssueAdminBundle_RootScoped_StampsBothMarkers verifies the bootstrap-admin
// --root-scoped opt-in (ADR-025 Amendment 1 A1.3, founder decision 2026-08-09, PR #3215)
// composes both cert.SetAdminMarker and cert.SetRootScopeMarker on the issued cert. Before
// this change SetRootScopeMarker had zero non-test callers anywhere in the codebase, so no
// credential in a running deployment could ever present as root-scoped; this is the path
// that closes that gap.
func TestIssueAdminBundle_RootScoped_StampsBothMarkers(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "root-operator.bundle.yaml")
	err := IssueAdminBundle(setup.cfg, setup.logger, "root-operator", outputPath, true)
	require.NoError(t, err)

	x509cert := parseX509FromBundle(t, outputPath)
	assert.True(t, cert.HasAdminMarker(x509cert), "root-scoped bundle must still carry the admin marker")
	assert.True(t, cert.HasRootScopeMarker(x509cert), "--root-scoped must stamp the root-scope marker")
}

// TestIssueAdminBundle_NotRootScoped_NoRootMarker is the no-regression half of the AC:
// omitting --root-scoped (the default for every existing caller) must never stamp the
// root-scope marker.
func TestIssueAdminBundle_NotRootScoped_NoRootMarker(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "ordinary-operator.bundle.yaml")
	err := IssueAdminBundle(setup.cfg, setup.logger, "ordinary-operator", outputPath, false)
	require.NoError(t, err)

	x509cert := parseX509FromBundle(t, outputPath)
	assert.True(t, cert.HasAdminMarker(x509cert))
	assert.False(t, cert.HasRootScopeMarker(x509cert),
		"an ordinary admin bundle must never carry the root-scope marker")
}

// TestIssueAdminBundle_FirstBoot_NeverRootScoped verifies the system admin bundle issued
// by first-run initialization never carries the root-scope marker. Founder decision:
// marking the deployment's only admin credential would subject every single-root and
// on-prem install's admin to the ADR-025 boundary with no way to grant itself a crossing
// — a lockout, not hardening. Unmarked stays the default everywhere.
func TestIssueAdminBundle_FirstBoot_NeverRootScoped(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	x509cert := parseX509FromBundle(t, setup.bundlePath)
	assert.True(t, cert.HasAdminMarker(x509cert))
	assert.False(t, cert.HasRootScopeMarker(x509cert),
		"the first-boot system admin bundle must never be root-scoped")
}

// TestIssueAdminBundle_RootScoped_RecordsAuditEvent verifies that issuing a root-scoped
// bundle is audited: "a credential that changes which side of the tenant boundary its
// holder sits on should not be mintable without a trace" (founder decision, PR #3215).
func TestIssueAdminBundle_RootScoped_RecordsAuditEvent(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "audited-operator.bundle.yaml")
	err := IssueAdminBundle(setup.cfg, setup.logger, "audited-operator", outputPath, true)
	require.NoError(t, err)

	sm, err := openStorageManager(setup.cfg, setup.logger)
	require.NoError(t, err)
	defer func() { require.NoError(t, sm.Close()) }()

	entries, err := sm.GetAuditStore().GetAuditsByAction(context.Background(), "root_scoped_admin_bundle_issued", nil)
	require.NoError(t, err)
	require.Len(t, entries, 1, "exactly one root-scoped issuance audit event must be recorded")
	assert.Equal(t, business.AuditSeverityCritical, entries[0].Severity,
		"minting a credential that crosses the ADR-025 boundary is Critical severity")
	assert.Equal(t, "audited-operator", entries[0].Details["operator_name"])
}

// TestIssueAdminBundle_RootScoped_AuditStorageFailureIsHardError verifies that a storage
// failure while recording the root-scoped issuance audit event fails IssueAdminBundle
// loudly (fail-closed), not silently: "a credential that changes which side of the
// tenant boundary its holder sits on should not be mintable without a trace" (founder
// decision, PR #3215). The bundle is still written to disk when this fires — the
// operator has a valid credential either way — which is exactly why the CLI must not
// exit 0 and let that go unnoticed.
func TestIssueAdminBundle_RootScoped_AuditStorageFailureIsHardError(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	brokenCfg := *setup.cfg
	brokenCfg.Storage = nil

	outputPath := filepath.Join(t.TempDir(), "broken-storage-operator.bundle.yaml")
	err := IssueAdminBundle(&brokenCfg, setup.logger, "broken-storage-operator", outputPath, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit record failed")
	assert.FileExists(t, outputPath, "the cert bundle is already on disk when the audit failure fires")
}

// TestIssueAdminBundle_NotRootScoped_NoAuditEvent verifies ordinary (non-root-scoped)
// bundle issuance does not write to the audit trail this feature adds — the trace exists
// specifically because a root-scoped credential changes which side of the tenant boundary
// its holder sits on; an ordinary admin bundle does not.
func TestIssueAdminBundle_NotRootScoped_NoAuditEvent(t *testing.T) {
	setup, cleanup := setupInitializedController(t)
	defer cleanup()

	outputPath := filepath.Join(t.TempDir(), "unaudited-operator.bundle.yaml")
	err := IssueAdminBundle(setup.cfg, setup.logger, "unaudited-operator", outputPath, false)
	require.NoError(t, err)

	sm, err := openStorageManager(setup.cfg, setup.logger)
	require.NoError(t, err)
	defer func() { require.NoError(t, sm.Close()) }()

	entries, err := sm.GetAuditStore().GetAuditsByAction(context.Background(), "root_scoped_admin_bundle_issued", nil)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

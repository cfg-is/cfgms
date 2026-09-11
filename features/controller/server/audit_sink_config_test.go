// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestServer_New_DefaultAuditSinkLogsADRBound is a REQUIRED test (Issue #4036
// AC): a controller with no audit config section starts on the "local" sink and
// logs a line naming that sink and stating that the weaker ADR-004/ADR-033
// bound applies, so an operator reading startup logs is never left to assume a
// stronger guarantee than the code provides.
func TestServer_New_DefaultAuditSinkLogsADRBound(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "audit-sink-default"),
	}

	logger := logging.NewCapturingLogger()
	srv, err := New(cfg, logger)
	require.NoError(t, err, "an absent audit config section must not block startup")
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	fields, found := logger.FindInfo("Audit sink selected")
	require.True(t, found, "startup must log which audit sink is active")
	assert.Equal(t, config.AuditSinkLocal, fields["sink"])

	bound, ok := fields["bound"].(string)
	require.True(t, ok, "the log entry must carry a bound field explaining the local sink's guarantee")
	assert.Contains(t, bound, "ADR-004", "the local-sink log line must name ADR-004 so an operator can look it up")
	assert.Contains(t, bound, "ADR-033", "the local-sink log line must name ADR-033 so an operator can look it up")
}

// TestServer_New_WormSinkRequiresBlobStoreConfig is a REQUIRED test (Issue
// #4037 AC): the worm sink is now implemented (Epic #4033 Story 4) — selecting
// it no longer fails with "not yet implemented". It still fails startup
// cleanly when the operator has not supplied the S3 blob store's required
// "bucket" config key, naming the actual misconfiguration rather than a
// vestigial not-implemented error. This does not exercise a real S3 endpoint:
// blob.CreateBlobStoreFromConfig rejects a missing bucket before any network
// call is made.
func TestServer_New_WormSinkRequiresBlobStoreConfig(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "audit-sink-worm"),
		Audit:       &config.AuditSinkConfig{Sink: config.AuditSinkWORM},
	}

	logger := logging.NewCapturingLogger()
	srv, err := New(cfg, logger)

	require.Error(t, err, "the worm sink must fail startup cleanly when its blob store config is incomplete")
	assert.Nil(t, srv)
	assert.False(t, strings.Contains(strings.ToLower(err.Error()), "not yet implemented"),
		"the worm sink is implemented as of Issue #4037 — the startup error must no longer claim it is not yet implemented")
	assert.Contains(t, err.Error(), "bucket", "the startup error must name the missing blob store config key")
}

// TestServer_New_UnknownAuditSinkFailsStartup guards the default branch of the
// sink switch: a typo'd or otherwise unrecognized sink name must fail startup
// naming the valid values, not silently resolve to local or worm.
func TestServer_New_UnknownAuditSinkFailsStartup(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "audit-sink-unknown"),
		Audit:       &config.AuditSinkConfig{Sink: "s3-glacier"},
	}

	srv, err := New(cfg, logging.NewNoopLogger())

	require.Error(t, err, "an unrecognized audit sink name must fail startup")
	assert.Nil(t, srv)
	assert.Contains(t, err.Error(), "s3-glacier")
}

// wormMarkerProbeTenantID mirrors auditsink's unexported tenantRegistryTenantID
// sentinel (pkg/storage/providers/auditsink/worm_store.go) — the tenant ID the
// startup writability probe always writes under, regardless of which real
// tenant IDs the deployment uses. This test lives outside that package and
// cannot reference the unexported constant, so the literal is duplicated here;
// pkg/storage/providers/auditsink/worm_store_test.go's own copy of this
// technique keeps this string honest.
const wormMarkerProbeTenantID = "_audit_worm_tenant_registry"

// TestServer_New_WormSinkMarkerStoreUnwritableFailsStartup is a REQUIRED test
// (Issue #4039 AC): the worm sink's marker store is what makes the
// buffer-then-flush design crash-safe, so an unwritable marker directory must
// fail controller startup with a named error rather than starting the worm
// sink without crash-safety. The marker root's parent exists and is writable,
// but a plain file sits where the marker store's registry probe needs a
// directory (<root>/<tenantRegistryTenantID>) — a real, non-permission-bit
// write failure that is reliable even when tests run as root, and on Windows
// (where os.Geteuid()/chmod-based permission bits don't apply the way they do
// on Unix). Mirrors TestNewWORMAuditStore_MarkerStoreUnwritableFailsStartup in
// pkg/storage/providers/auditsink/worm_store_test.go.
func TestServer_New_WormSinkMarkerStoreUnwritableFailsStartup(t *testing.T) {
	tempDir := t.TempDir()
	markerRoot := filepath.Join(tempDir, "marker-root")
	require.NoError(t, os.MkdirAll(markerRoot, 0o700))
	// The marker store's startup probe writes to
	// <markerRoot>/<wormMarkerProbeTenantID>/<namespace>/<name>. Pre-creating a
	// plain file at <markerRoot>/<wormMarkerProbeTenantID> blocks that write
	// unconditionally — the filesystem blob store's PutBlob needs that path
	// segment to be a creatable directory, and a regular file there fails
	// MkdirAll regardless of OS or which user runs the test.
	blockingPath := filepath.Join(markerRoot, wormMarkerProbeTenantID)
	require.NoError(t, os.WriteFile(blockingPath, []byte("not a directory"), 0o600))

	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "audit-sink-worm-marker-unwritable"),
		Audit: &config.AuditSinkConfig{
			Sink:       config.AuditSinkWORM,
			WORM:       map[string]interface{}{"bucket": "cfgms-audit-test"},
			MarkerRoot: markerRoot,
		},
	}

	logger := logging.NewCapturingLogger()
	srv, err := New(cfg, logger)

	require.Error(t, err, "an unwritable marker store must fail startup, never fall back to shipping without crash-safety")
	assert.Nil(t, srv)
	assert.Contains(t, err.Error(), "not writable")
	assert.Contains(t, err.Error(), markerRoot, "the startup error must name the marker store path")
}

// stubAuditStore embeds the interface rather than implementing it method by
// method: this test asserts only that SetAuditStore/GetAuditStore round-trip a
// distinct instance, never that the store behaves (same approach as
// registration_api_store_wiring_test.go's stubPendingStore).
type stubAuditStore struct{ business.AuditStore }

// TestStorageManager_SetAuditStore_RoundTrips is a REQUIRED test (Issue #4036
// AC): SetAuditStore must exist and swap the audit store after construction,
// with GetAuditStore reflecting the swap — the plumbing a later story uses to
// install a WORM-wrapped store without changing StorageManager's shape.
func TestStorageManager_SetAuditStore_RoundTrips(t *testing.T) {
	original := &stubAuditStore{}
	sm := interfaces.NewStorageManagerFromStores(
		nil, original, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	)
	require.Same(t, original, sm.GetAuditStore(),
		"precondition: the manager must start with the original store")

	replacement := &stubAuditStore{}
	sm.SetAuditStore(replacement)

	assert.Same(t, replacement, sm.GetAuditStore(),
		"GetAuditStore must reflect the store installed by SetAuditStore")
	assert.NotSame(t, original, sm.GetAuditStore(),
		"the original store must no longer be returned after the swap")
}

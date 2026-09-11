// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
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

// TestServer_New_WormSinkFailsStartupNotYetImplemented is a REQUIRED test
// (Issue #4036 AC): selecting the "worm" sink before Story 4 of Epic #4033
// lands must fail controller startup with a clear, named error — never fall
// back to the local sink silently.
func TestServer_New_WormSinkFailsStartupNotYetImplemented(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "audit-sink-worm"),
		Audit:       &config.AuditSinkConfig{Sink: config.AuditSinkWORM},
	}

	logger := logging.NewCapturingLogger()
	srv, err := New(cfg, logger)

	require.Error(t, err, "selecting the worm sink before Story 4 lands must fail startup, not silently run on local")
	assert.Nil(t, srv, "no Server may be returned when the configured sink is not yet implemented")
	assert.True(t, strings.Contains(err.Error(), config.AuditSinkWORM),
		"the startup error must name the worm sink")
	assert.True(t, strings.Contains(strings.ToLower(err.Error()), "not yet implemented"),
		"the startup error must state plainly that the worm sink is not yet implemented")

	_, found := logger.FindInfo("Audit sink selected")
	assert.False(t, found, "a startup that fails on an unimplemented sink must not also log it as selected")
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

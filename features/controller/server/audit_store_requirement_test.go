// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// auditDecliningFlatfileProvider wraps the real registered flatfile provider and
// declines exactly one store — AuditStore — while every other store stays real.
// It returns (nil, nil) rather than an error: that is the exact silent-nil shape
// audit.StoreRequirements exists to catch (Issue #4035) — CreateOSSStorageManager
// treats a non-nil error from CreateAuditStore as fatal already, so an error
// return does not reproduce the gap. A provider that hands back a nil store
// with no error, or a future WORM/local sink selector (Epic #4033, Story 2)
// that resolves to nil under some configuration, both compose successfully and
// must be caught by the requirement check, not by construction failing. It is a
// real provider implementation, not a mock — the embedded StorageProvider
// serves every call except the declined one.
type auditDecliningFlatfileProvider struct {
	interfaces.StorageProvider
}

var _ interfaces.StorageProvider = (*auditDecliningFlatfileProvider)(nil)

func (p *auditDecliningFlatfileProvider) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	return nil, nil
}

// TestCollectActiveStorageRequirements_IncludesAudit verifies that the audit
// subsystem's declaration reaches the startup gate. Audit is unconditionally
// active on a controller, so its requirement must be collected for every
// deployment shape, and it must be Required (not Optional) — an Optional severity
// would let a composition with no audit store sail through undetected (Issue #4035).
func TestCollectActiveStorageRequirements_IncludesAudit(t *testing.T) {
	cfg := config.DefaultConfig()

	reqs := collectActiveStorageRequirements(cfg)

	require.NotEmpty(t, audit.StoreRequirements,
		"audit must declare at least one store requirement")
	for _, want := range audit.StoreRequirements {
		assert.Contains(t, reqs, want,
			"collectActiveStorageRequirements must include the audit declaration verbatim")
	}
	assert.Contains(t, reqs, interfaces.StoreRequirement{
		Subsystem: "audit",
		Store:     interfaces.StoreNameAudit,
		Severity:  interfaces.RequirementRequired,
	}, "audit must require AuditStore at Required severity")
}

// TestValidateStorageRequirements_FailsWhenAuditStoreAbsent is the revert-proof
// acceptance test: a StorageManager with no audit store must fail
// ValidateStorageRequirements naming subsystem "audit" and store "AuditStore".
// This test fails if audit.StoreRequirements' severity is ever downgraded to
// RequirementOptional or the declaration is removed from
// collectActiveStorageRequirements.
func TestValidateStorageRequirements_FailsWhenAuditStoreAbsent(t *testing.T) {
	sm := interfaces.NewStorageManagerFromStores(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	)
	require.False(t, sm.HasStore(interfaces.StoreNameAudit),
		"precondition: a composite manager built with a nil audit store must report it absent")

	cfg := config.DefaultConfig()
	err := interfaces.ValidateStorageRequirements(sm, collectActiveStorageRequirements(cfg))

	require.Error(t, err,
		"a composition with no audit store must fail startup, not silently proceed")
	assert.Contains(t, err.Error(), "audit",
		"startup error must name the audit subsystem")
	assert.Contains(t, err.Error(), string(interfaces.StoreNameAudit),
		"startup error must name the missing AuditStore")
}

// TestServer_New_FailsWhenProviderDeclinesAuditStore is the server-level
// functional guard for the wiring between collectActiveStorageRequirements and
// the ValidateStorageRequirements gate in New(). A backend that declines
// AuditStore must abort controller startup with an error naming the audit
// subsystem and the missing store — not boot into a controller that calls
// audit.NewManager with a nil store and fails later wherever the store's
// methods are first called.
//
// The declining backend is installed by swapping the registered "flatfile"
// provider for a wrapper around the real one, so New() runs its real OSS
// composition path (flatfile + SQLite) and fails only on the declined store.
func TestServer_New_FailsWhenProviderDeclinesAuditStore(t *testing.T) {
	original, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err, "the real flatfile provider must be registered for this test to degrade it")
	interfaces.RegisterStorageProvider(&auditDecliningFlatfileProvider{StorageProvider: original})
	t.Cleanup(func() { interfaces.RegisterStorageProvider(original) })

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "audit-declined"),
	}

	srv, newErr := New(cfg, logging.NewNoopLogger())
	if srv != nil {
		t.Cleanup(func() { _ = srv.Stop() })
	}

	require.Error(t, newErr,
		"controller startup must fail closed when the storage backend declines the AuditStore audit requires")
	assert.Nil(t, srv, "no Server may be returned when a required store is missing")
	assert.Contains(t, newErr.Error(), "audit",
		"startup error must name the subsystem whose requirement was unmet")
	assert.Contains(t, newErr.Error(), string(interfaces.StoreNameAudit),
		"startup error must name the missing store")
}

// TestServer_New_SucceedsWhenAuditStoreAvailable is the counterpart guard: the
// requirement added to collectActiveStorageRequirements must not block a normal
// OSS deployment. The default composition supplies AuditStore, so New() passes
// the gate and the started controller holds a non-nil audit store.
func TestServer_New_SucceedsWhenAuditStoreAvailable(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "audit-available"),
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err,
		"the audit requirement must not block an OSS controller whose backend supplies AuditStore")
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	require.NotNil(t, srv.storageManager)
	assert.True(t, srv.storageManager.HasStore(interfaces.StoreNameAudit),
		"a controller that passed the gate must actually hold the audit store")
}

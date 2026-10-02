// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	workflowtrigger "github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// triggerDecliningSQLiteProvider wraps the real registered SQLite provider and
// declines exactly one store — TriggerStore — while every other store stays real.
// This reproduces, against the production composition path
// (interfaces.CreateOSSStorageManager), the condition workflow-trigger's
// StoreRequirements declaration exists to catch: a backend that cannot supply
// trigger persistence. It is a real provider implementation, not a mock — the
// embedded StorageProvider serves every call except the declined one.
//
// OpenBusinessStores is implemented (rather than left off so the composition
// falls back to per-store creation) because the OSS path prefers the bundle
// when the provider offers it; declining through the bundle keeps the test on
// the same branch a real deployment takes.
type triggerDecliningSQLiteProvider struct {
	interfaces.StorageProvider
}

var (
	_ interfaces.StorageProvider     = (*triggerDecliningSQLiteProvider)(nil)
	_ interfaces.BusinessStoreOpener = (*triggerDecliningSQLiteProvider)(nil)
)

func (p *triggerDecliningSQLiteProvider) CreateTriggerStore(_ map[string]interface{}) (business.TriggerStore, error) {
	return nil, business.ErrNotSupported
}

func (p *triggerDecliningSQLiteProvider) OpenBusinessStores(path string) (*interfaces.BusinessStoreBundle, error) {
	opener, ok := p.StorageProvider.(interfaces.BusinessStoreOpener)
	if !ok {
		return nil, fmt.Errorf("wrapped provider %q does not implement BusinessStoreOpener", p.Name())
	}
	bundle, err := opener.OpenBusinessStores(path)
	if err != nil {
		return nil, err
	}
	// Declined: the composed manager gets a nil TriggerStore, exactly as it would
	// if the backend's trigger schema were unavailable.
	bundle.Trigger = nil
	return bundle, nil
}

// TestCollectActiveStorageRequirements_IncludesWorkflowTrigger verifies that the
// workflow-trigger subsystem's declaration reaches the startup gate. The subsystem
// is unconditionally active on a controller, so its requirement must be collected
// for every deployment shape, and it must be Required (not Optional) — an Optional
// severity would let the #3400 class of silent nil back in.
func TestCollectActiveStorageRequirements_IncludesWorkflowTrigger(t *testing.T) {
	cfg := config.DefaultConfig()

	reqs := collectActiveStorageRequirements(cfg)

	require.NotEmpty(t, workflowtrigger.StoreRequirements,
		"workflow-trigger must declare at least one store requirement")
	for _, want := range workflowtrigger.StoreRequirements {
		assert.Contains(t, reqs, want,
			"collectActiveStorageRequirements must include the workflow-trigger declaration verbatim")
	}
	assert.Contains(t, reqs, interfaces.StoreRequirement{
		Subsystem: "workflow-trigger",
		Store:     interfaces.StoreNameTrigger,
		Severity:  interfaces.RequirementRequired,
	}, "workflow-trigger must require TriggerStore at Required severity")
}

// TestServer_New_FailsWhenProviderDeclinesTriggerStore is the server-level
// functional guard for the wiring between collectActiveStorageRequirements and
// the ValidateStorageRequirements gate in New(). A backend that declines
// TriggerStore must abort controller startup with an error naming the
// workflow-trigger subsystem and the missing store — not boot into a controller
// whose trigger endpoints 503 at request time (issue #3400 class).
//
// The declining backend is installed by swapping the registered "sqlite"
// provider for a wrapper around the real one, so New() runs its real OSS
// composition path (flatfile + SQLite) and fails only on the declined store.
func TestServer_New_FailsWhenProviderDeclinesTriggerStore(t *testing.T) {
	original, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err, "the real SQLite provider must be registered for this test to degrade it")
	interfaces.RegisterStorageProvider(&triggerDecliningSQLiteProvider{StorageProvider: original})
	t.Cleanup(func() { interfaces.RegisterStorageProvider(original) })

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "trigger-declined"),
	}

	srv, newErr := New(cfg, logging.NewNoopLogger())
	if srv != nil {
		t.Cleanup(func() { _ = srv.Stop() })
	}

	require.Error(t, newErr,
		"controller startup must fail closed when the storage backend declines the TriggerStore workflow-trigger requires")
	assert.Nil(t, srv, "no Server may be returned when a required store is missing")
	assert.Contains(t, newErr.Error(), "workflow-trigger",
		"startup error must name the subsystem whose requirement was unmet")
	assert.Contains(t, newErr.Error(), string(interfaces.StoreNameTrigger),
		"startup error must name the missing store")
}

// TestServer_New_SucceedsWhenTriggerStoreAvailable is the counterpart guard: the
// requirement added to collectActiveStorageRequirements must not block a normal
// OSS deployment. The default composition supplies TriggerStore, so New() passes
// the gate and the started controller holds a non-nil trigger store.
func TestServer_New_SucceedsWhenTriggerStoreAvailable(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage:     createTestStorageConfig(tempDir, "trigger-available"),
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err,
		"the workflow-trigger requirement must not block an OSS controller whose backend supplies TriggerStore")
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	require.NotNil(t, srv.storageManager)
	assert.True(t, srv.storageManager.HasStore(interfaces.StoreNameTrigger),
		"a controller that passed the gate must actually hold the trigger store")
}

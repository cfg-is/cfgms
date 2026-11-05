// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// lockdownAuditFixture is a lockdown audit observer over a real audit manager,
// a real flat-file steward store holding one registered steward, and a
// capturing logger.
type lockdownAuditFixture struct {
	obs    *lockdownAuditObserver
	mgr    *audit.Manager
	store  business.AuditStore
	logger *logging.CapturingLogger
}

func newLockdownAuditFixture(t *testing.T) *lockdownAuditFixture {
	t.Helper()
	storageManager := pkgtesting.SetupTestStorage(t)
	auditStore := storageManager.GetAuditStore()
	mgr, err := audit.NewManager(auditStore, "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })

	stewards := newAdapterStewardStore(t, &business.StewardRecord{
		ID:       "steward-known",
		TenantID: "tenant-a",
		Status:   business.StewardStatusActive,
	})
	logger := logging.NewCapturingLogger()
	return &lockdownAuditFixture{
		obs:    newLockdownAuditObserver(mgr, stewards, logger),
		mgr:    mgr,
		store:  auditStore,
		logger: logger,
	}
}

func (f *lockdownAuditFixture) entries(t *testing.T, action string) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, f.mgr.Flush(context.Background()))
	entries, err := f.store.ListAuditEntries(context.Background(), &business.AuditFilter{
		Actions: []string{action},
	})
	require.NoError(t, err)
	return entries
}

func TestLockdownAuditObserver_CommandRefusedWritesEventInStewardTenant(t *testing.T) {
	f := newLockdownAuditFixture(t)

	f.obs.CommandRefused(context.Background(), "steward-known", controlplaneTypes.CommandSyncConfig, "locked down")

	entries := f.entries(t, auditActionCommandRefusedLockedDown)
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, "tenant-a", e.TenantID)
	assert.Equal(t, business.AuditEventSecurityEvent, e.EventType)
	assert.Equal(t, business.AuditSeverityHigh, e.Severity)
	assert.Equal(t, business.AuditResultFailure, e.Result)
	assert.Equal(t, "controller", e.UserID)
	assert.Equal(t, business.AuditUserTypeSystem, e.UserType)
	assert.Equal(t, "steward", e.ResourceType)
	assert.Equal(t, "steward-known", e.ResourceID)
	assert.Equal(t, "steward-known", e.Details["steward_id"])
	assert.Equal(t, string(controlplaneTypes.CommandSyncConfig), e.Details["command_type"])
	assert.Equal(t, "locked down", e.Details["reason"])

	warn, ok := f.logger.FindWarn("Command refused: steward is locked down")
	require.True(t, ok)
	assert.Equal(t, "steward-known", warn["steward_id"])
	_, failed := f.logger.FindWarn("Failed to record command refusal audit event")
	assert.False(t, failed)
}

func TestLockdownAuditObserver_OperatorCommandAllowedWritesHumanEvent(t *testing.T) {
	f := newLockdownAuditFixture(t)

	f.obs.OperatorCommandAllowed(context.Background(), "alice", "steward-known", controlplaneTypes.CommandOpenTerminal)

	entries := f.entries(t, auditActionOperatorCommandLockedDown)
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, "tenant-a", e.TenantID)
	assert.Equal(t, business.AuditEventSecurityEvent, e.EventType)
	assert.Equal(t, business.AuditSeverityHigh, e.Severity)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.Equal(t, "alice", e.UserID)
	assert.Equal(t, business.AuditUserTypeHuman, e.UserType)
	assert.Equal(t, "steward", e.ResourceType)
	assert.Equal(t, "steward-known", e.ResourceID)
	assert.Equal(t, "alice", e.Details["operator"])
	assert.Equal(t, string(controlplaneTypes.CommandOpenTerminal), e.Details["command_type"])

	info, ok := f.logger.FindInfo("Operator command allowed to locked-down steward")
	require.True(t, ok)
	assert.Equal(t, "alice", info["operator"])
}

// A steward the store does not know is recorded under the fallback tenant, so
// the refusal is never lost to a failed tenant lookup.
func TestLockdownAuditObserver_UnknownStewardFallsBackToSystemTenant(t *testing.T) {
	f := newLockdownAuditFixture(t)

	f.obs.CommandRefused(context.Background(), "steward-unknown", controlplaneTypes.CommandSyncConfig, "lookup failed")

	entries := f.entries(t, auditActionCommandRefusedLockedDown)
	require.Len(t, entries, 1)
	assert.Equal(t, lockdownAuditFallbackTenant, entries[0].TenantID)
	assert.Equal(t, "steward-unknown", entries[0].ResourceID)
}

func TestLockdownAuditObserver_NoStewardStoreFallsBackToSystemTenant(t *testing.T) {
	f := newLockdownAuditFixture(t)
	obs := newLockdownAuditObserver(f.mgr, nil, f.logger)

	obs.OperatorCommandAllowed(context.Background(), "alice", "steward-known", controlplaneTypes.CommandOpenTerminal)

	entries := f.entries(t, auditActionOperatorCommandLockedDown)
	require.Len(t, entries, 1)
	assert.Equal(t, lockdownAuditFallbackTenant, entries[0].TenantID)
}

// With no audit manager the observer still logs and does not panic.
func TestLockdownAuditObserver_NoAuditManagerLogsOnly(t *testing.T) {
	logger := logging.NewCapturingLogger()
	obs := newLockdownAuditObserver(nil, nil, logger)

	obs.CommandRefused(context.Background(), "steward-x", controlplaneTypes.CommandSyncConfig, "locked down")
	obs.OperatorCommandAllowed(context.Background(), "alice", "steward-x", controlplaneTypes.CommandOpenTerminal)

	_, refused := logger.FindWarn("Command refused: steward is locked down")
	assert.True(t, refused)
	_, allowed := logger.FindInfo("Operator command allowed to locked-down steward")
	assert.True(t, allowed)
}

// A write the audit manager rejects is logged, never silently dropped.
func TestLockdownAuditObserver_RecordFailureIsLogged(t *testing.T) {
	f := newLockdownAuditFixture(t)
	require.NoError(t, f.mgr.Stop(context.Background()))

	f.obs.CommandRefused(context.Background(), "steward-known", controlplaneTypes.CommandSyncConfig, "locked down")
	f.obs.OperatorCommandAllowed(context.Background(), "alice", "steward-known", controlplaneTypes.CommandOpenTerminal)

	refusal, ok := f.logger.FindWarn("Failed to record command refusal audit event")
	require.True(t, ok)
	assert.Equal(t, "steward-known", refusal["steward_id"])
	assert.NotEmpty(t, refusal["error"])
	allowed, ok := f.logger.FindWarn("Failed to record operator command audit event")
	require.True(t, ok)
	assert.NotEmpty(t, allowed["error"])
}

// An operator-origin event with no operator principal fails audit validation;
// the failure is logged rather than written under an anonymous identity.
func TestLockdownAuditObserver_EmptyOperatorIsRejectedAndLogged(t *testing.T) {
	f := newLockdownAuditFixture(t)

	f.obs.OperatorCommandAllowed(context.Background(), "", "steward-known", controlplaneTypes.CommandOpenTerminal)

	assert.Empty(t, f.entries(t, auditActionOperatorCommandLockedDown))
	_, ok := f.logger.FindWarn("Failed to record operator command audit event")
	assert.True(t, ok)
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestIdentityConflictObserver_WritesHighSeverityAuditEvent(t *testing.T) {
	storageManager := pkgtesting.SetupTestStorage(t)
	store := storageManager.GetAuditStore()
	mgr, err := audit.NewManager(store, "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })

	obs := newIdentityConflictAuditObserver(mgr, logging.NewNoopLogger())
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	obs.now = func() time.Time { return clock }

	conflict := grpcCP.IdentityConflict{
		StewardID:      "steward-dup",
		TenantID:       "tenant-a",
		ExistingAddr:   "10.0.0.1:4000",
		NewAddr:        "10.0.0.2:5000",
		ExistingSerial: "111",
		NewSerial:      "222",
		DetectedAt:     clock,
	}
	list := func() []*business.AuditEntry {
		require.NoError(t, mgr.Flush(context.Background()))
		entries, err := store.ListAuditEntries(context.Background(), &business.AuditFilter{
			Actions: []string{"steward_identity_conflict_detected"},
		})
		require.NoError(t, err)
		return entries
	}

	obs.ObserveIdentityConflict(context.Background(), conflict)
	entries := list()
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, business.AuditSeverityHigh, e.Severity)
	assert.Equal(t, business.AuditEventSecurityEvent, e.EventType)
	assert.Equal(t, "tenant-a", e.TenantID)
	assert.Equal(t, "steward", e.ResourceType)
	assert.Equal(t, "steward-dup", e.ResourceID)
	assert.Equal(t, "10.0.0.1:4000", e.Details["existing_addr"])
	assert.Equal(t, "10.0.0.2:5000", e.Details["new_addr"])
	assert.Equal(t, "111", e.Details["existing_serial"])
	assert.Equal(t, "222", e.Details["new_serial"])

	// A second report inside one minute writes nothing.
	clock = clock.Add(30 * time.Second)
	obs.ObserveIdentityConflict(context.Background(), conflict)
	assert.Len(t, list(), 1)

	// A different steward is not rate-limited by the first.
	other := conflict
	other.StewardID = "steward-other"
	obs.ObserveIdentityConflict(context.Background(), other)
	assert.Len(t, list(), 2)

	// After the interval the same steward is reported again.
	clock = clock.Add(31 * time.Second)
	obs.ObserveIdentityConflict(context.Background(), conflict)
	assert.Len(t, list(), 3)
}

func TestIdentityConflictObserver_NoTenantFallsBack(t *testing.T) {
	storageManager := pkgtesting.SetupTestStorage(t)
	store := storageManager.GetAuditStore()
	mgr, err := audit.NewManager(store, "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })

	obs := newIdentityConflictAuditObserver(mgr, logging.NewNoopLogger())
	obs.ObserveIdentityConflict(context.Background(), grpcCP.IdentityConflict{StewardID: "s1"})
	require.NoError(t, mgr.Flush(context.Background()))
	entries, err := store.ListAuditEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, identityConflictFallbackTenant, entries[0].TenantID)
}

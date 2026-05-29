// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// fakeAuditStore is an in-memory business.AuditStore for testing.
// Only StoreAuditEntry and GetLastAuditEntry have real logic;
// all other methods are no-ops so the drain loop can operate.
type fakeAuditStore struct {
	mu      sync.Mutex
	entries []*business.AuditEntry
}

func (f *fakeAuditStore) StoreAuditEntry(_ context.Context, entry *business.AuditEntry) error {
	f.mu.Lock()
	f.entries = append(f.entries, entry)
	f.mu.Unlock()
	return nil
}

func (f *fakeAuditStore) GetAuditEntry(_ context.Context, _ string) (*business.AuditEntry, error) {
	return nil, nil
}

func (f *fakeAuditStore) ListAuditEntries(_ context.Context, _ *business.AuditFilter) ([]*business.AuditEntry, error) {
	return nil, nil
}

func (f *fakeAuditStore) StoreAuditBatch(_ context.Context, entries []*business.AuditEntry) error {
	f.mu.Lock()
	f.entries = append(f.entries, entries...)
	f.mu.Unlock()
	return nil
}

func (f *fakeAuditStore) GetAuditsByUser(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}

func (f *fakeAuditStore) GetAuditsByResource(_ context.Context, _, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}

func (f *fakeAuditStore) GetAuditsByAction(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}

func (f *fakeAuditStore) GetFailedActions(_ context.Context, _ *business.TimeRange, _ int) ([]*business.AuditEntry, error) {
	return nil, nil
}

func (f *fakeAuditStore) GetSuspiciousActivity(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}

func (f *fakeAuditStore) GetAuditStats(_ context.Context) (*business.AuditStats, error) {
	return &business.AuditStats{LastUpdated: time.Now()}, nil
}

func (f *fakeAuditStore) GetLastAuditEntry(_ context.Context, tenantID string) (*business.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.entries) - 1; i >= 0; i-- {
		if f.entries[i].TenantID == tenantID {
			return f.entries[i], nil
		}
	}
	return nil, nil
}

func (f *fakeAuditStore) ArchiveAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (f *fakeAuditStore) PurgeAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (f *fakeAuditStore) Close() error { return nil }

// captured returns a snapshot copy of all stored entries.
func (f *fakeAuditStore) captured() []*business.AuditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*business.AuditEntry, len(f.entries))
	copy(out, f.entries)
	return out
}

// newFakeAuditManager returns an audit.Manager backed by an in-memory store.
func newFakeAuditManager(t *testing.T) (*audit.Manager, *fakeAuditStore) {
	t.Helper()
	store := &fakeAuditStore{}
	mgr, err := audit.NewManager(store, "hyperv-test")
	require.NoError(t, err)
	return mgr, store
}

// ─── recordHypervOp tests ──────────────────────────────────────────────────────

// TestAuditRecordHypervOp_NilSafe verifies that a nil audit manager does not panic.
func TestAuditRecordHypervOp_NilSafe(t *testing.T) {
	// Must not panic — nil mgr is the default for lightweight edge stewards.
	recordHypervOp(context.Background(), nil, "tenant-1", "steward-1", "host-1", "New-VM", "cfgms-tenant-1__vm1", nil)
}

// TestAuditRecordHypervOp_NoRawPS verifies that Details contains no raw PowerShell
// script text or argument values such as VM names, VHD paths, or switch names.
func TestAuditRecordHypervOp_NoRawPS(t *testing.T) {
	mgr, store := newFakeAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	recordHypervOp(context.Background(), mgr, "tenant-1", "steward-1", "host-1", "New-VM", "cfgms-tenant-1__vm1", nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	entry := entries[0]
	// None of the Detail values should contain raw PS script text fragments
	// or any other user-supplied argument value that belongs in ArgumentList.
	for k, v := range entry.Details {
		vStr, _ := v.(string)
		assert.NotContains(t, vStr, "New-VM -Name", "Details[%q] must not contain raw PS command", k)
		assert.NotContains(t, vStr, "ArgumentList", "Details[%q] must not contain ArgumentList", k)
		assert.NotContains(t, vStr, ".vhdx", "Details[%q] must not contain VHD path fragments", k)
		assert.NotContains(t, vStr, "-MemoryStartupBytes", "Details[%q] must not contain PS parameter names", k)
	}
	// Only the allowed structured keys should appear.
	for k := range entry.Details {
		assert.Contains(t, []string{"host", "steward_id"}, k,
			"unexpected Detail key %q: only 'host' and 'steward_id' are allowed", k)
	}
}

// TestAuditRecordHypervOp_ErrorPath verifies that a non-nil opErr produces a
// non-success result with an error message, and that recordHypervOp does not
// change what error the caller sees (separation of concerns).
func TestAuditRecordHypervOp_ErrorPath(t *testing.T) {
	mgr, store := newFakeAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	opErr := errors.New("VM creation failed: disk quota exceeded")
	recordHypervOp(context.Background(), mgr, "tenant-1", "steward-1", "host-1", "New-VM", "cfgms-tenant-1__vm1", opErr)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	entry := entries[0]
	// Result must indicate failure (not success).
	assert.NotEqual(t, business.AuditResultSuccess, entry.Result,
		"opErr != nil must produce a non-success result")
	// Error message must carry the original message for forensics.
	assert.Contains(t, entry.ErrorMessage, "VM creation failed",
		"error message must contain the original error text")
}

// TestAuditLog_VMOperation verifies that a New-VM operation produces an audit
// entry with all required fields correctly populated and result Success.
func TestAuditLog_VMOperation(t *testing.T) {
	mgr, store := newFakeAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	tenantID := "tenant-a"
	stewardID := "steward-a"
	host := "winhost.example.com"
	verb := "New-VM"
	resourceID := vmHostName(tenantID, "myvm") // cfgms-tenant-a__myvm

	recordHypervOp(context.Background(), mgr, tenantID, stewardID, host, verb, resourceID, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, tenantID, entry.TenantID, "tenant_id")
	assert.Equal(t, verb, entry.Action, "action/verb")
	assert.Equal(t, "hyperv/"+verb, entry.ResourceType, "resource_type")
	assert.Equal(t, resourceID, entry.ResourceID, "resource_id")
	assert.Equal(t, business.AuditResultSuccess, entry.Result, "result")

	hostVal, ok := entry.Details["host"].(string)
	assert.True(t, ok, "Details[host] must be a string")
	assert.Equal(t, host, hostVal, "Details[host]")

	stewardVal, ok := entry.Details["steward_id"].(string)
	assert.True(t, ok, "Details[steward_id] must be a string")
	assert.Equal(t, stewardID, stewardVal, "Details[steward_id]")
}

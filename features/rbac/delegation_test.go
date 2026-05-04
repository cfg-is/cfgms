// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// newTestDelegationSetup constructs a DelegationManager backed by real storage.
func newTestDelegationSetup(t *testing.T) (*DelegationManager, *Manager) {
	t.Helper()
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})

	ctx := context.Background()
	require.NoError(t, manager.Initialize(ctx))

	return NewDelegationManager(manager), manager
}

// createTestSubjectWithAdmin creates a subject in the "root" tenant with system.admin role,
// granting it the ability to delegate any permission.
func createTestSubjectWithAdmin(t *testing.T, ctx context.Context, manager *Manager, subjectID string) {
	t.Helper()
	subject := &common.Subject{
		Id:          subjectID,
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: subjectID,
		TenantId:    "root",
		IsActive:    true,
	}
	require.NoError(t, manager.CreateSubject(ctx, subject))

	assignment := &common.RoleAssignment{
		SubjectId: subjectID,
		RoleId:    "system.admin",
		TenantId:  "root",
	}
	// M-AUTH-2: AssignRole requires justification in context
	ctxJ := WithSensitiveOperationJustification(ctx, "test: system admin role setup for delegation test subject")
	require.NoError(t, manager.AssignRole(ctxJ, assignment))
}

// createTestSubjectBasic creates a delegatee subject with no special roles.
func createTestSubjectBasic(t *testing.T, ctx context.Context, manager *Manager, subjectID string) {
	t.Helper()
	subject := &common.Subject{
		Id:          subjectID,
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: subjectID,
		TenantId:    "root",
		IsActive:    true,
	}
	require.NoError(t, manager.CreateSubject(ctx, subject))
}

func TestDelegationManager_ConcurrentAccess(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()
	tenantID := "root"

	const goroutines = 10
	delegatorIDs := make([]string, goroutines)
	delegateeIDs := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		delegatorIDs[i] = fmt.Sprintf("conc-delegator-%d", i)
		delegateeIDs[i] = fmt.Sprintf("conc-delegatee-%d", i)
		createTestSubjectWithAdmin(t, ctx, manager, delegatorIDs[i])
		createTestSubjectBasic(t, ctx, manager, delegateeIDs[i])
	}

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*3)
	createdIDs := make([]string, goroutines)
	var idsMu sync.Mutex

	// Phase 1: concurrent CreateDelegation
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			req := &DelegationRequest{
				DelegatorID:   delegatorIDs[i],
				DelegateeID:   delegateeIDs[i],
				PermissionIDs: []string{"steward.register"},
				ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
				TenantID:      tenantID,
			}
			d, err := dm.CreateDelegation(ctx, req)
			if err != nil {
				errCh <- fmt.Errorf("CreateDelegation[%d]: %w", i, err)
				return
			}
			idsMu.Lock()
			createdIDs[i] = d.Id
			idsMu.Unlock()
		}()
	}
	wg.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("unexpected error in concurrent CreateDelegation: %v", err)
	default:
	}

	// Phase 2: concurrent GetActiveDelegations (readers) and RevokeDelegation (writers)
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, err := dm.GetActiveDelegations(ctx, delegateeIDs[i], tenantID)
			if err != nil {
				errCh <- fmt.Errorf("GetActiveDelegations[%d]: %w", i, err)
			}
		}()
	}

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			if i%2 != 0 {
				idsMu.Lock()
				id := createdIDs[i]
				idsMu.Unlock()
				if id == "" {
					return
				}
				if err := dm.RevokeDelegation(ctx, id, delegatorIDs[i]); err != nil {
					errCh <- fmt.Errorf("RevokeDelegation[%d]: %w", i, err)
				}
			}
		}()
	}
	wg.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("unexpected error in concurrent read/revoke phase: %v", err)
	default:
	}
}

func TestDelegationManager_CreateDelegation(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "create-delegator")
	createTestSubjectBasic(t, ctx, manager, "create-delegatee")

	req := &DelegationRequest{
		DelegatorID:   "create-delegator",
		DelegateeID:   "create-delegatee",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	d, err := dm.CreateDelegation(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, d.Id)
	assert.Equal(t, "create-delegator", d.DelegatorId)
	assert.Equal(t, "create-delegatee", d.DelegateeId)
	assert.False(t, d.Revoked)
}

func TestDelegationManager_CreateDelegation_InvalidRequest(t *testing.T) {
	dm, _ := newTestDelegationSetup(t)
	ctx := context.Background()

	tests := []struct {
		name string
		req  *DelegationRequest
	}{
		{"empty delegator", &DelegationRequest{DelegateeID: "b", PermissionIDs: []string{"p"}, TenantID: "t"}},
		{"empty delegatee", &DelegationRequest{DelegatorID: "a", PermissionIDs: []string{"p"}, TenantID: "t"}},
		{"self delegation", &DelegationRequest{DelegatorID: "a", DelegateeID: "a", PermissionIDs: []string{"p"}, TenantID: "t"}},
		{"no permissions", &DelegationRequest{DelegatorID: "a", DelegateeID: "b", TenantID: "t"}},
		{"empty tenant", &DelegationRequest{DelegatorID: "a", DelegateeID: "b", PermissionIDs: []string{"p"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dm.CreateDelegation(ctx, tc.req)
			assert.Error(t, err)
		})
	}
}

func TestDelegationManager_RevokeDelegation(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "revoke-delegator")
	createTestSubjectBasic(t, ctx, manager, "revoke-delegatee")

	req := &DelegationRequest{
		DelegatorID:   "revoke-delegator",
		DelegateeID:   "revoke-delegatee",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	d, err := dm.CreateDelegation(ctx, req)
	require.NoError(t, err)

	err = dm.RevokeDelegation(ctx, d.Id, "revoke-delegator")
	require.NoError(t, err)

	got, err := dm.GetDelegation(ctx, d.Id)
	require.NoError(t, err)
	assert.True(t, got.Revoked)
}

func TestDelegationManager_RevokeDelegation_NotFound(t *testing.T) {
	dm, _ := newTestDelegationSetup(t)
	ctx := context.Background()
	err := dm.RevokeDelegation(ctx, "nonexistent", "someone")
	assert.Error(t, err)
}

func TestDelegationManager_GetDelegation_NotFound(t *testing.T) {
	dm, _ := newTestDelegationSetup(t)
	ctx := context.Background()
	_, err := dm.GetDelegation(ctx, "missing")
	assert.Error(t, err)
}

func TestDelegationManager_ListDelegations(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "list-delegator")
	createTestSubjectBasic(t, ctx, manager, "list-delegatee")

	req := &DelegationRequest{
		DelegatorID:   "list-delegator",
		DelegateeID:   "list-delegatee",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	_, err := dm.CreateDelegation(ctx, req)
	require.NoError(t, err)

	list, err := dm.ListDelegations(ctx, "list-delegator", "root")
	require.NoError(t, err)
	assert.Len(t, list, 1)

	list, err = dm.ListDelegations(ctx, "list-delegatee", "root")
	require.NoError(t, err)
	assert.Len(t, list, 1)

	list, err = dm.ListDelegations(ctx, "nobody", "root")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestDelegationManager_GetActiveDelegations(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "active-delegator")
	createTestSubjectBasic(t, ctx, manager, "active-delegatee")

	req := &DelegationRequest{
		DelegatorID:   "active-delegator",
		DelegateeID:   "active-delegatee",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	d, err := dm.CreateDelegation(ctx, req)
	require.NoError(t, err)

	active, err := dm.GetActiveDelegations(ctx, "active-delegatee", "root")
	require.NoError(t, err)
	assert.Len(t, active, 1)

	require.NoError(t, dm.RevokeDelegation(ctx, d.Id, "active-delegator"))
	active, err = dm.GetActiveDelegations(ctx, "active-delegatee", "root")
	require.NoError(t, err)
	assert.Empty(t, active)
}

func TestDelegationManager_CleanupExpiredDelegations(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "cleanup-delegator")
	createTestSubjectBasic(t, ctx, manager, "cleanup-delegatee")

	// Create with a valid future expiry, then fast-expire by mutating the stored
	// protobuf pointer directly. This avoids wall-clock sleeping.
	req := &DelegationRequest{
		DelegatorID:   "cleanup-delegator",
		DelegateeID:   "cleanup-delegatee",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	d, err := dm.CreateDelegation(ctx, req)
	require.NoError(t, err)

	// Move the expiry to the past via the returned pointer (same pointer stored in map).
	stored, err := dm.GetDelegation(ctx, d.Id)
	require.NoError(t, err)
	stored.ExpiresAt = time.Now().Unix() - 1

	require.NoError(t, dm.CleanupExpiredDelegations(ctx))

	_, err = dm.GetDelegation(ctx, d.Id)
	assert.Error(t, err)
}

func TestDelegationManager_CleanupExpiredDelegations_ActiveUnaffected(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "cleanup2-delegator")
	createTestSubjectBasic(t, ctx, manager, "cleanup2-delegatee-active")
	createTestSubjectBasic(t, ctx, manager, "cleanup2-delegatee-expired")

	activeReq := &DelegationRequest{
		DelegatorID:   "cleanup2-delegator",
		DelegateeID:   "cleanup2-delegatee-active",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	dActive, err := dm.CreateDelegation(ctx, activeReq)
	require.NoError(t, err)

	expiredReq := &DelegationRequest{
		DelegatorID:   "cleanup2-delegator",
		DelegateeID:   "cleanup2-delegatee-expired",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	dExpired, err := dm.CreateDelegation(ctx, expiredReq)
	require.NoError(t, err)

	// Fast-expire only the second delegation.
	storedExpired, err := dm.GetDelegation(ctx, dExpired.Id)
	require.NoError(t, err)
	storedExpired.ExpiresAt = time.Now().Unix() - 1

	require.NoError(t, dm.CleanupExpiredDelegations(ctx))

	_, err = dm.GetDelegation(ctx, dExpired.Id)
	assert.Error(t, err, "expired delegation should be removed")

	_, err = dm.GetDelegation(ctx, dActive.Id)
	assert.NoError(t, err, "active delegation should be unaffected")
}

func TestDelegationManager_CheckDelegatedPermission_Granted(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "cdp-delegator")
	createTestSubjectBasic(t, ctx, manager, "cdp-delegatee")

	req := &DelegationRequest{
		DelegatorID:   "cdp-delegator",
		DelegateeID:   "cdp-delegatee",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	_, err := dm.CreateDelegation(ctx, req)
	require.NoError(t, err)

	granted, reason, err := dm.CheckDelegatedPermission(ctx, "cdp-delegatee", "steward.register", "", "root", nil)
	require.NoError(t, err)
	assert.True(t, granted)
	assert.NotEmpty(t, reason)
}

func TestDelegationManager_CheckDelegatedPermission_NoActiveDelegations(t *testing.T) {
	dm, _ := newTestDelegationSetup(t)
	ctx := context.Background()

	granted, reason, err := dm.CheckDelegatedPermission(ctx, "nobody", "steward.register", "", "root", nil)
	require.NoError(t, err)
	assert.False(t, granted)
	assert.NotEmpty(t, reason)
}

func TestDelegationManager_CheckDelegatedPermission_PermissionNotInDelegation(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "cdp2-delegator")
	createTestSubjectBasic(t, ctx, manager, "cdp2-delegatee")

	req := &DelegationRequest{
		DelegatorID:   "cdp2-delegator",
		DelegateeID:   "cdp2-delegatee",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	_, err := dm.CreateDelegation(ctx, req)
	require.NoError(t, err)

	// Request a different permission than what was delegated.
	granted, _, err := dm.CheckDelegatedPermission(ctx, "cdp2-delegatee", "config.delete", "", "root", nil)
	require.NoError(t, err)
	assert.False(t, granted)
}

func TestDelegationManager_CheckDelegatedPermission_RevokedDelegation(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "cdp3-delegator")
	createTestSubjectBasic(t, ctx, manager, "cdp3-delegatee")

	req := &DelegationRequest{
		DelegatorID:   "cdp3-delegator",
		DelegateeID:   "cdp3-delegatee",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	d, err := dm.CreateDelegation(ctx, req)
	require.NoError(t, err)
	require.NoError(t, dm.RevokeDelegation(ctx, d.Id, "cdp3-delegator"))

	granted, _, err := dm.CheckDelegatedPermission(ctx, "cdp3-delegatee", "steward.register", "", "root", nil)
	require.NoError(t, err)
	assert.False(t, granted)
}

func TestDelegationManager_GetDelegationStats(t *testing.T) {
	dm, manager := newTestDelegationSetup(t)
	ctx := context.Background()

	createTestSubjectWithAdmin(t, ctx, manager, "stats-delegator")
	createTestSubjectBasic(t, ctx, manager, "stats-delegatee-1")
	createTestSubjectBasic(t, ctx, manager, "stats-delegatee-2")

	req1 := &DelegationRequest{
		DelegatorID:   "stats-delegator",
		DelegateeID:   "stats-delegatee-1",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	_, err := dm.CreateDelegation(ctx, req1)
	require.NoError(t, err)

	req2 := &DelegationRequest{
		DelegatorID:   "stats-delegator",
		DelegateeID:   "stats-delegatee-2",
		PermissionIDs: []string{"steward.register"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
		TenantID:      "root",
	}
	d2, err := dm.CreateDelegation(ctx, req2)
	require.NoError(t, err)
	require.NoError(t, dm.RevokeDelegation(ctx, d2.Id, "stats-delegator"))

	stats, err := dm.GetDelegationStats(ctx, "root")
	require.NoError(t, err)
	assert.Equal(t, "root", stats.TenantID)
	assert.Equal(t, 2, stats.TotalDelegations)
	assert.Equal(t, 1, stats.ActiveDelegations)
	assert.Equal(t, 1, stats.RevokedDelegations)
}

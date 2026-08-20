// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newOSSManagerWithoutTriggerAndPush creates a StorageManager that has all OSS
// stores except TriggerStore and PushStore, simulating a destination backend that
// does not support those record kinds (e.g. the database provider).
// The providerName is "composite" (set by NewStorageManagerFromStores).
func newOSSManagerWithoutTriggerAndPush(t *testing.T) *interfaces.StorageManager {
	t.Helper()
	full := newOSSManager(t)
	dst := interfaces.NewStorageManagerFromStores(
		full.GetConfigStore(),
		full.GetAuditStore(),
		full.GetRBACStore(),
		full.GetTenantStore(),
		full.GetClientTenantStore(),
		full.GetRegistrationTokenStore(),
		full.GetSessionStore(),
		full.GetStewardStore(),
		full.GetCommandStore(),
		nil, // no trigger store
		nil, // no push store
	)
	// Wire extended stores so other record kinds remain migratable.
	dst.SetPendingRegistrationStore(full.GetPendingRegistrationStore())
	dst.SetIPTrustStore(full.GetIPTrustStore())
	dst.SetPendingRefreshStore(full.GetPendingRefreshStore())
	dst.SetRefreshPolicyStore(full.GetRefreshPolicyStore())
	return dst
}

// seedTriggerOnly seeds a single trigger record in mgr using a synthetic tenant ID
// that does not need to exist in the tenant store (the SQLite trigger table has no
// FK constraint to tenants). The source export for tenantIDs will be empty, so no
// refresh_policy or ip_trust records are exported — only the one trigger record.
func seedTriggerOnly(t *testing.T, mgr *interfaces.StorageManager) {
	t.Helper()
	ctx := context.Background()
	trig := mgr.GetTriggerStore()
	require.NotNil(t, trig, "trigger store")
	require.NoError(t, trig.StoreTrigger(ctx, &business.TriggerRecord{
		ID:           "trigger-capability-test-1",
		TenantID:     "synthetic-tenant-no-fk",
		Name:         "capability-test-trigger",
		Type:         "webhook",
		Status:       "active",
		WorkflowName: "deploy",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}))
}

// seedPushOnly seeds a single push record in mgr using the given tenant ID.
func seedPushOnly(t *testing.T, mgr *interfaces.StorageManager) {
	t.Helper()
	ctx := context.Background()
	ps := mgr.GetPushStore()
	require.NotNil(t, ps, "push store")
	require.NoError(t, ps.CreatePush(ctx, &business.PushRecord{
		ID:          "push-capability-test-1",
		ConfigID:    "cfg1",
		TenantID:    "synthetic-tenant-no-fk",
		Version:     "v1",
		Status:      business.PushStatusPending,
		InitiatedBy: "user-test",
		Data:        []byte(`{}`),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}))
}

// newOSSManager creates a fresh OSS (flatfile+sqlite) StorageManager backed by
// a per-test temp directory.  Registered cleanup closes the manager on test exit.
func newOSSManager(t *testing.T) *interfaces.StorageManager {
	t.Helper()
	dir := t.TempDir()
	mgr, err := interfaces.CreateOSSStorageManager(
		dir+"/flatfile",
		dir+"/cfgms.db",
	)
	require.NoError(t, err, "create OSS storage manager")
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

// seedPendingRegistration inserts a single pending-registration entry with the
// given lifecycle status. Used to construct source/destination status pairs for
// the resync transition tests.
func seedPendingRegistration(t *testing.T, mgr *interfaces.StorageManager, pendingID, status string) {
	t.Helper()
	ctx := context.Background()

	preg := mgr.GetPendingRegistrationStore()
	require.NotNil(t, preg, "pending registration store")

	entry := &business.PendingRegistrationEntry{
		PendingID:    pendingID,
		StewardID:    "steward-" + pendingID,
		TenantID:     "tenant-seed-1",
		TokenStr:     "token-seed-1",
		SourceIP:     "10.0.0.9",
		RegisteredAt: time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       status,
	}
	if status == business.PendingRegistrationStatusClaimed {
		claimedAt := time.Now()
		entry.ClaimedAt = &claimedAt
	}
	require.NoError(t, preg.AddPending(ctx, entry))
}

// pendingRegistrationStatus reads back the stored status for pendingID.
func pendingRegistrationStatus(t *testing.T, mgr *interfaces.StorageManager, pendingID string) *business.PendingRegistrationEntry {
	t.Helper()
	entry, err := mgr.GetPendingRegistrationStore().GetPendingByID(context.Background(), pendingID)
	require.NoError(t, err, "read back pending registration %s", pendingID)
	require.NotNil(t, entry)
	return entry
}

// assertRBACMatches compares every RBAC record seeded by seedOSSManager between
// two managers field-for-field. A per-kind count alone would pass even if the
// migrator wrote an empty or truncated record.
func assertRBACMatches(ctx context.Context, t *testing.T, src, dst *interfaces.StorageManager) {
	t.Helper()

	srcRBAC, dstRBAC := src.GetRBACStore(), dst.GetRBACStore()
	require.NotNil(t, srcRBAC, "source RBAC store")
	require.NotNil(t, dstRBAC, "destination RBAC store")

	srcPerm, err := srcRBAC.GetPermission(ctx, "perm-seed-1")
	require.NoError(t, err, "source permission")
	dstPerm, err := dstRBAC.GetPermission(ctx, "perm-seed-1")
	require.NoError(t, err, "migrated permission must exist in destination")
	assert.Equal(t, srcPerm.Name, dstPerm.Name, "permission Name")
	assert.Equal(t, srcPerm.Description, dstPerm.Description, "permission Description")
	assert.Equal(t, srcPerm.ResourceType, dstPerm.ResourceType, "permission ResourceType")
	assert.Equal(t, srcPerm.Actions, dstPerm.Actions, "permission Actions")

	srcRole, err := srcRBAC.GetRole(ctx, "role-seed-1")
	require.NoError(t, err, "source role")
	dstRole, err := dstRBAC.GetRole(ctx, "role-seed-1")
	require.NoError(t, err, "migrated role must exist in destination")
	assert.Equal(t, srcRole.Name, dstRole.Name, "role Name")
	assert.Equal(t, srcRole.Description, dstRole.Description, "role Description")
	assert.Equal(t, srcRole.PermissionIds, dstRole.PermissionIds, "role PermissionIds")
	assert.Equal(t, srcRole.ParentRoleId, dstRole.ParentRoleId, "role ParentRoleId")

	srcSubj, err := srcRBAC.GetSubject(ctx, "subject-seed-1")
	require.NoError(t, err, "source subject")
	dstSubj, err := dstRBAC.GetSubject(ctx, "subject-seed-1")
	require.NoError(t, err, "migrated subject must exist in destination")
	assert.Equal(t, srcSubj.DisplayName, dstSubj.DisplayName, "subject DisplayName")
	assert.Equal(t, srcSubj.Type, dstSubj.Type, "subject Type")
	assert.Equal(t, srcSubj.TenantId, dstSubj.TenantId, "subject TenantId")
	assert.Equal(t, srcSubj.IsActive, dstSubj.IsActive, "subject IsActive")

	dstAssignments, err := dstRBAC.ListRoleAssignments(ctx, "subject-seed-1", "role-seed-1", "tenant-seed-1")
	require.NoError(t, err, "list migrated role assignments")
	require.Len(t, dstAssignments, 1, "exactly one migrated role assignment (no duplicates)")
	assert.Equal(t, "assignment-seed-1", dstAssignments[0].Id, "role assignment ID")
	assert.Equal(t, "subject-seed-1", dstAssignments[0].SubjectId, "role assignment SubjectId")
	assert.Equal(t, "role-seed-1", dstAssignments[0].RoleId, "role assignment RoleId")
	assert.Equal(t, "tenant-seed-1", dstAssignments[0].TenantId, "role assignment TenantId")
}

// assertClientTenantMatches compares the migrated client tenant against the source.
func assertClientTenantMatches(t *testing.T, src, dst *interfaces.StorageManager, tenantID string) {
	t.Helper()

	srcStore, dstStore := src.GetClientTenantStore(), dst.GetClientTenantStore()
	require.NotNil(t, srcStore, "source client tenant store")
	require.NotNil(t, dstStore, "destination client tenant store")

	srcCT, err := srcStore.GetClientTenant(tenantID)
	require.NoError(t, err, "source client tenant %s", tenantID)
	dstCT, err := dstStore.GetClientTenant(tenantID)
	require.NoError(t, err, "migrated client tenant %s must exist in destination", tenantID)

	assert.Equal(t, srcCT.ID, dstCT.ID, "client tenant ID")
	assert.Equal(t, srcCT.TenantName, dstCT.TenantName, "client tenant TenantName")
	assert.Equal(t, srcCT.DomainName, dstCT.DomainName, "client tenant DomainName")
	assert.Equal(t, srcCT.AdminEmail, dstCT.AdminEmail, "client tenant AdminEmail")
	assert.Equal(t, srcCT.Status, dstCT.Status, "client tenant Status")
	assert.Equal(t, srcCT.ClientIdentifier, dstCT.ClientIdentifier, "client tenant ClientIdentifier")
	assert.True(t, srcCT.ConsentedAt.Equal(dstCT.ConsentedAt), "client tenant ConsentedAt")
}

// seedOSSManager populates an OSS StorageManager with one representative record
// per store kind covered by the storage migrator.
func seedOSSManager(t *testing.T, mgr *interfaces.StorageManager) {
	t.Helper()
	ctx := context.Background()

	// tenant
	ts := mgr.GetTenantStore()
	require.NotNil(t, ts, "tenant store")
	require.NoError(t, ts.Initialize(ctx))
	require.NoError(t, ts.CreateTenant(ctx, &business.TenantData{
		ID:        "tenant-seed-1",
		Name:      "Seed Tenant",
		Status:    business.TenantStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	// config
	cs := mgr.GetConfigStore()
	require.NotNil(t, cs, "config store")
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:       &cfgconfig.ConfigKey{TenantID: "tenant-seed-1", Namespace: "ns", Name: "cfg1"},
		Data:      []byte(`key: value`),
		Format:    cfgconfig.ConfigFormatYAML,
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))

	// audit
	as := mgr.GetAuditStore()
	require.NotNil(t, as, "audit store")
	require.NoError(t, as.StoreAuditEntry(ctx, &business.AuditEntry{
		ID:           "audit-seed-1",
		TenantID:     "tenant-seed-1",
		Timestamp:    time.Now(),
		EventType:    business.AuditEventConfiguration,
		Action:       "create",
		UserID:       "user-1",
		UserType:     business.AuditUserTypeHuman,
		ResourceType: "config",
		ResourceID:   "cfg1",
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityLow,
		Source:       "test",
	}))

	// registration token
	rts := mgr.GetRegistrationTokenStore()
	require.NotNil(t, rts, "registration token store")
	require.NoError(t, rts.Initialize(ctx))
	require.NoError(t, rts.SaveToken(ctx, &business.RegistrationTokenData{
		Token:     "token-seed-1",
		TenantID:  "tenant-seed-1",
		CreatedAt: time.Now(),
	}))

	// session
	ss := mgr.GetSessionStore()
	require.NotNil(t, ss, "session store")
	require.NoError(t, ss.Initialize(ctx))
	require.NoError(t, ss.CreateSession(ctx, &business.Session{
		SessionID:    "session-seed-1",
		UserID:       "user-1",
		TenantID:     "tenant-seed-1",
		SessionType:  business.SessionTypeAPI,
		Status:       business.SessionStatusActive,
		Persistent:   true,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}))

	// steward (fleet / DNA)
	stw := mgr.GetStewardStore()
	require.NotNil(t, stw, "steward store")
	require.NoError(t, stw.Initialize(ctx))
	require.NoError(t, stw.RegisterSteward(ctx, &business.StewardRecord{
		ID:           "steward-seed-1",
		TenantID:     "tenant-seed-1",
		Hostname:     "host1.example.com",
		Platform:     "linux",
		Arch:         "amd64",
		Version:      "1.0.0",
		Status:       business.StewardStatusActive,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}))

	// command
	cmds := mgr.GetCommandStore()
	require.NotNil(t, cmds, "command store")
	require.NoError(t, cmds.CreateCommandRecord(ctx, &business.CommandRecord{
		ID:        "cmd-seed-1",
		Type:      "ping",
		StewardID: "steward-seed-1",
		TenantID:  "tenant-seed-1",
		Status:    business.CommandStatusPending,
		IssuedAt:  time.Now(),
	}))

	// trigger
	trig := mgr.GetTriggerStore()
	require.NotNil(t, trig, "trigger store")
	require.NoError(t, trig.StoreTrigger(ctx, &business.TriggerRecord{
		ID:            "trigger-seed-1",
		TenantID:      "tenant-seed-1",
		Name:          "test-trigger",
		Type:          "webhook",
		Status:        "active",
		WorkflowName:  "deploy",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		WebhookPath:   "/hooks/deploy",
		WebhookMethod: []string{"POST"},
	}))

	// push (pending — only pending/in-progress pushes are migratable)
	ps := mgr.GetPushStore()
	require.NotNil(t, ps, "push store")
	require.NoError(t, ps.CreatePush(ctx, &business.PushRecord{
		ID:          "push-seed-1",
		ConfigID:    "cfg1",
		TenantID:    "tenant-seed-1",
		Version:     "v1",
		Status:      business.PushStatusPending,
		InitiatedBy: "user-1",
		Data:        []byte(`{}`),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}))

	// ip trust
	ipts := mgr.GetIPTrustStore()
	require.NotNil(t, ipts, "ip trust store")
	require.NoError(t, ipts.AddTrustedRange(ctx, "tenant-seed-1", "192.168.1.0/24", false))

	// refresh policy (explicit, non-default)
	rps := mgr.GetRefreshPolicyStore()
	require.NotNil(t, rps, "refresh policy store")
	dormancy := 30
	require.NoError(t, rps.SetPolicy(ctx, &business.RefreshPolicy{
		TenantID:        "tenant-seed-1",
		Mode:            "auto_accept",
		MaxDormancyDays: &dormancy,
	}))

	// pending refresh entry
	prs := mgr.GetPendingRefreshStore()
	require.NotNil(t, prs, "pending refresh store")
	require.NoError(t, prs.AddPendingRefresh(ctx, &business.PendingRefreshEntry{
		PendingID:               "pending-refresh-seed-1",
		DeviceID:                "device-seed-1",
		TenantID:                "tenant-seed-1",
		SourceIP:                "10.0.0.1",
		ProvenanceMatchedFields: 4,
		ProvenanceTotalFields:   5,
		Status:                  business.PendingRefreshStatusPending,
		CreatedAt:               time.Now(),
		ExpiresAt:               time.Now().Add(24 * time.Hour),
	}))

	// pending registration entries (one pending, one claimed)
	preg := mgr.GetPendingRegistrationStore()
	require.NotNil(t, preg, "pending registration store")
	require.NoError(t, preg.AddPending(ctx, &business.PendingRegistrationEntry{
		PendingID:    "pending-reg-seed-1",
		StewardID:    "steward-seed-1",
		TenantID:     "tenant-seed-1",
		TokenStr:     "token-seed-1",
		SourceIP:     "10.0.0.2",
		RegisteredAt: time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}))
	claimedAt := time.Now()
	require.NoError(t, preg.AddPending(ctx, &business.PendingRegistrationEntry{
		PendingID:    "pending-reg-seed-2",
		StewardID:    "steward-seed-2",
		TenantID:     "tenant-seed-1",
		TokenStr:     "token-seed-1",
		SourceIP:     "10.0.0.3",
		RegisteredAt: time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		ClaimedAt:    &claimedAt,
		Status:       business.PendingRegistrationStatusClaimed,
	}))

	// RBAC: permission, role, subject, role assignment — exercises all four
	// export/import paths in exportRBAC / importRBAC*.
	rbac := mgr.GetRBACStore()
	require.NotNil(t, rbac, "RBAC store")
	require.NoError(t, rbac.Initialize(ctx))
	require.NoError(t, rbac.StorePermission(ctx, &common.Permission{
		Id:           "perm-seed-1",
		Name:         "steward.register",
		Description:  "Register a steward",
		ResourceType: "steward",
		Actions:      []string{"create"},
	}))
	require.NoError(t, rbac.StoreRole(ctx, &common.Role{
		Id:            "role-seed-1",
		Name:          "seed-role",
		Description:   "Seed role for migration tests",
		PermissionIds: []string{"perm-seed-1"},
	}))
	require.NoError(t, rbac.StoreSubject(ctx, &common.Subject{
		Id:          "subject-seed-1",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "seed-user",
		TenantId:    "tenant-seed-1",
		IsActive:    true,
	}))
	require.NoError(t, rbac.StoreRoleAssignment(ctx, &common.RoleAssignment{
		Id:         "assignment-seed-1",
		SubjectId:  "subject-seed-1",
		RoleId:     "role-seed-1",
		TenantId:   "tenant-seed-1",
		AssignedBy: "test-seeder",
	}))

	// client_tenant — exercises exportClientTenants / importClientTenant.
	cts := mgr.GetClientTenantStore()
	require.NotNil(t, cts, "client tenant store")
	require.NoError(t, cts.StoreClientTenant(&business.ClientTenant{
		ID:               "ct-seed-1",
		TenantID:         "ct-tenant-seed-1",
		TenantName:       "Seed Client Org",
		DomainName:       "seed-client.example.com",
		AdminEmail:       "admin@seed-client.example.com",
		ConsentedAt:      time.Now(),
		Status:           business.ClientTenantStatusActive,
		ClientIdentifier: "seed-client-id-1",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}))
}

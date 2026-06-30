// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

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
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package flatfile

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// TestFlatfileProvider_CreatesOwnerOnlyDirectories pins the owner-only
// contract: every directory the provider creates is 0700 and every file 0600.
// No umask is set; a umask can only clear bits, so exact equality proves the
// mode requested by the code.
func TestFlatfileProvider_CreatesOwnerOnlyDirectories(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "data")
	now := time.Now().UTC()

	alert, err := NewFlatFileAlertStore(root)
	require.NoError(t, err)
	require.NoError(t, alert.AcknowledgeAlert(ctx, "t1", "a1", "admin", now))

	approval, err := NewFlatFileApprovalStore(root)
	require.NoError(t, err)
	require.NoError(t, approval.CreateApproval(ctx, &business.WorkflowApproval{
		TenantID: "t1", ApprovalID: "ap1", Status: business.ApprovalStatusPending,
	}))

	audit, err := NewFlatFileAuditStore(root, 90)
	require.NoError(t, err)
	require.NoError(t, audit.StoreAuditEntry(ctx, &business.AuditEntry{
		TenantID: "t1", UserID: "u1", Action: "read", ResourceType: "cfg", ResourceID: "r1", Timestamp: now,
	}))

	cfg, err := NewFlatFileConfigStore(root)
	require.NoError(t, err)
	require.NoError(t, cfg.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "ns", Name: "n1"},
		Data:   []byte("a: b"),
		Format: cfgconfig.ConfigFormatYAML,
	}))

	ipTrust, err := NewFlatFileIPTrustStore(root)
	require.NoError(t, err)
	require.NoError(t, ipTrust.AddTrustedRange(ctx, "t1", "10.0.0.0/24", true))

	lease, err := NewFlatFileLeaseStore(root)
	require.NoError(t, err)
	_, err = lease.AcquireOrRenew(ctx, "lease1", "holder1", time.Minute)
	require.NoError(t, err)

	node, err := NewFlatFileNodeRegistryStore(root)
	require.NoError(t, err)
	require.NoError(t, node.RegisterNode(ctx, business.NodeRecord{ID: "node1"}))

	nonce, err := NewFlatFileNonceStore(root)
	require.NoError(t, err)
	require.NoError(t, nonce.PutNonce(ctx, "k1", []byte("v"), time.Minute))

	tmpl, err := NewFlatFileReportTemplateStore(root)
	require.NoError(t, err)
	require.NoError(t, tmpl.Save(ctx, "t1", &business.ReportTemplate{
		ID: "11111111-1111-4111-8111-111111111111", Name: "r", TenantID: "t1", CreatedAt: now, UpdatedAt: now,
	}))

	routing, err := NewFlatFileRoutingStore(root)
	require.NoError(t, err)
	require.NoError(t, routing.RecordConnection(ctx, "steward1", "node1"))

	steward, err := NewFlatFileStewardStore(root)
	require.NoError(t, err)
	require.NoError(t, steward.RegisterSteward(ctx, &business.StewardRecord{ID: "steward1", TenantID: "t1"}))

	wf, err := NewFlatFileWorkflowExecutionStore(root)
	require.NoError(t, err)
	require.NoError(t, wf.Save(ctx, &business.WorkflowExecutionRecord{
		TenantID: "t1", ExecutionID: "e1", WorkflowName: "w", StartTime: now,
	}))

	files := 0
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		info, err := d.Info()
		require.NoError(t, err)
		switch {
		case d.IsDir():
			require.Equal(t, fs.FileMode(0o700), info.Mode().Perm(), "directory %s", path)
		case info.Mode().IsRegular():
			files++
			require.Equal(t, fs.FileMode(0o600), info.Mode().Perm(), "file %s", path)
		}
		return nil
	}))
	require.NotZero(t, files, "stores wrote no files")
}

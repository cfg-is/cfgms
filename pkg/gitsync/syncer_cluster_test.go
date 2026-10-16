// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gitsync_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/gitsync"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// Two nodes share one config store and one lease store. Concurrent webhooks for
// one scope, one delivered to each node, must never run the sync in parallel.
func TestWebhookSyncsAcrossNodesNeverRunInParallel(t *testing.T) {
	bareDir, workDir, _ := newTestRepo(t, map[string]string{
		"a.yaml": "a: 1\n",
		"b.yaml": "b: 1\n",
	})
	t.Setenv("GITSYNC_CLUSTER_TEST_SECRET", "s3cret")

	real := pkgtesting.SetupTestStorage(t).GetConfigStore()
	store := &overlapStore{ConfigStore: real}
	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	renew := 200 * time.Millisecond

	binding := gitsync.ScopeBinding{
		TenantPath: "root/test-tenant", Namespace: "policies", OriginURL: bareDir, Branch: "main",
		WebhookSecretRef: "env:GITSYNC_CLUSTER_TEST_SECRET",
	}

	newNode := func(holder string) (*gitsync.WebhookHandler, *gitsync.BindingStore) {
		root := t.TempDir()
		m, err := lease.NewManager(leaseStore, 3*time.Second, renew, renew)
		require.NoError(t, err)
		bindings, err := gitsync.NewBindingStore(root)
		require.NoError(t, err)
		require.NoError(t, bindings.Add(binding))
		syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logging.ForComponent("gitsync-test"),
			gitsync.WithWebhookLeaseRetry(50*time.Millisecond),
			gitsync.WithLeaseJobFactory(func(name string) (lease.SingletonJob, error) {
				return lease.NewSingletonJob(m, name, holder, m.LeaseTTL(), renew, nil)
			}))
		require.NoError(t, err)
		h := gitsync.NewWebhookHandler(syncer, bindings, logging.ForComponent("gitsync-test"))
		t.Cleanup(func() { h.WaitForPendingSyncs(context.Background()) })
		t.Cleanup(syncer.Stop)
		return h, bindings
	}
	hA, bindingsA := newNode("node-a")
	hB, bindingsB := newNode("node-b")

	// Seed the store, then remove b at the origin so each node's sync prunes.
	seed := newTestSyncerOnStore(t, real)
	require.NoError(t, seed.TriggerSync(context.Background(), binding))
	store.maxInFlight.Store(0)
	commitRemoval(t, workDir, map[string]string{"b.yaml": ""}, nil)

	body := buildPushPayload(bareDir, "refs/heads/main")
	var wg sync.WaitGroup
	for _, h := range []*gitsync.WebhookHandler{hA, hB, hA, hB} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
			req.Header.Set("X-Hub-Signature-256", hmacSHA256Signature(body, "s3cret"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusAccepted, rec.Code)
		}()
	}
	wg.Wait()
	hA.WaitForPendingSyncs(context.Background())
	hB.WaitForPendingSyncs(context.Background())

	assert.EqualValues(t, 1, store.maxInFlight.Load(), "webhook syncs of one scope must not run in parallel across nodes")
	assert.NoError(t, getEntry(real, "policies", "a"))
	assert.Error(t, getEntry(real, "policies", "b"))
	head := strings.TrimSpace(runGit(t, workDir, "rev-parse", "HEAD"))
	var synced int
	for _, bs := range []*gitsync.BindingStore{bindingsA, bindingsB} {
		if got, _ := bs.Get("root/test-tenant", "policies"); got.LastSyncedSHA == head {
			synced++
		}
	}
	assert.GreaterOrEqual(t, synced, 1, "at least one node must record the new head")
}

// newTestSyncerOnStore builds a plain syncer over an existing store.
func newTestSyncerOnStore(t *testing.T, store cfgconfig.ConfigStore, opts ...gitsync.Option) *gitsync.Syncer {
	t.Helper()
	root := t.TempDir()
	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)
	syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logging.ForComponent("gitsync-test"), opts...)
	require.NoError(t, err)
	return syncer
}

// A prune records one audit event per deleted entry; entries that stay produce none.
func TestPruneRecordsAuditEvent(t *testing.T) {
	bareDir, workDir, _ := newTestRepo(t, map[string]string{
		"a.yaml": "a: 1\n",
		"b.yaml": "b: 1\n",
		"c.yaml": "c: 1\n",
	})
	auditManager := pkgtesting.SetupTestAuditManager(t)
	store := pkgtesting.SetupTestStorage(t).GetConfigStore()
	syncer := newTestSyncerOnStore(t, store, gitsync.WithAuditManager(auditManager))
	binding := gitsync.ScopeBinding{TenantPath: "root/test-tenant", Namespace: "policies", OriginURL: bareDir, Branch: "main"}
	ctx := context.Background()

	require.NoError(t, syncer.TriggerSync(ctx, binding))
	commitRemoval(t, workDir, map[string]string{"b.yaml": "", "c.yaml": ""}, nil)
	require.NoError(t, syncer.TriggerSync(ctx, binding))
	require.NoError(t, auditManager.Flush(ctx))

	entries, err := auditManager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "root/test-tenant",
		Actions:  []string{"git_sync_config_pruned"},
	})
	require.NoError(t, err)
	require.Len(t, entries, 2)
	names := map[string]bool{}
	for _, e := range entries {
		assert.Equal(t, "config", e.ResourceType)
		names[e.ResourceID] = true
	}
	assert.Equal(t, map[string]bool{"b": true, "c": true}, names)
}

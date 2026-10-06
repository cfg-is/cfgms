// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// twoNodes starts two trigger managers over one shared trigger store and secret
// store — two controller nodes of one cluster. Node B's periodic reconcile runs
// every interval.
func twoNodes(t *testing.T, interval time.Duration) (a, b *TriggerManagerImpl, bWorkflows *TestWorkflowTrigger) {
	t.Helper()
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "triggers.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	store := sm.GetTriggerStore()
	secrets := newTestSecretStore(t)

	a = NewControllerTriggerManager(nil, NewTestWorkflowTrigger())
	a.SetPersistence(store, secrets)
	require.NoError(t, a.Start(context.Background()))
	t.Cleanup(func() { _ = a.Stop(context.Background()) })

	bWorkflows = NewTestWorkflowTrigger()
	b = NewControllerTriggerManager(nil, bWorkflows)
	b.SetPersistence(store, secrets)
	b.syncInterval = interval
	require.NoError(t, b.Start(context.Background()))
	t.Cleanup(func() { _ = b.Stop(context.Background()) })
	return a, b, bWorkflows
}

func scheduledOn(t *testing.T, m *TriggerManagerImpl) map[string]*Trigger {
	t.Helper()
	cs, ok := m.scheduler.(*CronScheduler)
	require.True(t, ok)
	return cs.GetScheduledTriggers()
}

// TestTriggers_ClusterNodesShareTheStore guards Issue #4660: a trigger created,
// changed or deleted through one controller node is seen and (un)registered by
// another node over the shared store — before, each node knew only the triggers
// it had created itself since start, so a schedule never fired when another node
// held the scheduler lease and a webhook was reachable only through its
// creating node.
func TestTriggers_ClusterNodesShareTheStore(t *testing.T) {
	a, b, bWorkflows := twoNodes(t, time.Hour) // reads drive the reconcile here
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-a")

	require.NoError(t, a.CreateTrigger(ctx, &Trigger{
		ID: "nightly", Name: "nightly", Type: TriggerTypeSchedule, Status: TriggerStatusActive, WorkflowName: "backup",
		Schedule: &ScheduleConfig{CronExpression: "0 2 * * *", Enabled: true},
	}))
	got, err := b.GetTrigger(ctx, "nightly")
	require.NoError(t, err, "node B must see a trigger created through node A")
	assert.Equal(t, "0 2 * * *", got.Schedule.CronExpression)
	assert.Contains(t, scheduledOn(t, b), "nightly", "node B must arm the schedule, in case it holds the scheduler lease")

	listed, err := b.ListTriggers(ctx, &TriggerFilter{})
	require.NoError(t, err)
	assert.Len(t, listed, 1)

	// A change made through A reaches B.
	changed := *got
	changed.Schedule = &ScheduleConfig{CronExpression: "30 4 * * *", Enabled: true}
	require.NoError(t, a.UpdateTrigger(ctx, &changed))
	got, err = b.GetTrigger(ctx, "nightly")
	require.NoError(t, err)
	assert.Equal(t, "30 4 * * *", got.Schedule.CronExpression)

	// A webhook created through A is served by B with its credential.
	token := make([]byte, 16)
	_, err = rand.Read(token)
	require.NoError(t, err)
	bearer := hex.EncodeToString(token)
	require.NoError(t, a.CreateTrigger(ctx, &Trigger{
		ID: "on-push", Name: "on-push", Type: TriggerTypeWebhook, Status: TriggerStatusActive, WorkflowName: "deploy",
		Webhook: &WebhookConfig{Path: "/on-push", Authentication: &WebhookAuth{Type: WebhookAuthBearer, BearerToken: bearer}},
	}))
	_, err = b.GetTrigger(ctx, "on-push")
	require.NoError(t, err)
	_, err = b.webhookHandler.HandleWebhook(ctx, "on-push", []byte(`{}`), map[string]string{"Authorization": "Bearer " + bearer})
	require.NoError(t, err, "node B must serve a webhook created through node A")
	require.Eventually(t, func() bool { return len(bWorkflows.GetExecutions()) == 1 }, 5*time.Second, 10*time.Millisecond)

	// A deletion through A unregisters on B.
	require.NoError(t, a.DeleteTrigger(ctx, "nightly"))
	_, err = b.GetTrigger(ctx, "nightly")
	assert.Error(t, err, "node B must drop a trigger deleted through node A")
	assert.NotContains(t, scheduledOn(t, b), "nightly", "node B must disarm the deleted schedule")
}

// TestTriggers_PeriodicReconcileArmsSchedule guards Issue #4660: a node arms a
// schedule created through another node without any request reaching it — the
// node holding the scheduler lease may receive no trigger API traffic at all.
func TestTriggers_PeriodicReconcileArmsSchedule(t *testing.T) {
	a, b, _ := twoNodes(t, 50*time.Millisecond)
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-a")

	require.NoError(t, a.CreateTrigger(ctx, &Trigger{
		ID: "hourly", Name: "hourly", Type: TriggerTypeSchedule, Status: TriggerStatusActive, WorkflowName: "report",
		Schedule: &ScheduleConfig{CronExpression: "0 * * * *", Enabled: true},
	}))
	require.Eventually(t, func() bool {
		b.mutex.RLock()
		defer b.mutex.RUnlock()
		_, ok := scheduledOn(t, b)["hourly"]
		return ok
	}, 5*time.Second, 20*time.Millisecond, "node B must arm the schedule from the store on its own")
}

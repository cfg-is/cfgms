// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// TestRestoredTriggersFire guards Issue #4641: triggers reloaded from the durable
// store after a restart are registered with their handlers and fire — not merely
// listed. A schedule trigger in one tenant and an authenticated webhook trigger in
// another are created through one manager, and a second manager over the same
// trigger store and secret store (the controller after a restart) must have the
// schedule armed with its configuration intact and must run the webhook trigger's
// workflow when its credential is presented. Loading both tenants also pins the
// store's empty-tenant-filter semantics the restart relies on.
func TestRestoredTriggersFire(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "triggers.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	triggerStore := sm.GetTriggerStore()
	require.NotNil(t, triggerStore)
	secrets := newTestSecretStore(t)

	token := make([]byte, 16)
	_, err = rand.Read(token)
	require.NoError(t, err)
	bearer := hex.EncodeToString(token)

	ctxA := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-a")
	ctxB := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-b")

	first := NewControllerTriggerManager(nil, NewTestWorkflowTrigger())
	first.SetPersistence(triggerStore, secrets)
	require.NoError(t, first.Start(context.Background()))
	require.NoError(t, first.CreateTrigger(ctxA, &Trigger{
		ID: "nightly", Name: "nightly", Type: TriggerTypeSchedule, Status: TriggerStatusActive, WorkflowName: "backup",
		Schedule: &ScheduleConfig{CronExpression: "0 2 * * *", Enabled: true},
	}))
	require.NoError(t, first.CreateTrigger(ctxB, &Trigger{
		ID: "on-push", Name: "on-push", Type: TriggerTypeWebhook, Status: TriggerStatusActive, WorkflowName: "deploy",
		Webhook: &WebhookConfig{Path: "/on-push", Authentication: &WebhookAuth{Type: WebhookAuthBearer, BearerToken: bearer}},
	}))
	require.NoError(t, first.Stop(context.Background()))

	workflows := NewTestWorkflowTrigger()
	restarted := NewControllerTriggerManager(nil, workflows)
	restarted.SetPersistence(triggerStore, secrets)
	require.NoError(t, restarted.Start(context.Background()))
	t.Cleanup(func() { _ = restarted.Stop(context.Background()) })

	nightly, err := restarted.GetTrigger(ctxA, "nightly")
	require.NoError(t, err, "tenant-a's trigger must be reloaded")
	assert.Equal(t, TriggerStatusActive, nightly.Status)
	require.NotNil(t, nightly.Schedule, "the schedule configuration must be persisted")
	assert.Equal(t, "0 2 * * *", nightly.Schedule.CronExpression)

	scheduler, ok := restarted.scheduler.(*CronScheduler)
	require.True(t, ok)
	assert.Contains(t, scheduler.GetScheduledTriggers(), "nightly", "the restored schedule trigger must be armed")

	onPush, err := restarted.GetTrigger(ctxB, "on-push")
	require.NoError(t, err, "tenant-b's trigger must be reloaded")
	assert.Equal(t, TriggerStatusActive, onPush.Status)

	_, err = restarted.webhookHandler.HandleWebhook(ctxB, "on-push", []byte(`{}`), map[string]string{"Authorization": "Bearer " + bearer})
	require.NoError(t, err, "the restored webhook trigger must be registered and accept its credential")
	require.Eventually(t, func() bool { return len(workflows.GetExecutions()) == 1 }, 5e9, 1e7,
		"the restored webhook trigger must run its workflow")
}

// TestRestoredTriggerRegistrationFailure_MarkedError guards Issue #4641: a
// restored active trigger that cannot be registered is marked errored, not
// listed as active while nothing would ever run it.
func TestRestoredTriggerRegistrationFailure_MarkedError(t *testing.T) {
	mgr, ts, _ := newManagerWithPersistence(t, "tenant-err")
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-err")
	trig := &Trigger{
		ID: "orphan-schedule", TenantID: "tenant-err", Name: "orphan", Type: TriggerTypeSchedule, Status: TriggerStatusActive,
		WorkflowName: "wf", Schedule: &ScheduleConfig{CronExpression: "0 2 * * *", Enabled: true},
	}
	require.NoError(t, mgr.saveTriggerToStorage(ctx, trig))
	_, err := ts.GetTrigger(ctx, "orphan-schedule")
	require.NoError(t, err)

	// newManagerWithPersistence wires no scheduler, so registration fails.
	require.NoError(t, mgr.loadTriggersFromStorage(ctx))
	got, ok := mgr.triggers["orphan-schedule"]
	require.True(t, ok)
	assert.Equal(t, TriggerStatusError, got.Status)
}

// TestCreateTrigger_RejectsUnsafeID guards Issue #4641: a trigger ID becomes
// part of its credentials' secret names, so one containing a path separator or
// ".." is refused at create.
func TestCreateTrigger_RejectsUnsafeID(t *testing.T) {
	mgr := NewControllerTriggerManager(nil, NewTestWorkflowTrigger())
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-a")
	for _, id := range []string{"a/b", `a\b`, "..", "x..y"} {
		err := mgr.CreateTrigger(ctx, &Trigger{ID: id, Name: "n", Type: TriggerTypeManual, WorkflowName: "wf"})
		assert.Error(t, err, "trigger id %q must be refused", id)
	}
	require.NoError(t, mgr.CreateTrigger(ctx, &Trigger{ID: "nightly-backup_2", Name: "n", Type: TriggerTypeManual, WorkflowName: "wf"}))
}

// TestMarshalTriggerConfig_NoCredentialPersisted guards Issue #4641: the
// persisted trigger configuration never contains a credential value. Every
// string field of WebhookAuth other than the known non-secret settings is filled
// with a marker (so a credential field added later is covered without editing
// this test), along with the basic-auth pair, and the marker must not appear in
// the payload.
func TestMarshalTriggerConfig_NoCredentialPersisted(t *testing.T) {
	const marker = "credential-marker-4641"
	nonSecret := map[string]bool{"Type": true, "SignatureHeader": true, "APIKeyHeader": true}

	auth := &WebhookAuth{Type: WebhookAuthBearer, SignatureHeader: "X-Signature", APIKeyHeader: "X-API-Key"}
	v := reflect.ValueOf(auth).Elem()
	filled := 0
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.Type.Kind() == reflect.String && !nonSecret[field.Name] {
			v.Field(i).SetString(marker)
			filled++
		}
	}
	require.Positive(t, filled, "WebhookAuth must have credential fields to check")
	auth.BasicAuth = &BasicAuth{Username: marker, Password: marker}

	payload, err := marshalTriggerConfig(&Trigger{
		ID: "hook", TenantID: "tenant-a", Type: TriggerTypeWebhook, WorkflowName: "wf",
		Webhook: &WebhookConfig{Path: "/hook", Authentication: auth},
	})
	require.NoError(t, err)
	assert.NotContains(t, string(payload), marker, "no credential value may be persisted in the trigger config")
	assert.Contains(t, string(payload), string(WebhookAuthBearer), "the non-secret auth type is persisted")
}

// TestNestedTenantTriggerCredential_RestoreAndDelete guards Issue #4641 for a
// hierarchical tenant ID ("root/msp-a"): the credential of an authenticated
// webhook trigger is recovered after a restart — the trigger fires — and is
// removed when the trigger is deleted. The combined "<tenant>/<ref>" key the
// plain SecretStore API takes is ambiguous for such a tenant; the manager
// addresses the secret by (tenant, ref) through secretsif.TenantSecretAccessor.
func TestNestedTenantTriggerCredential_RestoreAndDelete(t *testing.T) {
	const tenant = "root/msp-a"
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "triggers.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	triggerStore := sm.GetTriggerStore()
	inner := newTestSecretStore(t)
	accessor, ok := inner.(secretsif.TenantSecretAccessor)
	require.True(t, ok, "the SOPS store must address secrets by tenant")
	secrets := &countingTenantSecretStore{SecretStore: inner, accessor: accessor}

	token := make([]byte, 16)
	_, err = rand.Read(token)
	require.NoError(t, err)
	bearer := hex.EncodeToString(token)
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tenant)

	first := NewControllerTriggerManager(nil, NewTestWorkflowTrigger())
	first.SetPersistence(triggerStore, secrets)
	require.NoError(t, first.Start(context.Background()))
	require.NoError(t, first.CreateTrigger(ctx, &Trigger{
		ID: "msp-hook", Name: "msp-hook", Type: TriggerTypeWebhook, Status: TriggerStatusActive, WorkflowName: "deploy",
		Webhook: &WebhookConfig{Path: "/msp-hook", Authentication: &WebhookAuth{Type: WebhookAuthBearer, BearerToken: bearer}},
	}))
	require.NoError(t, first.Stop(context.Background()))

	workflows := NewTestWorkflowTrigger()
	restarted := NewControllerTriggerManager(nil, workflows)
	restarted.SetPersistence(triggerStore, secrets)
	require.NoError(t, restarted.Start(context.Background()))
	t.Cleanup(func() { _ = restarted.Stop(context.Background()) })

	reloaded, err := restarted.GetTrigger(ctx, "msp-hook")
	require.NoError(t, err, "the nested tenant's trigger must be reloaded with its credential")
	assert.Equal(t, TriggerStatusActive, reloaded.Status)
	_, err = restarted.webhookHandler.HandleWebhook(ctx, "msp-hook", []byte(`{}`), map[string]string{"Authorization": "Bearer " + bearer})
	require.NoError(t, err, "the restored trigger must accept its credential")
	require.Eventually(t, func() bool { return len(workflows.GetExecutions()) == 1 }, 5*time.Second, 10*time.Millisecond)

	ref := triggerCredentialRef("msp-hook", "bearer")
	_, err = accessor.GetTenantSecret(context.Background(), tenant, ref)
	require.NoError(t, err)
	require.NoError(t, restarted.DeleteTrigger(ctx, "msp-hook"))
	_, err = accessor.GetTenantSecret(context.Background(), tenant, ref)
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound, "deleting the trigger must remove its credential")

	assert.Positive(t, secrets.gets.Load(), "credentials must be read by (tenant, ref)")
	assert.Positive(t, secrets.deletes.Load(), "credentials must be deleted by (tenant, ref)")
}

// countingTenantSecretStore is the real SOPS store, counting the tenant-explicit
// calls so the test pins that the manager addresses credentials by (tenant, ref)
// rather than through the combined key.
type countingTenantSecretStore struct {
	secretsif.SecretStore
	accessor secretsif.TenantSecretAccessor
	gets     atomic.Int64
	deletes  atomic.Int64
}

func (s *countingTenantSecretStore) GetTenantSecret(ctx context.Context, tenantID, key string) (*secretsif.Secret, error) {
	s.gets.Add(1)
	return s.accessor.GetTenantSecret(ctx, tenantID, key)
}

func (s *countingTenantSecretStore) DeleteTenantSecret(ctx context.Context, tenantID, key string) error {
	s.deletes.Add(1)
	return s.accessor.DeleteTenantSecret(ctx, tenantID, key)
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// triggerTenantFixture wires the trigger routes the way SetWorkflowHandler does —
// behind the Server's real tenant resolution — over a trigger manager persisting
// to a durable trigger store and the Server's secret store, as the controller
// wires it (Issue #4641).
func triggerTenantFixture(t *testing.T) (*Server, *mux.Router, *trigger.TriggerManagerImpl) {
	server, router, mgr, _ := triggerTenantFixtureWithStore(t)
	return server, router, mgr
}

func triggerTenantFixtureWithStore(t *testing.T) (*Server, *mux.Router, *trigger.TriggerManagerImpl, business.TriggerStore) {
	t.Helper()
	server := setupTestServer(t)
	prepareSelectedTenantServer(t, server)

	triggerStore := pkgtesting.SetupTestStorage(t).GetTriggerStore()
	require.NotNil(t, triggerStore)
	mgr := trigger.NewControllerTriggerManager(nil, nil)
	mgr.SetPersistence(triggerStore, server.secretStore)

	h, _ := newTestWorkflowHandler(t)
	h.triggerAPI = trigger.NewAPIHandler(mgr)
	h.triggerManager = mgr
	h.SetTenantResolution(server.rootTenantID, server.selectAuthorizedTenant)

	router := mux.NewRouter()
	h.RegisterTriggerRoutes(router.PathPrefix("/triggers").Subrouter())
	return server, router, mgr, triggerStore
}

func scheduleTriggerBody(t *testing.T, id string) []byte {
	t.Helper()
	body, err := json.Marshal(trigger.Trigger{
		ID: id, Name: id, Type: trigger.TriggerTypeSchedule, WorkflowName: "nightly",
		Schedule: &trigger.ScheduleConfig{CronExpression: "0 2 * * *", Enabled: true},
	})
	require.NoError(t, err)
	return body
}

func storedTriggerTenant(t *testing.T, mgr *trigger.TriggerManagerImpl, tenantID, id string) (string, error) {
	t.Helper()
	trig, err := mgr.GetTrigger(context.WithValue(context.Background(), ctxkeys.TenantID, tenantID), id)
	if err != nil {
		return "", err
	}
	return trig.TenantID, nil
}

// TestTriggers_RootScoped_UsesRootTenant guards Issue #4640: a root-scoped admin
// can create and list triggers, and they are stored in the root tenant — the
// trigger manager previously refused every root admin with "tenant context
// required".
func TestTriggers_RootScoped_UsesRootTenant(t *testing.T) {
	_, router, mgr := triggerTenantFixture(t)
	caller := rootScopedPrincipal("root-operator-trig")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, requestAsPrincipal(t, http.MethodPost, "/triggers", "", caller, scheduleTriggerBody(t, "root-nightly")))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	tenant, err := storedTriggerTenant(t, mgr, testRootTenantID, "root-nightly")
	require.NoError(t, err)
	assert.Equal(t, testRootTenantID, tenant)

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, requestAsPrincipal(t, http.MethodGet, "/triggers", "", caller, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "root-nightly")
}

// TestTriggers_RootScopedClientTenant_RequiresCrossing guards Issue #4640: a
// root-scoped admin selecting a client tenant with ?tenant= on the trigger routes
// is challenged without a crossing and nothing is created; with one the trigger
// lands in that tenant.
func TestTriggers_RootScopedClientTenant_RequiresCrossing(t *testing.T) {
	server, router, mgr := triggerTenantFixture(t)
	caller := rootScopedPrincipal("root-operator-trig")

	create := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, requestAsPrincipal(t, http.MethodPost, "/triggers?tenant=msp-sel", "", caller, scheduleTriggerBody(t, "client-nightly")))
		return rec
	}

	rec := create()
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
	_, err := storedTriggerTenant(t, mgr, "msp-sel", "client-nightly")
	assert.Error(t, err, "a challenged create must store nothing")

	grantSelectedTenantCrossing(t, server, caller.ID)
	rec = create()
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	tenant, err := storedTriggerTenant(t, mgr, "msp-sel", "client-nightly")
	require.NoError(t, err)
	assert.Equal(t, "msp-sel", tenant)
}

// TestTriggers_UnsetScope_Refused guards Issue #4640: a trigger request whose
// tenant scope was never established is refused before the trigger manager.
func TestTriggers_UnsetScope_Refused(t *testing.T) {
	_, router, _ := triggerTenantFixture(t)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withUnsetTenantScope(httptest.NewRequest(http.MethodGet, "/triggers", nil)))
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

// TestTriggers_PersistAcrossRestart guards Issue #4641: a trigger created through
// the API is in the durable trigger store and a fresh manager — the controller
// after a restart — loads it back. Before, the controller's manager had no store
// and every trigger was lost on restart.
func TestTriggers_PersistAcrossRestart(t *testing.T) {
	server, router, _, triggerStore := triggerTenantFixtureWithStore(t)
	caller := rootScopedPrincipal("root-operator-trig")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, requestAsPrincipal(t, http.MethodPost, "/triggers", "", caller, scheduleTriggerBody(t, "durable-nightly")))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	restarted := trigger.NewControllerTriggerManager(nil, nil)
	restarted.SetPersistence(triggerStore, server.secretStore)
	require.NoError(t, restarted.Start(context.Background()))
	t.Cleanup(func() { _ = restarted.Stop(context.Background()) })

	tenant, err := storedTriggerTenant(t, restarted, testRootTenantID, "durable-nightly")
	require.NoError(t, err, "the trigger must survive a restart")
	assert.Equal(t, testRootTenantID, tenant)
}

// TestTriggers_WebhookCredentialInSecretStore guards Issue #4641: a webhook
// trigger with a bearer credential persists, the credential lives in the secret
// store, and the durable trigger record holds only a reference to it.
func TestTriggers_WebhookCredentialInSecretStore(t *testing.T) {
	server, router, _, triggerStore := triggerTenantFixtureWithStore(t)
	caller := rootScopedPrincipal("root-operator-trig")

	token := make([]byte, 16)
	_, err := rand.Read(token)
	require.NoError(t, err)
	bearer := hex.EncodeToString(token)

	body, err := json.Marshal(trigger.Trigger{
		ID: "hook", Name: "hook", Type: trigger.TriggerTypeWebhook, WorkflowName: "on-push",
		Webhook: &trigger.WebhookConfig{Path: "/hook", Authentication: &trigger.WebhookAuth{Type: trigger.WebhookAuthBearer, BearerToken: bearer}},
	})
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, requestAsPrincipal(t, http.MethodPost, "/triggers", "", caller, body))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	record, err := triggerStore.GetTrigger(context.Background(), "hook")
	require.NoError(t, err)
	require.NotEmpty(t, record.BearerTokenRef, "the record must reference the credential")
	recordJSON, err := json.Marshal(record)
	require.NoError(t, err)
	assert.NotContains(t, string(recordJSON), bearer, "the credential must not be stored in the trigger record")

	secret, err := server.secretStore.GetSecret(context.Background(), testRootTenantID+"/"+record.BearerTokenRef)
	require.NoError(t, err)
	assert.Equal(t, bearer, secret.Value)

	// After a restart the trigger is loaded with its credential recovered from the
	// secret store — not skipped as unrecoverable.
	restarted := trigger.NewControllerTriggerManager(nil, nil)
	restarted.SetPersistence(triggerStore, server.secretStore)
	require.NoError(t, restarted.Start(context.Background()))
	t.Cleanup(func() { _ = restarted.Stop(context.Background()) })
	reloaded, err := restarted.GetTrigger(context.WithValue(context.Background(), ctxkeys.TenantID, testRootTenantID), "hook")
	require.NoError(t, err, "an authenticated webhook trigger must survive a restart")
	require.NotNil(t, reloaded.Webhook)
	require.NotNil(t, reloaded.Webhook.Authentication)
	assert.Equal(t, bearer, reloaded.Webhook.Authentication.BearerToken)
}

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
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
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
	h.SetPermissionCheck(server.requestHoldsPermission)

	router := mux.NewRouter()
	h.RegisterTriggerRoutes(router.PathPrefix("/triggers").Subrouter())
	return server, router, mgr, triggerStore
}

// triggerGateFixture serves the trigger routes the way SetWorkflowHandler does: at
// /api/v1/triggers behind the Server's real requirePermission("trigger", "manage")
// gate (assurance floor and presence tap) and the workflow:execute check. It also
// returns the trigger manager so tests can assert what was, or was not, stored
// (Issue #6488).
func triggerGateFixture(t *testing.T) (*Server, *mux.Router, *trigger.TriggerManagerImpl) {
	server, router, mgr, _ := triggerGateFixtureWithRuns(t)
	return server, router, mgr
}

// recordingWorkflowTrigger is the controller-side seam a trigger fires through. It
// records each run a trigger starts so a test can assert that a refused request
// started nothing.
type recordingWorkflowTrigger struct {
	mu   sync.Mutex
	runs []string
}

func (r *recordingWorkflowTrigger) TriggerWorkflow(_ context.Context, trig *trigger.Trigger, _ map[string]interface{}) (*workflow.WorkflowExecution, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = append(r.runs, trig.ID)
	return &workflow.WorkflowExecution{ID: "exec-" + trig.ID}, nil
}

func (r *recordingWorkflowTrigger) ValidateTrigger(_ context.Context, _ *trigger.Trigger) error {
	return nil
}

func (r *recordingWorkflowTrigger) started() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.runs...)
}

func triggerGateFixtureWithRuns(t *testing.T) (*Server, *mux.Router, *trigger.TriggerManagerImpl, *recordingWorkflowTrigger) {
	t.Helper()
	server := setupTestServer(t)
	prepareSelectedTenantServer(t, server)

	triggerStore := pkgtesting.SetupTestStorage(t).GetTriggerStore()
	require.NotNil(t, triggerStore)
	runs := &recordingWorkflowTrigger{}
	mgr := trigger.NewControllerTriggerManager(nil, runs)
	mgr.SetPersistence(triggerStore, server.secretStore)

	h, _ := newTestWorkflowHandler(t)
	h.triggerAPI = trigger.NewAPIHandler(mgr)
	h.triggerManager = mgr
	h.SetTenantResolution(server.rootTenantID, server.selectAuthorizedTenant)
	h.SetPermissionCheck(server.requestHoldsPermission)

	router := mux.NewRouter()
	sub := router.PathPrefix("/api/v1/triggers").Subrouter()
	sub.Use(server.requirePermission("trigger", "manage"))
	h.RegisterTriggerRoutes(sub)
	return server, router, mgr, runs
}

const triggerGateTenant = "msp-sel"

// triggerGatePrincipal returns a tenant-scoped principal holding exactly perms.
func triggerGatePrincipal(id string, level session.AssuranceLevel, perms ...string) *Principal {
	return &Principal{ID: id, Assurance: level, Permissions: perms, TenantID: triggerGateTenant}
}

// triggerGateRequest builds a request as authenticationMiddleware would hand it to the
// trigger routes: the principal, its tenant scope and ctxkeys.UserIDKey on the context.
func triggerGateRequest(method, path, body string, p *Principal) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, p)
	return req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, p.ID))
}

// tap mints a presence token bound to req and sets it on the request.
func tapTriggerRequest(t *testing.T, server *Server, req *http.Request, p *Principal) {
	t.Helper()
	req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, server, p.ID, req, "trigger:manage"))
}

func storedTriggerIDs(t *testing.T, mgr *trigger.TriggerManagerImpl) []string {
	t.Helper()
	list, err := mgr.ListTriggers(context.WithValue(context.Background(), ctxkeys.TenantID, triggerGateTenant), nil)
	require.NoError(t, err)
	ids := []string{}
	for _, tr := range list {
		ids = append(ids, tr.ID)
	}
	return ids
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

// TestTriggers_CreateRequiresWorkflowExecute guards Issue #6488: a trigger is a
// persistent way to run a workflow, so a principal holding trigger:manage and a
// presence tap but not workflow:execute is refused with 403 on create, update and
// manual execute and nothing is stored; the same principal with workflow:execute
// succeeds. The refusal does not depend on the named workflow.
func TestTriggers_CreateRequiresWorkflowExecute(t *testing.T) {
	server, router, mgr, runs := triggerGateFixtureWithRuns(t)

	manageOnly := triggerGatePrincipal("manage-only", session.AssuranceStrong, "trigger:manage")
	manageAndExecute := triggerGatePrincipal("manage-exec", session.AssuranceStrong, "trigger:manage", "workflow:execute")

	serve := func(method, path string, body []byte, p *Principal) *httptest.ResponseRecorder {
		req := triggerGateRequest(method, path, string(body), p)
		tapTriggerRequest(t, server, req, p)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// Seed a trigger through a principal that is allowed to, so update and execute
	// have a real target.
	rec := serve(http.MethodPost, "/api/v1/triggers", scheduleTriggerBody(t, "seeded"), manageAndExecute)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.Equal(t, []string{"seeded"}, storedTriggerIDs(t, mgr))

	t.Run("create refused without workflow:execute", func(t *testing.T) {
		rec := serve(http.MethodPost, "/api/v1/triggers", scheduleTriggerBody(t, "refused"), manageOnly)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Equal(t, []string{"seeded"}, storedTriggerIDs(t, mgr), "a refused create must store nothing")
	})

	t.Run("refusal does not depend on whether the workflow exists", func(t *testing.T) {
		unknown, err := json.Marshal(trigger.Trigger{
			ID: "ghost", Name: "ghost", Type: trigger.TriggerTypeSchedule, WorkflowName: "no-such-workflow-anywhere",
			Schedule: &trigger.ScheduleConfig{CronExpression: "0 2 * * *", Enabled: true},
		})
		require.NoError(t, err)
		a := serve(http.MethodPost, "/api/v1/triggers", unknown, manageOnly)
		b := serve(http.MethodPost, "/api/v1/triggers", scheduleTriggerBody(t, "other"), manageOnly)
		assert.Equal(t, http.StatusForbidden, a.Code)
		assert.Equal(t, http.StatusForbidden, b.Code)
		assert.Equal(t, a.Body.String(), b.Body.String(), "the refusal body must not vary with the workflow")
	})

	t.Run("update refused without workflow:execute", func(t *testing.T) {
		retarget, err := json.Marshal(trigger.Trigger{
			ID: "seeded", Name: "seeded", Type: trigger.TriggerTypeSchedule, WorkflowName: "somewhere-else",
			Schedule: &trigger.ScheduleConfig{CronExpression: "0 3 * * *", Enabled: true},
		})
		require.NoError(t, err)
		rec := serve(http.MethodPut, "/api/v1/triggers/seeded", retarget, manageOnly)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		got, err := mgr.GetTrigger(context.WithValue(context.Background(), ctxkeys.TenantID, triggerGateTenant), "seeded")
		require.NoError(t, err)
		assert.Equal(t, "nightly", got.WorkflowName, "a refused update must not re-target the trigger")
	})

	t.Run("manual execute refused without workflow:execute", func(t *testing.T) {
		rec := serve(http.MethodPost, "/api/v1/triggers/seeded/execute", []byte(`{}`), manageOnly)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Empty(t, runs.started(), "a refused execute must not start a run")
	})

	t.Run("same principal with workflow:execute succeeds", func(t *testing.T) {
		rec := serve(http.MethodPost, "/api/v1/triggers", scheduleTriggerBody(t, "allowed"), manageAndExecute)
		assert.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

		update, err := json.Marshal(trigger.Trigger{
			ID: "allowed", Name: "allowed", Type: trigger.TriggerTypeSchedule, WorkflowName: "nightly-v2",
			Schedule: &trigger.ScheduleConfig{CronExpression: "0 4 * * *", Enabled: true},
		})
		require.NoError(t, err)
		rec = serve(http.MethodPut, "/api/v1/triggers/allowed", update, manageAndExecute)
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		rec = serve(http.MethodPost, "/api/v1/triggers/allowed/execute", []byte(`{}`), manageAndExecute)
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, []string{"allowed"}, runs.started())
	})

	t.Run("an API key still needs workflow:execute", func(t *testing.T) {
		keyOnly := triggerGatePrincipal("key-manage", session.AssuranceMachine, "trigger:manage")
		rec := serve(http.MethodPost, "/api/v1/triggers", scheduleTriggerBody(t, "key-refused"), keyOnly)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

		keyBoth := triggerGatePrincipal("key-both", session.AssuranceMachine, "trigger:manage", "workflow:execute")
		req := triggerGateRequest(http.MethodPost, "/api/v1/triggers", string(scheduleTriggerBody(t, "key-ok")), keyBoth)
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusCreated, rec.Code, "a machine principal needs no tap: %s", rec.Body.String())
	})

	t.Run("delete and disable need only trigger:manage", func(t *testing.T) {
		rec := serve(http.MethodPost, "/api/v1/triggers/seeded/disable", nil, manageOnly)
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		rec = serve(http.MethodDelete, "/api/v1/triggers/seeded", nil, manageOnly)
		assert.Contains(t, []int{http.StatusOK, http.StatusNoContent}, rec.Code, rec.Body.String())
	})
}

// TestTriggers_WorkflowExecuteFailsClosedWithoutPermissionCheck guards Issue #6488:
// with no permission-check function wired, the workflow:execute check refuses.
func TestTriggers_WorkflowExecuteFailsClosedWithoutPermissionCheck(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	mgr := trigger.NewControllerTriggerManager(nil, nil)
	h.triggerAPI = trigger.NewAPIHandler(mgr)
	h.triggerManager = mgr
	// SetPermissionCheck deliberately not called.

	router := mux.NewRouter()
	h.RegisterTriggerRoutes(router.PathPrefix("/api/v1/triggers").Subrouter())

	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/triggers"},
		{http.MethodPut, "/api/v1/triggers/t1"},
		{http.MethodPost, "/api/v1/triggers/t1/execute"},
	} {
		rec := httptest.NewRecorder()
		// Even a principal that holds workflow:execute is refused: with no check
		// wired there is no way to know, so the route fails closed.
		holder := triggerGatePrincipal("holder", session.AssuranceStrong, "trigger:manage", "workflow:execute")
		router.ServeHTTP(rec, triggerGateRequest(c.method, c.path, `{}`, holder))
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s must fail closed", c.method, c.path)
	}
}

// TestTriggers_RecordsOwnerThroughAPI guards Issue #6488: a trigger created through
// the API records the authenticated principal as its creator (ignoring a body
// value), an update through a different principal keeps the creator and records the
// updater, and both survive a restart.
func TestTriggers_RecordsOwnerThroughAPI(t *testing.T) {
	server, router, mgr := triggerGateFixture(t)
	creator := triggerGatePrincipal("alice", session.AssuranceStrong, "trigger:manage", "workflow:execute")
	updater := triggerGatePrincipal("bob", session.AssuranceStrong, "trigger:manage", "workflow:execute")

	serve := func(method, path string, body []byte, p *Principal) *httptest.ResponseRecorder {
		req := triggerGateRequest(method, path, string(body), p)
		tapTriggerRequest(t, server, req, p)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	spoofed, err := json.Marshal(trigger.Trigger{
		ID: "owned", Name: "owned", Type: trigger.TriggerTypeSchedule, WorkflowName: "nightly", CreatedBy: "mallory",
		Schedule: &trigger.ScheduleConfig{CronExpression: "0 2 * * *", Enabled: true},
	})
	require.NoError(t, err)
	rec := serve(http.MethodPost, "/api/v1/triggers", spoofed, creator)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	update, err := json.Marshal(trigger.Trigger{
		ID: "owned", Name: "owned", Type: trigger.TriggerTypeSchedule, WorkflowName: "nightly",
		Schedule: &trigger.ScheduleConfig{CronExpression: "0 5 * * *", Enabled: true},
	})
	require.NoError(t, err)
	rec = serve(http.MethodPut, "/api/v1/triggers/owned", update, updater)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = serve(http.MethodGet, "/api/v1/triggers/owned", nil, updater)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var got trigger.Trigger
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "alice", got.CreatedBy)
	assert.Equal(t, "bob", got.UpdatedBy)
	assert.False(t, got.Ownerless)
	assert.NotContains(t, rec.Body.String(), "ownerless", "an owned trigger carries no ownerless marker")
	_ = mgr
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	reportapi "github.com/cfgis/cfgms/features/reports/api"
	reportscache "github.com/cfgis/cfgms/features/reports/cache"
	reportsengine "github.com/cfgis/cfgms/features/reports/engine"
	reportsexporters "github.com/cfgis/cfgms/features/reports/exporters"
	reportsprovider "github.com/cfgis/cfgms/features/reports/provider"
	reportstemplates "github.com/cfgis/cfgms/features/reports/templates"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// Issue #4722: the no-leak sweep. It seeds a client tenant below an MSP whose ID
// and name carry a unique marker, issues every crossing-class GET route (see
// rootReadClassification) as a boundary-subject root session with no crossing,
// and fails if any response body contains the marker. The same sweep with an
// active grant on the MSP is allowed to contain it, which proves the sweep can
// see the marker at all.

// sweepMarker is unique enough that no unrelated field of a response can contain it.
const sweepMarker = "zq7leakmarker"

const (
	sweepMSP        = "sweep-msp"
	sweepClient     = "sweep-client-" + sweepMarker
	sweepClientName = "Acme-" + sweepMarker + "-Holdings"
)

// registerOptionalRouteSubsystems wires every subsystem that registers its own
// /api/v1 GET routes after New() returns (rollback, reports, workflows, triggers,
// telemetry), so a route walk or a sweep sees the same route set a production
// controller serves.
func registerOptionalRouteSubsystems(t *testing.T, server *Server, eg *egsqlite.SQLiteEntityGraphProvider) {
	t.Helper()
	logger := logging.NewNoopLogger()
	server.SetRollbackManager(newRollbackStack(t).manager)

	engine := reportsengine.New(reportsprovider.New(eg, logger), reportstemplates.New(logger),
		reportsexporters.New(logger), reportscache.NewMemoryCache(), logger)
	server.SetReportsHandler(reportapi.New(engine, reportsexporters.New(logger), server.controllerService, nil, logger))

	wfEngine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logger, nil, nil, nil, nil, nil)
	server.SetWorkflowHandler(NewWorkflowHandler(wfEngine, pkgtesting.SetupTestStorage(t).GetConfigStore(),
		trigger.NewControllerTriggerManager(nil, nil), logger))

	// The stream itself is out of scope; the route and its tenant wrapper are real.
	server.SetTelemetryHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

// rootReadSweepFixture is a real server (real router, stores and crossing store)
// holding a root steward and, in the client tenant, one record of each kind a
// crossing-class read can return.
type rootReadSweepFixture struct {
	server  *Server
	sessMgr session.Manager
	// vars maps a path variable name to the ID of the client tenant's record.
	vars map[string]string
}

func newRootReadSweepFixture(t *testing.T) *rootReadSweepFixture {
	t.Helper()
	server, certMgr, _ := setupProvisionTestServer(t)
	server = wireCrossingStore(t, server)
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	sessCfg := session.DefaultConfig()
	sessStore := session.NewMemStore(sessCfg, time.Now)
	t.Cleanup(sessStore.Close)
	sessMgr := session.NewManager(sessCfg, sessStore, time.Now)
	server.SetSessionManager(sessMgr)
	sm := pkgtesting.SetupTestStorage(t)

	require.NoError(t, ensureTestRootTenant(ctx, server.tenantManager))
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: sweepMSP, Name: "Sweep-MSP", ParentID: testRootTenantID})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: sweepClient, Name: sweepClientName, ParentID: sweepMSP})
	require.NoError(t, err)

	// Stewards: one root-owned and one client-owned, in the registry, the durable
	// store and the fleet view.
	rootSteward := registerStewardUnderTenant(t, server, testRootTenantID, "sweep-root-host")
	clientSteward := registerStewardUnderTenant(t, server, sweepClient, "sweep-host-"+sweepMarker)
	for id, tn := range map[string]string{rootSteward: testRootTenantID, clientSteward: sweepClient} {
		require.NoError(t, server.stewardStore.RegisterSteward(ctx, &business.StewardRecord{
			ID: id, TenantID: tn, Hostname: "sweep-host-" + tn, Status: business.StewardStatusActive, LastSeen: time.Now().UTC(),
		}))
	}
	now := time.Now()
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: []fleet.StewardData{
		{ID: rootSteward, TenantID: testRootTenantID, Status: "active", LastHeartbeat: now,
			DNAAttributes: map[string]string{"hostname": "sweep-root-host", "os": "linux", "steward.version": "v1.0"}},
		{ID: clientSteward, TenantID: sweepClient, Status: "active", LastHeartbeat: now,
			DNAAttributes: map[string]string{"hostname": "sweep-host-" + sweepMarker, "os": "windows", "steward.version": "v2.0"}},
	}})

	// Account.
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: "sweep-user-" + sweepMarker, TenantID: sweepClient, Permissions: []string{"steward:list"}})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// Command, push, batch job, upgrade, rollout and run.
	commandStore := sm.GetCommandStore()
	require.NotNil(t, commandStore)
	server.SetCommandStore(commandStore)
	require.NoError(t, commandStore.CreateCommandRecord(ctx, &business.CommandRecord{
		ID: "cmd-" + sweepMarker, Type: "sync_config", StewardID: clientSteward, TenantID: sweepClient, IssuedBy: "test"}))
	server.pushStore = sm.GetPushStore()
	createPushRecord(t, server.pushStore, "push-"+sweepMarker, sweepClient, "cfg-"+sweepMarker)
	server.batchJobStore = newTestAPIBatchJobStore()
	require.NoError(t, server.batchJobStore.CreateBatchJob(ctx, &batchjob.BatchJob{
		ID: "job-" + sweepMarker, TenantID: sweepClient, Status: batchjob.BatchJobStatusPending, CreatedAt: now, UpdatedAt: now}))
	server.upgradeStore = newTestUpgradeStore()
	require.NoError(t, server.upgradeStore.CreateUpgrade(ctx, &business.UpgradeRecord{
		ID: "upg-" + sweepMarker, StewardID: clientSteward, TenantID: sweepClient, Version: "v1.0.0", Platform: "linux", Arch: "amd64",
		Status: business.UpgradeStatusCommitted, CreatedAt: now, OperationNonce: make([]byte, 32), BundleSignature: make([]byte, 64)}))
	server.rolloutStore = newTestRolloutStore()
	require.NoError(t, server.rolloutStore.CreateRollout(ctx, &business.RolloutRecord{
		ID: "roll-" + sweepMarker, TenantID: sweepClient, TargetVersion: "v1.0.0", Status: business.RolloutStatusCompleted, StartedAt: now}))
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	runStore := controllerrun.NewRunStoreSQL(db)
	require.NoError(t, runStore.Init(ctx))
	server.runManager = controllerrun.NewManager(runStore, nil)
	require.NoError(t, runStore.CreateRun(&controllerrun.RunRecord{
		RunID: "run-" + sweepMarker, TenantID: sweepClient, CreatedAt: now, Status: controllerrun.RunStatusCompleted, JobCount: 1}))

	// Case, entity and audit entries (one ordinary, one in the Decision 4 carve-out).
	server.SetCasesStore(sm.GetCaseStore())
	caseID := seedCase(t, sm.GetCaseStore(), sweepClient).ID
	eg, err := egsqlite.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = eg.Close() })
	server.SetEntityGraphProvider(eg)
	entityID := "host:" + sweepMarker + "-host"
	reportEntity(t, eg, entityID, sweepClient, "host")
	server.SetDataProvider(reportsprovider.New(eg, logger))
	for action, et := range map[string]business.AuditEventType{
		"sweep.action":    business.AuditEventConfiguration,
		"sweep.authfails": business.AuditEventAuthentication,
	} {
		require.NoError(t, server.auditManager.RecordEvent(ctx, audit.NewEventBuilder().
			Tenant(sweepClient).Type(et).Action(action).
			User("someone", business.AuditUserTypeHuman).Resource("res", "res-id", "res-"+sweepMarker).
			Result(business.AuditResultFailure).Severity(business.AuditSeverityMedium)))
	}
	require.NoError(t, server.auditManager.Flush(ctx))

	// Certificate (owned through its steward), registration token and pending
	// registration, RBAC role, API key, session and cluster.
	clientCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: clientSteward, Organization: "Test CFGMS", ClientID: clientSteward, ValidityDays: 365})
	require.NoError(t, err)
	tokenStore := newTestRegistrationStore(t)
	server.registrationTokenStore = tokenStore
	tok, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID: sweepClient, ControllerURL: "grpc://controller.example.com:7443", Group: "g"})
	require.NoError(t, err)
	require.NoError(t, tokenStore.SaveToken(ctx, tok))
	server.SetPendingStore(sm.GetPendingRegistrationStore())
	require.NoError(t, sm.GetPendingRegistrationStore().AddPending(ctx, &business.PendingRegistrationEntry{
		PendingID: "pending-sweep", StewardID: "steward-pending-sweep", TenantID: sweepClient,
		TokenStr: "tok-sweep", SourceIP: "10.0.0.9", RegisteredAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour), Status: business.PendingRegistrationStatusPending}))
	createRoleForTenant(t, server, sweepClient, "role-sweep", "role-"+sweepMarker)
	createSubjectForTenant(t, server, sweepClient, "subject-sweep", "subject-"+sweepMarker)
	injectAPIKey(server, &APIKey{ID: "key-sweep", Key: "sweep-client-secret", Name: "key-" + sweepMarker,
		TenantID: sweepClient, CreatedAt: time.Now()})
	_, _, err = sessMgr.Issue(ctx, "sweep-client-user", "cli", sweepClient)
	require.NoError(t, err)
	const clusterName = "sweep-cluster"
	seedClusterSteward(t, server, "sweep-cluster-steward", sweepClient, nil,
		clusterFragment(t, clusterName, map[string]string{"csv": "N1"}))

	registerOptionalRouteSubsystems(t, server, eg)

	return &rootReadSweepFixture{server: server, sessMgr: sessMgr, vars: map[string]string{
		"id": clientSteward, "device_id": clientSteward, "steward_id": clientSteward,
		"username": "sweep-user-" + sweepMarker, "eid": entityID, "case_id": caseID,
		"tenant_id": sweepClient, "tenant_path": sweepClient,
		"platform": "linux", "arch": "amd64", "version": "v1.0.0",
		"serial": clientCert.SerialNumber, "token": tok.Token, "name": clusterName,
		"rollback_id": "rollback-unseeded", "exec_id": "exec-unseeded", "execution_id": "exec-unseeded",
		"role_id": "role-sweep",
	}}
}

// rootReadSweepRoute names what one crossing-class route is sent with. A route
// needs an entry here only when the generic per-variable fixtures
// (rootReadSweepFixture.vars) do not fit it.
type rootReadSweepRoute struct {
	// Vars overrides a path variable for this route.
	Vars map[string]string
	// Query is appended to the URL: the client tenant a route is asked about, or a
	// required parameter.
	Query string
}

// rootReadSweepRoutes is the fixtures table for the sweep, keyed by the route's path
// template. Keep it beside rootReadClassification: a new crossing-class route is
// refused by the classification test until it is classified, and by the sweep until
// every path variable it has resolves.
var rootReadSweepRoutes = map[string]rootReadSweepRoute{
	"/api/v1/cases/{id}":                                      {Vars: map[string]string{"id": "$case_id"}},
	"/api/v1/cases/{id}/watch":                                {Vars: map[string]string{"id": "$case_id"}},
	"/api/v1/commands/{id}":                                   {Vars: map[string]string{"id": "cmd-" + sweepMarker}},
	"/api/v1/config/push/{id}":                                {Vars: map[string]string{"id": "push-" + sweepMarker}},
	"/api/v1/jobs/{id}":                                       {Vars: map[string]string{"id": "job-" + sweepMarker}},
	"/api/v1/runs/{run_id}":                                   {Vars: map[string]string{"run_id": "run-" + sweepMarker}},
	"/api/v1/runs/{run_id}/jobs":                              {Vars: map[string]string{"run_id": "run-" + sweepMarker}},
	"/api/v1/rollout/{rollout_id}":                            {Vars: map[string]string{"rollout_id": "roll-" + sweepMarker}},
	"/api/v1/stewards/upgrade/{upgrade_id}":                   {Vars: map[string]string{"upgrade_id": "upg-" + sweepMarker}},
	"/api/v1/rollback/points":                                 {Query: "target_type=device&target_id={id}"},
	"/api/v1/configs":                                         {Query: "tenant_id=" + sweepClient},
	"/api/v1/hyperv/profiles":                                 {Query: "tenant_id=" + sweepClient},
	"/api/v1/installer/artifacts":                             {Query: "tenant_id=" + sweepClient},
	"/api/v1/installer/artifacts/{platform}/{arch}":           {Query: "tenant_id=" + sweepClient},
	"/api/v1/workflows":                                       {Query: "tenant=" + sweepClient},
	"/api/v1/workflows/approvals":                             {Query: "tenant=" + sweepClient},
	"/api/v1/triggers":                                        {Query: "tenant=" + sweepClient},
	"/api/v1/registration/tokens":                             {Query: "tenant_id=" + sweepClient},
	"/api/v1/audit/entries":                                   {Query: "tenant_id=" + sweepClient},
	"/api/v1/rbac/roles/{id}":                                 {Vars: map[string]string{"id": "role-sweep"}},
	"/api/v1/rbac/subjects/{id}/roles":                        {Vars: map[string]string{"id": "subject-sweep"}},
	"/api/v1/api-keys/{id}":                                   {Vars: map[string]string{"id": "key-sweep"}},
	"/api/v1/configs/{id}/deployments":                        {Vars: map[string]string{"id": "cfg-" + sweepMarker}},
	"/api/v1/workflows/{id}":                                  {Vars: map[string]string{"id": "workflow-unseeded"}, Query: "tenant=" + sweepClient},
	"/api/v1/workflows/{id}/executions":                       {Vars: map[string]string{"id": "workflow-unseeded"}, Query: "tenant=" + sweepClient},
	"/api/v1/workflows/{id}/executions/{exec_id}":             {Vars: map[string]string{"id": "workflow-unseeded"}, Query: "tenant=" + sweepClient},
	"/api/v1/triggers/{id}":                                   {Vars: map[string]string{"id": "trigger-unseeded"}, Query: "tenant=" + sweepClient},
	"/api/v1/triggers/{id}/executions":                        {Vars: map[string]string{"id": "trigger-unseeded"}, Query: "tenant=" + sweepClient},
	"/api/v1/hyperv/profiles/{name}":                          {Vars: map[string]string{"name": "profile-unseeded"}, Query: "tenant_id=" + sweepClient},
	"/api/v1/roles/{name}":                                    {Vars: map[string]string{"name": "role-unseeded"}},
	"/api/v1/stewards/{id}/scripts/executions/{execution_id}": {Vars: map[string]string{"execution_id": "exec-" + sweepMarker}},
}

var routeVarPattern = regexp.MustCompile(`\{(\w+)(?::[^}]*)?\}`)

// resolveSweepRoute returns the request URL for a path template, plus the values
// the request itself carries that hold the marker (a response may repeat those
// back without disclosing anything), or an error naming the path variable no
// fixture covers.
func (f *rootReadSweepFixture) resolveSweepRoute(template string) (url string, echoed []string, err error) {
	route := rootReadSweepRoutes[template]
	var missing []string
	resolve := func(s string, overrides map[string]string) string {
		return routeVarPattern.ReplaceAllStringFunc(s, func(m string) string {
			name := routeVarPattern.FindStringSubmatch(m)[1]
			v, ok := overrides[name]
			if key, indirect := strings.CutPrefix(v, "$"); ok && indirect {
				v = f.vars[key]
			}
			if !ok {
				if v, ok = f.vars[name]; !ok {
					missing = append(missing, name)
					return m
				}
			}
			if strings.Contains(v, sweepMarker) {
				echoed = append(echoed, v)
			}
			return v
		})
	}
	url = resolve(template, route.Vars)
	if route.Query != "" {
		url += "?" + resolve(route.Query, route.Vars)
		for _, kv := range strings.Split(route.Query, "&") {
			if _, v, _ := strings.Cut(kv, "="); strings.Contains(v, sweepMarker) {
				echoed = append(echoed, v)
			}
		}
	}
	if len(missing) > 0 {
		return "", nil, &missingSweepVarError{template: template, vars: missing}
	}
	return url, echoed, nil
}

type missingSweepVarError struct {
	template string
	vars     []string
}

func (e *missingSweepVarError) Error() string {
	return "no sweep fixture for path variable(s) " + strings.Join(e.vars, ", ") + " of " + e.template
}

// rootSession returns a bearer token for a fresh root-scope account, elevated to
// AssuranceStrong so every route clears its assurance floor and only the tenant
// decision is in play.
func (f *rootReadSweepFixture) rootSession(t *testing.T, id string) string {
	t.Helper()
	ctx := context.Background()
	f.server.cacheAccount(&account{ID: id, Username: id, RootScope: true})
	sess, _, err := f.sessMgr.Issue(ctx, id, "cfg-cli", testRootTenantID)
	require.NoError(t, err)
	elevated, token, err := f.sessMgr.Elevate(ctx, sess.ID, []byte("sweep-credential"), "192.0.2.1")
	require.NoError(t, err)
	require.Equal(t, session.AssuranceStrong, elevated.Assurance)
	return token
}

func (f *rootReadSweepFixture) get(token, url string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)
	return rec
}

// grantMSP gives every root principal an active MSP-issued grant on the MSP.
func (f *rootReadSweepFixture) grantMSP(t *testing.T) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, f.server.tenantCrossingStore.CreateTenantCrossing(context.Background(), &business.TenantCrossing{
		ID: "sweep-grant", TenantID: sweepMSP, Kind: business.TenantCrossingKindGrant,
		GrantedBy: "sweep-msp-admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
}

// sweepResult is what one crossing-class route answered.
type sweepResult struct {
	route  string
	status int
	leaked bool
}

// sweepCrossingRoutes issues every crossing-class GET route as a boundary-subject
// root session and reports which responses contain the marker.
func sweepCrossingRoutes(t *testing.T, f *rootReadSweepFixture, token string) []sweepResult {
	t.Helper()
	var results []sweepResult
	for _, route := range crossingClassRoutes(t) {
		url, echoed, err := f.resolveSweepRoute(route)
		require.NoError(t, err)
		rec := f.get(token, url)
		body := rec.Body.String()
		for _, v := range echoed {
			body = strings.ReplaceAll(body, v, "")
		}
		results = append(results, sweepResult{
			route: "GET " + url, status: rec.Code,
			leaked: strings.Contains(body, sweepMarker) || strings.Contains(rec.Header().Get("Location"), sweepMarker),
		})
	}
	return results
}

// TestRootReadSweep_NoLeakWithoutCrossing is the strongest guard of the root read
// rule (Issue #4722): a boundary-subject root session with no crossing reads every
// crossing-class route, and nothing in any response carries the client tenant's ID,
// its name, or the ID of any record it owns.
func TestRootReadSweep_NoLeakWithoutCrossing(t *testing.T) {
	f := newRootReadSweepFixture(t)
	token := f.rootSession(t, "sweep-root-none")

	results := sweepCrossingRoutes(t, f, token)
	require.NotEmpty(t, results)
	var leaks []string
	for _, r := range results {
		if r.leaked {
			leaks = append(leaks, r.route)
		}
	}
	sort.Strings(leaks)
	assert.Empty(t, leaks, "a crossing-class route returned the client tenant's marker with no crossing")
}

// TestRootReadSweep_GrantRevealsMarker is the sweep's self-check: with an active
// grant on the MSP the same routes are allowed to carry the marker, and at least one
// does. Without this, a sweep that never reaches the client tenant's data would pass
// for the wrong reason.
func TestRootReadSweep_GrantRevealsMarker(t *testing.T) {
	f := newRootReadSweepFixture(t)
	f.grantMSP(t)
	token := f.rootSession(t, "sweep-root-granted")

	var seen []string
	for _, r := range sweepCrossingRoutes(t, f, token) {
		if r.leaked {
			seen = append(seen, r.route)
		}
	}
	sort.Strings(seen)
	assert.NotEmpty(t, seen, "no crossing-class route returned the marker under an active grant; the sweep cannot see it")
	t.Logf("routes that return the marker under a grant: %d: %v", len(seen), seen)
}

// TestRootReadSweep_EveryCrossingRouteResolves proves each crossing-class route has
// a fixture for every path variable it carries, so adding a route forces a fixture.
func TestRootReadSweep_EveryCrossingRouteResolves(t *testing.T) {
	f := newRootReadSweepFixture(t)
	for _, route := range crossingClassRoutes(t) {
		_, _, err := f.resolveSweepRoute(route)
		assert.NoError(t, err)
	}
	for template := range rootReadSweepRoutes {
		assert.Equal(t, rootReadCrossing, rootReadClassification[template].Class,
			"%s has a sweep fixture but is not crossing-class", template)
	}
}

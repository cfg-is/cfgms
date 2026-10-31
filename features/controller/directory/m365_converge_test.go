// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/workflow/modules/m365"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/entra_group"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/entra_user"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/audit"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	dirif "github.com/cfgis/cfgms/pkg/directory/interfaces"
	egif "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

const (
	cvUserA   = "aaaaaaaa-0000-0000-0000-00000000000a"
	cvUserB   = "bbbbbbbb-0000-0000-0000-00000000000b"
	cvGroupA  = "cccccccc-0000-0000-0000-00000000000c"
	cvUserOth = "dddddddd-0000-0000-0000-00000000000d"
)

type cgUser struct {
	ID, UPN, Name, Dept string
	Enabled             bool
}

type cgGroup struct {
	ID, Name, Desc string
	Members        []string
}

type cgTenant struct {
	users  map[string]*cgUser
	groups map[string]*cgGroup
}

// convGraph is an httptest Graph that serves reads and applies the writes the
// entra modules make, counting every mutating call per Entra app registration.
type convGraph struct {
	srv *httptest.Server

	mu      sync.Mutex
	tenants map[string]*cgTenant
	writes  map[string][]string // client -> "METHOD path"
	nextID  int
}

func newConvGraph(t *testing.T) *convGraph {
	t.Helper()
	g := &convGraph{tenants: map[string]*cgTenant{}, writes: map[string][]string{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *convGraph) tenant(client string) *cgTenant {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tenants[client] == nil {
		g.tenants[client] = &cgTenant{users: map[string]*cgUser{}, groups: map[string]*cgGroup{}}
	}
	return g.tenants[client]
}

func (g *convGraph) writeCount(client string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.writes[client])
}

func (g *convGraph) writeLog(client string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.writes[client]...)
}

func (g *convGraph) user(client, id string) *cgUser {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tenants[client].users[id]
}

func (g *convGraph) group(client, id string) *cgGroup {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tenants[client].groups[id]
}

func (u *cgUser) json() map[string]any {
	return map[string]any{"id": u.ID, "userPrincipalName": u.UPN, "displayName": u.Name,
		"mailNickname": strings.Split(u.UPN, "@")[0], "accountEnabled": u.Enabled, "department": u.Dept}
}

func (gr *cgGroup) json() map[string]any {
	return map[string]any{"id": gr.ID, "displayName": gr.Name, "description": gr.Desc,
		"mailNickname": "nick", "securityEnabled": true}
}

func (g *convGraph) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		_ = r.ParseForm()
		_, _ = w.Write([]byte(`{"access_token":"tok-` + r.PostForm.Get("client_id") + `","token_type":"Bearer","expires_in":3600}`))
		return
	}
	client := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
	g.mu.Lock()
	defer g.mu.Unlock()
	td := g.tenants[client]
	if td == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	notFound := func() {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`))
	}
	if r.Method != http.MethodGet {
		g.writes[client] = append(g.writes[client], r.Method+" "+r.URL.Path)
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case parts[0] == "users" && len(parts) == 2:
		var u *cgUser
		for _, c := range td.users {
			if c.ID == parts[1] || strings.EqualFold(c.UPN, parts[1]) {
				u = c
			}
		}
		if u == nil {
			notFound()
			return
		}
		if r.Method == http.MethodPatch {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if v, ok := body["displayName"].(string); ok {
				u.Name = v
			}
			if v, ok := body["accountEnabled"].(bool); ok {
				u.Enabled = v
			}
			if v, ok := body["department"].(string); ok {
				u.Dept = v
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(u.json())
	case parts[0] == "users" && len(parts) == 1 && r.Method == http.MethodGet:
		out := []map[string]any{}
		for _, u := range td.users {
			out = append(out, u.json())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": out})
	case parts[0] == "users" && len(parts) == 3 && (parts[2] == "licenseDetails" || parts[2] == "memberOf"):
		_, _ = w.Write([]byte(`{"value":[]}`))
	case parts[0] == "groups" && len(parts) == 1 && r.Method == http.MethodGet:
		out := []map[string]any{}
		for _, gr := range td.groups {
			out = append(out, gr.json())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": out})
	case parts[0] == "groups" && len(parts) == 1 && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.nextID++
		id := fmt.Sprintf("eeeeeeee-0000-0000-0000-%012d", g.nextID)
		name, _ := body["displayName"].(string)
		td.groups[id] = &cgGroup{ID: id, Name: name}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(td.groups[id].json())
	case parts[0] == "groups" && len(parts) == 2:
		gr := td.groups[parts[1]]
		if gr == nil {
			notFound()
			return
		}
		if r.Method == http.MethodPatch {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if v, ok := body["displayName"].(string); ok {
				gr.Name = v
			}
			if v, ok := body["description"].(string); ok {
				gr.Desc = v
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(gr.json())
	case parts[0] == "groups" && len(parts) == 3 && parts[2] == "members":
		gr := td.groups[parts[1]]
		out := []map[string]any{}
		if gr != nil {
			for _, m := range gr.Members {
				out = append(out, map[string]any{"id": "x", "userPrincipalName": m})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": out})
	case parts[0] == "groups" && len(parts) == 3 && parts[2] == "owners":
		_, _ = w.Write([]byte(`{"value":[]}`))
	default:
		notFound()
	}
}

// boundFactory is the test tenant-scoped module source: a real entra module per
// request, bound to the tenant it was created for the way the controller's factory
// binds an instance's credential, and recording every request.
type boundFactory struct {
	auth auth.Provider
	gc   graph.Client

	mu    sync.Mutex
	calls [][2]string // module, tenant
}

type tenantBoundModule struct {
	inner  modules.Module
	tenant string
}

func (m *tenantBoundModule) Get(ctx context.Context, id string) (modules.ConfigState, error) {
	return m.inner.Get(context.WithValue(ctx, ctxkeys.TenantID, m.tenant), id)
}

func (m *tenantBoundModule) Set(ctx context.Context, id string, c modules.ConfigState) error {
	return m.inner.Set(context.WithValue(ctx, ctxkeys.TenantID, m.tenant), id, c)
}

func (f *boundFactory) CreateTenantModuleInstance(_ context.Context, name, tenant string) (modules.Module, error) {
	if tenant == "" {
		return nil, fmt.Errorf("module %q requires an execution tenant", name)
	}
	f.mu.Lock()
	f.calls = append(f.calls, [2]string{name, tenant})
	f.mu.Unlock()
	switch name {
	case M365UserModule:
		return &tenantBoundModule{inner: entra_user.New(f.auth, f.gc), tenant: tenant}, nil
	case M365GroupModule:
		return &tenantBoundModule{inner: entra_group.New(f.auth, f.gc), tenant: tenant}, nil
	}
	return nil, fmt.Errorf("module %q is not available", name)
}

func (f *boundFactory) requests() [][2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]string(nil), f.calls...)
}

type svcSource struct {
	svc *service.ConfigurationServiceV2
}

func (s svcSource) EffectiveConfig(ctx context.Context, tenant string) (*stewardtypes.StewardConfig, error) {
	eff, err := s.svc.GetEffectiveConfiguration(ctx, tenant, "")
	if err != nil || eff == nil {
		return nil, err
	}
	return eff.Config, nil
}

// recWriter forwards to the real entity graph and keeps every observation.
type recWriter struct {
	inner ObservationWriter
	mu    sync.Mutex
	obs   []egtypes.Observation
}

func (w *recWriter) ReportObservations(ctx context.Context, b egif.ObservationBatch) error {
	w.mu.Lock()
	w.obs = append(w.obs, b.Observations...)
	w.mu.Unlock()
	return w.inner.ReportObservations(ctx, b)
}

func (w *recWriter) drift() []egtypes.Observation {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []egtypes.Observation
	for _, o := range w.obs {
		if o.Kind == egtypes.ObservationKindDriftDiff {
			out = append(out, o)
		}
	}
	return out
}

type cvEnv struct {
	t       *testing.T
	gr      *convGraph
	secrets tenantMemStore
	svc     *service.ConfigurationServiceV2
	store   cfgconfig.ConfigStore
	mgr     *dirif.DirectoryProviderManager
	factory *boundFactory
	writer  *recWriter
	audit   *audit.Manager
	eg      *egsqlite.SQLiteEntityGraphProvider
}

func newCvEnv(t *testing.T, tenants ...string) *cvEnv {
	t.Helper()
	e := &cvEnv{t: t, gr: newConvGraph(t), secrets: tenantMemStore{testutil.NewMemSecretStore()}}
	sm := pkgtesting.SetupTestStorage(t)
	sys := ctxkeys.WithSystem(context.Background())
	for _, id := range tenants {
		require.NoError(t, sm.GetTenantStore().CreateTenant(sys,
			&business.TenantData{ID: id, Name: id, Status: business.TenantStatusActive}))
	}
	e.svc = service.NewConfigurationServiceV2(logging.NewNoopLogger(), sm, nil)
	t.Cleanup(e.svc.Close)
	e.store = newFlatStore(t)

	logger := logging.NewNoopLogger()
	authp := auth.NewOAuth2Provider(auth.NewSecretStoreCredentialStore(e.secrets), nil, logger)
	gc := graph.NewRateLimitedHTTPClient(graph.WithBaseURL(e.gr.srv.URL))
	e.factory = &boundFactory{auth: authp, gc: gc}
	e.mgr = dirif.NewDirectoryProviderManager(nil)
	entra := m365.NewEntraIDDirectoryProvider(logger, authp, gc)
	require.NoError(t, e.mgr.RegisterProvider(entra.GetProviderInfo().Name, entra, nil))
	t.Cleanup(func() { _ = e.mgr.Close(context.Background()) })

	var err error
	e.eg, err = egsqlite.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.eg.Close() })
	e.writer = &recWriter{inner: e.eg}

	e.audit, err = audit.NewManager(sm.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.audit.Stop(sys) })
	return e
}

func (e *cvEnv) connect(tenant, clientID, guid string) M365Connection {
	e.t.Helper()
	require.NoError(e.t, auth.NewSecretStoreCredentialStore(e.secrets).StoreConfig(tenant, &auth.OAuth2Config{
		ClientID: clientID, ClientSecret: "secret-" + clientID, TenantID: guid,
		AuthorityURL: e.gr.srv.URL, Scopes: []string{"https://graph.microsoft.com/.default"}, UseClientCredentials: true,
	}))
	e.gr.tenant(clientID)
	return M365Connection{Tenant: tenant, EntraTenantID: guid}
}

func (e *cvEnv) declare(tenant string, settings stewardtypes.StewardSettings, res ...stewardtypes.ResourceConfig) {
	e.t.Helper()
	settings.ID = tenant
	cfg := &stewardtypes.StewardConfig{Steward: settings, Resources: res}
	// A tenant-level document, which the effective-config cascade resolves for the tenant.
	key, ok := pkgconfig.TenantLevelConfigKey(pkgconfig.TenantLevelForDepth(0), tenant)
	require.True(e.t, ok)
	data, err := yaml.Marshal(cfg)
	require.NoError(e.t, err)
	require.NoError(e.t, e.svc.GetConfigStore().StoreConfig(ctxkeys.WithSystem(context.Background()), &cfgconfig.ConfigEntry{
		Key: key, Data: data, Format: cfgconfig.ConfigFormatYAML, CreatedBy: "test", UpdatedBy: "test",
	}))
}

func (e *cvEnv) converger() *M365Converge {
	e.t.Helper()
	c, err := NewM365Converge(M365ConvergeConfig{
		Config: svcSource{e.svc}, Modules: e.factory, Providers: e.mgr, Writer: e.writer,
		Store: e.store, Audit: e.audit,
	})
	require.NoError(e.t, err)
	return c
}

func userRes(name, upn string, extra map[string]interface{}) stewardtypes.ResourceConfig {
	cfg := map[string]interface{}{"user_principal_name": upn}
	for k, v := range extra {
		cfg[k] = v
	}
	return stewardtypes.ResourceConfig{Name: name, Module: M365UserModule, Config: cfg}
}

func groupRes(name, display string, extra map[string]interface{}) stewardtypes.ResourceConfig {
	cfg := map[string]interface{}{"display_name": display}
	for k, v := range extra {
		cfg[k] = v
	}
	return stewardtypes.ResourceConfig{Name: name, Module: M365GroupModule, Config: cfg}
}

func (e *cvEnv) outcomes(c *M365Converge, tenant string) map[string]ResourceOutcome {
	e.t.Helper()
	st, ok, err := c.Status(context.Background(), tenant)
	require.NoError(e.t, err)
	require.True(e.t, ok, "a status is recorded")
	out := map[string]ResourceOutcome{}
	for _, r := range st.Resources {
		out[r.Resource] = r
	}
	return out
}

func apply(extra ...func(*stewardtypes.StewardSettings)) stewardtypes.StewardSettings {
	s := stewardtypes.StewardSettings{DriftMode: stewardtypes.DriftModeApply}
	for _, f := range extra {
		f(&s)
	}
	return s
}

func monitor() stewardtypes.StewardSettings {
	return stewardtypes.StewardSettings{DriftMode: stewardtypes.DriftModeMonitor}
}

func TestM365Converge_MonitorModeReportsAndDoesNotSet(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	e.gr.tenant("app-a").users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Alice Changed", Enabled: true}
	e.declare("tenant-a", monitor(),
		userRes("alice", "alice@example.com", map[string]interface{}{"display_name": "Alice", "adopt": true}))

	c := e.converger()
	c.Converge(context.Background(), conn)

	assert.Zero(t, e.gr.writeCount("app-a"), "monitor mode makes no mutating Graph call")
	assert.Equal(t, "Alice Changed", e.gr.user("app-a", cvUserA).Name)
	out := e.outcomes(c, "tenant-a")["alice"]
	assert.Equal(t, ConvergeStateDriftReported, out.State)
	assert.Equal(t, []string{"display_name"}, out.Fields)

	drift := e.writer.drift()
	require.Len(t, drift, 1)
	eid, err := egtypes.NewEID(m365Source, guidA, "user:"+cvUserA)
	require.NoError(t, err)
	assert.Equal(t, eid.String(), drift[0].Subject)
	assert.Equal(t, "alice", drift[0].Payload["resource_id"], "the cfg-declared resource id")
}

func TestM365Converge_ApplyModeRevertsDirectChange(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	e.gr.tenant("app-a").users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Alice", Enabled: true}
	e.declare("tenant-a", apply(),
		userRes("alice", "alice@example.com", map[string]interface{}{"display_name": "Alice", "adopt": true}))

	c := e.converger()
	c.Converge(context.Background(), conn)
	assert.Zero(t, e.gr.writeCount("app-a"), "a matching object is not written")
	assert.Equal(t, ConvergeStateConverged, e.outcomes(c, "tenant-a")["alice"].State)

	// A direct change in M365 is seen on the next pass and reverted.
	e.gr.mu.Lock()
	e.gr.tenants["app-a"].users[cvUserA].Name = "Mallory"
	e.gr.mu.Unlock()
	c.Converge(context.Background(), conn)

	assert.Equal(t, "Alice", e.gr.user("app-a", cvUserA).Name)
	assert.Equal(t, []string{"PATCH /users/" + cvUserA}, e.gr.writeLog("app-a"))
	assert.Equal(t, ConvergeStateReverted, e.outcomes(c, "tenant-a")["alice"].State)
}

func TestM365Converge_UndeclaredObjectNeverWritten(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	td := e.gr.tenant("app-a")
	td.users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Alice Old", Enabled: true}
	td.users[cvUserOth] = &cgUser{ID: cvUserOth, UPN: "bob@example.com", Name: "Bob", Enabled: true}
	td.groups[cvGroupA] = &cgGroup{ID: cvGroupA, Name: "Everyone", Desc: "old"}
	e.declare("tenant-a", apply(),
		userRes("alice", "alice@example.com", map[string]interface{}{"display_name": "Alice", "adopt": true}))

	e.converger().Converge(context.Background(), conn)

	assert.Equal(t, []string{"PATCH /users/" + cvUserA}, e.gr.writeLog("app-a"), "only the declared object is written")
	assert.Equal(t, "Bob", e.gr.user("app-a", cvUserOth).Name)
	assert.Equal(t, "old", e.gr.group("app-a", cvGroupA).Desc)
}

func TestM365Converge_ExistingUnboundUPN_NotAdopted(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	e.gr.tenant("app-a").users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Someone", Enabled: true}
	e.declare("tenant-a", apply(), userRes("alice", "alice@example.com", map[string]interface{}{"display_name": "Alice"}))

	c := e.converger()
	c.Converge(context.Background(), conn)

	assert.Zero(t, e.gr.writeCount("app-a"))
	out := e.outcomes(c, "tenant-a")["alice"]
	assert.Equal(t, ConvergeStateRefused, out.State)
	assert.Contains(t, out.Message, "adopt")
	assert.False(t, c.IsDeclared(kindUser, cvUserA), "an unbound object is not managed")
}

func TestM365Converge_BindsObjectID(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	td := e.gr.tenant("app-a")
	td.users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Alice", Enabled: true}
	e.declare("tenant-a", apply(), userRes("alice", "alice@example.com",
		map[string]interface{}{"display_name": "Alice", "adopt": true}))

	c := e.converger()
	c.Converge(context.Background(), conn)
	assert.True(t, c.IsDeclared(kindUser, cvUserA))

	// The binding persists: a restarted loop still knows it.
	restarted := e.converger()
	assert.True(t, restarted.IsDeclared(kindUser, cvUserA))

	// The UPN now resolves to a different object id (the bound one was deleted and
	// the name re-issued): refused, and nothing is written to the new object.
	e.gr.mu.Lock()
	delete(td.users, cvUserA)
	td.users[cvUserOth] = &cgUser{ID: cvUserOth, UPN: "alice@example.com", Name: "Impostor", Enabled: true}
	e.gr.mu.Unlock()
	restarted.Converge(context.Background(), conn)

	out := e.outcomes(restarted, "tenant-a")["alice"]
	assert.Equal(t, ConvergeStateRefused, out.State)
	assert.Contains(t, out.Message, "different object")
	assert.Zero(t, e.gr.writeCount("app-a"))
	assert.Equal(t, "Impostor", e.gr.user("app-a", cvUserOth).Name)
}

func TestM365Converge_ModuleOverrideBeatsGlobalMode(t *testing.T) {
	e := newCvEnv(t, "tenant-a", "tenant-b")
	connA := e.connect("tenant-a", "app-a", guidA)
	connB := e.connect("tenant-b", "app-b", guidB)
	for _, client := range []string{"app-a", "app-b"} {
		td := e.gr.tenant(client)
		td.users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Drifted", Enabled: true}
		td.groups[cvGroupA] = &cgGroup{ID: cvGroupA, Name: "Staff", Desc: "drifted"}
	}
	decls := []stewardtypes.ResourceConfig{
		userRes("alice", "alice@example.com", map[string]interface{}{"display_name": "Alice", "adopt": true}),
		groupRes("staff", "Staff", map[string]interface{}{"description": "declared", "adopt": true}),
	}
	// Global monitor, users overridden to apply.
	e.declare("tenant-a", stewardtypes.StewardSettings{
		DriftMode:        stewardtypes.DriftModeMonitor,
		ModuleDriftModes: map[string]stewardtypes.DriftMode{M365UserModule: stewardtypes.DriftModeApply},
	}, decls...)
	// Global apply, groups overridden to monitor.
	e.declare("tenant-b", stewardtypes.StewardSettings{
		DriftMode:        stewardtypes.DriftModeApply,
		ModuleDriftModes: map[string]stewardtypes.DriftMode{M365GroupModule: stewardtypes.DriftModeMonitor},
	}, decls...)

	c := e.converger()
	c.Converge(context.Background(), connA)
	c.Converge(context.Background(), connB)

	assert.Equal(t, "Alice", e.gr.user("app-a", cvUserA).Name, "user override applies under global monitor")
	assert.Equal(t, "drifted", e.gr.group("app-a", cvGroupA).Desc, "group follows global monitor")
	assert.Equal(t, "Alice", e.gr.user("app-b", cvUserA).Name, "user follows global apply")
	assert.Equal(t, "drifted", e.gr.group("app-b", cvGroupA).Desc, "group override holds under global apply")
	assert.Equal(t, ConvergeStateDriftReported, e.outcomes(c, "tenant-b")["staff"].State)
}

func TestM365Converge_OneBadResourceDoesNotStopOthers(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	td := e.gr.tenant("app-a")
	td.users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Old", Enabled: true}
	e.declare("tenant-a", apply(),
		userRes("broken", "", nil),
		userRes("ghost", "ghost@example.com", map[string]interface{}{"display_name": "Ghost"}),
		userRes("alice", "alice@example.com", map[string]interface{}{"display_name": "Alice", "adopt": true}))

	c := e.converger()
	c.Converge(context.Background(), conn)

	out := e.outcomes(c, "tenant-a")
	assert.Equal(t, ConvergeStateRefused, out["broken"].State)
	assert.Equal(t, ConvergeStateAbsent, out["ghost"].State)
	assert.Equal(t, ConvergeStateReverted, out["alice"].State)
	assert.Equal(t, "Alice", e.gr.user("app-a", cvUserA).Name)
}

func TestM365Converge_ManagedFlagSetOnInventoryRecord(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	td := e.gr.tenant("app-a")
	td.users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Alice", Enabled: true}
	td.users[cvUserOth] = &cgUser{ID: cvUserOth, UPN: "bob@example.com", Name: "Bob", Enabled: true}
	e.declare("tenant-a", monitor(), userRes("alice", "alice@example.com",
		map[string]interface{}{"display_name": "Alice", "adopt": true}))

	c := e.converger()
	c.Converge(context.Background(), conn)

	// Run the real collector over the same Graph with the loop as its DeclaredSet.
	ie := &invEnv{t: t, fg: nil, secrets: e.secrets, mgr: e.mgr, eg: e.eg, writer: &countingWriter{inner: e.eg},
		store: e.store, conns: &fakeConns{}}
	ie.mem, _ = NewMembership(e.store, nil)
	ie.conns.set(conn)
	coll := ie.collector(ie.job(nil, "n1"), func(cfg *M365InventoryConfig) { cfg.Declared = c })
	require.True(t, coll.RunOnce(context.Background()))

	assert.Equal(t, true, ie.entity("tenant-a", userSubject(guidA, cvUserA)).Entity.Attributes["managed"])
	assert.Equal(t, false, ie.entity("tenant-a", userSubject(guidA, cvUserOth)).Entity.Attributes["managed"])
}

func TestM365Converge_WriteIsAuditedUnderDeclaredResourceID(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	e.gr.tenant("app-a").users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Drift", Enabled: true}
	e.declare("tenant-a", apply(), userRes("alice-declared", "alice@example.com",
		map[string]interface{}{"display_name": "Alice", "adopt": true}))

	c := e.converger()
	c.Converge(context.Background(), conn)
	c.Converge(context.Background(), conn) // converged: no second write

	ctx := context.Background()
	require.NoError(t, e.audit.Flush(ctx))
	entries, err := e.audit.QueryEntries(ctx, &business.AuditFilter{TenantID: "tenant-a", ResourceTypes: []string{M365UserModule}})
	require.NoError(t, err)
	require.Len(t, entries, 1, "one write, one audit event")
	ev := entries[0]
	assert.Equal(t, "alice-declared", ev.ResourceID, "the cfg-declared id, not the Entra object id")
	assert.Equal(t, "controller", ev.UserID)
	assert.Equal(t, "update", ev.Action)
	assert.Equal(t, business.AuditResultSuccess, ev.Result)
	assert.NotContains(t, fmt.Sprint(ev.Details), cvUserA)
}

func TestM365Converge_UsesTenantScopedModuleInstance(t *testing.T) {
	e := newCvEnv(t, "tenant-a", "tenant-b")
	connA := e.connect("tenant-a", "app-a", guidA)
	connB := e.connect("tenant-b", "app-b", guidB)
	e.gr.tenant("app-a").users[cvUserA] = &cgUser{ID: cvUserA, UPN: "alice@example.com", Name: "Old", Enabled: true}
	e.gr.tenant("app-b").users[cvUserB] = &cgUser{ID: cvUserB, UPN: "bob@example.com", Name: "Old", Enabled: true}
	e.declare("tenant-a", apply(), userRes("alice", "alice@example.com", map[string]interface{}{"display_name": "A", "adopt": true}))
	e.declare("tenant-b", apply(), userRes("bob", "bob@example.com", map[string]interface{}{"display_name": "B", "adopt": true}))

	c := e.converger()
	c.Converge(context.Background(), connA)
	c.Converge(context.Background(), connB)

	assert.ElementsMatch(t, [][2]string{
		{M365UserModule, "tenant-a"}, {M365UserModule, "tenant-b"},
	}, e.factory.requests(), "each pass asks for an instance of its own tenant")
	assert.Equal(t, []string{"PATCH /users/" + cvUserA}, e.gr.writeLog("app-a"))
	assert.Equal(t, []string{"PATCH /users/" + cvUserB}, e.gr.writeLog("app-b"))

	// An instance for tenant A cannot be pointed at tenant B's Entra tenant.
	inst, err := e.factory.CreateTenantModuleInstance(context.Background(), M365UserModule, "tenant-a")
	require.NoError(t, err)
	_, err = inst.Get(context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-b"), guidB+":bob@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
	assert.Equal(t, 1, e.gr.writeCount("app-b"), "no further write reached tenant B")

	// A tenant-less request is refused outright.
	_, err = e.factory.CreateTenantModuleInstance(context.Background(), M365UserModule, "")
	require.Error(t, err)
}

func TestM365Converge_GroupCreatedInApplyAndBound(t *testing.T) {
	e := newCvEnv(t, "tenant-a")
	conn := e.connect("tenant-a", "app-a", guidA)
	e.declare("tenant-a", apply(), groupRes("staff", "Staff", map[string]interface{}{"description": "d"}))

	c := e.converger()
	c.Converge(context.Background(), conn)

	assert.Equal(t, ConvergeStateCreated, e.outcomes(c, "tenant-a")["staff"].State)
	require.Len(t, e.gr.tenant("app-a").groups, 1)
	for id := range e.gr.tenant("app-a").groups {
		assert.True(t, c.IsDeclared(kindGroup, id))
	}
}

func TestM365Converge_NeverPassesGroupsToUser(t *testing.T) {
	spec, err := newResourceSpec(userRes("alice", "alice@example.com", map[string]interface{}{
		"display_name": "Alice", "groups": []string{"g1"}, "licenses": []string{"x"},
		"password_profile": map[string]interface{}{"password": "p"},
	}), guidA)
	require.NoError(t, err)
	m := spec.state(nil).AsMap()
	for _, k := range []string{"groups", "licenses", "password_profile"} {
		assert.NotContains(t, m, k)
	}
	assert.Equal(t, []string{"display_name"}, m["managed_fields"])
}

func TestM365Inventory_AfterTenantRunsOncePerTenantUnderTheLease(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	seedSmall(e.fg, "client-b")
	e.conns.set(e.connect("tenant-a", "client-a", guidA), e.connect("tenant-b", "client-b", guidB))

	var mu sync.Mutex
	var ran []string
	c := e.collector(e.job(nil, "n1"), func(cfg *M365InventoryConfig) {
		cfg.AfterTenant = func(_ context.Context, conn M365Connection) {
			mu.Lock()
			ran = append(ran, conn.Tenant)
			mu.Unlock()
		}
	})
	require.True(t, c.RunOnce(context.Background()))
	assert.ElementsMatch(t, []string{"tenant-a", "tenant-b"}, ran)

	// A node that does not hold the lease runs neither the inventory nor the hook.
	store := newLeaseStore(t)
	m1, err := lease.NewManager(store, 30*time.Second, 5*time.Second, 5*time.Second)
	require.NoError(t, err)
	m2, err := lease.NewManager(store, 30*time.Second, 5*time.Second, 5*time.Second)
	require.NoError(t, err)
	leader := e.collector(e.job(m1, "node-1"))
	follower := e.collector(e.job(m2, "node-2"), func(cfg *M365InventoryConfig) {
		cfg.AfterTenant = func(context.Context, M365Connection) { t.Error("hook ran without the lease") }
	})
	require.True(t, leader.RunOnce(context.Background()))
	assert.False(t, follower.RunOnce(context.Background()))
}

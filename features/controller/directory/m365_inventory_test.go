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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	dirif "github.com/cfgis/cfgms/pkg/directory/interfaces"
	egif "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/testutil"
)

const (
	guidA = "11111111-1111-1111-1111-111111111111"
	guidB = "22222222-2222-2222-2222-222222222222"
)

type gUser struct{ ID, UPN, Name string }
type gMember struct{ ID, Type, Name string }

// gTenant is one Entra tenant's directory as the fake Graph serves it.
type gTenant struct {
	users   []gUser
	groups  map[string]string // id -> display name
	members map[string][]gMember
	status  int // non-zero: every Graph call fails with it
}

// fakeGraph is an httptest server standing in for the token authority and Graph.
// The bearer token names the app registration, which selects the Entra tenant.
type fakeGraph struct {
	srv *httptest.Server

	mu            sync.Mutex
	tenants       map[string]*gTenant // by client id
	tokenClients  []string
	memberOfCalls int
	memberCalls   map[string]int
	maxPage       int
}

func newFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()
	f := &fakeGraph{tenants: map[string]*gTenant{}, memberCalls: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGraph) tenant(client string) *gTenant {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tenants[client] == nil {
		f.tenants[client] = &gTenant{groups: map[string]string{}, members: map[string][]gMember{}}
	}
	return f.tenants[client]
}

func (f *fakeGraph) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		_ = r.ParseForm()
		c := r.PostForm.Get("client_id")
		f.mu.Lock()
		f.tokenClients = append(f.tokenClients, c)
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"access_token":"tok-` + c + `","token_type":"Bearer","expires_in":3600}`))
		return
	}
	client := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
	f.mu.Lock()
	defer f.mu.Unlock()
	td := f.tenants[client]
	if td == nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Forbidden","message":"no such app"}}`))
		return
	}
	if td.status != 0 {
		w.WriteHeader(td.status)
		_, _ = w.Write([]byte(`{"error":{"code":"Forbidden","message":"denied for tenant secret-detail"}}`))
		return
	}
	top, _ := strconv.Atoi(r.URL.Query().Get("$top"))
	if top <= 0 {
		top = 100
	}
	if f.maxPage > 0 && top > f.maxPage {
		top = f.maxPage
	}
	off, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))

	page := func(n int, item func(i int) map[string]any) {
		end := off + top
		if end > n {
			end = n
		}
		vals := make([]map[string]any, 0, end-off)
		for i := off; i < end; i++ {
			vals = append(vals, item(i))
		}
		out := map[string]any{"value": vals}
		if end < n {
			q := r.URL.Query()
			q.Set("$skiptoken", strconv.Itoa(end))
			out["@odata.nextLink"] = f.srv.URL + r.URL.Path + "?" + q.Encode()
		}
		_ = json.NewEncoder(w).Encode(out)
	}

	switch {
	case r.URL.Path == "/users":
		page(len(td.users), func(i int) map[string]any {
			u := td.users[i]
			return map[string]any{"id": u.ID, "userPrincipalName": u.UPN, "displayName": u.Name, "accountEnabled": true}
		})
	case r.URL.Path == "/groups":
		ids := sortedKeys(td.groups)
		page(len(ids), func(i int) map[string]any {
			return map[string]any{"id": ids[i], "displayName": td.groups[ids[i]], "securityEnabled": true}
		})
	case strings.HasPrefix(r.URL.Path, "/groups/") && strings.HasSuffix(r.URL.Path, "/members"):
		gid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/groups/"), "/members")
		f.memberCalls[gid]++
		ms := td.members[gid]
		page(len(ms), func(i int) map[string]any {
			m := ms[i]
			return map[string]any{"id": m.ID, "@odata.type": "#microsoft.graph." + m.Type, "displayName": m.Name}
		})
	case strings.HasSuffix(r.URL.Path, "/memberOf"):
		f.memberOfCalls++
		_, _ = w.Write([]byte(`{"value":[]}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f *fakeGraph) tokenClientsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tokenClients...)
}

func (f *fakeGraph) calls() (memberOf int, members map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	members = map[string]int{}
	for k, v := range f.memberCalls {
		members[k] = v
	}
	return f.memberOfCalls, members
}

type fakeConns struct {
	mu    sync.Mutex
	conns []M365Connection
}

func (c *fakeConns) set(conns ...M365Connection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns = conns
}

func (c *fakeConns) M365Connections(context.Context) ([]M365Connection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]M365Connection(nil), c.conns...), nil
}

// countingWriter forwards to the real entity graph and counts the writes.
type countingWriter struct {
	inner   ObservationWriter
	batches atomic.Int64
	obs     atomic.Int64
}

func (w *countingWriter) ReportObservations(ctx context.Context, b egif.ObservationBatch) error {
	w.batches.Add(1)
	w.obs.Add(int64(len(b.Observations)))
	return w.inner.ReportObservations(ctx, b)
}

func (w *countingWriter) reset() { w.batches.Store(0); w.obs.Store(0) }

// tenantMemStore addresses secrets by the explicit (tenant, key) pair, the way the
// controller's SOPS store does, over the in-memory store.
type tenantMemStore struct{ *testutil.MemSecretStore }

func (s tenantMemStore) GetTenantSecret(ctx context.Context, tenantID, key string) (*secretsif.Secret, error) {
	sec, err := s.GetSecret(ctx, tenantID+"/"+key)
	if err != nil {
		return nil, err
	}
	sec.TenantID = tenantID
	return sec, nil
}

func (s tenantMemStore) DeleteTenantSecret(ctx context.Context, tenantID, key string) error {
	return s.DeleteSecret(ctx, tenantID+"/"+key)
}

type invEnv struct {
	t       *testing.T
	fg      *fakeGraph
	secrets tenantMemStore
	mgr     *dirif.DirectoryProviderManager
	eg      *egsqlite.SQLiteEntityGraphProvider
	writer  *countingWriter
	store   cfgconfig.ConfigStore
	mem     *Membership
	conns   *fakeConns
	events  []SecurityEvent
	evMu    sync.Mutex
}

func newInvEnv(t *testing.T) *invEnv { return newInvEnvOn(t, newFlatStore(t)) }

// newInvEnvOn runs the env over store; the scale tests use the in-memory store the
// membership scale tests use, since an fsync-per-write file store cannot reach 60,000
// member records in a CI time bound.
func newInvEnvOn(t *testing.T, store cfgconfig.ConfigStore) *invEnv {
	t.Helper()
	e := &invEnv{t: t, fg: newFakeGraph(t), secrets: tenantMemStore{testutil.NewMemSecretStore()}, conns: &fakeConns{}}

	logger := logging.NewNoopLogger()
	e.mgr = dirif.NewDirectoryProviderManager(nil)
	entra := m365.NewEntraIDDirectoryProvider(logger,
		auth.NewOAuth2Provider(auth.NewSecretStoreCredentialStore(e.secrets), nil, logger),
		graph.NewRateLimitedHTTPClient(graph.WithBaseURL(e.fg.srv.URL)))
	require.NoError(t, e.mgr.RegisterProvider(entra.GetProviderInfo().Name, entra, nil))
	t.Cleanup(func() { _ = e.mgr.Close(context.Background()) })

	var err error
	e.eg, err = egsqlite.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.eg.Close() })
	e.writer = &countingWriter{inner: e.eg}

	e.store = store
	e.mem, err = NewMembership(e.store, nil)
	require.NoError(t, err)
	return e
}

// connect seeds a CFGMS tenant's M365 connection (app registration clientID, Entra
// tenant guid) and registers it with the connection source.
func (e *invEnv) connect(tenant, clientID, guid string) M365Connection {
	e.t.Helper()
	require.NoError(e.t, auth.NewSecretStoreCredentialStore(e.secrets).StoreConfig(tenant, &auth.OAuth2Config{
		ClientID: clientID, ClientSecret: "secret-" + clientID, TenantID: guid,
		AuthorityURL: e.fg.srv.URL, Scopes: []string{"https://graph.microsoft.com/.default"}, UseClientCredentials: true,
	}))
	return M365Connection{Tenant: tenant, EntraTenantID: guid}
}

func (e *invEnv) job(mgr *lease.Manager, holder string) lease.SingletonJob {
	e.t.Helper()
	if mgr == nil {
		j, err := lease.NewSingletonJob(nil, "m365-inventory", holder, 0, 0, nil)
		require.NoError(e.t, err)
		return j
	}
	j, err := lease.NewSingletonJob(mgr, "m365-inventory", holder, 30*time.Second, 5*time.Second, nil)
	require.NoError(e.t, err)
	return j
}

func (e *invEnv) collector(job lease.SingletonJob, mut ...func(*M365InventoryConfig)) *M365Inventory {
	e.t.Helper()
	cfg := M365InventoryConfig{
		Providers: e.mgr, ProviderName: "entraid", Connections: e.conns, Writer: e.writer,
		Membership: e.mem, Store: e.store, Job: job, Jitter: -1,
		OnSecurity: func(_ context.Context, ev SecurityEvent) {
			e.evMu.Lock()
			e.events = append(e.events, ev)
			e.evMu.Unlock()
		},
	}
	for _, m := range mut {
		m(&cfg)
	}
	c, err := NewM365Inventory(cfg)
	require.NoError(e.t, err)
	return c
}

func (e *invEnv) securityEvents() []SecurityEvent {
	e.evMu.Lock()
	defer e.evMu.Unlock()
	return append([]SecurityEvent(nil), e.events...)
}

func (e *invEnv) entities(tenant, guid, kind string) map[string]*egtypes.EntityView {
	e.t.Helper()
	out := map[string]*egtypes.EntityView{}
	tok := ""
	for {
		page, err := e.eg.QueryEntities(context.Background(), egif.EntityFilter{
			TenantFilter: tenant, SubjectPrefix: "m365:" + guid + "/", Kind: kind,
		}, egif.PageToken{Token: tok, PageSize: 500})
		require.NoError(e.t, err)
		for _, v := range page.Entities {
			out[v.Entity.EID.String()] = v
		}
		if page.NextToken == "" {
			return out
		}
		tok = page.NextToken
	}
}

func (e *invEnv) entity(tenant, subject string) *egtypes.EntityView {
	e.t.Helper()
	eid, err := egtypes.ParseEID(subject)
	require.NoError(e.t, err)
	v, err := e.eg.GetEntity(context.Background(), eid, egif.GetEntityOpts{TenantFilter: tenant})
	require.NoError(e.t, err)
	return v
}

func userSubject(guid, id string) string  { return "m365:" + guid + "/user:" + id }
func groupSubject(guid, id string) string { return "m365:" + guid + "/group:" + id }

func objID(prefix string, n int) string { return fmt.Sprintf("%s-%06d", prefix, n) }

func seedSmall(f *fakeGraph, client string) {
	td := f.tenant(client)
	td.users = []gUser{{"u1", "u1@a.test", "User One"}, {"u2", "u2@a.test", "User Two"}}
	td.groups = map[string]string{"g1": "Group One", "g2": "Group Two"}
	td.members = map[string][]gMember{
		"g1": {{"u1", "user", "User One"}, {"u2", "user", "User Two"}, {"g2", "group", "Group Two"}},
		"g2": {{"u1", "user", "User One"}},
	}
}

func TestM365Inventory_RecordsUsersGroupsAndMembership(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	c := e.collector(e.job(nil, "n1"))

	require.True(t, c.RunOnce(context.Background()))

	users := e.entities("root/tenant-a", guidA, "")
	require.Len(t, users, 4, "two users and two groups")
	require.Contains(t, users, userSubject(guidA, "u1"))
	u1 := e.entity("root/tenant-a", userSubject(guidA, "u1"))
	assert.Equal(t, "root/tenant-a", u1.Entity.OwningTenant)
	assert.Equal(t, "m365", u1.Entity.Attributes["source"])
	assert.Equal(t, "u1@a.test", u1.Entity.Attributes["user_principal_name"])
	assert.Equal(t, false, u1.Entity.Attributes["managed"])
	assert.Equal(t, "directory_user:u1", u1.Entity.Attributes["fragment_id"])
	assert.Len(t, u1.Entity.Attributes["fragment_hash"], 64)
	assert.ElementsMatch(t, []interface{}{"g1", "g2"}, u1.Entity.Attributes["member_of"].([]interface{}))

	g2 := e.entity("root/tenant-a", groupSubject(guidA, "g2"))
	assert.ElementsMatch(t, []interface{}{"g1"}, g2.Entity.Attributes["member_of"].([]interface{}), "a group that is a member of a group is recorded")

	ms, err := e.mem.ListMembers(context.Background(), "root/tenant-a", "m365:"+guidA, "g1", "", 100)
	require.NoError(t, err)
	got := map[string]MemberType{}
	for _, m := range ms.Members {
		got[m.ID] = m.Type
	}
	assert.Equal(t, map[string]MemberType{"u1": MemberTypeUser, "u2": MemberTypeUser, "g2": MemberTypeGroup}, got)

	st, ok, err := c.Status(context.Background(), "root/tenant-a")
	require.NoError(t, err)
	require.True(t, ok)
	assert.False(t, st.Stale)
	assert.Equal(t, 2, st.Users)
	assert.Equal(t, 2, st.Groups)
}

func TestM365Inventory_UnchangedTenantWritesNothing(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	c := e.collector(e.job(nil, "n1"))

	require.True(t, c.RunOnce(context.Background()))
	require.Positive(t, e.writer.obs.Load())
	e.writer.reset()

	require.True(t, c.RunOnce(context.Background()))
	assert.Zero(t, e.writer.batches.Load(), "an unchanged tenant must not call the entity graph")

	// One changed user writes exactly that object.
	e.fg.mu.Lock()
	e.fg.tenant2("client-a").users[0].Name = "Renamed"
	e.fg.mu.Unlock()
	require.True(t, c.RunOnce(context.Background()))
	assert.EqualValues(t, 1, e.writer.obs.Load())
}

func (f *fakeGraph) tenant2(client string) *gTenant { return f.tenants[client] }

func TestM365Inventory_RestartDoesNotRewrite(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	require.True(t, e.collector(e.job(nil, "n1")).RunOnce(context.Background()))
	e.writer.reset()

	restarted := e.collector(e.job(nil, "n1")) // a fresh process: no in-memory state
	require.True(t, restarted.RunOnce(context.Background()))
	assert.Zero(t, e.writer.batches.Load(), "the persisted manifest must prevent a rewrite after restart")
}

func TestM365Inventory_RemovedUserIsRetracted(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	c := e.collector(e.job(nil, "n1"))
	require.True(t, c.RunOnce(context.Background()))
	require.Contains(t, e.entities("root/tenant-a", guidA, ""), userSubject(guidA, "u2"))

	e.fg.mu.Lock()
	td := e.fg.tenants["client-a"]
	td.users = td.users[:1]
	delete(td.groups, "g2")
	td.members = map[string][]gMember{"g1": {{"u1", "user", "User One"}}}
	e.fg.mu.Unlock()
	e.writer.reset()
	require.True(t, c.RunOnce(context.Background()))

	left := e.entities("root/tenant-a", guidA, "")
	assert.NotContains(t, left, userSubject(guidA, "u2"))
	assert.NotContains(t, left, groupSubject(guidA, "g2"))
	assert.Contains(t, left, userSubject(guidA, "u1"))

	// The removed group's members are logged as removed.
	page, err := e.mem.ListChanges(context.Background(), "root/tenant-a", ChangeQuery{Authority: "m365:" + guidA, GroupID: "g2", IncludeBaseline: true, Limit: 100})
	require.NoError(t, err)
	assert.Equal(t, 1, opCount(page.Events, OpRemoved))
}

func TestM365Inventory_FailedEnumerationRetractsNothing(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	c := e.collector(e.job(nil, "n1"))
	require.True(t, c.RunOnce(context.Background()))
	before := e.entities("root/tenant-a", guidA, "")

	e.fg.mu.Lock()
	e.fg.tenants["client-a"].status = http.StatusForbidden
	e.fg.mu.Unlock()
	e.writer.reset()
	require.True(t, c.RunOnce(context.Background()))

	assert.Equal(t, len(before), len(e.entities("root/tenant-a", guidA, "")), "nothing retracted")
	assert.Zero(t, e.writer.batches.Load())
	st, ok, err := c.Status(context.Background(), "root/tenant-a")
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, st.Stale)
	assert.NotEmpty(t, st.Error)
	assert.LessOrEqual(t, len(st.Error), 256)

	// A recovered Graph clears the flag.
	e.fg.mu.Lock()
	e.fg.tenants["client-a"].status = 0
	e.fg.mu.Unlock()
	require.True(t, c.RunOnce(context.Background()))
	st, _, _ = c.Status(context.Background(), "root/tenant-a")
	assert.False(t, st.Stale)
	assert.Empty(t, st.Error)
}

func TestM365Inventory_TwoTenantsIsolated(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	tb := e.fg.tenant("client-b")
	tb.users = []gUser{{"b1", "b1@b.test", "Bee"}}
	tb.groups = map[string]string{"bg": "B Group"}
	tb.members = map[string][]gMember{"bg": {{"b1", "user", "Bee"}}}
	a := e.connect("root/tenant-a", "client-a", guidA)
	b := e.connect("root/tenant-b", "client-b", guidB)
	e.conns.set(a, b)
	c := e.collector(e.job(nil, "n1"))

	// A failing tenant does not stop the other.
	e.fg.mu.Lock()
	e.fg.tenants["client-a"].status = http.StatusForbidden
	e.fg.mu.Unlock()
	require.True(t, c.RunOnce(context.Background()))
	assert.Len(t, e.entities("root/tenant-b", guidB, ""), 2)
	assert.Empty(t, e.entities("root/tenant-a", guidA, ""))

	e.fg.mu.Lock()
	e.fg.tenants["client-a"].status = 0
	e.fg.mu.Unlock()
	require.True(t, c.RunOnce(context.Background()))

	assert.Len(t, e.entities("root/tenant-a", guidA, ""), 4)
	for subj, v := range e.entities("root/tenant-a", guidA, "") {
		assert.Equal(t, "root/tenant-a", v.Entity.OwningTenant, subj)
	}
	for subj, v := range e.entities("root/tenant-b", guidB, "") {
		assert.Equal(t, "root/tenant-b", v.Entity.OwningTenant, subj)
	}
	// Tenant B's view never contains tenant A's objects.
	assert.Empty(t, e.entities("root/tenant-b", guidA, ""))
	// Each run read only its own tenant's credential.
	assert.ElementsMatch(t, []string{"client-a", "client-b"}, uniq(e.fg.tokenClientsSeen()))
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func TestM365Inventory_SameEntraTenantTwoCfgmsTenants_NeitherCollected(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.fg.tenants["client-x"] = e.fg.tenants["client-a"]
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA), e.connect("root/tenant-x", "client-x", strings.ToUpper(guidA)))
	c := e.collector(e.job(nil, "n1"))

	require.True(t, c.RunOnce(context.Background()))
	require.True(t, c.RunOnce(context.Background()))

	assert.Empty(t, e.entities("root/tenant-a", guidA, ""))
	assert.Empty(t, e.entities("root/tenant-x", guidA, ""))
	assert.Zero(t, e.writer.batches.Load())
	assert.Empty(t, e.fg.tokenClientsSeen(), "no Graph credential is used for a contested Entra tenant")

	evs := e.securityEvents()
	require.Len(t, evs, 1, "raised once, not once per cycle")
	assert.Equal(t, SecurityEventSameEntraTenant, evs[0].Kind)
	assert.Equal(t, guidA, evs[0].EntraTenantID)
	assert.Equal(t, []string{"root/tenant-a", "root/tenant-x"}, evs[0].Tenants)
}

func TestM365Inventory_OnlyLeaderCollects(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))

	store := newLeaseStore(t)
	m1, err := lease.NewManager(store, 30*time.Second, 5*time.Second, 5*time.Second)
	require.NoError(t, err)
	m2, err := lease.NewManager(store, 30*time.Second, 5*time.Second, 5*time.Second)
	require.NoError(t, err)
	c1 := e.collector(e.job(m1, "node-1"))
	c2 := e.collector(e.job(m2, "node-2"))

	assert.True(t, c1.RunOnce(context.Background()))
	e.writer.reset()
	assert.False(t, c2.RunOnce(context.Background()), "the follower must not collect while the leader's lease is live")
	assert.Zero(t, e.writer.batches.Load())
	assert.Len(t, e.entities("root/tenant-a", guidA, ""), 4)
}

func TestM365Inventory_50000Users_OneChange_WritesOneObject(t *testing.T) {
	e := newInvEnv(t)
	td := e.fg.tenant("client-a")
	for i := 0; i < 50000; i++ {
		td.users = append(td.users, gUser{objID("u", i), fmt.Sprintf("u%d@a.test", i), "User " + strconv.Itoa(i)})
	}
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	c := e.collector(e.job(nil, "n1"))

	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	require.True(t, c.RunOnce(ctx))
	require.EqualValues(t, 50000, e.writer.obs.Load())
	e.writer.reset()

	e.fg.mu.Lock()
	td.users[12345].Name = "Changed"
	e.fg.mu.Unlock()
	require.True(t, c.RunOnce(ctx))
	assert.EqualValues(t, 1, e.writer.obs.Load())
	assert.EqualValues(t, 1, e.writer.batches.Load())
}

func TestM365Inventory_GroupWith60000Members_AllRecorded(t *testing.T) {
	e := newInvEnvOn(t, newMemStore())
	td := e.fg.tenant("client-a")
	td.groups = map[string]string{"big": "Big Group"}
	for i := 0; i < 60000; i++ {
		id := objID("u", i)
		// Only the first 10 members are also listed as users: the test is about
		// the member set, and each listed user costs an entity graph write.
		if i < 10 {
			td.users = append(td.users, gUser{id, id + "@a.test", id})
		}
		td.members["big"] = append(td.members["big"], gMember{id, "user", id})
	}
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	c := e.collector(e.job(nil, "n1"))

	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	require.True(t, c.RunOnce(ctx))

	_, members := e.fg.calls()
	assert.Equal(t, 61, members["big"], "one paged members call per page of 999")
	total, cursor := 0, ""
	for {
		page, err := e.mem.ListMembers(ctx, "root/tenant-a", "m365:"+guidA, "big", cursor, 1000)
		require.NoError(t, err)
		total += len(page.Members)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	assert.Equal(t, 60000, total)
	u := e.entity("root/tenant-a", userSubject(guidA, objID("u", 9)))
	assert.Equal(t, []interface{}{"big"}, u.Entity.Attributes["member_of"])
}

func TestM365Inventory_UserIn300Groups_AllRecorded(t *testing.T) {
	e := newInvEnvOn(t, newMemStore())
	td := e.fg.tenant("client-a")
	td.users = []gUser{{"u1", "u1@a.test", "One"}}
	td.groups = map[string]string{}
	for i := 0; i < 300; i++ {
		gid := objID("g", i)
		td.groups[gid] = gid
		td.members[gid] = []gMember{{"u1", "user", "One"}}
	}
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	require.True(t, e.collector(e.job(nil, "n1")).RunOnce(context.Background()))

	u := e.entity("root/tenant-a", userSubject(guidA, "u1"))
	assert.Len(t, u.Entity.Attributes["member_of"], 300)
	assert.Nil(t, u.Entity.Attributes["member_of_truncated"])
	page, err := e.mem.ListGroupsOf(context.Background(), "root/tenant-a", "m365:"+guidA, "u1", "", 1000)
	require.NoError(t, err)
	assert.Len(t, page.GroupIDs, 300)
}

func TestM365Inventory_MemberRemovedInGraph_LogsRemovedEvent(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	c := e.collector(e.job(nil, "n1"))
	require.True(t, c.RunOnce(context.Background()))

	e.fg.mu.Lock()
	e.fg.tenants["client-a"].members["g1"] = []gMember{{"u1", "user", "User One"}, {"g2", "group", "Group Two"}}
	e.fg.mu.Unlock()
	require.True(t, c.RunOnce(context.Background()))

	page, err := e.mem.ListChanges(context.Background(), "root/tenant-a", ChangeQuery{Authority: "m365:" + guidA, GroupID: "g1", Limit: 100})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	assert.Equal(t, OpRemoved, page.Events[0].Op)
	assert.Equal(t, "u2", page.Events[0].MemberID)
	u2 := e.entity("root/tenant-a", userSubject(guidA, "u2"))
	assert.Empty(t, u2.Entity.Attributes["member_of"])
}

func TestM365Inventory_MemberOfDerivedFromGroupEnumeration_NoPerUserMemberOfCalls(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	require.True(t, e.collector(e.job(nil, "n1")).RunOnce(context.Background()))

	memberOf, members := e.fg.calls()
	assert.Zero(t, memberOf)
	assert.Equal(t, map[string]int{"g1": 1, "g2": 1}, members)
}

func TestM365Inventory_GroupWithDeviceAndServicePrincipalMembers_PassedWithTypeIDName(t *testing.T) {
	e := newInvEnv(t)
	td := e.fg.tenant("client-a")
	td.users = []gUser{{"u1", "u1@a.test", "One"}}
	td.groups = map[string]string{"g1": "G"}
	td.members["g1"] = []gMember{
		{"u1", "user", "One"}, {"d1", "device", "Laptop 7"}, {"sp1", "servicePrincipal", "Backup App"},
		{"c1", "orgContact", "Contact"}, {"x1", "somethingNew", "Other thing"},
	}
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	require.True(t, e.collector(e.job(nil, "n1")).RunOnce(context.Background()))

	page, err := e.mem.ListMembers(context.Background(), "root/tenant-a", "m365:"+guidA, "g1", "", 100)
	require.NoError(t, err)
	got := map[string]Member{}
	for _, m := range page.Members {
		got[m.ID] = m
	}
	require.Len(t, got, 5)
	assert.Equal(t, MemberTypeDevice, got["d1"].Type)
	assert.Equal(t, "Laptop 7", got["d1"].DisplayName)
	assert.Equal(t, MemberTypeServicePrincipal, got["sp1"].Type)
	assert.Equal(t, "Backup App", got["sp1"].DisplayName)
	assert.Equal(t, MemberTypeContact, got["c1"].Type)
	assert.Equal(t, MemberTypeOther, got["x1"].Type)

	all := e.entities("root/tenant-a", guidA, "")
	assert.Len(t, all, 2, "non-user, non-group members do not become fragments")
}

func TestM365Inventory_MemberOfTruncatedBeyondLimit(t *testing.T) {
	groups := make([]string, MaxMemberOf+5)
	for i := range groups {
		groups[i] = objID("g", i)
	}
	st := fragState{}
	memberOfAttrs(st, groups)
	assert.Len(t, st[attrMemberOf], MaxMemberOf)
	assert.Equal(t, true, st[attrMemberOfTruncated])

	st = fragState{}
	memberOfAttrs(st, groups[:3])
	assert.Nil(t, st[attrMemberOfTruncated])
}

type declaredFn func(kind, id string) bool

func (f declaredFn) IsDeclared(kind, id string) bool { return f(kind, id) }

func TestM365Inventory_DeclaredSetMarksManaged(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	c := e.collector(e.job(nil, "n1"), func(cfg *M365InventoryConfig) {
		cfg.Declared = declaredFn(func(kind, id string) bool { return kind == "directory_user" && id == "u1" })
	})
	require.True(t, c.RunOnce(context.Background()))
	assert.Equal(t, true, e.entity("root/tenant-a", userSubject(guidA, "u1")).Entity.Attributes["managed"])
	assert.Equal(t, false, e.entity("root/tenant-a", userSubject(guidA, "u2")).Entity.Attributes["managed"])
}

func TestM365Inventory_ExistingSubjectOwnerNeverChanges(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	require.True(t, e.collector(e.job(nil, "n1")).RunOnce(context.Background()))

	// A different CFGMS tenant later claims the same Entra tenant on its own.
	e.fg.tenants["client-z"] = e.fg.tenants["client-a"]
	e.conns.set(e.connect("root/tenant-z", "client-z", guidA))
	require.True(t, e.collector(e.job(nil, "n2")).RunOnce(context.Background()))
	for subj, v := range e.entities("root/tenant-a", guidA, "") {
		assert.Equal(t, "root/tenant-a", v.Entity.OwningTenant, subj)
	}
	assert.Empty(t, e.entities("root/tenant-z", guidA, ""))
}

func TestM365Inventory_FirstRunJitteredPerTenant(t *testing.T) {
	e := newInvEnv(t)
	seedSmall(e.fg, "client-a")
	e.conns.set(e.connect("root/tenant-a", "client-a", guidA))
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	c := e.collector(e.job(nil, "n1"), func(cfg *M365InventoryConfig) {
		cfg.Jitter = 10 * time.Minute
		cfg.Interval = time.Hour
		cfg.Now = func() time.Time { return now }
	})
	c.started = start
	off := c.jitterFor("root/tenant-a")
	require.Less(t, off, 10*time.Minute)
	assert.Equal(t, off, c.jitterFor("root/tenant-a"), "stable per tenant")

	c.cfg.Job.RunIfLeader(context.Background(), func(ctx context.Context) { c.collect(ctx, false) })
	if off > 0 {
		assert.Zero(t, e.writer.batches.Load(), "not due before its jittered offset")
	}
	now = start.Add(off)
	c.cfg.Job.RunIfLeader(context.Background(), func(ctx context.Context) { c.collect(ctx, false) })
	assert.Positive(t, e.writer.batches.Load())
	e.writer.reset()
	now = now.Add(30 * time.Minute)
	c.cfg.Job.RunIfLeader(context.Background(), func(ctx context.Context) { c.collect(ctx, false) })
	assert.Zero(t, e.writer.batches.Load(), "not due again before the interval")
}

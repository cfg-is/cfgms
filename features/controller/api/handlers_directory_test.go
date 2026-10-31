// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/directory"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ---- fixtures ----

// dirMemStore is a real in-memory conditional config store. It lets the 60,000-member
// tests run at full scale; the file-backed store fsyncs every entry.
type dirMemStore struct {
	cfgconfig.ConfigStore // unused operations panic on the nil interface
	mu                    sync.Mutex
	entries               map[string]*cfgconfig.ConfigEntry
}

func newDirMemStore() *dirMemStore {
	return &dirMemStore{entries: map[string]*cfgconfig.ConfigEntry{}}
}

func dirClone(e *cfgconfig.ConfigEntry) *cfgconfig.ConfigEntry {
	c := *e
	k := *e.Key
	c.Key = &k
	c.Data = append([]byte(nil), e.Data...)
	c.Tags = append([]string(nil), e.Tags...)
	return &c
}

func (s *dirMemStore) StoreConfig(_ context.Context, e *cfgconfig.ConfigEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := dirClone(e)
	c.Version = 1
	if old, ok := s.entries[e.Key.String()]; ok {
		c.Version = old.Version + 1
	}
	s.entries[e.Key.String()] = c
	return nil
}

func (s *dirMemStore) GetConfig(_ context.Context, k *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[k.String()]
	if !ok {
		return nil, cfgconfig.ErrConfigNotFound
	}
	return dirClone(e), nil
}

func (s *dirMemStore) DeleteConfig(_ context.Context, k *cfgconfig.ConfigKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, k.String())
	return nil
}

func (s *dirMemStore) CompareAndSwapConfig(_ context.Context, e *cfgconfig.ConfigEntry, expected int64) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cur int64
	if old, ok := s.entries[e.Key.String()]; ok {
		cur = old.Version
	}
	if cur != expected {
		return cur, false, nil
	}
	c := dirClone(e)
	c.Version = cur + 1
	s.entries[e.Key.String()] = c
	return c.Version, true, nil
}

func (s *dirMemStore) ListConfigs(_ context.Context, f *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*cfgconfig.ConfigEntry
	for _, e := range s.entries {
		if f.TenantID != "" && e.Key.TenantID != f.TenantID {
			continue
		}
		if f.Namespace != "" && e.Key.Namespace != f.Namespace {
			continue
		}
		out = append(out, dirClone(e))
	}
	return out, nil
}

type dirOwners map[string]string

func (o dirOwners) Owner(_ context.Context, domain string) (string, bool, error) {
	t, ok := o[domain]
	return t, ok, nil
}

type dirClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *dirClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *dirClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const (
	dirAuthA = "directory:a.example"
	dirAuthB = "directory:b.example"
)

type dirFixture struct {
	t     *testing.T
	eg    *sqlite.SQLiteEntityGraphProvider
	srv   *Server
	mem   *directory.Membership
	clock *dirClock
}

func newDirFixture(t *testing.T) *dirFixture {
	t.Helper()
	eg := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, eg)
	clock := &dirClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	mem, err := directory.NewMembership(newDirMemStore(),
		dirOwners{"a.example": "tenant-a", "b.example": "tenant-b"}, directory.WithClock(clock.now))
	require.NoError(t, err)
	srv.SetDirectoryMembershipStore(mem)
	return &dirFixture{t: t, eg: eg, srv: srv, mem: mem, clock: clock}
}

// report stores one directory entity as the entity graph holds it.
func (f *dirFixture) report(eid, tenant, kind string, attrs map[string]interface{}) {
	f.t.Helper()
	now := time.Now().UTC()
	payload := map[string]interface{}{"entity_kind": kind, "owning_tenant": tenant}
	for k, v := range attrs {
		payload[k] = v
	}
	require.NoError(f.t, f.eg.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test:reporter",
		Observations: []egtypes.Observation{{
			Source: "test:reporter", ObservedAt: now, RecordedAt: now, Subject: eid,
			Kind: egtypes.ObservationKindState, Confidence: egtypes.ConfidenceHigh, Payload: payload,
		}},
	}), "report %s", eid)
}

func (f *dirFixture) user(authority, tenant, id string, attrs map[string]interface{}) {
	f.t.Helper()
	f.report(authority+"/user:"+id, tenant, "user", attrs)
}

func (f *dirFixture) group(authority, tenant, id string, attrs map[string]interface{}) {
	f.t.Helper()
	f.report(authority+"/group:"+id, tenant, "group", attrs)
}

func (f *dirFixture) key(perms []string, tenant string) string {
	return NewEphemeralTestKey(f.t, f.srv, perms, tenant, 5*time.Minute)
}

func (f *dirFixture) get(apiKey, path string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

func (f *dirFixture) batch(authority string, ups []directory.Fragment) {
	f.t.Helper()
	_, err := f.mem.ApplyBatch(context.Background(), "steward-1", authority, ups, nil)
	require.NoError(f.t, err)
}

func dirUserFrag(id string, groups ...string) directory.Fragment {
	return directory.Fragment{Kind: egtypes.KindDirectoryUser, ObjectID: id, Attributes: map[string]any{"member_of": groups}}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), "body: %s", rec.Body.String())
	return m
}

func itemIDs(t *testing.T, body map[string]interface{}) []string {
	t.Helper()
	items, _ := body["items"].([]interface{})
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.(map[string]interface{})["id"].(string))
	}
	return ids
}

var dirRead = []string{"directory:read"}

// ---- permissions and parameter bounds ----

func TestDirectory_ViewerRoleHasReadPermission_NonDirectoryRoleDoesNot(t *testing.T) {
	f := newDirFixture(t)
	f.user(dirAuthA, "tenant-a", "u1", map[string]interface{}{"display_name": "Ann"})
	assert.True(t, knownPermissions["directory:read"], "directory:read must be a grantable permission")

	viewer := f.key(dirRead, "tenant-a")
	other := f.key([]string{"entity:list", "entity:read", "steward:list"}, "tenant-a")

	for _, path := range []string{
		"/api/v1/directory/users",
		"/api/v1/directory/groups",
		"/api/v1/directory/users/ad/u1",
		"/api/v1/directory/users/ad/u1/groups",
		"/api/v1/directory/groups/ad/g1/members",
		"/api/v1/directory/groups/ad/g1/membership-changes",
	} {
		assert.NotEqual(t, http.StatusForbidden, f.get(viewer, path).Code, "viewer must reach %s", path)
		assert.Equal(t, http.StatusForbidden, f.get(other, path).Code, "non-directory role must be refused %s", path)
		unauth := httptest.NewRecorder()
		f.srv.router.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, http.StatusUnauthorized, unauth.Code, path)
	}
	assert.Equal(t, http.StatusOK, f.get(viewer, "/api/v1/directory/users/ad/u1").Code)
}

func TestDirectoryUsers_QueryParamBounds(t *testing.T) {
	f := newDirFixture(t)
	key := f.key(dirRead, "tenant-a")
	f.user(dirAuthA, "tenant-a", "u1", map[string]interface{}{"display_name": "Ann"})

	bad := map[string]string{
		"limit zero":       "limit=0",
		"limit too large":  "limit=501",
		"limit negative":   "limit=-1",
		"limit not number": "limit=abc",
		"q too long":       "q=" + strings.Repeat("a", 257),
		"q bad charset":    "q=" + url.QueryEscape("<script>"),
		"q wildcard":       "q=" + url.QueryEscape("a%"),
		"q control":        "q=" + url.QueryEscape("a\x00b"),
		"unknown source":   "source=ldap",
		"enabled invalid":  "enabled=maybe",
		"managed invalid":  "managed=1",
		"garbage token":    "page_token=!!notatoken!!",
		"foreign token":    "page_token=" + strings.Repeat("A", 4096),
	}
	for name, qs := range bad {
		rec := f.get(key, "/api/v1/directory/users?"+qs)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
	}
	assert.Equal(t, http.StatusBadRequest, f.get(key, "/api/v1/directory/groups?enabled=true").Code, "enabled is for users")

	for _, qs := range []string{"limit=1", "limit=500", "q=" + strings.Repeat("a", 256), "q=ann+o%27brien%40x.example", "source=m365", "enabled=false", "managed=true"} {
		rec := f.get(key, "/api/v1/directory/users?"+qs)
		assert.Equal(t, http.StatusOK, rec.Code, "%s: %s", qs, rec.Body.String())
	}

	for _, p := range []string{
		"/api/v1/directory/users/ldap/u1", "/api/v1/directory/users/ad/" + strings.Repeat("a", 65),
		"/api/v1/directory/users/ad/u%201", "/api/v1/directory/users/ad/u1?authority=a%2Fb",
	} {
		assert.Equal(t, http.StatusBadRequest, f.get(key, p).Code, p)
	}
}

// ---- tenant scoping ----

func TestDirectoryUsers_ListIsTenantScoped(t *testing.T) {
	f := newDirFixture(t)
	f.user(dirAuthA, "tenant-a", "a-1", map[string]interface{}{"display_name": "Alice A"})
	f.user(dirAuthA, "tenant-a", "a-2", map[string]interface{}{"display_name": "Alan A"})
	f.user(dirAuthB, "tenant-b", "b-1", map[string]interface{}{"display_name": "Bob B"})
	f.group(dirAuthB, "tenant-b", "b-g", map[string]interface{}{"display_name": "B Group"})

	rec := f.get(f.key(dirRead, "tenant-a"), "/api/v1/directory/users")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"a-1", "a-2"}, itemIDs(t, decodeBody(t, rec)))

	rec = f.get(f.key(dirRead, "tenant-b"), "/api/v1/directory/users")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"b-1"}, itemIDs(t, decodeBody(t, rec)))

	rec = f.get(f.key(dirRead, "tenant-a"), "/api/v1/directory/groups")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, itemIDs(t, decodeBody(t, rec)), "tenant-a must not see tenant-b's group")

	// A page token minted for one tenant is refused for another.
	f.user(dirAuthA, "tenant-a", "a-3", nil)
	rec = f.get(f.key(dirRead, "tenant-a"), "/api/v1/directory/users?limit=1")
	require.Equal(t, http.StatusOK, rec.Code)
	tok, _ := decodeBody(t, rec)["next_page_token"].(string)
	require.NotEmpty(t, tok)
	rec = f.get(f.key(dirRead, "tenant-b"), "/api/v1/directory/users?limit=1&page_token="+url.QueryEscape(tok))
	assert.Equal(t, http.StatusBadRequest, rec.Code, "a token bound to tenant-a must not work for tenant-b")
}

func TestDirectoryUser_ByID_OtherTenant_404(t *testing.T) {
	f := newDirFixture(t)
	f.user(dirAuthB, "tenant-b", "secret-user", map[string]interface{}{"display_name": "Bob B"})
	f.group(dirAuthB, "tenant-b", "secret-group", map[string]interface{}{"display_name": "Secret"})
	f.batch(dirAuthB, []directory.Fragment{dirUserFrag("secret-user", "secret-group")})

	key := f.key(dirRead, "tenant-a")
	missing := f.get(key, "/api/v1/directory/users/ad/nobody")
	require.Equal(t, http.StatusNotFound, missing.Code)

	for _, p := range []string{
		"/api/v1/directory/users/ad/secret-user",
		"/api/v1/directory/users/ad/secret-user?authority=b.example",
		"/api/v1/directory/users/ad/secret-user/groups",
		"/api/v1/directory/users/ad/secret-user/groups?authority=b.example",
		"/api/v1/directory/groups/ad/secret-group",
		"/api/v1/directory/groups/ad/secret-group/members?authority=b.example",
		"/api/v1/directory/groups/ad/secret-group/membership-changes?authority=b.example",
	} {
		rec := f.get(key, p)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s must be 404, not 403: %s", p, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "secret", "no existence signal in %s", p)
		if !strings.Contains(p, "?") {
			assert.JSONEq(t, stripTimestamp(t, missing.Body.String()), stripTimestamp(t, rec.Body.String()),
				"a hidden object must look exactly like a missing one: %s", p)
		}
	}
	// The owner still reads it.
	assert.Equal(t, http.StatusOK, f.get(f.key(dirRead, "tenant-b"), "/api/v1/directory/users/ad/secret-user").Code)
}

func stripTimestamp(t *testing.T, body string) string {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(body), &m))
	delete(m, "timestamp")
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return string(b)
}

func TestDirectoryUsers_ExcludesHostLocalUsers(t *testing.T) {
	f := newDirFixture(t)
	f.user(dirAuthA, "tenant-a", "dir-user", map[string]interface{}{"display_name": "Dir"})
	f.user("m365:0f0e0d0c-0000-0000-0000-000000000001", "tenant-a", "cloud-user", map[string]interface{}{"display_name": "Cloud"})
	f.report("host:steward-9/user:alice", "tenant-a", "user", map[string]interface{}{"display_name": "Local alice"})
	f.report("host:steward-9/user:bob", "tenant-a", "user", nil)

	key := f.key(dirRead, "tenant-a")
	rec := f.get(key, "/api/v1/directory/users")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.ElementsMatch(t, []string{"dir-user", "cloud-user"}, itemIDs(t, decodeBody(t, rec)))

	rec = f.get(key, "/api/v1/directory/users?source=ad")
	assert.Equal(t, []string{"dir-user"}, itemIDs(t, decodeBody(t, rec)))
	rec = f.get(key, "/api/v1/directory/users?source=m365")
	assert.Equal(t, []string{"cloud-user"}, itemIDs(t, decodeBody(t, rec)))

	for _, p := range []string{"/api/v1/directory/users/ad/alice", "/api/v1/directory/users/m365/alice", "/api/v1/directory/users/ad/bob"} {
		assert.Equal(t, http.StatusNotFound, f.get(key, p).Code, "host-local user %s is not a directory object", p)
	}
}

// ---- listing: filters, paging, fields ----

func TestDirectoryUsers_FiltersAndPaging(t *testing.T) {
	f := newDirFixture(t)
	f.user(dirAuthA, "tenant-a", "u1", map[string]interface{}{"display_name": "Ann Lee", "mail": "ann@a.example", "enabled": true, "managed": true})
	f.user(dirAuthA, "tenant-a", "u2", map[string]interface{}{"display_name": "Bo Lee", "sam_account_name": "blee", "enabled": false, "managed": false})
	f.user(dirAuthA, "tenant-a", "u3", map[string]interface{}{"display_name": "Cy Moss", "enabled": true, "managed": false})
	for i := 0; i < 250; i++ {
		f.user(dirAuthA, "tenant-a", fmt.Sprintf("bulk-%03d", i), map[string]interface{}{"display_name": "Bulk", "enabled": true})
	}
	key := f.key(dirRead, "tenant-a")

	ids := func(qs string) []string {
		rec := f.get(key, "/api/v1/directory/users?"+qs)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return itemIDs(t, decodeBody(t, rec))
	}
	assert.Equal(t, []string{"u1", "u2"}, ids("q=lee"))
	assert.Equal(t, []string{"u1"}, ids("q=ANN%40A.EXAMPLE"))
	assert.Equal(t, []string{"u2"}, ids("q=blee"))
	assert.Equal(t, []string{"u2"}, ids("enabled=false"))
	assert.Equal(t, []string{"u1"}, ids("managed=true"))
	assert.Equal(t, []string{"u3"}, ids("q=moss&enabled=true&managed=false"))

	// Walk every page of the whole list: each user once, none skipped, at most limit per page.
	var seen []string
	tok := ""
	for pages := 0; pages < 100; pages++ {
		qs := "limit=60"
		if tok != "" {
			qs += "&page_token=" + url.QueryEscape(tok)
		}
		rec := f.get(key, "/api/v1/directory/users?"+qs)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := decodeBody(t, rec)
		got := itemIDs(t, body)
		require.LessOrEqual(t, len(got), 60)
		seen = append(seen, got...)
		tok, _ = body["next_page_token"].(string)
		if tok == "" {
			break
		}
	}
	assert.Len(t, seen, 253)
	uniq := map[string]bool{}
	for _, id := range seen {
		assert.False(t, uniq[id], "%s returned twice", id)
		uniq[id] = true
	}

	// The same token under different filters is refused.
	rec := f.get(key, "/api/v1/directory/users?limit=60")
	tok, _ = decodeBody(t, rec)["next_page_token"].(string)
	require.NotEmpty(t, tok)
	assert.Equal(t, http.StatusBadRequest, f.get(key, "/api/v1/directory/users?limit=60&enabled=true&page_token="+url.QueryEscape(tok)).Code)
}

func TestDirectoryUsers_ResponseFieldSet(t *testing.T) {
	f := newDirFixture(t)
	f.user(dirAuthA, "tenant-a", "u0", map[string]interface{}{
		"display_name": "Ann", "sam_account_name": "ann", "user_principal_name": "ann@a.example", "mail": "ann@a.example",
		"enabled": true, "managed": true, "member_of": []string{"g1"}, "member_of_truncated": true,
		"distinguished_name": "CN=Ann,DC=a", "object_sid": "S-1-5-21-1", "password": "hunter2", "api_token": "tok", "secret": "s",
	})
	f.group(dirAuthA, "tenant-a", "g0", map[string]interface{}{
		"display_name": "Staff", "sam_account_name": "staff", "managed": false, "member_of": []string{"g1"},
		"other_members": []string{"x"}, "distinguished_name": "CN=Staff,DC=a",
	})
	key := f.key(dirRead, "tenant-a")

	fields := func(raw interface{}) []string {
		var out []string
		for k := range raw.(map[string]interface{}) {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	userFields := []string{"authority", "display_name", "enabled", "groups_truncated", "id", "kind", "last_observed", "mail", "managed", "sam_account_name", "source", "stale", "user_principal_name"}
	groupFields := []string{"authority", "display_name", "id", "kind", "last_observed", "managed", "sam_account_name", "source", "stale"}

	rec := f.get(key, "/api/v1/directory/users")
	require.Equal(t, http.StatusOK, rec.Code)
	list := decodeBody(t, rec)["items"].([]interface{})
	require.Len(t, list, 1)
	assert.Equal(t, userFields, fields(list[0]))
	for _, banned := range []string{"member_of", "password", "api_token", "secret", "distinguished_name", "object_sid", "hunter2", "S-1-5-21"} {
		assert.NotContains(t, rec.Body.String(), banned)
	}

	rec = f.get(key, "/api/v1/directory/groups")
	require.Equal(t, http.StatusOK, rec.Code)
	list = decodeBody(t, rec)["items"].([]interface{})
	require.Len(t, list, 1)
	assert.Equal(t, groupFields, fields(list[0]))
	assert.NotContains(t, rec.Body.String(), "member_of")
	assert.NotContains(t, rec.Body.String(), "other_members")

	rec = f.get(key, "/api/v1/directory/users/ad/u0")
	require.Equal(t, http.StatusOK, rec.Code)
	obj := decodeBody(t, rec)
	assert.Equal(t, userFields, fields(obj), "a user with no stored membership shows the list fields only")
	assert.Equal(t, "ad", obj["source"])
	assert.Equal(t, true, obj["enabled"])
	assert.Equal(t, true, obj["managed"])
	assert.Equal(t, false, obj["stale"])
	assert.NotEmpty(t, obj["last_observed"])
	for _, banned := range []string{"password", "api_token", "distinguished_name", "object_sid", "hunter2"} {
		assert.NotContains(t, rec.Body.String(), banned)
	}

	// A 500-row list page carries no membership of any kind.
	for i := 0; i < 520; i++ {
		f.user(dirAuthA, "tenant-a", fmt.Sprintf("row-%04d", i), map[string]interface{}{
			"display_name": "Row", "member_of": []string{"g1", "g2"}, "enabled": true,
		})
	}
	rec = f.get(key, "/api/v1/directory/users?limit=500")
	require.Equal(t, http.StatusOK, rec.Code)
	items := decodeBody(t, rec)["items"].([]interface{})
	assert.Len(t, items, 500)
	for _, it := range items {
		m := it.(map[string]interface{})
		assert.NotContains(t, m, "member_of")
		assert.NotContains(t, m, "groups")
	}
	assert.NotContains(t, rec.Body.String(), "member_of")
	assert.NotContains(t, rec.Body.String(), `"groups"`)
}

func TestDirectoryUser_Show_StaleAndLastObserved(t *testing.T) {
	f := newDirFixture(t)
	f.user(dirAuthA, "tenant-a", "u1", map[string]interface{}{"display_name": "Ann"})
	rec := f.get(f.key(dirRead, "tenant-a"), "/api/v1/directory/users/ad/u1")
	require.Equal(t, http.StatusOK, rec.Code)
	obj := decodeBody(t, rec)
	last, err := time.Parse(time.RFC3339Nano, obj["last_observed"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), last, time.Minute)
	assert.Equal(t, "u1", obj["id"])
	assert.Equal(t, "a.example", obj["authority"])
}

func TestDirectoryUser_AmbiguousIDAcrossDomains(t *testing.T) {
	f := newDirFixture(t)
	f.user(dirAuthA, "tenant-a", "same", map[string]interface{}{"display_name": "In A"})
	f.user("directory:c.example", "tenant-a", "same", map[string]interface{}{"display_name": "In C"})
	key := f.key(dirRead, "tenant-a")
	assert.Equal(t, http.StatusConflict, f.get(key, "/api/v1/directory/users/ad/same").Code)
	rec := f.get(key, "/api/v1/directory/users/ad/same?authority=c.example")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "In C", decodeBody(t, rec)["display_name"])
}

// ---- membership ----

func TestDirectoryUser_GroupsOverflowReportsUnavailable(t *testing.T) {
	f := newDirFixture(t)
	groups := make([]string, 150)
	for i := range groups {
		groups[i] = fmt.Sprintf("g-%03d", i)
	}
	f.user(dirAuthA, "tenant-a", "big", map[string]interface{}{"display_name": "Big"})
	f.user(dirAuthA, "tenant-a", "small", map[string]interface{}{"display_name": "Small"})
	f.user(dirAuthA, "tenant-a", "cut", map[string]interface{}{"display_name": "Cut", "member_of_truncated": true})
	f.group(dirAuthA, "tenant-a", "g-007", map[string]interface{}{"display_name": "Group Seven"})
	f.batch(dirAuthA, []directory.Fragment{
		dirUserFrag("big", groups...),
		dirUserFrag("small", "g-007"),
		{Kind: egtypes.KindDirectoryUser, ObjectID: "cut", Attributes: map[string]any{"member_of": []string{"g-007"}, "member_of_truncated": true}},
	})
	key := f.key(dirRead, "tenant-a")

	big := decodeBody(t, f.get(key, "/api/v1/directory/users/ad/big"))
	assert.Len(t, big["groups"], 100, "inline groups are bounded")
	assert.Equal(t, true, big["groups_truncated"], "beyond 100 groups the list is reported incomplete")

	small := decodeBody(t, f.get(key, "/api/v1/directory/users/ad/small"))
	require.Len(t, small["groups"], 1)
	assert.NotContains(t, small, "groups_truncated")
	g := small["groups"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "g-007", g["id"])
	assert.Equal(t, "Group Seven", g["display_name"])

	cut := decodeBody(t, f.get(key, "/api/v1/directory/users/ad/cut"))
	assert.Equal(t, true, cut["groups_truncated"], "a fragment with member_of_truncated reports it")

	// The list rows carry the flag but never the groups.
	rec := f.get(key, "/api/v1/directory/users?q=cut")
	items := decodeBody(t, rec)["items"].([]interface{})
	require.Len(t, items, 1)
	assert.Equal(t, true, items[0].(map[string]interface{})["groups_truncated"])
	assert.NotContains(t, items[0], "groups")

	// With no membership store the list is reported unavailable, not empty.
	f.srv.SetDirectoryMembershipStore(nil)
	none := decodeBody(t, f.get(key, "/api/v1/directory/users/ad/small"))
	assert.Equal(t, true, none["groups_truncated"])
	assert.NotContains(t, none, "groups")
	assert.Equal(t, http.StatusServiceUnavailable, f.get(key, "/api/v1/directory/users/ad/small/groups").Code)
	assert.Equal(t, http.StatusServiceUnavailable, f.get(key, "/api/v1/directory/groups/ad/g-007/members").Code)
	assert.Equal(t, http.StatusServiceUnavailable, f.get(key, "/api/v1/directory/groups/ad/g-007/membership-changes").Code)
}

func TestDirectoryUserGroups_300GroupsListed(t *testing.T) {
	f := newDirFixture(t)
	groups := make([]string, 300)
	for i := range groups {
		groups[i] = fmt.Sprintf("grp-%03d", i)
	}
	f.user(dirAuthA, "tenant-a", "u300", map[string]interface{}{"display_name": "Many"})
	for _, g := range groups[:50] {
		f.group(dirAuthA, "tenant-a", g, map[string]interface{}{"display_name": "Name of " + g})
	}
	f.batch(dirAuthA, []directory.Fragment{dirUserFrag("u300", groups...)})
	key := f.key(dirRead, "tenant-a")

	var got []string
	names := 0
	tok := ""
	for pages := 0; pages < 10; pages++ {
		p := "/api/v1/directory/users/ad/u300/groups?limit=100"
		if tok != "" {
			p += "&page_token=" + url.QueryEscape(tok)
		}
		rec := f.get(key, p)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := decodeBody(t, rec)
		for _, g := range body["groups"].([]interface{}) {
			m := g.(map[string]interface{})
			got = append(got, m["id"].(string))
			if m["display_name"] != nil {
				names++
			}
		}
		tok, _ = body["next_page_token"].(string)
		if tok == "" {
			break
		}
	}
	assert.Len(t, got, 300)
	assert.ElementsMatch(t, groups, got)
	assert.Equal(t, 50, names, "display names come from the stored group entities")

	// The store cursor is bound to the owning tenant and the user.
	rec := f.get(key, "/api/v1/directory/users/ad/u300/groups?limit=10")
	tok, _ = decodeBody(t, rec)["next_page_token"].(string)
	require.NotEmpty(t, tok)
	f.user(dirAuthA, "tenant-a", "other", nil)
	assert.Equal(t, http.StatusBadRequest, f.get(key, "/api/v1/directory/users/ad/other/groups?page_token="+url.QueryEscape(tok)).Code)
}

func TestDirectoryGroupMembers_60000MembersPagedFromStore(t *testing.T) {
	f := newDirFixture(t)
	f.group(dirAuthA, "tenant-a", "big-group", map[string]interface{}{"display_name": "Everyone"})
	const total, batchSize = 60000, 2000
	for start := 0; start < total; start += batchSize {
		ups := make([]directory.Fragment, 0, batchSize)
		for i := start; i < start+batchSize; i++ {
			ups = append(ups, dirUserFrag(fmt.Sprintf("u-%06d", i), "big-group"))
		}
		f.batch(dirAuthA, ups)
	}
	key := f.key(dirRead, "tenant-a")

	seen := make(map[string]struct{}, total)
	tok := ""
	pages := 0
	for {
		p := "/api/v1/directory/groups/ad/big-group/members?limit=500"
		if tok != "" {
			p += "&page_token=" + url.QueryEscape(tok)
		}
		rec := f.get(key, p)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := decodeBody(t, rec)
		for _, m := range body["members"].([]interface{}) {
			mm := m.(map[string]interface{})
			id := mm["id"].(string)
			_, dup := seen[id]
			require.False(t, dup, "member %s returned twice", id)
			seen[id] = struct{}{}
			require.Equal(t, "user", mm["type"])
		}
		pages++
		tok, _ = body["next_page_token"].(string)
		if tok == "" {
			break
		}
	}
	assert.Len(t, seen, total)
	assert.Equal(t, total/500, pages)

	// The group itself is cheap to read: it never loads its members.
	assert.Equal(t, http.StatusOK, f.get(key, "/api/v1/directory/groups/ad/big-group").Code)
	// Another tenant cannot use the cursor, and does not learn the group exists.
	rec := f.get(key, "/api/v1/directory/groups/ad/big-group/members?limit=10")
	tok, _ = decodeBody(t, rec)["next_page_token"].(string)
	assert.Equal(t, http.StatusNotFound, f.get(f.key(dirRead, "tenant-b"), "/api/v1/directory/groups/ad/big-group/members?page_token="+url.QueryEscape(tok)).Code)
	assert.Equal(t, http.StatusBadRequest, f.get(key, "/api/v1/directory/groups/ad/big-group/members?page_token=bogus").Code)
}

func TestDirectoryMembershipChanges_AddedAndRemovedAreReturned(t *testing.T) {
	f := newDirFixture(t)
	f.group(dirAuthA, "tenant-a", "g1", map[string]interface{}{"display_name": "G1"})
	key := f.key(dirRead, "tenant-a")

	f.batch(dirAuthA, []directory.Fragment{dirUserFrag("u-base", "g1")}) // baseline
	f.clock.advance(time.Hour)
	f.batch(dirAuthA, []directory.Fragment{dirUserFrag("u-base", "g1"), dirUserFrag("u-new", "g1")})
	f.clock.advance(time.Hour)
	f.batch(dirAuthA, []directory.Fragment{dirUserFrag("u-base"), dirUserFrag("u-new", "g1")})

	rec := f.get(key, "/api/v1/directory/groups/ad/g1/membership-changes")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	evs := decodeBody(t, rec)["events"].([]interface{})
	require.Len(t, evs, 2, "baseline is excluded by default")
	first, second := evs[0].(map[string]interface{}), evs[1].(map[string]interface{})
	assert.Equal(t, "removed", first["op"], "newest first")
	assert.Equal(t, "directory:a.example/user:u-base", first["member"])
	assert.Equal(t, "added", second["op"])
	assert.Equal(t, "directory:a.example/user:u-new", second["member"])
	assert.Equal(t, "directory:a.example/group:g1", second["group"])
	assert.Equal(t, "user", second["member_type"])
	assert.Equal(t, dirAuthA, second["source"])
	assert.Equal(t, false, second["baseline"])
	assert.Contains(t, second, "observed_at")
	assert.Contains(t, second, "recorded_at")
	assert.Len(t, second, 8, "exactly the documented fields")

	rec = f.get(key, "/api/v1/directory/groups/ad/g1/membership-changes?include_baseline=true")
	evs = decodeBody(t, rec)["events"].([]interface{})
	require.Len(t, evs, 3)
	assert.Equal(t, true, evs[2].(map[string]interface{})["baseline"])

	rec = f.get(key, "/api/v1/directory/groups/ad/g1/membership-changes?member=u-new&include_baseline=true")
	evs = decodeBody(t, rec)["events"].([]interface{})
	assert.Len(t, evs, 1)

	since := f.clock.now().Add(-90 * time.Minute).Format(time.RFC3339)
	rec = f.get(key, "/api/v1/directory/groups/ad/g1/membership-changes?include_baseline=true&since="+url.QueryEscape(since))
	assert.Len(t, decodeBody(t, rec)["events"], 2)
	until := f.clock.now().Add(-90 * time.Minute).Format(time.RFC3339)
	rec = f.get(key, "/api/v1/directory/groups/ad/g1/membership-changes?include_baseline=true&until="+url.QueryEscape(until))
	assert.Len(t, decodeBody(t, rec)["events"], 1)

	// Paging walks newest to oldest with no repeats.
	rec = f.get(key, "/api/v1/directory/groups/ad/g1/membership-changes?include_baseline=true&limit=2")
	body := decodeBody(t, rec)
	require.Len(t, body["events"], 2)
	tok, _ := body["next_page_token"].(string)
	require.NotEmpty(t, tok)
	rec = f.get(key, "/api/v1/directory/groups/ad/g1/membership-changes?include_baseline=true&limit=2&page_token="+url.QueryEscape(tok))
	body = decodeBody(t, rec)
	require.Len(t, body["events"], 1)
	assert.Equal(t, true, body["events"].([]interface{})[0].(map[string]interface{})["baseline"])
	assert.NotContains(t, body, "next_page_token")
	// The token is tied to its filters.
	assert.Equal(t, http.StatusBadRequest, f.get(key, "/api/v1/directory/groups/ad/g1/membership-changes?limit=2&page_token="+url.QueryEscape(tok)).Code)
}

func TestDirectoryMembershipChanges_OtherTenantGroup_404(t *testing.T) {
	f := newDirFixture(t)
	f.group(dirAuthB, "tenant-b", "bg", map[string]interface{}{"display_name": "B"})
	f.batch(dirAuthB, []directory.Fragment{dirUserFrag("bu", "bg")})
	f.clock.advance(time.Hour)
	f.batch(dirAuthB, []directory.Fragment{dirUserFrag("bu")})

	rec := f.get(f.key(dirRead, "tenant-a"), "/api/v1/directory/groups/ad/bg/membership-changes?include_baseline=true")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "bu")
	rec = f.get(f.key(dirRead, "tenant-b"), "/api/v1/directory/groups/ad/bg/membership-changes?include_baseline=true")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Len(t, decodeBody(t, rec)["events"], 2)
}

func TestDirectoryMembershipChanges_ParamBounds(t *testing.T) {
	f := newDirFixture(t)
	f.group(dirAuthA, "tenant-a", "g1", nil)
	key := f.key(dirRead, "tenant-a")
	base := "/api/v1/directory/groups/ad/g1/membership-changes?"
	for name, qs := range map[string]string{
		"limit zero":       "limit=0",
		"limit too large":  "limit=501",
		"limit not number": "limit=x",
		"since bad":        "since=yesterday",
		"until bad":        "until=2026-13-45",
		"since date only":  "since=2026-10-01",
		"until before":     "since=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z",
		"member control":   "member=" + url.QueryEscape("a\x00b"),
		"member too long":  "member=" + strings.Repeat("m", 257),
		"baseline bad":     "include_baseline=yes",
		"token bad":        "page_token=@@@",
	} {
		assert.Equal(t, http.StatusBadRequest, f.get(key, base+qs).Code, name)
	}
	for _, qs := range []string{"limit=500", "since=2026-10-01T00:00:00Z&until=2026-10-02T00:00:00Z", "member=u1", "include_baseline=false"} {
		rec := f.get(key, base+qs)
		assert.Equal(t, http.StatusOK, rec.Code, "%s: %s", qs, rec.Body.String())
	}
}

// ---- no live calls ----

func TestDirectoryRead_NeverCallsStewardOrGraph(t *testing.T) {
	f := newDirFixture(t)
	require.Nil(t, f.srv.commandPublisher, "the server under test has no command publisher")
	f.user(dirAuthA, "tenant-a", "u1", map[string]interface{}{"display_name": "Ann"})
	f.group(dirAuthA, "tenant-a", "g1", map[string]interface{}{"display_name": "G"})
	f.user("m365:0f0e0d0c-0000-0000-0000-000000000001", "tenant-a", "cu", map[string]interface{}{"display_name": "Cloud"})
	f.batch(dirAuthA, []directory.Fragment{dirUserFrag("u1", "g1")})
	key := f.key(dirRead, "tenant-a")

	for _, p := range []string{
		"/api/v1/directory/users", "/api/v1/directory/groups?source=m365",
		"/api/v1/directory/users/ad/u1", "/api/v1/directory/users/m365/cu",
		"/api/v1/directory/users/ad/u1/groups", "/api/v1/directory/groups/ad/g1",
		"/api/v1/directory/groups/ad/g1/members", "/api/v1/directory/groups/ad/g1/membership-changes",
	} {
		rec := f.get(key, p)
		assert.Equal(t, http.StatusOK, rec.Code, "%s: %s", p, rec.Body.String())
	}
	members := decodeBody(t, f.get(key, "/api/v1/directory/groups/ad/g1/members"))["members"].([]interface{})
	require.Len(t, members, 1)
	assert.Equal(t, "u1", members[0].(map[string]interface{})["id"])
}

func TestDirectoryRead_NoEntityGraph_503(t *testing.T) {
	srv := setupTestServer(t)
	key := NewEphemeralTestKey(t, srv, dirRead, "tenant-a", 5*time.Minute)
	for _, p := range []string{"/api/v1/directory/users", "/api/v1/directory/users/ad/u1", "/api/v1/directory/groups/ad/g1/members"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("X-API-Key", key)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, p)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package m365

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
)

// recordingAuthProvider records the tenant of every GetAccessToken call.
type recordingAuthProvider struct {
	stubAuthProvider
	mu      sync.Mutex
	tenants []string
}

func (r *recordingAuthProvider) GetAccessToken(ctx context.Context, tenantID string) (*auth.AccessToken, error) {
	r.mu.Lock()
	r.tenants = append(r.tenants, tenantID)
	r.mu.Unlock()
	return &auth.AccessToken{Token: "tok-" + tenantID, TenantID: tenantID}, nil
}

func (r *recordingAuthProvider) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tenants...)
}

func tenantCtx(tenant string) context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, tenant)
}

func connectedProvider(t *testing.T, ap auth.Provider, gc graph.Client) *EntraIDDirectoryProvider {
	t.Helper()
	p := NewEntraIDDirectoryProvider(&stubLogger{}, ap, gc)
	require.NoError(t, p.Connect(context.Background(), interfaces.ProviderConfig{}))
	return p
}

// memoryDirectory is an in-test interfaces.DirectoryProvider holding users and
// groups in maps. It embeds the interface, so only the methods the sync paths
// use are implemented; any other call panics and fails the test loudly.
type memoryDirectory struct {
	interfaces.DirectoryProvider
	users  map[string]*interfaces.DirectoryUser
	groups map[string]*interfaces.DirectoryGroup
}

func newMemoryDirectory() *memoryDirectory {
	return &memoryDirectory{users: map[string]*interfaces.DirectoryUser{}, groups: map[string]*interfaces.DirectoryGroup{}}
}

func (m *memoryDirectory) GetUser(_ context.Context, id string) (*interfaces.DirectoryUser, error) {
	if u, ok := m.users[id]; ok {
		return u, nil
	}
	return nil, errors.New("not found")
}
func (m *memoryDirectory) CreateUser(_ context.Context, u *interfaces.DirectoryUser) (*interfaces.DirectoryUser, error) {
	c := *u
	c.ID = "mem-" + u.UserPrincipalName
	m.users[u.UserPrincipalName] = &c
	return &c, nil
}
func (m *memoryDirectory) UpdateUser(_ context.Context, id string, u *interfaces.DirectoryUser) (*interfaces.DirectoryUser, error) {
	for upn, existing := range m.users {
		if existing.ID == id {
			c := *u
			c.ID = id
			m.users[upn] = &c
			return &c, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *memoryDirectory) GetGroup(_ context.Context, id string) (*interfaces.DirectoryGroup, error) {
	if g, ok := m.groups[id]; ok {
		return g, nil
	}
	return nil, errors.New("not found")
}
func (m *memoryDirectory) CreateGroup(_ context.Context, g *interfaces.DirectoryGroup) (*interfaces.DirectoryGroup, error) {
	c := *g
	c.ID = "mem-" + g.Name
	m.groups[g.Name] = &c
	return &c, nil
}
func (m *memoryDirectory) UpdateGroup(_ context.Context, id string, g *interfaces.DirectoryGroup) (*interfaces.DirectoryGroup, error) {
	for name, existing := range m.groups {
		if existing.ID == id {
			c := *g
			c.ID = id
			m.groups[name] = &c
			return &c, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *memoryDirectory) GetProviderInfo() interfaces.ProviderInfo {
	return interfaces.ProviderInfo{Name: "memory"}
}

func validUser(upn string) *interfaces.DirectoryUser {
	return &interfaces.DirectoryUser{UserPrincipalName: upn, DisplayName: "User " + upn, AccountEnabled: true}
}

func TestEntraProvider_TokenUsesExecutionTenant(t *testing.T) {
	ap := &recordingAuthProvider{}
	gc := &stubGraphClient{}
	p := connectedProvider(t, ap, gc)

	_, err := p.GetUser(tenantCtx("root/msp-a/client-1"), "u1")
	require.NoError(t, err)
	_, err = p.GetUser(tenantCtx("root/msp-a/client-2"), "u1")
	require.NoError(t, err)
	_, err = p.ListUsers(tenantCtx("root/msp-b"), nil)
	require.NoError(t, err)

	assert.Equal(t, []string{"root/msp-a/client-1", "root/msp-a/client-2", "root/msp-b"}, ap.seen(),
		"every Graph call must take its token for the tenant in the context")
}

func TestEntraProvider_ConnectCarriesNoTenant(t *testing.T) {
	ap := &recordingAuthProvider{}
	p := NewEntraIDDirectoryProvider(&stubLogger{}, ap, &stubGraphClient{})

	require.NoError(t, p.Connect(context.Background(), interfaces.ProviderConfig{
		TenantID: "connect-tenant", ClientID: "cid", Password: "secret",
	}))
	assert.Empty(t, ap.seen(), "Connect must not request a token")

	_, err := p.GetUser(tenantCtx("exec-tenant"), "u1")
	require.NoError(t, err)
	assert.Equal(t, []string{"exec-tenant"}, ap.seen())
}

func TestEntraProvider_MissingExecutionTenantFailsClosed(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"absent": context.Background(),
		"empty":  context.WithValue(context.Background(), ctxkeys.TenantID, ""),
	} {
		t.Run(name, func(t *testing.T) {
			ap := &recordingAuthProvider{}
			gc := &stubGraphClient{}
			p := connectedProvider(t, ap, gc)

			_, err := p.GetUser(ctx, "u1")
			assert.Error(t, err)
			_, err = p.ListUsers(ctx, nil)
			assert.Error(t, err)
			_, err = p.CreateUser(ctx, validUser("a@acme-corp.example"))
			assert.Error(t, err)

			assert.Zero(t, gc.calls.Load(), "Graph client must not be called")
			assert.Empty(t, ap.seen(), "no token may be requested without a tenant")
		})
	}
}

func TestEntraProvider_NotConnectedFailsClosed(t *testing.T) {
	gc := &stubGraphClient{}
	p := NewEntraIDDirectoryProvider(&stubLogger{}, &recordingAuthProvider{}, gc)
	_, err := p.GetUser(tenantCtx("t"), "u1")
	assert.Error(t, err)
	assert.Zero(t, gc.calls.Load())

	require.NoError(t, p.Connect(context.Background(), interfaces.ProviderConfig{}))
	assert.True(t, p.IsConnected(context.Background()))
	require.NoError(t, p.Disconnect(context.Background()))
	assert.False(t, p.IsConnected(context.Background()))
}

func TestEntraProvider_Connect_Config(t *testing.T) {
	p := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, &stubGraphClient{})
	require.NoError(t, p.Connect(context.Background(), interfaces.ProviderConfig{
		ProviderConfig: map[string]interface{}{"graph_url": "https://graph.example/v1.0"},
	}))
	assert.Equal(t, "https://graph.example/v1.0", p.config.GraphURL)

	err := p.Connect(context.Background(), interfaces.ProviderConfig{
		ProviderConfig: map[string]interface{}{"graph_url": 7},
	})
	assert.Error(t, err)
	err = p.Connect(context.Background(), interfaces.ProviderConfig{
		ProviderConfig: map[string]interface{}{"graph_url": "http://graph.example"},
	})
	assert.Error(t, err)
}

func TestEntraProvider_HealthCheck(t *testing.T) {
	t.Run("no execution tenant reports unhealthy by design", func(t *testing.T) {
		p := connectedProvider(t, &recordingAuthProvider{}, &stubGraphClient{})
		h, err := p.HealthCheck(context.Background())
		require.NoError(t, err)
		assert.False(t, h.IsHealthy)
		assert.NotEmpty(t, h.Errors)
	})
	t.Run("healthy with tenant", func(t *testing.T) {
		ap := &recordingAuthProvider{}
		p := connectedProvider(t, ap, &stubGraphClient{})
		h, err := p.HealthCheck(tenantCtx("t1"))
		require.NoError(t, err)
		assert.True(t, h.IsHealthy)
		assert.Equal(t, []string{"t1"}, ap.seen())
	})
	t.Run("not connected", func(t *testing.T) {
		p := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, &stubGraphClient{})
		h, err := p.HealthCheck(tenantCtx("t1"))
		require.NoError(t, err)
		assert.False(t, h.IsHealthy)
	})
	t.Run("token failure is reported", func(t *testing.T) {
		ap := &stubAuthProvider{getAccessTokenFn: func(context.Context, string) (*auth.AccessToken, error) {
			return nil, errors.New("token failed")
		}}
		p := connectedProvider(t, ap, &stubGraphClient{})
		h, err := p.HealthCheck(tenantCtx("t1"))
		require.NoError(t, err)
		assert.False(t, h.IsHealthy)
		require.Len(t, h.Errors, 1)
		assert.Contains(t, h.Errors[0], "token retrieval failed")
	})
}

func TestEntraProvider_ListUsersAndListGroupsPaginate(t *testing.T) {
	var users []graph.User
	var groups []graph.Group
	for i := 0; i < 5; i++ {
		users = append(users, graph.User{ID: fmt.Sprintf("u%d", i), UserPrincipalName: fmt.Sprintf("u%d@acme-corp.example", i), DisplayName: "U"})
		groups = append(groups, graph.Group{ID: fmt.Sprintf("g%d", i), DisplayName: "G", SecurityEnabled: true})
	}
	var gotFilter string
	gc := &stubGraphClient{
		listUsersFn: func(_ context.Context, _ *auth.AccessToken, f string) ([]graph.User, error) {
			gotFilter = f
			return users, nil
		},
		listGroupsFn: func(context.Context, *auth.AccessToken, string) ([]graph.Group, error) { return groups, nil },
	}
	p := connectedProvider(t, &recordingAuthProvider{}, gc)
	ctx := tenantCtx("t1")

	page1, err := p.ListUsers(ctx, &interfaces.SearchFilters{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, page1.Users, 2)
	assert.Equal(t, 5, page1.TotalCount)
	assert.True(t, page1.HasMore)
	assert.Equal(t, "2", page1.NextToken)
	assert.Equal(t, "u0", page1.Users[0].ID)
	assert.Equal(t, "entraid", page1.Users[0].Source)

	page3, err := p.ListUsers(ctx, &interfaces.SearchFilters{Offset: 4, Limit: 2})
	require.NoError(t, err)
	require.Len(t, page3.Users, 1)
	assert.Equal(t, "u4", page3.Users[0].ID)
	assert.False(t, page3.HasMore)
	assert.Empty(t, page3.NextToken)

	beyond, err := p.ListUsers(ctx, &interfaces.SearchFilters{Offset: 50, Limit: 2})
	require.NoError(t, err)
	assert.Empty(t, beyond.Users)
	assert.False(t, beyond.HasMore)

	g1, err := p.ListGroups(ctx, &interfaces.SearchFilters{Limit: 3})
	require.NoError(t, err)
	assert.Len(t, g1.Groups, 3)
	assert.True(t, g1.HasMore)
	assert.Equal(t, 5, g1.TotalCount)
	g2, err := p.ListGroups(ctx, &interfaces.SearchFilters{Offset: 3, Limit: 3})
	require.NoError(t, err)
	require.Len(t, g2.Groups, 2)
	assert.False(t, g2.HasMore)
	assert.Equal(t, "entraid", g2.Groups[0].Source)

	// Filters reach Graph as an OData filter with quotes escaped.
	_, err = p.ListUsers(ctx, &interfaces.SearchFilters{Query: "o'brien", Department: "IT"})
	require.NoError(t, err)
	assert.Contains(t, gotFilter, "o''brien")
	assert.Contains(t, gotFilter, "department eq 'IT'")
}

func TestEntraProvider_BulkOperationsReportPerItemResults(t *testing.T) {
	failUPN := "bad@acme-corp.example"
	gc := &stubGraphClient{
		createUserFn: func(_ context.Context, _ *auth.AccessToken, req *graph.CreateUserRequest) (*graph.User, error) {
			if req.UserPrincipalName == failUPN {
				return nil, errors.New("graph rejected")
			}
			return &graph.User{ID: "id-" + req.UserPrincipalName, UserPrincipalName: req.UserPrincipalName, DisplayName: req.DisplayName}, nil
		},
		updateUserFn: func(_ context.Context, _ *auth.AccessToken, id string, _ *graph.UpdateUserRequest) error {
			if id == "u-bad" {
				return errors.New("graph rejected")
			}
			return nil
		},
		deleteUserFn: func(_ context.Context, _ *auth.AccessToken, id string) error {
			if id == "u-bad" {
				return errors.New("graph rejected")
			}
			return nil
		},
	}
	p := connectedProvider(t, &recordingAuthProvider{}, gc)
	ctx := tenantCtx("t1")
	cont := &interfaces.BulkOptions{ContinueOnError: true}

	t.Run("create", func(t *testing.T) {
		res, err := p.BulkCreateUsers(ctx, []*interfaces.DirectoryUser{
			validUser("a@acme-corp.example"), validUser(failUPN), {UserPrincipalName: "no-name@acme-corp.example"}, validUser("c@acme-corp.example"),
		}, cont)
		require.NoError(t, err)
		assert.Equal(t, 4, res.TotalItems)
		assert.Equal(t, 2, res.SuccessCount)
		assert.Equal(t, 2, res.ErrorCount)
		require.Len(t, res.ItemResults, 4)
		assert.True(t, res.ItemResults[0].Success)
		assert.Equal(t, "id-a@acme-corp.example", res.ItemResults[0].ItemID)
		assert.False(t, res.ItemResults[1].Success)
		assert.NotEmpty(t, res.ItemResults[1].Error)
		assert.False(t, res.ItemResults[2].Success, "validation failure is reported per item")
		assert.True(t, res.ItemResults[3].Success)
		assert.Equal(t, []int{1, 2}, []int{res.Errors[0].ItemIndex, res.Errors[1].ItemIndex})
	})

	t.Run("update", func(t *testing.T) {
		res, err := p.BulkUpdateUsers(ctx, []*interfaces.UserUpdate{
			{UserID: "u1", Updates: validUser("u1@acme-corp.example")},
			{UserID: "u-bad", Updates: validUser("u2@acme-corp.example")},
			nil,
		}, cont)
		require.NoError(t, err)
		assert.Equal(t, 3, res.TotalItems)
		assert.Equal(t, 1, res.SuccessCount)
		assert.Equal(t, 2, res.ErrorCount)
		assert.True(t, res.ItemResults[0].Success)
		assert.False(t, res.ItemResults[1].Success)
	})

	t.Run("delete", func(t *testing.T) {
		res, err := p.BulkDeleteUsers(ctx, []string{"u1", "u-bad", "u3"}, cont)
		require.NoError(t, err)
		assert.Equal(t, 3, res.TotalItems)
		assert.Equal(t, 2, res.SuccessCount)
		assert.Equal(t, 1, res.ErrorCount)
		assert.Equal(t, "u-bad", res.Errors[0].ItemID)
	})

	t.Run("stops at first error unless ContinueOnError", func(t *testing.T) {
		res, err := p.BulkDeleteUsers(ctx, []string{"u-bad", "u2", "u3"}, &interfaces.BulkOptions{})
		require.NoError(t, err)
		assert.Equal(t, 3, res.TotalItems)
		assert.Len(t, res.ItemResults, 1)
		assert.Equal(t, 1, res.ErrorCount)
	})

	t.Run("missing tenant fails every item", func(t *testing.T) {
		res, err := p.BulkDeleteUsers(context.Background(), []string{"u1", "u2"}, cont)
		require.NoError(t, err)
		assert.Equal(t, 2, res.ErrorCount)
		assert.Zero(t, res.SuccessCount)
	})
}

func TestEntraProvider_SourceAndValidateBeforeCreate(t *testing.T) {
	var created int
	gc := &stubGraphClient{
		createUserFn: func(_ context.Context, _ *auth.AccessToken, req *graph.CreateUserRequest) (*graph.User, error) {
			created++
			return &graph.User{ID: "id1", UserPrincipalName: req.UserPrincipalName, DisplayName: req.DisplayName}, nil
		},
		createGroupFn: func(_ context.Context, _ *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error) {
			created++
			return &graph.Group{ID: "g1", DisplayName: req.DisplayName, SecurityEnabled: req.SecurityEnabled}, nil
		},
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.Group, error) {
			return &graph.Group{ID: id, DisplayName: "Eng", SecurityEnabled: true}, nil
		},
		getUserGroupsFn: func(context.Context, *auth.AccessToken, string) ([]string, error) { return []string{"g1"}, nil },
		listGroupMembersFn: func(context.Context, *auth.AccessToken, string) ([]string, error) {
			return []string{"m@acme-corp.example"}, nil
		},
	}
	p := connectedProvider(t, &recordingAuthProvider{}, gc)
	ctx := tenantCtx("t1")

	_, err := p.CreateUser(ctx, &interfaces.DirectoryUser{UserPrincipalName: "not-a-upn", DisplayName: "X"})
	assert.Error(t, err)
	_, err = p.CreateUser(ctx, &interfaces.DirectoryUser{UserPrincipalName: "a@acme-corp.example"})
	assert.Error(t, err)
	_, err = p.CreateGroup(ctx, &interfaces.DirectoryGroup{})
	assert.Error(t, err)
	assert.Zero(t, created, "invalid objects must be rejected before Graph is called")

	assert.Error(t, p.ValidateUser(nil))
	assert.Error(t, p.ValidateGroup(nil))

	u, err := p.CreateUser(ctx, validUser("a@acme-corp.example"))
	require.NoError(t, err)
	assert.Equal(t, "entraid", u.Source)
	g, err := p.CreateGroup(ctx, &interfaces.DirectoryGroup{DisplayName: "Eng", GroupType: interfaces.GroupTypeSecurity})
	require.NoError(t, err)
	assert.Equal(t, "entraid", g.Source)
	assert.Equal(t, 2, created)

	groups, err := p.GetUserGroups(ctx, "u1")
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, "entraid", groups[0].Source)
	members, err := p.GetGroupMembers(ctx, "g1")
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "entraid", members[0].Source)
}

func TestEntraProvider_GetCapabilities_NoOUsNoAdminUnits(t *testing.T) {
	p := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, &stubGraphClient{})
	caps := p.GetCapabilities()
	assert.True(t, caps.SupportsUserManagement)
	assert.True(t, caps.SupportsGroupManagement)
	assert.False(t, caps.SupportsOUManagement)
	assert.True(t, caps.SupportsBulkOperations)
	assert.Equal(t, caps, p.GetProviderInfo().Capabilities)
	assert.Equal(t, "entraid", p.GetProviderInfo().Name)
	for _, st := range p.GetProviderInfo().SupportedTypes {
		assert.NotEqual(t, interfaces.DirectoryObjectTypeOU, st)
	}

	ctx := tenantCtx("t1")
	_, err := p.GetOU(ctx, "x")
	assert.Error(t, err)
	_, err = p.CreateOU(ctx, &interfaces.OrganizationalUnit{})
	assert.Error(t, err)
	_, err = p.UpdateOU(ctx, "x", &interfaces.OrganizationalUnit{})
	assert.Error(t, err)
	assert.Error(t, p.DeleteOU(ctx, "x"))
	ous, err := p.ListOUs(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, ous)
	assert.Empty(t, ous.OUs)

	schema, err := p.GetSchema(ctx)
	require.NoError(t, err)
	assert.Equal(t, interfaces.DirectoryObjectTypeUser, schema.UserSchema.ObjectType)
	assert.Equal(t, interfaces.DirectoryObjectTypeGroup, schema.GroupSchema.ObjectType)
}

func TestEntraProvider_SyncUser_ToOtherProvider(t *testing.T) {
	gc := &stubGraphClient{
		getUserFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.User, error) {
			return &graph.User{ID: id, UserPrincipalName: "sync@acme-corp.example", DisplayName: "Sync User", AccountEnabled: true}, nil
		},
	}
	p := connectedProvider(t, &recordingAuthProvider{}, gc)
	target := newMemoryDirectory()
	ctx := tenantCtx("t1")

	require.NoError(t, p.SyncUser(ctx, "src-id", target))
	created, ok := target.users["sync@acme-corp.example"]
	require.True(t, ok, "user must be created in the target")
	assert.Equal(t, "Sync User", created.DisplayName)

	// Second sync updates in place instead of duplicating.
	gc.getUserFn = func(_ context.Context, _ *auth.AccessToken, id string) (*graph.User, error) {
		return &graph.User{ID: id, UserPrincipalName: "sync@acme-corp.example", DisplayName: "Renamed", AccountEnabled: true}, nil
	}
	require.NoError(t, p.SyncUser(ctx, "src-id", target))
	assert.Len(t, target.users, 1)
	assert.Equal(t, "Renamed", target.users["sync@acme-corp.example"].DisplayName)
	assert.Equal(t, created.ID, target.users["sync@acme-corp.example"].ID)

	assert.Error(t, p.SyncUser(ctx, "src-id", nil))
	assert.Error(t, p.SyncUser(context.Background(), "src-id", target), "missing tenant fails closed")
}

func TestEntraProvider_SyncGroup_ToOtherProvider(t *testing.T) {
	gc := &stubGraphClient{
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.Group, error) {
			return &graph.Group{ID: id, DisplayName: "Eng", MailNickname: "eng", SecurityEnabled: true}, nil
		},
	}
	p := connectedProvider(t, &recordingAuthProvider{}, gc)
	target := newMemoryDirectory()
	ctx := tenantCtx("t1")

	require.NoError(t, p.SyncGroup(ctx, "gid", target))
	require.Len(t, target.groups, 1)
	require.NoError(t, p.SyncGroup(ctx, "gid", target))
	assert.Len(t, target.groups, 1)
}

func TestEntraProvider_SearchRejectsEmptyAndEscapes(t *testing.T) {
	var userFilter, groupFilter string
	gc := &stubGraphClient{
		listUsersFn: func(_ context.Context, _ *auth.AccessToken, f string) ([]graph.User, error) {
			userFilter = f
			return []graph.User{{ID: "u1", UserPrincipalName: "a@acme-corp.example"}}, nil
		},
		listGroupsFn: func(_ context.Context, _ *auth.AccessToken, f string) ([]graph.Group, error) {
			groupFilter = f
			return []graph.Group{{ID: "g1", DisplayName: "G"}}, nil
		},
	}
	p := connectedProvider(t, &recordingAuthProvider{}, gc)
	ctx := tenantCtx("t1")

	_, err := p.Search(ctx, &interfaces.DirectoryQuery{Filter: "  "})
	assert.Error(t, err)
	_, err = p.Search(ctx, nil)
	assert.Error(t, err)

	res, err := p.Search(ctx, &interfaces.DirectoryQuery{Filter: "o'x"})
	require.NoError(t, err)
	assert.Equal(t, 2, res.TotalCount)
	assert.True(t, strings.Contains(userFilter, "o''x") && strings.Contains(groupFilter, "o''x"))
}

func TestEntraProvider_CrudAndMembership(t *testing.T) {
	var updated *graph.UpdateUserRequest
	var deleted []string
	gc := &stubGraphClient{
		updateUserFn: func(_ context.Context, _ *auth.AccessToken, _ string, r *graph.UpdateUserRequest) error {
			updated = r
			return nil
		},
		deleteUserFn: func(_ context.Context, _ *auth.AccessToken, id string) error {
			deleted = append(deleted, id)
			return nil
		},
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.Group, error) {
			return &graph.Group{ID: id, DisplayName: "Eng"}, nil
		},
		deleteGroupFn: func(context.Context, *auth.AccessToken, string) error { return errors.New("boom") },
	}
	p := connectedProvider(t, &recordingAuthProvider{}, gc)
	ctx := tenantCtx("t1")

	u, err := p.UpdateUser(ctx, "u1", &interfaces.DirectoryUser{DisplayName: "New"})
	require.NoError(t, err)
	assert.Equal(t, "entraid", u.Source)
	require.NotNil(t, updated)
	assert.Equal(t, "New", *updated.DisplayName)
	_, err = p.UpdateUser(ctx, "u1", nil)
	assert.Error(t, err)

	require.NoError(t, p.DeleteUser(ctx, "u1"))
	assert.Equal(t, []string{"u1"}, deleted)

	g, err := p.UpdateGroup(ctx, "g1", &interfaces.DirectoryGroup{DisplayName: "Eng"})
	require.NoError(t, err)
	assert.Equal(t, "g1", g.ID)
	assert.Error(t, p.DeleteGroup(ctx, "g1"))

	require.NoError(t, p.AddUserToGroup(ctx, "u1", "g1"))
	require.NoError(t, p.RemoveUserFromGroup(ctx, "u1", "g1"))
	_, err = p.GetUser(ctx, "u1")
	require.NoError(t, err)
}

// --- struct-based test doubles (no mock framework) ---

// stubLogger is a no-op logger double
type stubLogger struct{}

func (s *stubLogger) Debug(msg string, _ ...interface{})                       {}
func (s *stubLogger) Info(msg string, _ ...interface{})                        {}
func (s *stubLogger) Warn(msg string, _ ...interface{})                        {}
func (s *stubLogger) Error(msg string, _ ...interface{})                       {}
func (s *stubLogger) Fatal(msg string, _ ...interface{})                       {}
func (s *stubLogger) DebugCtx(_ context.Context, msg string, _ ...interface{}) {}
func (s *stubLogger) InfoCtx(_ context.Context, msg string, _ ...interface{})  {}
func (s *stubLogger) WarnCtx(_ context.Context, msg string, _ ...interface{})  {}
func (s *stubLogger) ErrorCtx(_ context.Context, msg string, _ ...interface{}) {}
func (s *stubLogger) FatalCtx(_ context.Context, msg string, _ ...interface{}) {}
func (s *stubLogger) With(_ ...interface{}) interface{}                        { return s }
func (s *stubLogger) WithContext(_ context.Context) interface{}                { return s }
func (s *stubLogger) Named(_ string) interface{}                               { return s }
func (s *stubLogger) Sync() error                                              { return nil }

// stubAuthProvider returns a fixed token by default; set getAccessTokenFn to override.
type stubAuthProvider struct {
	getAccessTokenFn func(ctx context.Context, tenantID string) (*auth.AccessToken, error)
}

func (s *stubAuthProvider) GetAccessToken(ctx context.Context, tenantID string) (*auth.AccessToken, error) {
	if s.getAccessTokenFn != nil {
		return s.getAccessTokenFn(ctx, tenantID)
	}
	return &auth.AccessToken{Token: "stub-token"}, nil
}
func (s *stubAuthProvider) GetDelegatedAccessToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return &auth.AccessToken{Token: "stub-token"}, nil
}
func (s *stubAuthProvider) RefreshToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return &auth.AccessToken{Token: "stub-token"}, nil
}
func (s *stubAuthProvider) RefreshDelegatedToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return &auth.AccessToken{Token: "stub-token"}, nil
}
func (s *stubAuthProvider) IsTokenValid(_ *auth.AccessToken) bool { return true }
func (s *stubAuthProvider) ValidatePermissions(_ context.Context, _ *auth.AccessToken, _ []string) error {
	return nil
}

// stubGraphClient is a configurable graph.Client double with function fields
type stubGraphClient struct {
	getGroupFn            func(ctx context.Context, token *auth.AccessToken, groupID string) (*graph.Group, error)
	listGroupsFn          func(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.Group, error)
	createGroupFn         func(ctx context.Context, token *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error)
	updateGroupFn         func(ctx context.Context, token *auth.AccessToken, groupID string, req *graph.UpdateGroupRequest) error
	deleteGroupFn         func(ctx context.Context, token *auth.AccessToken, groupID string) error
	getUserGroupsFn       func(ctx context.Context, token *auth.AccessToken, userID string) ([]string, error)
	addUserToGroupFn      func(ctx context.Context, token *auth.AccessToken, userID, groupName string) error
	removeUserFromGroupFn func(ctx context.Context, token *auth.AccessToken, userID, groupName string) error
	listGroupMembersFn    func(ctx context.Context, token *auth.AccessToken, groupID string) ([]string, error)
	listUsersFn           func(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.User, error)
	getUserFn             func(ctx context.Context, token *auth.AccessToken, upn string) (*graph.User, error)
	createUserFn          func(ctx context.Context, token *auth.AccessToken, req *graph.CreateUserRequest) (*graph.User, error)
	updateUserFn          func(ctx context.Context, token *auth.AccessToken, userID string, req *graph.UpdateUserRequest) error
	deleteUserFn          func(ctx context.Context, token *auth.AccessToken, userID string) error

	// calls counts every Graph call, so fail-closed tests can assert none happened.
	calls atomic.Int32
}

// Mandatory interface method stubs
func (s *stubGraphClient) GetUser(ctx context.Context, t *auth.AccessToken, u string) (*graph.User, error) {
	s.calls.Add(1)
	if s.getUserFn != nil {
		return s.getUserFn(ctx, t, u)
	}
	return &graph.User{ID: u, UserPrincipalName: u}, nil
}
func (s *stubGraphClient) ListUsers(ctx context.Context, t *auth.AccessToken, filter string) ([]graph.User, error) {
	s.calls.Add(1)
	if s.listUsersFn != nil {
		return s.listUsersFn(ctx, t, filter)
	}
	return nil, nil
}
func (s *stubGraphClient) CreateUser(ctx context.Context, t *auth.AccessToken, req *graph.CreateUserRequest) (*graph.User, error) {
	s.calls.Add(1)
	if s.createUserFn != nil {
		return s.createUserFn(ctx, t, req)
	}
	return &graph.User{ID: "id-" + req.UserPrincipalName, UserPrincipalName: req.UserPrincipalName, DisplayName: req.DisplayName}, nil
}
func (s *stubGraphClient) UpdateUser(ctx context.Context, t *auth.AccessToken, id string, req *graph.UpdateUserRequest) error {
	s.calls.Add(1)
	if s.updateUserFn != nil {
		return s.updateUserFn(ctx, t, id, req)
	}
	return nil
}
func (s *stubGraphClient) DeleteUser(ctx context.Context, t *auth.AccessToken, id string) error {
	s.calls.Add(1)
	if s.deleteUserFn != nil {
		return s.deleteUserFn(ctx, t, id)
	}
	return nil
}
func (s *stubGraphClient) GetUserLicenses(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.LicenseAssignment, error) {
	return nil, nil
}
func (s *stubGraphClient) AssignLicense(_ context.Context, _ *auth.AccessToken, _, _ string, _ []string) error {
	return nil
}
func (s *stubGraphClient) RemoveLicense(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) GetUserGroups(ctx context.Context, t *auth.AccessToken, userID string) ([]string, error) {
	if s.getUserGroupsFn != nil {
		return s.getUserGroupsFn(ctx, t, userID)
	}
	return nil, nil
}
func (s *stubGraphClient) AddUserToGroup(ctx context.Context, t *auth.AccessToken, userID, groupName string) error {
	if s.addUserToGroupFn != nil {
		return s.addUserToGroupFn(ctx, t, userID, groupName)
	}
	return nil
}
func (s *stubGraphClient) RemoveUserFromGroup(ctx context.Context, t *auth.AccessToken, userID, groupName string) error {
	if s.removeUserFromGroupFn != nil {
		return s.removeUserFromGroupFn(ctx, t, userID, groupName)
	}
	return nil
}
func (s *stubGraphClient) GetConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string) (*graph.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ *graph.CreateConditionalAccessPolicyRequest) (*graph.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (s *stubGraphClient) UpdateConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateConditionalAccessPolicyRequest) error {
	return nil
}
func (s *stubGraphClient) DeleteConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubGraphClient) GetDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string) (*graph.DeviceConfiguration, error) {
	return nil, nil
}
func (s *stubGraphClient) ListDeviceConfigurationAssignments(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.DeviceConfigurationAssignment, error) {
	return nil, nil
}
func (s *stubGraphClient) AssignDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string, _ []graph.DeviceConfigurationAssignment) error {
	return nil
}
func (s *stubGraphClient) CreateDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ *graph.CreateDeviceConfigurationRequest) (*graph.DeviceConfiguration, error) {
	return nil, nil
}
func (s *stubGraphClient) UpdateDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateDeviceConfigurationRequest) error {
	return nil
}
func (s *stubGraphClient) DeleteDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubGraphClient) GetApplication(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Application, error) {
	return nil, nil
}
func (s *stubGraphClient) ListApplications(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.Application, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateApplication(_ context.Context, _ *auth.AccessToken, _ *graph.CreateApplicationRequest) (*graph.Application, error) {
	return nil, nil
}
func (s *stubGraphClient) UpdateApplication(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateApplicationRequest) error {
	return nil
}
func (s *stubGraphClient) DeleteApplication(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubGraphClient) AddApplicationPassword(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.AddApplicationPasswordRequest) (*graph.ApplicationPasswordCredential, error) {
	return nil, nil
}
func (s *stubGraphClient) RemoveApplicationPassword(_ context.Context, _ *auth.AccessToken, _ string, _ string) error {
	return nil
}
func (s *stubGraphClient) AddApplicationKey(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.AddApplicationKeyRequest) (*graph.ApplicationKeyCredential, error) {
	return nil, nil
}
func (s *stubGraphClient) RemoveApplicationKey(_ context.Context, _ *auth.AccessToken, _ string, _ string) error {
	return nil
}
func (s *stubGraphClient) ListServicePrincipals(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.ServicePrincipal, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateServicePrincipal(_ context.Context, _ *auth.AccessToken, _ *graph.CreateServicePrincipalRequest) (*graph.ServicePrincipal, error) {
	return nil, nil
}
func (s *stubGraphClient) GetAdministrativeUnit(ctx context.Context, t *auth.AccessToken, unitID string) (*graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubGraphClient) ListAdministrativeUnits(ctx context.Context, t *auth.AccessToken, filter string) ([]graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateAdministrativeUnit(ctx context.Context, t *auth.AccessToken, req *graph.CreateAdministrativeUnitRequest) (*graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubGraphClient) UpdateAdministrativeUnit(ctx context.Context, t *auth.AccessToken, unitID string, req *graph.UpdateAdministrativeUnitRequest) error {
	return nil
}
func (s *stubGraphClient) DeleteAdministrativeUnit(ctx context.Context, t *auth.AccessToken, unitID string) error {
	return nil
}
func (s *stubGraphClient) GetGroup(ctx context.Context, t *auth.AccessToken, groupID string) (*graph.Group, error) {
	s.calls.Add(1)
	if s.getGroupFn != nil {
		return s.getGroupFn(ctx, t, groupID)
	}
	return nil, nil
}
func (s *stubGraphClient) ListGroups(ctx context.Context, t *auth.AccessToken, filter string) ([]graph.Group, error) {
	s.calls.Add(1)
	if s.listGroupsFn != nil {
		return s.listGroupsFn(ctx, t, filter)
	}
	return nil, nil
}
func (s *stubGraphClient) CreateGroup(ctx context.Context, t *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error) {
	if s.createGroupFn != nil {
		return s.createGroupFn(ctx, t, req)
	}
	return nil, nil
}
func (s *stubGraphClient) UpdateGroup(ctx context.Context, t *auth.AccessToken, groupID string, req *graph.UpdateGroupRequest) error {
	if s.updateGroupFn != nil {
		return s.updateGroupFn(ctx, t, groupID, req)
	}
	return nil
}
func (s *stubGraphClient) DeleteGroup(ctx context.Context, t *auth.AccessToken, groupID string) error {
	if s.deleteGroupFn != nil {
		return s.deleteGroupFn(ctx, t, groupID)
	}
	return nil
}
func (s *stubGraphClient) ListGroupMembers(ctx context.Context, t *auth.AccessToken, groupID string) ([]string, error) {
	if s.listGroupMembersFn != nil {
		return s.listGroupMembersFn(ctx, t, groupID)
	}
	return nil, nil
}
func (s *stubGraphClient) AddGroupMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) RemoveGroupMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) ListGroupOwners(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubGraphClient) AddGroupOwner(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) RemoveGroupOwner(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) ListAdminUnitUserMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubGraphClient) ListAdminUnitGroupMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubGraphClient) ListAdminUnitScopedRoleMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}
func (s *stubGraphClient) AddAdminUnitMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) AddAdminUnitScopedRoleMember(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.AddScopedRoleMemberRequest) (*graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}
func (s *stubGraphClient) RemoveAdminUnitMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) RemoveAdminUnitScopedRoleMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) GetTeam(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Team, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateTeam(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.CreateTeamRequest) error {
	return nil
}
func (s *stubGraphClient) UpdateTeamSettings(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateTeamSettingsRequest) error {
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package directory

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// testProvider is a real in-memory Provider for use in unit tests.
// It stores users and groups by ID, and returns them via SearchUsers/SearchGroups.
// Set failSearch to make SearchUsers/SearchGroups return an error for error-path testing.
type testProvider struct {
	mu         sync.RWMutex
	name       string
	users      map[string]*types.DirectoryUser
	groups     map[string]*types.DirectoryGroup
	failSearch bool
}

func newTestProvider(name string) *testProvider {
	return &testProvider{
		name:   name,
		users:  make(map[string]*types.DirectoryUser),
		groups: make(map[string]*types.DirectoryGroup),
	}
}

func (p *testProvider) addUser(u *types.DirectoryUser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[u.ID] = u
}

func (p *testProvider) addGroup(g *types.DirectoryGroup) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.groups[g.ID] = g
}

// Provider interface implementation

func (p *testProvider) Name() string        { return p.name }
func (p *testProvider) DisplayName() string { return p.name }
func (p *testProvider) Description() string { return "test provider" }
func (p *testProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{UserManagement: true, GroupManagement: true}
}
func (p *testProvider) Connect(_ context.Context, _ ProviderConfig) error { return nil }
func (p *testProvider) Disconnect(_ context.Context) error                { return nil }
func (p *testProvider) IsConnected() bool                                 { return true }
func (p *testProvider) HealthCheck(_ context.Context) (*ProviderHealth, error) {
	return &ProviderHealth{IsHealthy: true, LastCheck: time.Now()}, nil
}

func (p *testProvider) GetUser(_ context.Context, userID string) (*types.DirectoryUser, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	u, ok := p.users[userID]
	if !ok {
		return nil, fmt.Errorf("user %q not found", userID)
	}
	return u, nil
}

func (p *testProvider) CreateUser(_ context.Context, u *types.DirectoryUser) (*types.DirectoryUser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[u.ID] = u
	return u, nil
}

func (p *testProvider) UpdateUser(_ context.Context, userID string, updates *types.DirectoryUser) (*types.DirectoryUser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[userID] = updates
	return updates, nil
}

func (p *testProvider) DeleteUser(_ context.Context, userID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.users, userID)
	return nil
}

func (p *testProvider) SearchUsers(_ context.Context, _ *SearchQuery) ([]*types.DirectoryUser, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.failSearch {
		return nil, fmt.Errorf("simulated search failure")
	}
	users := make([]*types.DirectoryUser, 0, len(p.users))
	for _, u := range p.users {
		users = append(users, u)
	}
	return users, nil
}

func (p *testProvider) GetGroup(_ context.Context, groupID string) (*types.DirectoryGroup, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	g, ok := p.groups[groupID]
	if !ok {
		return nil, fmt.Errorf("group %q not found", groupID)
	}
	return g, nil
}

func (p *testProvider) CreateGroup(_ context.Context, g *types.DirectoryGroup) (*types.DirectoryGroup, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.groups[g.ID] = g
	return g, nil
}

func (p *testProvider) UpdateGroup(_ context.Context, groupID string, updates *types.DirectoryGroup) (*types.DirectoryGroup, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.groups[groupID] = updates
	return updates, nil
}

func (p *testProvider) DeleteGroup(_ context.Context, groupID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.groups, groupID)
	return nil
}

func (p *testProvider) SearchGroups(_ context.Context, _ *SearchQuery) ([]*types.DirectoryGroup, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.failSearch {
		return nil, fmt.Errorf("simulated search failure")
	}
	groups := make([]*types.DirectoryGroup, 0, len(p.groups))
	for _, g := range p.groups {
		groups = append(groups, g)
	}
	return groups, nil
}

func (p *testProvider) AddUserToGroup(_ context.Context, _, _ string) error      { return nil }
func (p *testProvider) RemoveUserFromGroup(_ context.Context, _, _ string) error { return nil }
func (p *testProvider) GetUserGroups(_ context.Context, _ string) ([]*types.DirectoryGroup, error) {
	return nil, nil
}
func (p *testProvider) GetGroupMembers(_ context.Context, _ string) ([]*types.DirectoryUser, error) {
	return nil, nil
}

func (p *testProvider) SupportsOUs() bool { return false }
func (p *testProvider) GetOU(_ context.Context, _ string) (*OrganizationalUnit, error) {
	return nil, fmt.Errorf("OUs not supported")
}
func (p *testProvider) CreateOU(_ context.Context, _ *OrganizationalUnit) (*OrganizationalUnit, error) {
	return nil, fmt.Errorf("OUs not supported")
}
func (p *testProvider) UpdateOU(_ context.Context, _ string, _ *OrganizationalUnit) (*OrganizationalUnit, error) {
	return nil, fmt.Errorf("OUs not supported")
}
func (p *testProvider) DeleteOU(_ context.Context, _ string) error {
	return fmt.Errorf("OUs not supported")
}
func (p *testProvider) ListOUs(_ context.Context) ([]*OrganizationalUnit, error) {
	return nil, fmt.Errorf("OUs not supported")
}

func (p *testProvider) SupportsAdminUnits() bool { return false }
func (p *testProvider) GetAdminUnit(_ context.Context, _ string) (*AdministrativeUnit, error) {
	return nil, fmt.Errorf("admin units not supported")
}
func (p *testProvider) CreateAdminUnit(_ context.Context, _ *AdministrativeUnit) (*AdministrativeUnit, error) {
	return nil, fmt.Errorf("admin units not supported")
}
func (p *testProvider) UpdateAdminUnit(_ context.Context, _ string, _ *AdministrativeUnit) (*AdministrativeUnit, error) {
	return nil, fmt.Errorf("admin units not supported")
}
func (p *testProvider) DeleteAdminUnit(_ context.Context, _ string) error {
	return fmt.Errorf("admin units not supported")
}
func (p *testProvider) ListAdminUnits(_ context.Context) ([]*AdministrativeUnit, error) {
	return nil, fmt.Errorf("admin units not supported")
}

// newTestService creates a DirectoryService with the given providers registered.
func newTestService(t *testing.T, providers ...*testProvider) *DirectoryService {
	t.Helper()
	svc := NewDirectoryService(logging.NewNoopLogger())
	for _, p := range providers {
		require.NoError(t, svc.RegisterProvider(p))
	}
	return svc
}

// TestCompareDirectories_IdenticalProviders_ZeroDiffs asserts that two providers carrying
// identical users and groups produce TotalDifferences == 0.
func TestCompareDirectories_IdenticalProviders_ZeroDiffs(t *testing.T) {
	p1 := newTestProvider("alpha")
	p2 := newTestProvider("beta")

	user := &types.DirectoryUser{
		ID:                "u1",
		UserPrincipalName: "alice@example.com",
		DisplayName:       "Alice",
		AccountEnabled:    true,
	}
	group := &types.DirectoryGroup{
		ID:          "g1",
		Name:        "engineers",
		DisplayName: "Engineers",
		GroupType:   types.GroupTypeSecurity,
		GroupScope:  types.GroupScopeGlobal,
	}

	p1.addUser(user)
	p2.addUser(user)
	p1.addGroup(group)
	p2.addGroup(group)

	svc := newTestService(t, p1, p2)

	result, err := svc.CompareDirectories(context.Background(), "alpha", "beta")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "alpha", result.Provider1)
	assert.Equal(t, "beta", result.Provider2)
	assert.Equal(t, 0, result.Summary.TotalDifferences)
	assert.Empty(t, result.UserDifferences)
	assert.Empty(t, result.GroupDifferences)
}

// TestCompareDirectories_DetectsRealDiffs asserts that differences between providers are
// detected and surfaced with a non-zero TotalDifferences count.
func TestCompareDirectories_DetectsRealDiffs(t *testing.T) {
	p1 := newTestProvider("alpha")
	p2 := newTestProvider("beta")

	// alice exists in both but with a different DisplayName in p2
	p1.addUser(&types.DirectoryUser{
		ID:                "u1",
		UserPrincipalName: "alice@example.com",
		DisplayName:       "Alice",
		AccountEnabled:    true,
	})
	p2.addUser(&types.DirectoryUser{
		ID:                "u1",
		UserPrincipalName: "alice@example.com",
		DisplayName:       "Alice Smith", // differs
		AccountEnabled:    true,
	})

	// bob exists only in p1 — should count as a create relative to p2
	p1.addUser(&types.DirectoryUser{
		ID:                "u2",
		UserPrincipalName: "bob@example.com",
		DisplayName:       "Bob",
		AccountEnabled:    true,
	})

	svc := newTestService(t, p1, p2)

	result, err := svc.CompareDirectories(context.Background(), "alpha", "beta")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, result.Summary.TotalDifferences, 0,
		"expected at least one difference; got %+v", result.Summary)
	assert.NotEmpty(t, result.UserDifferences)
}

// TestCompareDirectories_GroupDiffs asserts that group-level differences are detected.
func TestCompareDirectories_GroupDiffs(t *testing.T) {
	p1 := newTestProvider("alpha")
	p2 := newTestProvider("beta")

	// Same group, different description
	p1.addGroup(&types.DirectoryGroup{
		ID:          "g1",
		Name:        "engineers",
		DisplayName: "Engineers",
		Description: "Build things",
		GroupType:   types.GroupTypeSecurity,
		GroupScope:  types.GroupScopeGlobal,
	})
	p2.addGroup(&types.DirectoryGroup{
		ID:          "g1",
		Name:        "engineers",
		DisplayName: "Engineers",
		Description: "Ship things", // differs
		GroupType:   types.GroupTypeSecurity,
		GroupScope:  types.GroupScopeGlobal,
	})

	svc := newTestService(t, p1, p2)

	result, err := svc.CompareDirectories(context.Background(), "alpha", "beta")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, result.Summary.TotalDifferences, 0)
	assert.NotEmpty(t, result.GroupDifferences)
}

// TestCompareDirectories_UnknownProvider returns an error for a missing provider.
func TestCompareDirectories_UnknownProvider(t *testing.T) {
	p1 := newTestProvider("alpha")
	svc := newTestService(t, p1)

	_, err := svc.CompareDirectories(context.Background(), "alpha", "nonexistent")
	require.Error(t, err)
}

// TestGetProviderStatistics_ReturnsRealCounts asserts that user and group counts reflect
// the actual objects stored in the provider.
func TestGetProviderStatistics_ReturnsRealCounts(t *testing.T) {
	p := newTestProvider("alpha")
	p.addUser(&types.DirectoryUser{
		ID:                "u1",
		UserPrincipalName: "alice@example.com",
		DisplayName:       "Alice",
		AccountEnabled:    true,
	})
	p.addUser(&types.DirectoryUser{
		ID:                "u2",
		UserPrincipalName: "bob@example.com",
		DisplayName:       "Bob",
		AccountEnabled:    true,
	})
	p.addGroup(&types.DirectoryGroup{
		ID:          "g1",
		Name:        "engineers",
		DisplayName: "Engineers",
		GroupType:   types.GroupTypeSecurity,
		GroupScope:  types.GroupScopeGlobal,
	})

	svc := newTestService(t, p)

	stats, err := svc.GetProviderStatistics(context.Background(), "alpha")
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, int64(2), stats.TotalUsers)
	assert.Equal(t, int64(1), stats.TotalGroups)
}

// TestGetProviderStatistics_TracksRequestCount asserts that SearchUsers calls are counted
// in the provider's request counter.
func TestGetProviderStatistics_TracksRequestCount(t *testing.T) {
	p := newTestProvider("alpha")
	p.addUser(&types.DirectoryUser{
		ID:                "u1",
		UserPrincipalName: "alice@example.com",
		DisplayName:       "Alice",
		AccountEnabled:    true,
	})

	svc := newTestService(t, p)
	ctx := context.Background()

	// Issue two search calls to increment the counter
	_, err := svc.SearchUsers(ctx, "alpha", &SearchQuery{})
	require.NoError(t, err)
	_, err = svc.SearchUsers(ctx, "alpha", &SearchQuery{})
	require.NoError(t, err)

	stats, err := svc.GetProviderStatistics(ctx, "alpha")
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, int64(2), stats.RequestCount)
}

// TestGetProviderStatistics_PropagatesSearchError asserts that a provider search failure
// is returned as an error rather than silently producing zero counts.
func TestGetProviderStatistics_PropagatesSearchError(t *testing.T) {
	p := newTestProvider("alpha")
	p.failSearch = true
	svc := newTestService(t, p)

	_, err := svc.GetProviderStatistics(context.Background(), "alpha")
	require.Error(t, err, "expected error when provider search fails")
}

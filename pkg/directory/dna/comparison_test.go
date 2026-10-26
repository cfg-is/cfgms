// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// sliceProvider is an in-test DirectoryProvider backed by slices. It embeds the
// interface so any method other than the three below panics on a nil receiver,
// proving CompareDirectories calls nothing else.
type sliceProvider struct {
	interfaces.DirectoryProvider
	name     string
	users    []interfaces.DirectoryUser
	groups   []interfaces.DirectoryGroup
	pageSize int // 0 = everything in one page
	err      error
	// stuck makes every call return an empty page with HasMore=true
	stuck bool
}

func (p *sliceProvider) GetProviderInfo() interfaces.ProviderInfo {
	return interfaces.ProviderInfo{Name: p.name}
}

func page(total, offset, size int) (int, int, bool) {
	if offset > total {
		offset = total
	}
	end := total
	if size > 0 && offset+size < total {
		end = offset + size
	}
	return offset, end, end < total
}

func (p *sliceProvider) ListUsers(_ context.Context, f *interfaces.SearchFilters) (*interfaces.UserList, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.stuck {
		return &interfaces.UserList{HasMore: true}, nil
	}
	start, end, more := page(len(p.users), f.Offset, p.pageSize)
	return &interfaces.UserList{Users: p.users[start:end], TotalCount: len(p.users), HasMore: more}, nil
}

func (p *sliceProvider) ListGroups(_ context.Context, f *interfaces.SearchFilters) (*interfaces.GroupList, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.stuck {
		return &interfaces.GroupList{HasMore: true}, nil
	}
	start, end, more := page(len(p.groups), f.Offset, p.pageSize)
	return &interfaces.GroupList{Groups: p.groups[start:end], TotalCount: len(p.groups), HasMore: more}, nil
}

func testUser(upn, display string) interfaces.DirectoryUser {
	return interfaces.DirectoryUser{ID: upn, UserPrincipalName: upn, DisplayName: display, AccountEnabled: true}
}

func testGroup(name, desc string) interfaces.DirectoryGroup {
	return interfaces.DirectoryGroup{
		ID: name, Name: name, DisplayName: name, Description: desc,
		GroupType: interfaces.GroupTypeSecurity, GroupScope: interfaces.GroupScopeGlobal,
	}
}

func TestCompareDirectories_IdenticalProviders_ZeroDiffs(t *testing.T) {
	users := []interfaces.DirectoryUser{testUser("alice@example.com", "Alice")}
	groups := []interfaces.DirectoryGroup{testGroup("engineers", "Build things")}
	p1 := &sliceProvider{name: "alpha", users: users, groups: groups}
	p2 := &sliceProvider{name: "beta", users: users, groups: groups}

	result, err := CompareDirectories(context.Background(), p1, p2, logging.NewNoopLogger())
	require.NoError(t, err)
	assert.Equal(t, "alpha", result.Provider1)
	assert.Equal(t, "beta", result.Provider2)
	assert.Equal(t, 0, result.Summary.TotalDifferences)
	assert.Empty(t, result.UserDifferences)
	assert.Empty(t, result.GroupDifferences)
}

func TestCompareDirectories_DetectsRealDiffs(t *testing.T) {
	p1 := &sliceProvider{name: "alpha", users: []interfaces.DirectoryUser{
		testUser("alice@example.com", "Alice"),
		testUser("bob@example.com", "Bob"), // only in p1
	}}
	p2 := &sliceProvider{name: "beta", users: []interfaces.DirectoryUser{
		testUser("alice@example.com", "Alice Smith"), // modified
	}}

	result, err := CompareDirectories(context.Background(), p1, p2, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Summary.UsersToCreate)
	assert.Equal(t, 1, result.Summary.UsersToUpdate)
	assert.Equal(t, 2, result.Summary.TotalDifferences)

	var sawCreate, sawUpdate bool
	for _, d := range result.UserDifferences {
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, d.ObjectType)
		switch d.Action {
		case "create":
			sawCreate = true
			assert.Equal(t, "bob@example.com", d.ObjectID)
		case "update":
			sawUpdate = true
			assert.Equal(t, "display_name", d.Field)
			assert.Equal(t, "Alice Smith", d.OldValue) // baseline (provider 2)
			assert.Equal(t, "Alice", d.NewValue) // current (provider 1)
		}
	}
	assert.True(t, sawCreate && sawUpdate, "got %+v", result.UserDifferences)
}

func TestCompareDirectories_GroupDiffs(t *testing.T) {
	p1 := &sliceProvider{name: "alpha", groups: []interfaces.DirectoryGroup{testGroup("engineers", "Build things")}}
	p2 := &sliceProvider{name: "beta", groups: []interfaces.DirectoryGroup{testGroup("engineers", "Ship things")}}

	result, err := CompareDirectories(context.Background(), p1, p2, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Summary.GroupsToUpdate)
	require.NotEmpty(t, result.GroupDifferences)
	assert.Equal(t, interfaces.DirectoryObjectTypeGroup, result.GroupDifferences[0].ObjectType)
	assert.Equal(t, "description", result.GroupDifferences[0].Field)
}

func TestCompareDirectories_PagesThroughAllResults(t *testing.T) {
	var users []interfaces.DirectoryUser
	var groups []interfaces.DirectoryGroup
	for i := 0; i < 7; i++ {
		users = append(users, testUser(fmt.Sprintf("u%d@example.com", i), "User"))
		groups = append(groups, testGroup(fmt.Sprintf("g%d", i), "Group"))
	}
	// p1 pages in threes; p2 has the same objects in a single page.
	p1 := &sliceProvider{name: "alpha", users: users, groups: groups, pageSize: 3}
	p2 := &sliceProvider{name: "beta", users: users, groups: groups}

	result, err := CompareDirectories(context.Background(), p1, p2, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Summary.TotalDifferences, "objects on later pages must be seen")

	// Drop one object from p2: only visible if p1's last page was read.
	p2.users = users[:6]
	result, err = CompareDirectories(context.Background(), p1, p2, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Summary.UsersToCreate)
}

func TestCompareDirectories_EmptyPageWithHasMoreTerminates(t *testing.T) {
	good := &sliceProvider{name: "alpha"}
	stuck := &sliceProvider{name: "beta", stuck: true}

	_, err := CompareDirectories(context.Background(), good, stuck, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty page")
}

func TestCompareDirectories_ProviderErrorPropagates(t *testing.T) {
	sentinel := errors.New("backend down")
	good := &sliceProvider{name: "alpha"}
	bad := &sliceProvider{name: "beta", err: sentinel}

	_, err := CompareDirectories(context.Background(), good, bad, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)

	_, err = CompareDirectories(context.Background(), bad, good, nil)
	assert.ErrorIs(t, err, sentinel)
}

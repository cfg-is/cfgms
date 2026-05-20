// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newConnectedProvider(t *testing.T) (*ActiveDirectoryProvider, *MockStewardClient) {
	t.Helper()
	client := NewMockStewardClient()
	client.AddSteward(StewardInfo{
		ID:        "steward-dc01",
		Hostname:  "dc01.example.com",
		Modules:   []string{"activedirectory"},
		IsHealthy: true,
		LastSeen:  time.Now(),
	})
	provider := NewActiveDirectoryProvider(client, logging.NewNoopLogger())
	err := provider.Connect(context.Background(), interfaces.ProviderConfig{
		ServerAddress: "example.com",
		AuthMethod:    interfaces.AuthMethodLDAP,
	})
	require.NoError(t, err)
	return provider, client
}

func TestSearch_NilQueryReturnsError(t *testing.T) {
	provider := &ActiveDirectoryProvider{logger: logging.NewNoopLogger()}
	_, err := provider.Search(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query is required")
}

func TestSearch_EmptyFilterReturnsError(t *testing.T) {
	provider := &ActiveDirectoryProvider{logger: logging.NewNoopLogger()}
	_, err := provider.Search(context.Background(), &interfaces.DirectoryQuery{Filter: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LDAP filter is required")
}

func TestSearch_MalformedFilterReturnsValidationError(t *testing.T) {
	provider := &ActiveDirectoryProvider{logger: logging.NewNoopLogger()}
	ctx := context.Background()

	cases := []struct{ name, filter string }{
		{"unclosed paren", "(&(objectClass=user)(department=Engineering)"},
		{"extra close paren", "(objectClass=user))"},
		{"close before open", ")objectClass=user("},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.Search(ctx, &interfaces.DirectoryQuery{Filter: tc.filter})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unbalanced parentheses")
		})
	}
}

func TestSearch_CompoundFilterForwardedUnmodified(t *testing.T) {
	provider, client := newConnectedProvider(t)
	ctx := context.Background()

	filter := "(&(objectClass=user)(department=Engineering))"
	client.SetModuleState("steward-dc01", "search:"+filter, map[string]interface{}{
		"success":     true,
		"total_count": 2,
		"has_more":    false,
		"users": []map[string]interface{}{
			{"id": "u1", "display_name": "Alice Smith", "account_enabled": true},
			{"id": "u2", "display_name": "Bob Jones", "account_enabled": true},
		},
	})

	results, err := provider.Search(ctx, &interfaces.DirectoryQuery{
		Filter:     filter,
		SearchBase: "DC=example,DC=com",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, results.TotalCount)
	assert.Len(t, results.Users, 2)
	assert.False(t, results.HasMore)
}

func TestSearch_NegationAndExtensibleFilterForwardedUnmodified(t *testing.T) {
	provider, client := newConnectedProvider(t)
	ctx := context.Background()

	// Compound filter with negation and extensible match — operators that the
	// old conversion-to-simple-operations approach could not represent.
	filter := "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	client.SetModuleState("steward-dc01", "search:"+filter, map[string]interface{}{
		"success":     true,
		"total_count": 1,
		"has_more":    false,
		"users": []map[string]interface{}{
			{"id": "u1", "display_name": "Active User", "account_enabled": true},
		},
	})

	results, err := provider.Search(ctx, &interfaces.DirectoryQuery{Filter: filter})
	require.NoError(t, err)
	assert.Equal(t, 1, results.TotalCount)
	assert.Len(t, results.Users, 1)
}

func TestSearch_StewardTransportErrorPropagated(t *testing.T) {
	provider, client := newConnectedProvider(t)
	client.SetError(true, "steward communication failed")

	_, err := provider.Search(context.Background(), &interfaces.DirectoryQuery{
		Filter: "(objectClass=user)",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LDAP search failed")
}

func TestSearch_StewardReportsQueryFailure(t *testing.T) {
	provider, client := newConnectedProvider(t)

	filter := "(objectClass=user)"
	client.SetModuleState("steward-dc01", "search:"+filter, map[string]interface{}{
		"success": false,
		"error":   "LDAP search timed out",
	})

	_, err := provider.Search(context.Background(), &interfaces.DirectoryQuery{Filter: filter})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LDAP search timed out")
}

func TestBulkCreateUsers_ReturnsDesignDecisionError(t *testing.T) {
	provider := &ActiveDirectoryProvider{
		logger: logging.NewNoopLogger(),
	}
	ctx := context.Background()

	_, err := provider.BulkCreateUsers(ctx, []*interfaces.DirectoryUser{}, &interfaces.BulkOptions{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "design decision"),
		"expected design decision error, got: %s", err.Error())
}

func TestBulkDeleteUsers_ReturnsDesignDecisionError(t *testing.T) {
	provider := &ActiveDirectoryProvider{
		logger: logging.NewNoopLogger(),
	}
	ctx := context.Background()

	_, err := provider.BulkDeleteUsers(ctx, []string{}, &interfaces.BulkOptions{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "design decision"),
		"expected design decision error, got: %s", err.Error())
}

func TestBulkUpdateUsers_ReturnsDesignDecisionError(t *testing.T) {
	provider := &ActiveDirectoryProvider{
		logger: logging.NewNoopLogger(),
	}
	ctx := context.Background()

	_, err := provider.BulkUpdateUsers(ctx, []*interfaces.UserUpdate{}, &interfaces.BulkOptions{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "design decision"),
		"expected design decision error, got: %s", err.Error())
}

// SPDX-License-Identifier: AGPL-3.0-only
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

// TestSearch_NotSupportedByModule locks in the Issue #4448 design decision:
// SearchDirectory fails fast with a capability error, for both simple and
// compound/extensible-match filters, and never reaches the steward. Search
// previously forwarded the filter unmodified (and these tests asserted a
// successful round-trip); the activedirectory module has no operation that
// accepts an arbitrary LDAP filter, and interpolating one into the module's
// PowerShell execution path has no safe escaping mechanism today, so a
// delimiter-style fix here would trade one injection class for a worse one.
func TestSearch_NotSupportedByModule(t *testing.T) {
	provider, client := newConnectedProvider(t)
	ctx := context.Background()

	cases := []struct {
		name   string
		filter string
	}{
		{"simple filter", "(objectClass=user)"},
		{"compound filter", "(&(objectClass=user)(department=Engineering))"},
		{"negation and extensible match", "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client.SetModuleState("steward-dc01", "search:"+tc.filter, map[string]interface{}{
				"success":     true,
				"total_count": 1,
				"has_more":    false,
				"users":       []map[string]interface{}{{"id": "u1", "display_name": "Should Not Be Reached"}},
			})

			_, err := provider.Search(ctx, &interfaces.DirectoryQuery{Filter: tc.filter})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "design decision")
			assert.Contains(t, err.Error(), "not supported")
		})
	}
}

func TestSearch_NeverReachesSteward(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	_, err := provider.Search(context.Background(), &interfaces.DirectoryQuery{
		Filter: "(objectClass=user)",
	})
	require.Error(t, err)
	assert.Equal(t, int64(0), provider.GetRequestCount(), "Search must not contact the steward at all")
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

// TestDelimiterInjection_CannotShiftQueriedObject is the Issue #4448
// [REQUIRED TEST]: a caller-supplied value containing the reserved resourceID
// delimiter must not cause the steward to be asked about a different object
// than the caller named. It asserts on the resourceID actually reaching
// GetModuleState, so it needs no live AD server. Each case must fail against
// the pre-fix code (no validation) and pass after it; this was confirmed in
// that order while developing this story.
func TestDelimiterInjection_CannotShiftQueriedObject(t *testing.T) {
	ctx := context.Background()

	t.Run("GetComputer", func(t *testing.T) {
		provider, client := newConnectedProvider(t)
		client.SetModuleState("steward-dc01", "query:computer:alice", map[string]interface{}{
			"success": true,
			"user":    map[string]interface{}{"id": "wrong-object", "display_name": "Wrong Object"},
		})

		_, err := provider.GetComputer(ctx, "alice:bob")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reserved resourceID delimiter")
		assert.Equal(t, int64(0), provider.GetRequestCount(), "GetModuleState must not be called with a truncated id")
	})

	t.Run("GetGroupPolicy", func(t *testing.T) {
		provider, client := newConnectedProvider(t)
		client.SetModuleState("steward-dc01", "query:gpo:alice", map[string]interface{}{
			"success":        true,
			"generic_object": map[string]interface{}{"name": "Wrong GPO"},
		})

		_, err := provider.GetGroupPolicy(ctx, "alice:bob")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reserved resourceID delimiter")
		assert.Equal(t, int64(0), provider.GetRequestCount(), "GetModuleState must not be called with a truncated id")
	})

	t.Run("GetDomainTrust", func(t *testing.T) {
		provider, client := newConnectedProvider(t)
		client.SetModuleState("steward-dc01", "query:trust:alice", map[string]interface{}{
			"success":        true,
			"generic_object": map[string]interface{}{"name": "Wrong Trust"},
		})

		_, err := provider.GetDomainTrust(ctx, "alice:bob")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reserved resourceID delimiter")
		assert.Equal(t, int64(0), provider.GetRequestCount(), "GetModuleState must not be called with a truncated id")
	})
}

func TestQueryForest_NotSupportedByModule(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	_, err := provider.QueryForest(context.Background(), "user", "admin.user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "design decision")
	assert.Contains(t, err.Error(), "not supported")
}

func TestQueryForest_NeverReachesSteward(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	_, err := provider.QueryForest(context.Background(), "user", "admin.user")
	require.Error(t, err)
	assert.Equal(t, int64(0), provider.GetRequestCount(), "QueryForest must not contact the steward at all")
}

func TestQueryForest_RejectsDelimiterInInputsBeforeFailingFast(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	_, err := provider.QueryForest(context.Background(), "user:evil", "admin.user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved resourceID delimiter")

	_, err = provider.QueryForest(context.Background(), "user", "admin.user:evil")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved resourceID delimiter")
}

func TestValidateCrossDomainTrust_NotSupportedByModule(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	err := provider.ValidateCrossDomainTrust(context.Background(), "dev.contoso.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "design decision")
	assert.Contains(t, err.Error(), "trust")
}

func TestValidateCrossDomainTrust_NeverReachesSteward(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	err := provider.ValidateCrossDomainTrust(context.Background(), "dev.contoso.com")
	require.Error(t, err)
	assert.Equal(t, int64(0), provider.GetRequestCount(), "ValidateCrossDomainTrust must not contact the steward at all")
}

func TestValidateCrossDomainTrust_RejectsDelimiterBeforeFailingFast(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	err := provider.ValidateCrossDomainTrust(context.Background(), "dev.contoso.com:evil")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved resourceID delimiter")
}

func TestQueryTrustedDomain_NotSupportedByModule(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	_, err := provider.QueryTrustedDomain(context.Background(), "dev.contoso.com", "user", "jane.smith")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "design decision")
	assert.Contains(t, err.Error(), "trust")
}

func TestQueryTrustedDomain_NeverReachesSteward(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	_, err := provider.QueryTrustedDomain(context.Background(), "dev.contoso.com", "user", "jane.smith")
	require.Error(t, err)
	assert.Equal(t, int64(0), provider.GetRequestCount(), "QueryTrustedDomain must not contact the steward at all")
}

// TestQueryTrustedDomain_ObjectTypeClosedSet is the Issue #4448 AC: at
// advanced_operations.go's QueryTrustedDomain, objectType is the one
// composition site where the type segment is caller-supplied directly, so an
// injected value changes which type of object is named rather than merely
// truncating an id. A closed set rejects any value outside the known
// directory object types, independent of whether it contains the delimiter.
func TestQueryTrustedDomain_ObjectTypeClosedSet(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	_, err := provider.QueryTrustedDomain(context.Background(), "dev.contoso.com", "not-a-real-type", "jane.smith")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported object type")
}

func TestQueryTrustedDomain_RejectsDelimiterInInputs(t *testing.T) {
	provider, _ := newConnectedProvider(t)

	_, err := provider.QueryTrustedDomain(context.Background(), "dev.contoso.com", "user", "jane.smith:evil")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved resourceID delimiter")

	_, err = provider.QueryTrustedDomain(context.Background(), "dev.contoso.com:evil", "user", "jane.smith")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved resourceID delimiter")
}

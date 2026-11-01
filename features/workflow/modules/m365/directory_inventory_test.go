// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package m365

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestMemberTypeOf(t *testing.T) {
	cases := map[string]string{
		"#microsoft.graph.user":             "user",
		"#microsoft.graph.group":            "group",
		"#microsoft.graph.device":           "device",
		"#microsoft.graph.servicePrincipal": "service_principal",
		"#microsoft.graph.orgContact":       "contact",
		"#microsoft.graph.somethingNew":     "other",
		"":                                  "other",
	}
	for in, want := range cases {
		assert.Equal(t, want, memberTypeOf(in), in)
	}
}

// A Graph client that cannot page fails the inventory call instead of silently
// returning a bounded list.
func TestInventoryReader_NonPagingGraphClientFails(t *testing.T) {
	p := NewEntraIDDirectoryProvider(logging.NewNoopLogger(), nil, struct{ graph.Client }{})
	require.NoError(t, p.Connect(context.Background(), interfaces.ProviderConfig{}))
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "t")

	_, _, err := p.ListUsersPage(ctx, "", 10)
	require.Error(t, err)
	_, _, err = p.ListGroupsPage(ctx, "", 10)
	require.Error(t, err)
	_, _, err = p.ListGroupMembersPage(ctx, "g", "", 10)
	require.Error(t, err)
}

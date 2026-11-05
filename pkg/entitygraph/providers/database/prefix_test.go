// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// TestErrorPrefix pins the provider-specific error prefix on the paths shared
// through egcommon. Both fail before any database access, so no connection is
// needed.
func TestErrorPrefix(t *testing.T) {
	p := &DatabaseEntityGraphProvider{}

	_, err := p.Watch(context.Background(), interfaces.WatchFilter{}, "abc")
	require.EqualError(t, err, `entitygraph/database: watch: invalid cursor "abc": must be a decimal integer`)

	root, err := types.ParseEID("host:a")
	require.NoError(t, err)
	_, err = p.GetNeighborhood(context.Background(), root, nil, types.TraversalBoth, 4, interfaces.TenantCut{})
	require.EqualError(t, err, "entitygraph/database: depth 4 exceeds maximum 3")
}

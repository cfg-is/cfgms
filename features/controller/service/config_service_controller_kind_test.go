// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

func TestConfigBuild_ControllerKindResourcesNotSentToSteward(t *testing.T) {
	svc := newDirectoryTestService(t, "tenant-a")
	ctx := ctxkeys.WithSystem(context.Background())

	cfg := &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: "dev-1"},
		Resources: []stewardtypes.ResourceConfig{
			{Name: "alice", Module: "m365-entra-user", Config: map[string]interface{}{
				"user_principal_name": "alice@example.com", "display_name": "Alice"}},
			{Name: "staff", Module: "m365-entra-group", Config: map[string]interface{}{"display_name": "Staff"}},
			{Name: "motd", Module: "file", Config: map[string]interface{}{"path": "/etc/motd"}},
		},
	}
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-a", "dev-1", cfg))

	// The controller's own view keeps every declaration.
	eff, err := svc.GetEffectiveConfiguration(ctx, "tenant-a", "dev-1")
	require.NoError(t, err)
	require.Len(t, eff.Config.Resources, 3)

	tctx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-a")
	resp, err := svc.GetConfiguration(tctx, &controllerpb.ConfigRequest{StewardId: "dev-1"})
	require.NoError(t, err)
	require.NotNil(t, resp.Config)

	var names []string
	for _, r := range resp.Config.Config.Resources {
		assert.NotContains(t, r.Module, "m365-entra", "controller-kind resource reached the steward cfg")
		names = append(names, r.Name)
	}
	assert.Equal(t, []string{"motd"}, names)
}

func TestDropControllerKindResources_DoesNotMutateInput(t *testing.T) {
	in := &stewardtypes.StewardConfig{Resources: []stewardtypes.ResourceConfig{
		{Name: "a", Module: "m365-entra-user"}, {Name: "b", Module: "file"},
	}}
	out := dropControllerKindResources(in)
	assert.Len(t, in.Resources, 2)
	require.Len(t, out.Resources, 1)
	assert.Equal(t, "b", out.Resources[0].Name)
	assert.Nil(t, dropControllerKindResources(nil))
}

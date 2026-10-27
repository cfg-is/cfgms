// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

func TestObserveSweep_CopiesPerObjectFlagFromManifest(t *testing.T) {
	cp := &inObserveSweepControlPlane{}
	m := makeManifest("ad", "ad_user", "role", "dc")
	m.Owns = []modules.OwnershipDeclaration{
		{Kind: "ad_user", PerObject: true},
		{Kind: "ad_site"},
	}
	srv := newObserveServer(t, cp, &inMemoryManifestProvider{manifests: []*modules.ModuleMetadata{m}})

	require.NoError(t, srv.handleObserveSweepRequest(context.Background(),
		sweepEvent("steward-1", map[string]string{"role": "dc"})))

	cmds := cp.sentCommandsOfType(controlplaneTypes.CommandObserveModules)
	require.Len(t, cmds, 1)
	raw, ok := cmds[0].Command.Params["modules"].(string)
	require.True(t, ok)
	var specs []controlplaneTypes.ObserveModuleSpec
	require.NoError(t, json.Unmarshal([]byte(raw), &specs))
	require.Len(t, specs, 2)
	byKind := map[string]bool{}
	for _, s := range specs {
		byKind[s.Kind] = s.PerObject
	}
	assert.True(t, byKind["ad_user"], "per_object owns entry must set PerObject")
	assert.False(t, byKind["ad_site"], "plain owns entry must leave PerObject false")
}

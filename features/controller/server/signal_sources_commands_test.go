// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newCommandSignalTestPublisher builds a publisher over a real memory control
// plane with one connected steward, "steward-1".
func newCommandSignalTestPublisher(t *testing.T) *commands.Publisher {
	t.Helper()
	ctx := context.Background()
	bus := memory.NewBus()

	cp := memory.New(memory.ModeServer)
	require.NoError(t, cp.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, cp.Start(ctx))
	t.Cleanup(func() { _ = cp.Stop(context.Background()) })

	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": "steward-1"}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	pub, err := commands.New(&commands.Config{ControlPlane: cp, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Stop(context.Background()) })
	return pub
}

// TestCommandSignalsScrape runs the registered source against a server and
// proves a send and a completion appear in the registry's scrape output.
func TestCommandSignalsScrape(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	srv.commandPublisher = newCommandSignalTestPublisher(t)

	assert.Equal(t, 0, srv.runSignalSources(), "the command source must register cleanly")

	ctx := context.Background()
	id, err := srv.commandPublisher.PublishCommandWithCallback(ctx, "steward-1", types.CommandSyncConfig, nil, 60e9, nil, nil)
	require.NoError(t, err)
	require.NoError(t, srv.commandPublisher.HandleEventUpdate(ctx, &types.Event{
		Type: types.EventCommandCompleted, StewardID: "steward-1", CommandID: id,
	}))
	require.Error(t, srv.commandPublisher.PublishCommandWithID(ctx, "cmd-2", "steward-gone", types.CommandSyncDNA, nil))

	var sb strings.Builder
	require.NoError(t, srv.healthCollector.Signals().WriteText(&sb))
	out := sb.String()
	assert.Contains(t, out, `cfgms_command_send_total{command_type="sync_config",outcome="sent"} 1`)
	assert.Contains(t, out, `cfgms_command_send_total{command_type="sync_dna",outcome="send_failed"} 1`)
	assert.Contains(t, out, `cfgms_command_completion_seconds_count{command_type="sync_config",outcome="completed"} 1`)
}

func TestCommandSignalSourceWithoutPublisher(t *testing.T) {
	srv := newSignalSourceTestServer(t)

	require.NoError(t, commandSignalSource(srv))

	var sb strings.Builder
	require.NoError(t, srv.healthCollector.Signals().WriteText(&sb))
	assert.NotContains(t, sb.String(), "cfgms_command_")
}

func TestCommandSignalSourceDuplicateRegistrationFails(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	srv.commandPublisher = newCommandSignalTestPublisher(t)

	require.NoError(t, commandSignalSource(srv))
	require.Error(t, commandSignalSource(srv))
}

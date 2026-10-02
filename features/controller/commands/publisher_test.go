// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"

	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
)

// staticTermSource implements TermSource and returns a fixed term value.
type staticTermSource struct {
	term uint64
}

func (s *staticTermSource) GetTerm() uint64 { return s.term }

// newTestPublisher creates a Publisher backed by a real memory controlplane.
// The returned client provider can be used to observe sent commands.
func newTestPublisher(t *testing.T, termSource commands.TermSource) (*commands.Publisher, *memory.Provider) {
	t.Helper()
	ctx := context.Background()

	bus := memory.NewBus()

	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, server.Stop(stopCtx))
	})

	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{
		"bus":        bus,
		"steward_id": "steward-test",
	}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, client.Stop(stopCtx))
	})

	logger := logging.NewLogger("error")

	pub, err := commands.New(&commands.Config{
		ControlPlane: server,
		TermSource:   termSource,
		Logger:       logger,
	})
	require.NoError(t, err)

	return pub, client
}

// TestPublishCommand_StampsTermFromSource verifies that a configured TermSource
// causes PublishCommand to set Command.Term to the value returned by GetTerm().
func TestPublishCommand_StampsTermFromSource(t *testing.T) {
	const wantTerm uint64 = 42

	pub, client := newTestPublisher(t, &staticTermSource{term: wantTerm})

	ctx := context.Background()
	received := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
		received <- cmd
		return nil
	})))

	_, err := pub.PublishCommand(ctx, "steward-test", types.CommandSyncConfig, nil)
	require.NoError(t, err)

	select {
	case cmd := <-received:
		assert.Equal(t, wantTerm, cmd.Command.Term, "published command must carry the TermSource's term")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command")
	}
}

// TestPublishCommand_ZeroTermWhenNoSource verifies that a nil TermSource leaves
// Command.Term at zero (pre-fencing behaviour, wire-compatible with old stewards).
func TestPublishCommand_ZeroTermWhenNoSource(t *testing.T) {
	pub, client := newTestPublisher(t, nil)

	ctx := context.Background()
	received := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
		received <- cmd
		return nil
	})))

	_, err := pub.PublishCommand(ctx, "steward-test", types.CommandSyncConfig, nil)
	require.NoError(t, err)

	select {
	case cmd := <-received:
		assert.Equal(t, uint64(0), cmd.Command.Term, "nil TermSource must leave term at zero")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command")
	}
}

// TestPublishCommandWithSigner_StampsTerm verifies that PublishCommandWithSigner
// also stamps the term from a configured TermSource.
func TestPublishCommandWithSigner_StampsTerm(t *testing.T) {
	const wantTerm uint64 = 7

	pub, client := newTestPublisher(t, &staticTermSource{term: wantTerm})

	ctx := context.Background()
	received := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
		received <- cmd
		return nil
	})))

	_, err := pub.PublishCommandWithSigner(ctx, "steward-test", types.CommandSyncConfig, nil, nil)
	require.NoError(t, err)

	select {
	case cmd := <-received:
		assert.Equal(t, wantTerm, cmd.Command.Term, "PublishCommandWithSigner must carry the TermSource's term")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command")
	}
}

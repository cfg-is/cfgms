// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// allCommandTypes is every command type number the current build handles.
func allCommandTypes() []int32 {
	out := make([]int32, 0, 15)
	for n := int32(1); n <= 15; n++ {
		out = append(out, n)
	}
	return out
}

func TestCapabilityResolver_SupportsCommandType(t *testing.T) {
	ctx := context.Background()

	t.Run("floor connection supports the floor types only", func(t *testing.T) {
		f := newResolverFixture(t)
		f.connect("conn-1", 0).SettleCapabilities(registry.CapabilityFloor, types.FloorProfile().CommandTypes, []uint32{1})
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandSyncConfig))
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandObserveModules))
		assert.False(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandStewardAction))
		assert.False(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandAdvertiseTransportAddress))
	})

	t.Run("declared current connection supports every type", func(t *testing.T) {
		f := newResolverFixture(t)
		f.connect("conn-1", 0).SettleCapabilities(registry.CapabilityDeclared, allCommandTypes(), current())
		for _, cmdType := range types.KnownCommandTypes() {
			assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, cmdType), string(cmdType))
		}
	})

	t.Run("declared set is the authority, not the floor", func(t *testing.T) {
		f := newResolverFixture(t)
		f.connect("conn-1", 0).SettleCapabilities(registry.CapabilityDeclared, []int32{1, 2, 14}, current())
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandStewardAction))
		assert.False(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandAdvertiseTransportAddress))
		assert.False(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandExecuteScript))
	})

	t.Run("connection silent past the wait is taken at the floor", func(t *testing.T) {
		f := newResolverFixture(t)
		f.connect("conn-1", time.Hour)
		assert.False(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandStewardAction))
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandSyncConfig))
	})

	t.Run("a late declaration is picked up by the next call", func(t *testing.T) {
		f := newResolverFixture(t)
		conn := f.connect("conn-1", time.Hour)
		require.False(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandStewardAction))
		conn.SettleCapabilities(registry.CapabilityFloor, types.FloorProfile().CommandTypes, []uint32{1})
		conn.SettleCapabilities(registry.CapabilityDeclared, allCommandTypes(), current())
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandStewardAction))
	})

	t.Run("a type unknown to the controller is not gated", func(t *testing.T) {
		f := newResolverFixture(t)
		f.connect("conn-1", 0).SettleCapabilities(registry.CapabilityFloor, types.FloorProfile().CommandTypes, []uint32{1})
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandType("from_the_future")))
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandType("")))
	})

	t.Run("a steward with no record is not gated", func(t *testing.T) {
		f := newResolverFixture(t)
		assert.True(t, f.resolver.SupportsCommandType(ctx, "nobody", types.CommandStewardAction))
	})

	t.Run("a nil resolver and nil sources are not gated", func(t *testing.T) {
		var nilResolver *commands.CapabilityResolver
		assert.True(t, nilResolver.SupportsCommandType(ctx, "s", types.CommandStewardAction))
		bare := commands.NewCapabilityResolver(nil, nil, nil)
		assert.True(t, bare.SupportsCommandType(ctx, "s", types.CommandStewardAction))
	})

	t.Run("an unreadable record is not gated", func(t *testing.T) {
		r := commands.NewCapabilityResolver(nil, failingReader{}, nil)
		assert.True(t, r.SupportsCommandType(ctx, "s", types.CommandStewardAction))
	})
}

func TestCapabilityResolver_SupportsCommandTypeFromTheDurableRecord(t *testing.T) {
	ctx := context.Background()
	seed := func(f *resolverFixture, state string, cmds []int32) {
		t.Helper()
		require.NoError(t, f.store.ResetCapabilities(ctx, f.id, "other-node-conn"))
		applied, err := f.store.DeclareCapabilities(ctx, f.id, "other-node-conn", business.StewardCapabilityRecord{
			State: state, CommandTypes: cmds, SigningPayloadVersions: current(),
		})
		require.NoError(t, err)
		require.True(t, applied)
	}

	t.Run("floor record", func(t *testing.T) {
		f := newResolverFixture(t)
		seed(f, business.StewardCapabilityFloor, types.FloorProfile().CommandTypes)
		assert.False(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandStewardAction))
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandSyncConfig))
	})
	t.Run("declared record", func(t *testing.T) {
		f := newResolverFixture(t)
		seed(f, business.StewardCapabilityDeclared, allCommandTypes())
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandStewardAction))
		assert.True(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandAdvertiseTransportAddress))
	})
	t.Run("pending record past the wait is the floor", func(t *testing.T) {
		f := newResolverFixture(t)
		require.NoError(t, f.store.ResetCapabilities(ctx, f.id, "other-node-conn"))
		assert.False(t, f.resolver.SupportsCommandType(ctx, f.id, types.CommandAdvertiseTransportAddress))
	})
}

func TestPublisher_RefusesACommandTypeOutsideTheStewardsProfile(t *testing.T) {
	ctx := context.Background()

	t.Run("floor steward: type 15 is refused and nothing is sent", func(t *testing.T) {
		h := newSigningVersionHarness(t)
		h.connect("conn-1", 0).SettleCapabilities(registry.CapabilityFloor, types.FloorProfile().CommandTypes, []uint32{1})

		err := h.pub.PublishCommandWithID(ctx, "cmd-15", h.id, types.CommandAdvertiseTransportAddress,
			map[string]interface{}{types.ParamTransportAddress: "controller.example:4433"})
		require.Error(t, err)
		assert.True(t, errors.Is(err, commands.ErrCommandTypeUnsupportedByPeer), "got %v", err)
		assert.Empty(t, h.sent, "an unsupported type is never signed or sent")

		// The same steward still receives a shared type.
		require.NoError(t, h.pub.PublishCommandWithID(ctx, "cmd-1", h.id, types.CommandSyncConfig, nil))
		sc := h.next(t)
		assert.Equal(t, "cmd-1", sc.Command.ID)
		assert.Equal(t, types.CommandSyncConfig, sc.Command.Type)
		assert.Empty(t, h.sent)
	})

	t.Run("every entry point refuses", func(t *testing.T) {
		h := newSigningVersionHarness(t)
		h.connect("conn-1", 0).SettleCapabilities(registry.CapabilityFloor, types.FloorProfile().CommandTypes, []uint32{1})

		_, err := h.pub.PublishCommand(ctx, h.id, types.CommandStewardAction, nil)
		assert.True(t, errors.Is(err, commands.ErrCommandTypeUnsupportedByPeer))
		_, err = h.pub.PublishCommandWithCallback(ctx, h.id, types.CommandStewardAction, nil, time.Minute, nil, nil)
		assert.True(t, errors.Is(err, commands.ErrCommandTypeUnsupportedByPeer))
		_, err = h.pub.PublishCommandWithSigner(ctx, h.id, types.CommandStewardAction, nil, h.signer)
		assert.True(t, errors.Is(err, commands.ErrCommandTypeUnsupportedByPeer))
		_, err = h.pub.PublishCommandWithSignerAndCallback(ctx, h.id, types.CommandStewardAction, nil, h.signer, time.Minute, nil, nil)
		assert.True(t, errors.Is(err, commands.ErrCommandTypeUnsupportedByPeer))
		assert.Empty(t, h.sent)
		assert.Empty(t, h.pub.GetPendingCommands(), "a refused command leaves no pending entry")
	})

	t.Run("current steward: type 15 is sent", func(t *testing.T) {
		h := newSigningVersionHarness(t)
		h.connect("conn-1", 0).SettleCapabilities(registry.CapabilityDeclared, allCommandTypes(), current())

		require.NoError(t, h.pub.PublishCommandWithID(ctx, "cmd-15", h.id, types.CommandAdvertiseTransportAddress,
			map[string]interface{}{types.ParamTransportAddress: "controller.example:4433"}))
		assert.Equal(t, types.CommandAdvertiseTransportAddress, h.next(t).Command.Type)
	})

	t.Run("a type unknown to the controller is not gated", func(t *testing.T) {
		h := newSigningVersionHarness(t)
		h.connect("conn-1", 0).SettleCapabilities(registry.CapabilityFloor, types.FloorProfile().CommandTypes, []uint32{1})

		require.NoError(t, h.pub.PublishCommandWithID(ctx, "cmd-x", h.id, types.CommandType("from_the_future"), nil))
		assert.Equal(t, types.CommandType("from_the_future"), h.next(t).Command.Type)
	})

	t.Run("a steward with no record is not gated", func(t *testing.T) {
		h := newSigningVersionHarness(t)
		require.NoError(t, h.pub.PublishCommandWithID(ctx, "cmd-n", "nobody", types.CommandStewardAction, nil))
		assert.Equal(t, types.CommandStewardAction, h.next(t).Command.Type)
	})
}

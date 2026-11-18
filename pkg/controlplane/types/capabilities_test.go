// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package types

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFloorProfile(t *testing.T) {
	p := FloorProfile()

	assert.Equal(t, CapabilityFloor, p.State)
	require.Len(t, p.CommandTypes, 13)
	for i := int32(1); i <= 13; i++ {
		assert.Equal(t, i, p.CommandTypes[i-1], "floor command type at position %d", i-1)
		assert.True(t, p.SupportsCommandType(i))
	}
	assert.False(t, p.SupportsCommandType(0))
	assert.False(t, p.SupportsCommandType(14))
	assert.Equal(t, []uint32{1}, p.SigningPayloadVersions)
	assert.True(t, p.SupportsSigningPayloadVersion(SigningPayloadV1))
	assert.False(t, p.SupportsSigningPayloadVersion(SigningPayloadV2))
}

func TestFloorProfileIsFreshCopy(t *testing.T) {
	a := FloorProfile()
	a.CommandTypes[0] = 99
	a.SigningPayloadVersions[0] = 99

	b := FloorProfile()
	assert.Equal(t, int32(1), b.CommandTypes[0])
	assert.Equal(t, uint32(1), b.SigningPayloadVersions[0])
}

func TestSupportedSigningPayloadVersionsMatchesSigningCode(t *testing.T) {
	got := SupportedSigningPayloadVersions()
	assert.Equal(t, []uint32{SigningPayloadV1, SigningPayloadV2}, got)

	for _, v := range got {
		_, err := CommandSigningBytesVersion(&Command{}, nil, v)
		assert.NoError(t, err, "version %d is declared, so signing bytes must exist for it", v)
	}
}

func TestNormalizeCapabilityLists(t *testing.T) {
	known := func(n int32) bool { return n >= 1 && n <= 14 }

	t.Run("sorts, deduplicates and drops unknown or non-positive numbers", func(t *testing.T) {
		cmds, vers := NormalizeCapabilityLists([]int32{14, 2, 2, 999, 0, -3, 1}, []uint32{2, 1, 2, 0}, known)
		assert.Equal(t, []int32{1, 2, 14}, cmds)
		assert.Equal(t, []uint32{1, 2}, vers)
	})

	t.Run("nil known keeps every positive number", func(t *testing.T) {
		cmds, _ := NormalizeCapabilityLists([]int32{999, 1}, nil, nil)
		assert.Equal(t, []int32{1, 999}, cmds)
	})

	t.Run("oversized lists are capped", func(t *testing.T) {
		rawCmds := make([]int32, 0, 5000)
		rawVers := make([]uint32, 0, 5000)
		for i := 1; i <= 5000; i++ {
			rawCmds = append(rawCmds, int32(i))
			rawVers = append(rawVers, uint32(i))
		}
		cmds, vers := NormalizeCapabilityLists(rawCmds, rawVers, nil)
		assert.Len(t, cmds, MaxDeclaredCommandTypes)
		assert.Len(t, vers, MaxDeclaredSigningPayloadVersions)
		assert.Equal(t, int32(1), cmds[0])
		assert.Equal(t, uint32(1), vers[0])
	})

	t.Run("empty input yields empty non-nil lists", func(t *testing.T) {
		cmds, vers := NormalizeCapabilityLists(nil, nil, known)
		assert.NotNil(t, cmds)
		assert.Empty(t, cmds)
		assert.NotNil(t, vers)
		assert.Empty(t, vers)
	})
}

func TestCommandTypeNumber(t *testing.T) {
	n, ok := CommandTypeNumber(CommandSyncConfig)
	assert.True(t, ok)
	assert.Equal(t, int32(1), n)

	n, ok = CommandTypeNumber(CommandStewardAction)
	assert.True(t, ok)
	assert.Equal(t, int32(14), n)

	n, ok = CommandTypeNumber(CommandAdvertiseTransportAddress)
	assert.True(t, ok)
	assert.Equal(t, int32(15), n)

	for _, unknown := range []CommandType{"", "from_the_future"} {
		n, ok = CommandTypeNumber(unknown)
		assert.False(t, ok)
		assert.Zero(t, n)
	}
}

// Every type above the floor is a type a floor steward does not handle; every
// type at or below it is one it does. The gate depends on this split.
func TestKnownCommandTypesSplitAtTheFloor(t *testing.T) {
	floor := FloorProfile()
	var above []CommandType
	for _, cmdType := range KnownCommandTypes() {
		n, ok := CommandTypeNumber(cmdType)
		require.True(t, ok)
		if floor.SupportsCommandType(n) {
			assert.LessOrEqual(t, n, int32(floorCommandTypeMax))
		} else {
			above = append(above, cmdType)
		}
	}
	assert.Equal(t, []CommandType{CommandStewardAction, CommandAdvertiseTransportAddress}, above)
}

type commandSupportSource struct{ allow bool }

func (commandSupportSource) SigningVersionFor(context.Context, string) uint32 {
	return SigningPayloadV2
}
func (s commandSupportSource) SupportsCommandType(context.Context, string, CommandType) bool {
	return s.allow
}

type signingOnlySource struct{}

func (signingOnlySource) SigningVersionFor(context.Context, string) uint32 { return SigningPayloadV2 }

func TestPeerSupportsCommandType(t *testing.T) {
	ctx := context.Background()
	assert.True(t, PeerSupportsCommandType(ctx, nil, "s", CommandStewardAction), "nil source gates nothing")
	assert.True(t, PeerSupportsCommandType(ctx, signingOnlySource{}, "s", CommandStewardAction), "a source that only signs gates nothing")
	assert.True(t, PeerSupportsCommandType(ctx, commandSupportSource{allow: true}, "s", CommandStewardAction))
	assert.False(t, PeerSupportsCommandType(ctx, commandSupportSource{allow: false}, "s", CommandStewardAction))
}

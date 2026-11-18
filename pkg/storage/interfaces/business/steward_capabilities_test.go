// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStewardCapabilities_EncodeDecodeRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC)
	in := &StewardCapabilityRecord{
		State: StewardCapabilityDeclared, ConnectionID: "c1", ConnectedAt: now, UpdatedAt: now,
		CommandTypes: []int32{1, 2}, SigningPayloadVersions: []uint32{3},
	}
	enc, err := EncodeStewardCapabilities(in)
	require.NoError(t, err)
	out := DecodeStewardCapabilities(enc)
	require.NotNil(t, out)
	assert.Equal(t, in.State, out.State)
	assert.Equal(t, in.ConnectionID, out.ConnectionID)
	assert.True(t, in.ConnectedAt.Equal(out.ConnectedAt))
	assert.Equal(t, in.CommandTypes, out.CommandTypes)
	assert.Equal(t, in.SigningPayloadVersions, out.SigningPayloadVersions)
}

func TestStewardCapabilities_AbsentAndMalformedReadAbsent(t *testing.T) {
	enc, err := EncodeStewardCapabilities(nil)
	require.NoError(t, err)
	assert.Equal(t, "", enc)

	assert.Nil(t, DecodeStewardCapabilities(""), "legacy empty column")
	assert.Nil(t, DecodeStewardCapabilities("{not json"), "malformed")
	assert.Nil(t, DecodeStewardCapabilities(`{"state":"bogus","connection_id":"c"}`), "undefined state")
}

func TestStewardCapabilities_NewDeclared(t *testing.T) {
	now := time.Now().UTC()
	connected := now.Add(-time.Minute)
	existing := &StewardCapabilityRecord{State: StewardCapabilityPending, ConnectionID: "c1", ConnectedAt: connected}

	rec, err := NewDeclaredStewardCapabilities(existing, "c1", StewardCapabilityRecord{ConnectionID: "ignored", CommandTypes: []int32{5}}, now)
	require.NoError(t, err)
	assert.Equal(t, StewardCapabilityDeclared, rec.State, "empty state means declared")
	assert.Equal(t, "c1", rec.ConnectionID, "the argument wins over the record's own field")
	assert.True(t, connected.Equal(rec.ConnectedAt))
	assert.True(t, now.Equal(rec.UpdatedAt))

	_, err = NewDeclaredStewardCapabilities(existing, "", StewardCapabilityRecord{}, now)
	assert.Error(t, err)
	_, err = NewDeclaredStewardCapabilities(existing, "c1", StewardCapabilityRecord{State: "x"}, now)
	assert.Error(t, err)
}

func TestStewardCapabilities_NewPendingAndClone(t *testing.T) {
	now := time.Now().UTC()
	rec, err := NewPendingStewardCapabilities("c1", now)
	require.NoError(t, err)
	assert.Equal(t, StewardCapabilityPending, rec.State)
	assert.True(t, now.Equal(rec.ConnectedAt))

	_, err = NewPendingStewardCapabilities("", now)
	assert.Error(t, err)

	var nilRec *StewardCapabilityRecord
	assert.Nil(t, nilRec.Clone())
	src := &StewardCapabilityRecord{CommandTypes: []int32{1}}
	cp := src.Clone()
	cp.CommandTypes[0] = 9
	assert.Equal(t, int32(1), src.CommandTypes[0], "clone does not alias slices")
}

func TestStewardCapabilities_ApplyDeclaration(t *testing.T) {
	now := time.Now().UTC()
	pending, err := NewPendingStewardCapabilities("b", now.Add(-time.Minute))
	require.NoError(t, err)
	stored, err := EncodeStewardCapabilities(pending)
	require.NoError(t, err)

	t.Run("matching connection applies", func(t *testing.T) {
		enc, applied, err := ApplyStewardCapabilityDeclaration(stored, "b", StewardCapabilityRecord{CommandTypes: []int32{7}}, now)
		require.NoError(t, err)
		require.True(t, applied)
		got := DecodeStewardCapabilities(enc)
		require.NotNil(t, got)
		assert.Equal(t, StewardCapabilityDeclared, got.State)
		assert.Equal(t, "b", got.ConnectionID)
		assert.Equal(t, []int32{7}, got.CommandTypes)
		assert.True(t, pending.ConnectedAt.Equal(got.ConnectedAt), "connect time is kept")
	})

	t.Run("stale connection is not applied", func(t *testing.T) {
		enc, applied, err := ApplyStewardCapabilityDeclaration(stored, "a", StewardCapabilityRecord{}, now)
		require.NoError(t, err)
		assert.False(t, applied)
		assert.Empty(t, enc)
	})

	t.Run("absent or legacy record is not applied", func(t *testing.T) {
		_, applied, err := ApplyStewardCapabilityDeclaration("", "b", StewardCapabilityRecord{}, now)
		require.NoError(t, err)
		assert.False(t, applied)
	})

	t.Run("invalid arguments error", func(t *testing.T) {
		_, applied, err := ApplyStewardCapabilityDeclaration(stored, "", StewardCapabilityRecord{}, now)
		assert.Error(t, err)
		assert.False(t, applied)
		_, applied, err = ApplyStewardCapabilityDeclaration(stored, "b", StewardCapabilityRecord{State: "x"}, now)
		assert.Error(t, err)
		assert.False(t, applied)
	})
}

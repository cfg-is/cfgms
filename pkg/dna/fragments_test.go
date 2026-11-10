// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// TestFlattenFragments_ProjectsStringValues covers the flat projection the
// controller feeds its not-yet-re-homed attribute consumers from: string values
// are carried, non-string and empty values are dropped.
func TestFlattenFragments_ProjectsStringValues(t *testing.T) {
	osFrag, err := NewFragment("host:os", "gatherer", MapState(map[string]interface{}{
		"os":          "linux",
		"hostname":    "cfg-70-02",
		"os_name":     "",   // empty string: indistinguishable from absent, dropped
		"cpu_count":   8,    // non-string: not representable in a flat string map
		"secure_boot": true, // non-string
	}))
	require.NoError(t, err)

	flat := FlattenFragments([]*commonpb.Fragment{osFrag})

	assert.Equal(t, map[string]string{"os": "linux", "hostname": "cfg-70-02"}, flat)
}

// TestFlattenFragments_SkipsHostileFragments proves one unusable fragment cannot
// blank the projection. Stewards run on hosts that may be compromised, so a
// fragment with undecodable or empty canonical bytes must be skipped rather than
// abort the merge — otherwise a single crafted fragment wipes the controller's
// view of every other one.
func TestFlattenFragments_SkipsHostileFragments(t *testing.T) {
	good, err := NewFragment("host:os", "gatherer", MapState(map[string]interface{}{"os": "linux"}))
	require.NoError(t, err)

	flat := FlattenFragments([]*commonpb.Fragment{
		nil,
		{FragmentId: "host:empty"},
		{FragmentId: "host:garbage", CanonicalBytes: []byte{0xff, 0xff, 0xff, 0xff, 0x01}},
		good,
	})

	assert.Equal(t, map[string]string{"os": "linux"}, flat)
}

// TestFlattenFragments_DeterministicOnKeyCollision pins the merge order. When two
// fragments declare the same key the highest fragment_id wins, every time —
// independent of slice order. The controller hashes this projection into the DNA
// fingerprint (features/controller/fleet/storage/storage.go), so a
// map-iteration-order merge would make the fingerprint flap between identical
// snapshots and drive spurious resyncs.
func TestFlattenFragments_DeterministicOnKeyCollision(t *testing.T) {
	lower, err := NewFragment("host:aaa", "gatherer", MapState(map[string]interface{}{"hostname": "from-aaa"}))
	require.NoError(t, err)
	upper, err := NewFragment("host:zzz", "gatherer", MapState(map[string]interface{}{"hostname": "from-zzz"}))
	require.NoError(t, err)

	forward := FlattenFragments([]*commonpb.Fragment{lower, upper})
	reverse := FlattenFragments([]*commonpb.Fragment{upper, lower})

	assert.Equal(t, "from-zzz", forward["hostname"], "highest fragment_id must win")
	assert.Equal(t, forward, reverse, "projection must not depend on input slice order")

	// Repeated runs over the same input must be byte-identical: map iteration
	// order varies per run, so a single comparison would not catch a regression.
	for i := 0; i < 50; i++ {
		assert.Equal(t, forward, FlattenFragments([]*commonpb.Fragment{lower, upper}))
	}
}

// TestNewFragment_CanonicalBytesAndHashAgree proves NewFragment's hash is the
// FragmentHash of its own canonical bytes and that the id and authority are carried
// onto the fragment.
func TestNewFragment_CanonicalBytesAndHashAgree(t *testing.T) {
	frag, err := NewFragment("host:os", "gatherer", MapState(map[string]interface{}{"os": "linux"}))
	require.NoError(t, err)

	canonical, err := CanonicalizeFragment("host:os", "gatherer", MapState(map[string]interface{}{"os": "linux"}))
	require.NoError(t, err)

	assert.Equal(t, "host:os", frag.GetFragmentId())
	assert.Equal(t, "gatherer", frag.GetAuthority())
	assert.Equal(t, canonical, frag.GetCanonicalBytes())
	assert.Equal(t, FragmentHash(canonical), frag.GetFragmentHash())
}

// TestMapState_InertConfigStateMethods pins MapState's contract: AsMap returns the
// wrapped snapshot and every other ConfigState method is inert.
func TestMapState_InertConfigStateMethods(t *testing.T) {
	s := MapState{"k": "v"}
	assert.Equal(t, map[string]interface{}{"k": "v"}, s.AsMap())
	y, err := s.ToYAML()
	assert.NoError(t, err)
	assert.Nil(t, y)
	assert.NoError(t, s.FromYAML([]byte("k: other")))
	assert.NoError(t, s.Validate())
	assert.Nil(t, s.GetManagedFields())
	assert.Equal(t, "v", s.AsMap()["k"], "FromYAML must not mutate the snapshot")
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package egcommon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeAttributeChanges(t *testing.T) {
	require.Empty(t, ComputeAttributeChanges(nil, nil))

	t1 := map[string]interface{}{"keep": "x", "chg": 1, "gone": "g", "nilval": nil}
	t2 := map[string]interface{}{"keep": "x", "chg": 2, "added": "a", "nilval": nil}
	got := ComputeAttributeChanges(t1, t2)
	require.Len(t, got, 3)
	require.Equal(t, "added", got[0].Attribute)
	require.Nil(t, got[0].Before)
	require.Equal(t, "a", got[0].After)
	require.Equal(t, "chg", got[1].Attribute)
	require.Equal(t, 1, got[1].Before)
	require.Equal(t, 2, got[1].After)
	require.Equal(t, "gone", got[2].Attribute)
	require.Nil(t, got[2].After)

	// A nil value present on one side only is still a change.
	got = ComputeAttributeChanges(map[string]interface{}{"k": nil}, nil)
	require.Len(t, got, 1)
	require.Equal(t, "k", got[0].Attribute)
}

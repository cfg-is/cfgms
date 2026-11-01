// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTenantCut(t *testing.T) {
	t.Run("InactiveSeesEverything", func(t *testing.T) {
		c := NewTenantCut("", []string{"client-1"})
		assert.False(t, c.Active())
		assert.True(t, c.Visible("anything"))
		assert.Empty(t, c.Members())
	})

	t.Run("DescendantSetMembership", func(t *testing.T) {
		c := NewTenantCut("msp-a", []string{"client-1"})
		assert.True(t, c.Visible("msp-a"))
		assert.True(t, c.Visible("client-1"))
		assert.False(t, c.Visible("msp-b"))
		assert.False(t, c.Visible("msp-ab"))
		assert.False(t, c.Visible(""))
	})

	t.Run("NoResolvedSetIsExactOnly", func(t *testing.T) {
		c := NewTenantCut("msp-a", nil)
		assert.True(t, c.Visible("msp-a"))
		assert.False(t, c.Visible("client-1"))
		assert.False(t, c.Visible("msp-a/client-1"))
	})

	t.Run("MembersDedupAndDropEmpty", func(t *testing.T) {
		c := NewTenantCut("msp-a", []string{"", "msp-a", "client-1", "client-1"})
		assert.Equal(t, []string{"msp-a", "client-1"}, c.Members())
	})
}

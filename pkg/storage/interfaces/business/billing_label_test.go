// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBillingLabel(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		l, err := NewBillingLabel()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(l, "bl-"))
		assert.Len(t, l, len("bl-")+16, "80 bits encode to 16 base32 characters")
		assert.Equal(t, strings.ToLower(l), l)
		assert.False(t, seen[l])
		seen[l] = true
	}
}

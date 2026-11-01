// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package moduleset

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContains(t *testing.T) {
	for _, n := range Names() {
		assert.True(t, Contains(n), n)
	}
	assert.False(t, Contains(""))
	assert.False(t, Contains("file"))
	assert.False(t, Contains("M365-ENTRA-USER"))
}

func TestNames_SortedCopy(t *testing.T) {
	a := Names()
	assert.Len(t, a, len(names))
	assert.True(t, sort.StringsAreSorted(a))
	a[0] = "mutated"
	assert.NotEqual(t, "mutated", Names()[0])
}

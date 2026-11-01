// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShort_PrependV(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "0.5.0-dev"

	assert.Equal(t, "v0.5.0-dev", Short())
}

func TestShort_NoPrependWhenVPresent(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "v1.0.0"

	assert.Equal(t, "v1.0.0", Short())
}

func TestShortWithoutPrefix_StripsV(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "v1.0.0"

	assert.Equal(t, "1.0.0", ShortWithoutPrefix())
}

func TestShortWithoutPrefix_NoPrefix(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "1.0.0"

	assert.Equal(t, "1.0.0", ShortWithoutPrefix())
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
)

// TestWorkflowModuleFactory_NilCache verifies that a factory built without
// a cache rejects every CreateModuleInstance call with a clear message —
// rather than panicking or returning a generic error. REST-only controllers
// that don't resolve modules through the engine intentionally pass nil; if
// such a deployment somehow tries to instantiate a module the error must
// be self-explanatory.
func TestWorkflowModuleFactory_NilCache(t *testing.T) {
	loader := NewWorkflowModuleFactory(nil)
	module, err := loader.CreateModuleInstance("any-module")
	require.Error(t, err)
	assert.Nil(t, module)
	assert.Contains(t, err.Error(), "no cache backing")
}

// TestWorkflowModuleFactory_ModuleNotCached verifies that a name that does
// not match any cached bundle returns the ErrModuleNotCached sentinel
// wrapped with the requested name — the caller-facing path operators
// expect when surfacing "no bundle available" to an operator.
func TestWorkflowModuleFactory_ModuleNotCached(t *testing.T) {
	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	require.NoError(t, err)

	loader := NewWorkflowModuleFactory(c)
	module, err := loader.CreateModuleInstance("nonexistent-module")

	require.Error(t, err)
	assert.Nil(t, module)
	assert.True(t, errors.Is(err, ErrModuleNotCached),
		"missing bundle must surface as ErrModuleNotCached, got: %v", err)
	assert.Contains(t, err.Error(), "nonexistent-module")
}

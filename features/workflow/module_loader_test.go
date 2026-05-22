// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNullModuleFactory_CreateModuleInstance_ReturnsError(t *testing.T) {
	moduleName := "any-module"
	loader := NewNullModuleFactory()
	module, err := loader.CreateModuleInstance(moduleName)

	require.Error(t, err)
	assert.Nil(t, module)
	assert.Contains(t, err.Error(), moduleName)
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package-private genericConfigState YAML round-trip tests (TestGenericConfigState_*)
// intentionally retained in package execution per epic #730 Story 7.
// All other tests use package execution_test via export_test.go bridges.
// Rationale: genericConfigState is package-private and its tests directly construct
// &genericConfigState{data: ...}. Moving them to package execution_test would require
// either making the type public (semantic change) or a type-alias bridge — both expose
// internal details. The clean break is a documented exemption here.
package execution

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestExecutor creates an Executor with injected components for package-internal tests.
// Tests in package execution_test have their own copy of this helper using the exported API.
func newTestExecutor(t *testing.T, errorConfig config.ErrorHandlingConfig) *Executor {
	t.Helper()
	registry := discovery.ModuleRegistry{}
	moduleFactory := factory.New(registry, errorConfig, logging.NewNoopLogger())
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")
	executor, err := NewExecutor(&ExecutorConfig{
		Logger:        logger,
		Factory:       moduleFactory,
		Comparator:    comparator,
		ErrorHandling: errorConfig,
	})
	require.NoError(t, err)
	return executor
}

func TestGenericConfigState(t *testing.T) {
	data := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	state := &genericConfigState{data: data}

	assert.Equal(t, data, state.AsMap())

	fields := state.GetManagedFields()
	assert.Len(t, fields, 3)
	assert.Contains(t, fields, "key1")
	assert.Contains(t, fields, "key2")
	assert.Contains(t, fields, "key3")

	assert.NoError(t, state.Validate())
}

func TestGenericConfigState_ToYAMLFromYAML(t *testing.T) {
	original := &genericConfigState{data: map[string]interface{}{
		"host": "localhost",
		"port": 8080,
	}}

	// ToYAML produces valid YAML
	yamlBytes, err := original.ToYAML()
	require.NoError(t, err)
	assert.NotEmpty(t, yamlBytes)

	// FromYAML round-trips the data
	restored := &genericConfigState{data: map[string]interface{}{}}
	require.NoError(t, restored.FromYAML(yamlBytes))
	assert.Equal(t, "localhost", restored.data["host"])
}

func TestGenericConfigState_ExcludesIdentifierFields(t *testing.T) {
	state := &genericConfigState{data: map[string]interface{}{
		"path":    "/etc/hosts",
		"name":    "hosts-file",
		"content": "127.0.0.1 localhost",
	}}

	fields := state.GetManagedFields()
	assert.Len(t, fields, 1)
	assert.Contains(t, fields, "content")
	assert.NotContains(t, fields, "path")
	assert.NotContains(t, fields, "name")
}

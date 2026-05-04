// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package execution

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestNewExecutorWithComponents(t *testing.T) {
	registry := discovery.ModuleRegistry{}
	errorConfig := config.ErrorHandlingConfig{}
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
	assert.NotNil(t, executor)
	assert.Equal(t, moduleFactory, executor.factory)
	assert.Equal(t, comparator, executor.comparator)
	assert.Equal(t, errorConfig, executor.config)
	assert.Equal(t, logger, executor.logger)
}

func TestExecuteConfiguration_EmptyResources(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure: config.ActionFail,
	}
	executor := newTestExecutor(t, errorConfig)

	cfg := config.StewardConfig{
		Resources: []config.ResourceConfig{},
	}

	ctx := context.Background()
	report := executor.ExecuteConfiguration(ctx, cfg)

	assert.Equal(t, 0, report.TotalResources)
	assert.Equal(t, 0, report.SuccessfulCount)
	assert.Equal(t, 0, report.FailedCount)
	assert.Equal(t, 0, report.SkippedCount)
	assert.Len(t, report.ResourceResults, 0)
	assert.False(t, report.EndTime.Before(report.StartTime))
}

func TestExecuteConfiguration_WithUnknownModule(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{
		ModuleLoadFailure: config.ActionContinue,
		ResourceFailure:   config.ActionWarn,
	}
	executor := newTestExecutor(t, errorConfig)

	cfg := config.StewardConfig{
		Resources: []config.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "unknown-module",
				Config: map[string]interface{}{"key": "value"},
			},
		},
	}

	ctx := context.Background()
	report := executor.ExecuteConfiguration(ctx, cfg)

	assert.Equal(t, 1, report.TotalResources)
	assert.Equal(t, 0, report.SuccessfulCount)
	assert.Equal(t, 0, report.FailedCount)
	assert.Equal(t, 1, report.SkippedCount)
	assert.Len(t, report.ResourceResults, 1)

	result := report.ResourceResults[0]
	assert.Equal(t, "test-resource", result.ResourceName)
	assert.Equal(t, "unknown-module", result.ModuleName)
	assert.Equal(t, StatusSkipped, result.Status)
	assert.GreaterOrEqual(t, result.ExecutionTime, time.Duration(0))
}

func TestExecuteConfiguration_CanceledContext(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{}
	executor := newTestExecutor(t, errorConfig)

	cfg := config.StewardConfig{
		Resources: []config.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "test-module",
				Config: map[string]interface{}{"key": "value"},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report := executor.ExecuteConfiguration(ctx, cfg)

	assert.Equal(t, 1, report.TotalResources)
	assert.Contains(t, report.Errors, "execution cancelled: context canceled")
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

// TestHandleResourceError_ActionFail_NoPanic verifies that ActionFail returns an
// error instead of panicking, so the steward process survives a policy failure.
func TestHandleResourceError_ActionFail_NoPanic(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure: config.ActionFail,
	}
	executor := newTestExecutor(t, errorConfig)

	resource := config.ResourceConfig{
		Name:   "test-resource",
		Module: "test-module",
		Config: map[string]interface{}{"key": "value"},
	}
	origErr := fmt.Errorf("something went wrong")

	// Must not panic — ActionFail used to panic, now returns an error.
	var rerr error
	require.NotPanics(t, func() {
		rerr = executor.handleResourceError(resource, origErr)
	})
	require.Error(t, rerr)
	assert.Contains(t, rerr.Error(), "convergence aborted by ActionFail policy")
	assert.ErrorIs(t, rerr, origErr)
}

// TestHandleResourceError_ActionContinue_NoError verifies ActionContinue returns nil.
func TestHandleResourceError_ActionContinue_NoError(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure: config.ActionContinue,
	}
	executor := newTestExecutor(t, errorConfig)

	resource := config.ResourceConfig{Name: "r", Module: "m", Config: map[string]interface{}{}}
	rerr := executor.handleResourceError(resource, fmt.Errorf("oops"))
	assert.NoError(t, rerr)
}

// TestHandleResourceError_ActionWarn_NoError verifies ActionWarn returns nil.
func TestHandleResourceError_ActionWarn_NoError(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure: config.ActionWarn,
	}
	executor := newTestExecutor(t, errorConfig)

	resource := config.ResourceConfig{Name: "r", Module: "m", Config: map[string]interface{}{}}
	rerr := executor.handleResourceError(resource, fmt.Errorf("oops"))
	assert.NoError(t, rerr)
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Executor-wiring and ExecuteConfiguration tests. TestGenericConfigState_* are
// intentionally kept in execution_internal_test.go (package execution) — see that
// file for the exemption rationale.
package execution_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

func newTestExecutor(t *testing.T, errorConfig config.ErrorHandlingConfig) *execution.Executor {
	t.Helper()
	registry := discovery.ModuleRegistry{}
	moduleFactory := factory.New(registry, errorConfig, logging.NewNoopLogger())
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
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

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:        logger,
		Factory:       moduleFactory,
		Comparator:    comparator,
		ErrorHandling: errorConfig,
	})

	require.NoError(t, err)
	assert.NotNil(t, executor)
	assert.Equal(t, moduleFactory, execution.ExecutorFactory(executor))
	assert.Equal(t, comparator, execution.ExecutorComparator(executor))
	// executor.config and executor.logger are not bridged; their wiring is verified
	// functionally by the ExecuteConfiguration and HandleResourceError tests below.
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
	assert.Equal(t, execution.StatusSkipped, result.Status)
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
		rerr = execution.HandleResourceError(executor, resource, origErr)
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
	rerr := execution.HandleResourceError(executor, resource, fmt.Errorf("oops"))
	assert.NoError(t, rerr)
}

// TestHandleResourceError_ActionWarn_NoError verifies ActionWarn returns nil.
func TestHandleResourceError_ActionWarn_NoError(t *testing.T) {
	errorConfig := config.ErrorHandlingConfig{
		ResourceFailure: config.ActionWarn,
	}
	executor := newTestExecutor(t, errorConfig)

	resource := config.ResourceConfig{Name: "r", Module: "m", Config: map[string]interface{}{}}
	rerr := execution.HandleResourceError(executor, resource, fmt.Errorf("oops"))
	assert.NoError(t, rerr)
}

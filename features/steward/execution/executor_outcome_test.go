// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package execution_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// writingModule converges on Set and reports the audited writes it performed
// through modules.OperationReporter, as a directory module does.
type writingModule struct {
	converged bool
	pending   []string
	ops       []string
}

func (w *writingModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	if w.converged {
		return &mapConfigState{data: map[string]interface{}{"state": "present"}}, nil
	}
	return &mapConfigState{data: map[string]interface{}{"state": "absent"}}, nil
}

func (w *writingModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	w.converged = true
	w.pending = append(w.pending, w.ops...)
	return nil
}

func (w *writingModule) TakeOperations() []string {
	ops := w.pending
	w.pending = nil
	return ops
}

var (
	_ modules.Module            = (*writingModule)(nil)
	_ modules.OperationReporter = (*writingModule)(nil)
)

func applyWithModule(t *testing.T, name string, m modules.Module) *execution.Executor {
	t.Helper()
	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.ForModule("executor_outcome_test"))
	f.RegisterModule(name, m)
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:        logging.ForModule("executor_outcome_test"),
		Factory:       f,
		ErrorHandling: errCfg,
	})
	require.NoError(t, err)
	return executor
}

// TestExecutor_OutcomeCarriesOperationAndChanged verifies the apply outcome
// carries the operation the module reported and changed = true, and that a
// module reporting no operation leaves both empty (Issue #5564).
func TestExecutor_OutcomeCarriesOperationAndChanged(t *testing.T) {
	cfg := func(module string) []byte {
		return []byte(`{
  "steward": {"id": "s1"},
  "resources": [{"name": "alice", "module": "` + module + `.user", "config": {"state": "present"}}]
}`)
	}

	t.Run("reported operations", func(t *testing.T) {
		m := &writingModule{ops: []string{"create_user", "set_user_enabled"}}
		report, err := applyWithModule(t, "adtest", m).ApplyConfiguration(context.Background(), cfg("adtest"), "v1")
		require.NoError(t, err)
		require.Len(t, report.ApplyOutcomes, 2)
		for i, op := range []string{"create_user", "set_user_enabled"} {
			rec := report.ApplyOutcomes[i]
			assert.Equal(t, "alice", rec.ResourceID)
			assert.Equal(t, "applied", rec.Status)
			assert.Equal(t, op, rec.Operation)
			assert.True(t, rec.Changed)
		}
	})

	t.Run("module reports no operation", func(t *testing.T) {
		m := &writingModule{}
		report, err := applyWithModule(t, "adtest", m).ApplyConfiguration(context.Background(), cfg("adtest"), "v1")
		require.NoError(t, err)
		require.Len(t, report.ApplyOutcomes, 1)
		assert.Empty(t, report.ApplyOutcomes[0].Operation)
		assert.False(t, report.ApplyOutcomes[0].Changed)
	})

	t.Run("no drift reports nothing", func(t *testing.T) {
		m := &writingModule{converged: true, ops: []string{"create_user"}}
		report, err := applyWithModule(t, "adtest", m).ApplyConfiguration(context.Background(), cfg("adtest"), "v1")
		require.NoError(t, err)
		require.Len(t, report.ApplyOutcomes, 1)
		assert.Empty(t, report.ApplyOutcomes[0].Operation)
		assert.False(t, report.ApplyOutcomes[0].Changed)
	})
}

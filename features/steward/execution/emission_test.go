// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package execution_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/modules"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// recordingEmitter is a real in-process channel-backed EventEmitter for test use.
// It satisfies execution.EventEmitter without any mock library.
type recordingEmitter struct {
	mu      sync.Mutex
	entries []*transportpb.LogEntry
}

func (r *recordingEmitter) Enqueue(entry *transportpb.LogEntry) {
	r.mu.Lock()
	r.entries = append(r.entries, entry)
	r.mu.Unlock()
}

func (r *recordingEmitter) Entries() []*transportpb.LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*transportpb.LogEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// Compile-time check: recordingEmitter implements execution.EventEmitter.
var _ execution.EventEmitter = (*recordingEmitter)(nil)

// TestExecutor_EmitsDetectionAndOutcomePair_ApplyMode verifies that a resource
// needing a change yields exactly two entries with matching correlation_id:
// event_kind=detection (before module.Get) and event_kind=outcome with
// action=applied (after verifyChanges succeeds).
func TestExecutor_EmitsDetectionAndOutcomePair_ApplyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows")
	}
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "apply_emission.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("initial content\n"), 0644))

	emitter := &recordingEmitter{}
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:       logging.ForModule("emission_test"),
		StewardID:    "test-steward-apply",
		EventEmitter: emitter,
		DriftMode:    stewardconfig.DriftModeApply,
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "apply-emission-file",
		Module: "file",
		Config: map[string]interface{}{
			"path":              filepath.ToSlash(filePath),
			"content":           "desired content\n",
			"permissions":       420, // 0644 octal
			"allowed_base_path": filepath.ToSlash(tempDir),
		},
	}

	result := executor.ExecuteResource(context.Background(), resource)
	require.Equal(t, execution.StatusSuccess, result.Status,
		"apply mode must correct drift and return StatusSuccess")

	entries := emitter.Entries()
	require.Len(t, entries, 2,
		"a drifted resource in apply mode must emit exactly detection + outcome")

	detection := entries[0]
	assert.Equal(t, "detection", detection.Fields["event_kind"],
		"first entry must be the detection event")
	assert.Equal(t, "apply", detection.Fields["drift_mode"],
		"detection must record apply drift_mode")
	assert.NotEmpty(t, detection.CorrelationId,
		"detection must carry a non-empty correlation_id")
	assert.Equal(t, "test-steward-apply", detection.StewardId,
		"detection must carry the configured steward ID")
	assert.NotEmpty(t, detection.Fields["resource_id"],
		"detection must carry a resource_id")

	outcome := entries[1]
	assert.Equal(t, "outcome", outcome.Fields["event_kind"],
		"second entry must be the outcome event")
	assert.Equal(t, "applied", outcome.Fields["action"],
		"outcome action must be 'applied' after successful convergence")
	assert.NotEmpty(t, outcome.Fields["duration_ms"],
		"outcome must include duration_ms")
	assert.Equal(t, detection.CorrelationId, outcome.CorrelationId,
		"detection and outcome must share the same correlation_id")
}

// TestExecutor_EmitsDetectionAndOutcomePair_DriftReportMode verifies that
// report-only (monitor) mode yields the detection+outcome pair with
// outcome action=drift_reported and no file modification.
func TestExecutor_EmitsDetectionAndOutcomePair_DriftReportMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not applicable on Windows")
	}
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "report_emission.txt")
	initialContent := "initial content\n"
	require.NoError(t, os.WriteFile(filePath, []byte(initialContent), 0644))

	emitter := &recordingEmitter{}
	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:       logging.ForModule("emission_test"),
		StewardID:    "test-steward-report",
		EventEmitter: emitter,
		DriftMode:    stewardconfig.DriftModeMonitor,
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "report-emission-file",
		Module: "file",
		Config: map[string]interface{}{
			"path":              filepath.ToSlash(filePath),
			"content":           "desired content\n",
			"permissions":       420,
			"allowed_base_path": filepath.ToSlash(tempDir),
		},
	}

	result := executor.ExecuteResource(context.Background(), resource)
	require.Equal(t, execution.StatusNonCompliant, result.Status,
		"monitor mode with drift must return StatusNonCompliant")
	assert.False(t, result.ChangesApplied,
		"Set() must NOT be called in monitor mode")

	entries := emitter.Entries()
	require.Len(t, entries, 2,
		"drift-report mode must emit exactly detection + outcome")

	detection := entries[0]
	assert.Equal(t, "detection", detection.Fields["event_kind"])
	assert.Equal(t, "report", detection.Fields["drift_mode"],
		"detection must record report drift_mode for monitor-mode executor")
	assert.NotEmpty(t, detection.CorrelationId)

	outcome := entries[1]
	assert.Equal(t, "outcome", outcome.Fields["event_kind"])
	assert.Equal(t, "drift_reported", outcome.Fields["action"],
		"outcome action must be 'drift_reported' in monitor mode")
	assert.Equal(t, detection.CorrelationId, outcome.CorrelationId,
		"detection and outcome must share the same correlation_id")

	// Verify Set() was NOT called — file content must remain unchanged.
	got, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, initialContent, string(got),
		"monitor mode must not modify the file (Set() skipped)")
}

// TestExecutor_NoEventEmitter_DoesNotPanic verifies that an Executor created
// without an EventEmitter processes resources normally without panicking.
func TestExecutor_NoEventEmitter_DoesNotPanic(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "no_emitter.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("old\n"), 0644))

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger: logging.ForModule("emission_test"),
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "no-emitter-file",
		Module: "file",
		Config: map[string]interface{}{
			"path":              filepath.ToSlash(filePath),
			"content":           "new\n",
			"allowed_base_path": filepath.ToSlash(tempDir),
		},
	}

	// Must not panic.
	result := executor.ExecuteResource(context.Background(), resource)
	assert.Equal(t, execution.StatusSuccess, result.Status)
}

// mapConfigState is a real map-backed ConfigState used to drive the comparator
// in the error-outcome tests. It satisfies modules.ConfigState without any mock
// library.
type mapConfigState struct {
	data map[string]interface{}
}

func (m *mapConfigState) AsMap() map[string]interface{} { return m.data }
func (m *mapConfigState) ToYAML() ([]byte, error)       { return nil, nil }
func (m *mapConfigState) FromYAML([]byte) error         { return nil }
func (m *mapConfigState) Validate() error               { return nil }
func (m *mapConfigState) GetManagedFields() []string {
	fields := make([]string, 0, len(m.data))
	for k := range m.data {
		fields = append(fields, k)
	}
	return fields
}

// badSetModule is a real module implementation that reports drift on Get()
// (returning state that differs from the desired config in a managed field) and
// always fails on Set(). It exercises the executor's action=error outcome path
// without any mock library.
type badSetModule struct {
	setErr error
}

func (b *badSetModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	// Return a state guaranteed to differ from the desired "content" field so
	// the comparator reports drift and the executor proceeds to Set().
	return &mapConfigState{data: map[string]interface{}{
		"content": "current-drifted-content\n",
	}}, nil
}

func (b *badSetModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return b.setErr
}

// Compile-time check: badSetModule implements modules.Module.
var _ modules.Module = (*badSetModule)(nil)

// TestExecutor_EmitsErrorOutcome_SetFailure verifies that when module.Set()
// fails, the executor emits a detection event followed by an outcome event with
// action=error, both sharing the same correlation_id.
func TestExecutor_EmitsErrorOutcome_SetFailure(t *testing.T) {
	emitter := &recordingEmitter{}

	// Build a factory and register a real test module that errors on Set().
	f := factory.New(discovery.ModuleRegistry{}, stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}, logging.ForModule("emission_test"))
	f.RegisterModule("file", &badSetModule{setErr: errors.New("set failed: read-only target")})

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:       logging.ForModule("emission_test"),
		StewardID:    "test-steward-error",
		EventEmitter: emitter,
		DriftMode:    stewardconfig.DriftModeApply,
		Factory:      f,
		ErrorHandling: stewardconfig.ErrorHandlingConfig{
			ModuleLoadFailure:  stewardconfig.ActionContinue,
			ResourceFailure:    stewardconfig.ActionWarn,
			ConfigurationError: stewardconfig.ActionFail,
		},
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "error-outcome-file",
		Module: "file",
		Config: map[string]interface{}{
			"content": "desired content\n",
		},
	}

	result := executor.ExecuteResource(context.Background(), resource)
	require.Equal(t, execution.StatusFailed, result.Status,
		"a Set() failure under ActionWarn must yield StatusFailed")

	entries := emitter.Entries()
	require.Len(t, entries, 2,
		"a Set() failure must emit exactly detection + outcome")

	detection := entries[0]
	assert.Equal(t, "detection", detection.Fields["event_kind"],
		"first entry must be the detection event")
	assert.NotEmpty(t, detection.CorrelationId,
		"detection must carry a non-empty correlation_id")

	outcome := entries[1]
	assert.Equal(t, "outcome", outcome.Fields["event_kind"],
		"second entry must be the outcome event")
	assert.Equal(t, "error", outcome.Fields["action"],
		"outcome action must be 'error' when Set() fails")
	assert.Equal(t, detection.CorrelationId, outcome.CorrelationId,
		"detection and outcome must share the same correlation_id")
}

// badVerifyModule is a real module implementation that reports drift on every
// Get() (so post-Set verification always finds remaining drift) and succeeds on
// Set(). It exercises the executor's action=error outcome path triggered by a
// failed verification, distinct from the Set()-failure path.
type badVerifyModule struct{}

func (b *badVerifyModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	// Always return drifted state — even after Set() — so verifyChanges fails.
	return &mapConfigState{data: map[string]interface{}{
		"content": "still-drifted-content\n",
	}}, nil
}

func (b *badVerifyModule) Set(_ context.Context, _ string, _ modules.ConfigState) error {
	return nil // Set "succeeds" but does not actually converge the resource.
}

// Compile-time check: badVerifyModule implements modules.Module.
var _ modules.Module = (*badVerifyModule)(nil)

// TestExecutor_EmitsErrorOutcome_VerifyFailure verifies that when Set()
// succeeds but post-Set verification still detects drift, the executor emits a
// detection event followed by an outcome event with action=error.
func TestExecutor_EmitsErrorOutcome_VerifyFailure(t *testing.T) {
	emitter := &recordingEmitter{}

	f := factory.New(discovery.ModuleRegistry{}, stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}, logging.ForModule("emission_test"))
	f.RegisterModule("file", &badVerifyModule{})

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:       logging.ForModule("emission_test"),
		StewardID:    "test-steward-verify",
		EventEmitter: emitter,
		DriftMode:    stewardconfig.DriftModeApply,
		Factory:      f,
		ErrorHandling: stewardconfig.ErrorHandlingConfig{
			ModuleLoadFailure:  stewardconfig.ActionContinue,
			ResourceFailure:    stewardconfig.ActionWarn,
			ConfigurationError: stewardconfig.ActionFail,
		},
	})
	require.NoError(t, err)

	resource := stewardconfig.ResourceConfig{
		Name:   "verify-error-file",
		Module: "file",
		Config: map[string]interface{}{
			"content": "desired content\n",
		},
	}

	result := executor.ExecuteResource(context.Background(), resource)
	require.Equal(t, execution.StatusFailed, result.Status,
		"a verification failure under ActionWarn must yield StatusFailed")

	entries := emitter.Entries()
	require.Len(t, entries, 2,
		"a verification failure must emit exactly detection + outcome")

	detection := entries[0]
	assert.Equal(t, "detection", detection.Fields["event_kind"])
	assert.NotEmpty(t, detection.CorrelationId)

	outcome := entries[1]
	assert.Equal(t, "outcome", outcome.Fields["event_kind"])
	assert.Equal(t, "error", outcome.Fields["action"],
		"outcome action must be 'error' when post-Set verification fails")
	assert.Equal(t, detection.CorrelationId, outcome.CorrelationId,
		"detection and outcome must share the same correlation_id")
}

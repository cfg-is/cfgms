// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file" // registers the "file" provider used by this test
)

// TestDebugAPI_SanitizesActionInLogFile covers the log-injection finding at
// features/workflow/debug_api.go:184 (Issue #4086): StepExecution logs
// req.Action, a DebugAction-typed field decoded straight from the request body.
//
// DebugAPI.logger is a concrete *logging.ModuleLogger with no injectable
// interface, so the only way to observe what actually reaches the sink is to
// point the global logging manager at a real file provider and read back the
// written JSON line — this exercises the real ModuleLogger -> LoggingManager
// -> FileProvider path end to end rather than a fake.
//
// req.Action is deliberately the field under test rather than "error" or
// "execution_id" (also flagged at other call sites in this file): pkg/logging's
// keysAndValuesToMap runs every field through sanitizeValueRecursive before a
// ModuleLogger call ever reaches a provider, and that recursive sanitizer's
// type switch already catches plain `string` and `error` values by their exact
// Go type — so a call site logging a bare `string` or `error` is redundantly
// safe at the sink regardless of the SanitizeLogValue wrap this story adds,
// which would make a revert of that wrap invisible to a sink-level test. A type
// switch matches concrete types exactly: DebugAction ("type DebugAction
// string", no String()/Error() method) does not match any case in that switch
// and falls through to `default: return v` unsanitized. That makes the action
// field the one flagged site in this file where the call-site wrap is not
// merely defense-in-depth but the only thing standing between attacker input
// and the log file, and the only one where an end-to-end test through the real
// sink can actually fail on revert.
//
// This fails on revert: removing the logging.SanitizeLogValue wrap around
// string(req.Action) at that call site writes the raw control-character value
// into the log file's "action" field.
//
// Global logging state is process-wide, so this test cannot run t.Parallel()
// and must be the only test in this package touching it (verified: no other
// features/workflow test calls InitializeGlobalLogging or
// GetGlobalLoggingManager).
func TestDebugAPI_SanitizesActionInLogFile(t *testing.T) {
	if manager := logging.GetGlobalLoggingManager(); manager != nil {
		_ = manager.Close()
	}
	logging.InitializeGlobalLoggerFactory("", "")

	tmpDir := t.TempDir()
	loggingConfig := &logging.LoggingConfig{
		Provider:      "file",
		Level:         "DEBUG",
		ServiceName:   "test-service",
		Component:     "workflow-debug",
		AsyncWrites:   false,
		BatchSize:     1,
		FlushInterval: time.Second,
		Config: map[string]interface{}{
			"directory":        tmpDir,
			"file_prefix":      "test",
			"max_file_size":    1024 * 1024,
			"max_files":        5,
			"compress_rotated": false,
		},
	}
	require.NoError(t, logging.InitializeGlobalLogging(loggingConfig))
	logging.InitializeGlobalLoggerFactory("test-service", "workflow-debug")

	t.Cleanup(func() {
		if manager := logging.GetGlobalLoggingManager(); manager != nil {
			_ = manager.Close()
		}
		logging.InitializeGlobalLoggerFactory("", "")
	})

	engine := NewEngine(nil, logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	debugEngine := NewDebugEngine(engine, logging.NewNoopLogger())
	api := NewDebugAPI(debugEngine, logging.NewNoopLogger())

	// No debug session exists for "nonexistent-session", so
	// DebugEngine.StepExecution fails before ever inspecting the action value —
	// the API logs the attacker-supplied action purely because it was decoded
	// off the request, not because it was semantically meaningful.
	const controlAction = DebugAction("step\x07evil")
	body, err := json.Marshal(StepExecutionRequest{Action: controlAction})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/debug/sessions/nonexistent-session/step", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	api.StepExecution(rec, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	require.NoError(t, logging.GetGlobalLoggingManager().Flush(context.Background()))

	entries := readLogEntries(t, tmpDir)
	found := false
	for _, e := range entries {
		if e["message"] != "Failed to execute debug step" {
			continue
		}
		fields, _ := e["fields"].(map[string]interface{})
		actionVal, ok := fields["action"].(string)
		if !ok {
			continue
		}
		found = true
		if strings.Contains(actionVal, string(controlAction)) {
			t.Fatalf("log entry contains the raw control-character action: %q", actionVal)
		}
		require.Equal(t, logging.SanitizeLogValue(string(controlAction)), actionVal)
	}
	require.True(t, found, "expected a 'Failed to execute debug step' log entry with an action field")
}

// readLogEntries reads every JSON-lines log file under dir and decodes each
// line into a generic map for field-level assertions.
func readLogEntries(t *testing.T, dir string) []map[string]interface{} {
	t.Helper()
	files, err := os.ReadDir(dir)
	require.NoError(t, err)

	var entries []map[string]interface{}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		file, err := os.Open(filepath.Join(dir, f.Name()))
		require.NoError(t, err)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var entry map[string]interface{}
			require.NoError(t, json.Unmarshal(line, &entry))
			entries = append(entries, entry)
		}
		require.NoError(t, scanner.Err())
		require.NoError(t, file.Close())
	}
	return entries
}

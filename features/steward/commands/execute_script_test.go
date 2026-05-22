// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"encoding/base64"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/script"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestResolveRelayUID_SystemContext verifies that a system-context script
// resolves to the steward process UID, making the relay socket chown a no-op.
func TestResolveRelayUID_SystemContext(t *testing.T) {
	uid := resolveRelayUID(script.ExecutionContextSystem, logging.NewNoopLogger())
	assert.Equal(t, os.Getuid(), uid, "system context must resolve to the process UID")
}

// TestResolveRelayUID_LoggedInUser_FallsBackOnError verifies that when the
// logged-in user cannot be resolved (e.g. no interactive session), resolveRelayUID
// falls back to the steward process UID rather than returning a bogus value.
// The executor independently fails the run with the same underlying error.
func TestResolveRelayUID_LoggedInUser_FallsBackOnError(t *testing.T) {
	uid := resolveRelayUID(script.ExecutionContextLoggedInUser, logging.NewNoopLogger())
	if runtime.GOOS == "windows" {
		// On Windows, ResolveExecutionUID always returns -1 with no error:
		// process identity is SID-based and the relay pipe is DACL-controlled,
		// so -1 is the intentional "skip UID ownership" sentinel, not a failure.
		assert.Equal(t, -1, uid, "resolveRelayUID must return the Windows -1 sentinel")
		return
	}
	// On Unix, regardless of whether a user is logged in, the result must be a
	// valid UID: either the resolved logged-in user's UID, or the process-UID
	// fallback. It must never be a negative/zero sentinel from a partial
	// resolution.
	assert.GreaterOrEqual(t, uid, 0, "resolveRelayUID must always return a usable UID")
}

// ---------------------------------------------------------------------------
// Issue #1675 — handler-level relay-socket guard tests.
//
// AC1 [REQUIRED TEST]: a per-execution relay socket is created ONLY for a
// library script (non-empty script_id) with a non-empty required_api_scope.
// Inline run-command dispatches (empty script_id) must NOT create a socket
// regardless of required_api_scope.
//
// Detection: the relay sets CFGMS_API_SOCKET in the script's environment. A
// probe script echoes that variable; the value observed in stdout_preview is
// the proof of whether a relay was created for this execution.
// ---------------------------------------------------------------------------

const socketProbeOpen = "SOCKVAL["
const socketProbeClose = "]"

// socketEnvProbeScriptBody returns a script body that writes the value of the
// CFGMS_API_SOCKET environment variable to stdout, wrapped in SOCKVAL[...]
// markers. An empty value (SOCKVAL[]) means no relay socket was injected.
func socketEnvProbeScriptBody() string {
	if runtime.GOOS == "windows" {
		return `Write-Output ("` + socketProbeOpen + `" + $env:CFGMS_API_SOCKET + "` + socketProbeClose + `")`
	}
	return `echo "` + socketProbeOpen + `$CFGMS_API_SOCKET` + socketProbeClose + `"`
}

// socketValFromStdout extracts the CFGMS_API_SOCKET value the probe script
// observed from a stdout_preview string. It requires the SOCKVAL[...] marker
// to be present so a test never silently passes on missing output.
func socketValFromStdout(t *testing.T, stdout string) string {
	t.Helper()
	start := strings.Index(stdout, socketProbeOpen)
	require.GreaterOrEqual(t, start, 0, "probe marker %q missing from stdout: %q", socketProbeOpen, stdout)
	rest := stdout[start+len(socketProbeOpen):]
	end := strings.Index(rest, socketProbeClose)
	require.GreaterOrEqual(t, end, 0, "probe close marker missing from stdout: %q", stdout)
	return rest[:end]
}

// runScriptProbe executes the socket-env probe script through handleExecuteScript
// with the supplied params merged in, and returns the observed CFGMS_API_SOCKET
// value. extraParams supplies script_id / required_api_scope per test case.
func runScriptProbe(t *testing.T, h *Handler, getEvents func() []*cpTypes.Event,
	executionID string, extraParams map[string]interface{}) string {
	t.Helper()

	params := map[string]interface{}{
		"script_content": base64.StdEncoding.EncodeToString([]byte(socketEnvProbeScriptBody())),
		"shell":          platformShell(),
		"execution_id":   executionID,
	}
	for k, v := range extraParams {
		params[k] = v
	}

	cmd := &cpTypes.Command{
		ID:        "cmd-" + executionID,
		Type:      cpTypes.CommandExecuteScript,
		StewardID: "steward-test",
		Timestamp: time.Now(),
		Params:    params,
	}
	require.NoError(t, h.handleExecuteScript(context.Background(), cmd))

	events := getEvents()
	failEvt := firstEventOfType(events, cpTypes.EventCommandFailed)
	require.Nil(t, failEvt, "script execution must not fail: %+v", failEvt)
	evt := firstEventOfType(events, cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "expected EventScriptCompleted event")
	stdout, ok := evt.Details["stdout_preview"].(string)
	require.True(t, ok, "stdout_preview must be a string")
	return socketValFromStdout(t, stdout)
}

// TestExecuteScriptHandler_LibraryScriptWithScope_CreatesRelaySocket verifies
// that a library script (non-empty script_id) with a non-empty
// required_api_scope runs with CFGMS_API_SOCKET pointing at a per-execution
// relay socket — i.e. the relay IS created.
func TestExecuteScriptHandler_LibraryScriptWithScope_CreatesRelaySocket(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	socketVal := runScriptProbe(t, h, getEvents, "exec-relay-lib", map[string]interface{}{
		"script_id":          "lib-script-1",
		"required_api_scope": []string{"read:inventory"},
	})

	assert.NotEmpty(t, socketVal,
		"library script with non-empty required_api_scope must run with CFGMS_API_SOCKET set")
	assert.Contains(t, socketVal, "exec-relay-lib",
		"CFGMS_API_SOCKET must reference the per-execution relay for this execution_id")
}

// TestExecuteScriptHandler_LibraryScriptNoScope_NoRelaySocket verifies that a
// library script with an EMPTY required_api_scope does NOT get a relay socket.
func TestExecuteScriptHandler_LibraryScriptNoScope_NoRelaySocket(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	socketVal := runScriptProbe(t, h, getEvents, "exec-relay-noscope", map[string]interface{}{
		"script_id": "lib-script-2",
		// required_api_scope intentionally omitted
	})

	assert.Empty(t, socketVal,
		"library script with empty required_api_scope must NOT create a relay socket")
}

// TestExecuteScriptHandler_InlineCommandWithScope_NoRelaySocket is the AC1
// "regardless" guard: an inline run-command dispatch (empty script_id) must
// NOT create a relay socket even when required_api_scope is non-empty. The
// handler enforces this invariant rather than trusting the dispatcher to omit
// the param.
func TestExecuteScriptHandler_InlineCommandWithScope_NoRelaySocket(t *testing.T) {
	capLog := &capturingLogger{}
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: capLog})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	socketVal := runScriptProbe(t, h, getEvents, "exec-relay-inline", map[string]interface{}{
		// script_id intentionally omitted → inline command
		"required_api_scope": []string{"read:inventory"},
	})

	assert.Empty(t, socketVal,
		"inline command must NOT create a relay socket regardless of required_api_scope")

	// The handler must also surface the anomaly: an inline command carrying a
	// non-empty required_api_scope indicates a dispatcher bug or tampering.
	var sawWarn bool
	for _, line := range capLog.Lines() {
		if strings.Contains(line, "ignoring required_api_scope on inline command") {
			sawWarn = true
		}
	}
	assert.True(t, sawWarn,
		"handler must log a warning when an inline command carries required_api_scope")
}

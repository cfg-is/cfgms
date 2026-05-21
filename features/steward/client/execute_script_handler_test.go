// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client exercises the CommandExecuteScript handler registered in setupCommandHandler.
//
// Issue #1669: setupCommandHandler must call handler.RegisterExecuteScriptHandler()
// so a controller-sent execute_script command is dispatched through the script
// module executor and produces EventScriptCompleted — not EventCommandFailed
// ("no handler for command type").
package client

import (
	"context"
	"encoding/base64"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/execution"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// platformShell returns a shell supported by the current OS. bash is unavailable
// on Windows runners, so Windows uses powershell; both are recognised by the
// script-module executor (Issue #1669).
func platformShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

// echoScriptBody returns a script body that writes s to stdout using the syntax
// of the current platform's shell (see platformShell).
func echoScriptBody(s string) string {
	if runtime.GOOS == "windows" {
		return "Write-Output '" + s + "'"
	}
	return "echo '" + s + "'"
}

// TestSetupCommandHandler_RegistersExecuteScript verifies that the command
// handler built by setupCommandHandler dispatches CommandExecuteScript through
// the production registration path. A real TransportClient with an in-process
// eventCapture control plane is used — no mocks (Issue #1669).
func TestSetupCommandHandler_RegistersExecuteScript(t *testing.T) {
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, newTestSession(), exec, capture, "steward-exec-script", "tenant-exec-script")

	handler, err := c.setupCommandHandler(context.Background(), "steward-exec-script")
	require.NoError(t, err)

	cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID:        "cmd-exec-script-1",
		Type:      cpTypes.CommandExecuteScript,
		StewardID: "steward-exec-script",
		TenantID:  "tenant-exec-script",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"script_content": base64.StdEncoding.EncodeToString([]byte(echoScriptBody("hello"))),
			"shell":          platformShell(),
			"execution_id":   "exec-1669-test",
		},
	}}
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))
	handler.Wait()

	events := drainEvents(capture.events)
	require.NotEmpty(t, events, "execute_script dispatch must publish a status event")

	var completed *cpTypes.Event
	for _, evt := range events {
		require.NotEqualf(t, cpTypes.EventCommandFailed, evt.Type,
			"execute_script must be registered in setupCommandHandler — got EventCommandFailed: %v", evt.Details)
		if evt.Type == cpTypes.EventScriptCompleted {
			completed = evt
		}
	}
	require.NotNil(t, completed, "execute_script dispatch must publish EventScriptCompleted")
	require.Equal(t, "exec-1669-test", completed.Details["execution_id"])
	require.Equal(t, 0, completed.Details["exit_code"])
}

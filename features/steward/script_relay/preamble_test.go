// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package scriptrelay

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInjectBashPreamble(t *testing.T) {
	socketPath := "/tmp/cfgms-exec123/api.sock"
	script := `echo "hello world"`

	result := InjectBashPreamble(script, socketPath)

	// Must contain the CFGMS_API_SOCKET assignment.
	assert.Contains(t, result, socketPath)
	// Must define cfgms_api shell function.
	assert.Contains(t, result, "cfgms_api()")
	// Must reference curl --unix-socket.
	assert.Contains(t, result, "--unix-socket")
	// Must preserve original script content.
	assert.Contains(t, result, script)
	// Preamble must appear before original content.
	preambleEnd := strings.Index(result, "cfgms_api()")
	scriptStart := strings.Index(result, script)
	require.Greater(t, scriptStart, preambleEnd, "preamble must precede original content")
}

func TestInjectBashPreamble_EmptyScript(t *testing.T) {
	result := InjectBashPreamble("", "/tmp/cfgms-x/api.sock")
	assert.Contains(t, result, "cfgms_api()")
}

func TestInjectPowerShellPreamble(t *testing.T) {
	socketPath := `\\.\pipe\cfgms-exec456`
	script := `Write-Host "hello"`

	result := InjectPowerShellPreamble(script, socketPath)

	// Must contain the socket path assignment.
	assert.Contains(t, result, "CFGMS_API_SOCKET")
	// Must define Invoke-CfgApi function.
	assert.Contains(t, result, "function Invoke-CfgApi")
	// Must use System.Net.Sockets.Socket (not Invoke-WebRequest).
	assert.Contains(t, result, "System.Net.Sockets.Socket")
	// Must reference UnixDomainSocketEndPoint.
	assert.Contains(t, result, "UnixDomainSocketEndPoint")
	// Must preserve original script content.
	assert.Contains(t, result, script)
}

func TestInjectPowerShellPreamble_SyntaxCheck(t *testing.T) {
	// Verify that the preamble can be parsed as valid PowerShell by checking
	// for balanced braces — a parse-only sanity check without execution.
	result := InjectPowerShellPreamble(`$x = 1`, "/tmp/test.sock")

	open := strings.Count(result, "{")
	close := strings.Count(result, "}")
	assert.Equal(t, open, close, "PowerShell preamble must have balanced braces")

	// Function definition must be present.
	assert.Contains(t, result, "function Invoke-CfgApi {")
}

func TestInjectBashPreamble_SocketPathQuoting(t *testing.T) {
	// Socket paths with spaces must be safely quoted.
	socketPath := "/tmp/path with spaces/api.sock"
	result := InjectBashPreamble("echo hi", socketPath)
	// The path should appear quoted in the result.
	assert.Contains(t, result, `"/tmp/path with spaces/api.sock"`)
}

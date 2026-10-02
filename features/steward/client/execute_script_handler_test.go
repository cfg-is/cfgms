// SPDX-License-Identifier: AGPL-3.0-only
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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/execution"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
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

// signedInlineExecuteScriptParams builds the cmd.Params entries
// preflightScriptSignature requires for an inline (ad-hoc) command as of Issue
// #3694: script_content, shell, execution_id, plus a valid operator envelope —
// targeted at stewardID, a fresh nonce, and a 5-minute expiry — signed with a
// freshly generated (untrusted-CA) RSA key. This package tests dispatch through
// setupCommandHandler, not signature-rejection specifics, so an ad-hoc, valid
// signature is sufficient (no controllerCARoots are wired here, so cert-chain
// verification does not apply).
func signedInlineExecuteScriptParams(t *testing.T, content []byte, shell, stewardID, executionID string) map[string]interface{} {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	nonceBytes := make([]byte, 16)
	_, err = rand.Read(nonceBytes)
	require.NoError(t, err)

	env := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   []string{stewardID},
		Nonce:     hex.EncodeToString(nonceBytes),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)

	digest := sha256.Sum256(canonical)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	return map[string]interface{}{
		"script_content":       base64.StdEncoding.EncodeToString(content),
		"shell":                shell,
		"execution_id":         executionID,
		"signature_algorithm":  "rsa-sha256",
		"signature_value":      base64.StdEncoding.EncodeToString(sigBytes),
		"signature_public_key": string(pubPEM),
		"targets":              env.Targets,
		"nonce":                env.Nonce,
		"expires_at":           env.ExpiresAt.UTC().Format(time.RFC3339),
	}
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
		Params: signedInlineExecuteScriptParams(t, []byte(echoScriptBody("hello")), platformShell(),
			"steward-exec-script", "exec-1669-test"),
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

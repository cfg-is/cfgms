// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package commands exercises executeCommand's timeout behavior directly (Issue
// #3801). CommandSyncConfig was decoupled from executeCommand's 30s-unless-
// overridden deadline so ApplyConfiguration/StartMonitors run under the
// executor's own per-call ModuleCallTimeoutSec budget instead. This file guards
// against that fix leaking into the general command path: CommandExecuteScript
// (and, by the same code path, CommandOpenTerminal) must keep the exact
// pre-existing behavior at handler.go:475, untouched by this story.
package commands

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// TestExecuteCommand_CommandExecuteScript_Default30sDeadline verifies that a
// CommandExecuteScript command with no timeout_seconds override still receives
// a context.Context with a deadline ~30s out from executeCommand — the same
// default that applied before Issue #3801 decoupled CommandSyncConfig from it.
//
// The registered handler intercepts dispatch instead of calling
// RegisterExecuteScriptHandler (which would run a real script executor) — this
// test is only about the ctx executeCommand hands to whatever CommandExecuteScript
// handler is registered, not about script execution itself. The command still
// has to pass HandleCommand's script-signature preflight (handler.go:420-424,
// unconditional for CommandExecuteScript type, independent of which handler
// function is registered), so it carries a validly signed inline envelope.
func TestExecuteCommand_CommandExecuteScript_Default30sDeadline(t *testing.T) {
	h := newTestHandler(t, nil)

	deadlineCh := make(chan time.Time, 1)
	hasDeadlineCh := make(chan bool, 1)
	h.RegisterHandler(cpTypes.CommandExecuteScript, func(ctx context.Context, cmd *cpTypes.Command) error {
		dl, ok := ctx.Deadline()
		hasDeadlineCh <- ok
		deadlineCh <- dl
		return nil
	})

	before := time.Now()
	params := signedInlineEnvelopeParams(t, []byte(echoScriptBody("hello")), platformShell(), "steward-test")
	sc := testSignedCommandWithParams("script-deadline-default", cpTypes.CommandExecuteScript, params)
	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	hasDeadline := <-hasDeadlineCh
	deadline := <-deadlineCh

	require.True(t, hasDeadline,
		"executeCommand must still impose a deadline on CommandExecuteScript")
	delta := deadline.Sub(before)
	assert.True(t, delta > 29*time.Second && delta < 31*time.Second,
		"CommandExecuteScript's default deadline must remain ~30s from dispatch, got %s", delta)
}

// TestExecuteCommand_CommandExecuteScript_TimeoutSecondsOverrideUnaffected
// verifies that the existing per-command timeout_seconds override still works
// for CommandExecuteScript, unaffected by the CommandSyncConfig-specific fix.
func TestExecuteCommand_CommandExecuteScript_TimeoutSecondsOverrideUnaffected(t *testing.T) {
	h := newTestHandler(t, nil)

	deadlineCh := make(chan time.Time, 1)
	h.RegisterHandler(cpTypes.CommandExecuteScript, func(ctx context.Context, cmd *cpTypes.Command) error {
		dl, _ := ctx.Deadline()
		deadlineCh <- dl
		return nil
	})

	before := time.Now()
	params := signedInlineEnvelopeParams(t, []byte(echoScriptBody("hello")), platformShell(), "steward-test")
	params["timeout_seconds"] = float64(5)
	sc := testSignedCommandWithParams("script-deadline-override", cpTypes.CommandExecuteScript, params)
	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	deadline := <-deadlineCh
	delta := deadline.Sub(before)
	assert.True(t, delta > 4*time.Second && delta < 6*time.Second,
		"timeout_seconds override must still be honored for CommandExecuteScript, got %s", delta)
}

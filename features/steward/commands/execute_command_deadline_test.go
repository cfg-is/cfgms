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

	// Build the signed envelope before opening the measurement window: it runs an
	// RSA-2048 keygen plus signing, whose cost is unbounded and would otherwise be
	// charged against the deadline tolerance.
	params := signedInlineEnvelopeParams(t, []byte(echoScriptBody("hello")), platformShell(), "steward-test")
	sc := testSignedCommandWithParams("script-deadline-default", cpTypes.CommandExecuteScript, params)

	before := time.Now()
	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()
	after := time.Now()

	hasDeadline := <-hasDeadlineCh
	deadline := <-deadlineCh

	require.True(t, hasDeadline,
		"executeCommand must still impose a deadline on CommandExecuteScript")
	// executeCommand computed the deadline at some instant T with
	// before <= T <= after, so an exactly-30s default lands in
	// [before+30s, after+30s]. Bounding both ends makes the assertion
	// load-independent instead of relying on a fixed slack window.
	assertDeadlineWithin(t, deadline, before, after, 30*time.Second,
		"CommandExecuteScript's default deadline must remain 30s from dispatch")
}

// assertDeadlineWithin asserts that deadline is exactly want past the instant
// executeCommand created its context, which is known only to lie in
// [before, after]. Any deadline in [before+want, after+want] is therefore
// consistent with a want-second timeout and nothing else — the assertion has no
// arbitrary slack and cannot flake under load or slow scheduling.
func assertDeadlineWithin(t *testing.T, deadline, before, after time.Time, want time.Duration, msg string) {
	t.Helper()
	lower, upper := before.Add(want), after.Add(want)
	assert.False(t, deadline.Before(lower),
		"%s: deadline %s is earlier than dispatch+%s (%s)", msg, deadline, want, lower)
	assert.False(t, deadline.After(upper),
		"%s: deadline %s is later than completion+%s (%s)", msg, deadline, want, upper)
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

	// Envelope construction (RSA-2048 keygen + signing) stays outside the
	// measurement window — see the default-deadline test above.
	params := signedInlineEnvelopeParams(t, []byte(echoScriptBody("hello")), platformShell(), "steward-test")
	params["timeout_seconds"] = float64(5)
	sc := testSignedCommandWithParams("script-deadline-override", cpTypes.CommandExecuteScript, params)

	before := time.Now()
	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()
	after := time.Now()

	deadline := <-deadlineCh
	assertDeadlineWithin(t, deadline, before, after, 5*time.Second,
		"timeout_seconds override must still be honored for CommandExecuteScript")
}

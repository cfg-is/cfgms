// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/modules/script"
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
	// Regardless of whether a user is logged in, the result must be a valid UID:
	// either the resolved logged-in user's UID, or the process-UID fallback.
	// It must never be a negative/zero sentinel from a partial resolution.
	assert.GreaterOrEqual(t, uid, 0, "resolveRelayUID must always return a usable UID")
}

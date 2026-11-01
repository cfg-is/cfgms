// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoAPIKeyDowngrade_ExecutionAndNonExecutionCommandsFail is the required
// behavioral test for Issue #3688: with CFGMS_API_KEY set in the environment, no
// admin bundle present, and no active session, both a representative execution
// command (steward run-command) and a representative non-execution command
// (steward list) must fail with an error explicitly naming the required
// credential — proving the fix is CLI-wide, not limited to execution commands.
//
// Before this story, an operator whose bundle was missing or session had expired
// was transparently downgraded to CFGMS_API_KEY authentication and the command
// still succeeded, with no signal a weaker credential was used. That silent
// success path no longer exists: both commands below must return an error.
func TestNoAPIKeyDowngrade_ExecutionAndNonExecutionCommandsFail(t *testing.T) {
	tmpDir := t.TempDir()

	// No bundle anywhere: point every discovery candidate at a nonexistent path
	// and make sure the env-var candidate and --bundle/--no-bundle flags are unset.
	origBundlePath := bundlePath
	origNoBundle := noBundle
	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	t.Cleanup(func() {
		bundlePath = origBundlePath
		noBundle = origNoBundle
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
	})
	bundlePath = ""
	noBundle = false
	userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "no-userconfig"), nil }
	systemBundlePathFn = func() string { return filepath.Join(tmpDir, "no-system.bundle.yaml") }
	t.Setenv("CFGMS_ADMIN_BUNDLE", "")

	// No active session: force the OS-keychain lookup to report "unavailable".
	origSessionStoreFn := sessionStoreFn
	t.Cleanup(func() { sessionStoreFn = origSessionStoreFn })
	sessionStoreFn = func() (interfaces.SecretStore, error) { return nil, nil }

	// The downgrade this story closes: an operator (or a stale automation script)
	// has CFGMS_API_KEY exported. It must never be read as a fallback credential.
	t.Setenv("CFGMS_API_KEY", "leftover-automation-key")

	// --- Representative non-execution command: steward list ---
	origStewardURL := stewardURL
	origStewardTLSInsecure := stewardTLSInsecure
	t.Cleanup(func() {
		stewardURL = origStewardURL
		stewardTLSInsecure = origStewardTLSInsecure
	})
	stewardURL = "https://controller.invalid:9443"
	stewardTLSInsecure = false

	listErr := runStewardList(stewardListCmd, []string{})
	require.Error(t, listErr, "steward list must fail when no bundle or session credential is available")
	assert.Contains(t, listErr.Error(), "credential",
		"error must explicitly name the required credential, not fail generically")
	assert.True(t,
		strings.Contains(listErr.Error(), "bundle") && strings.Contains(listErr.Error(), "session"),
		"error must guide the operator to the two accepted credentials (bundle or session): %q", listErr.Error())

	// --- Representative execution command: steward run-command ---
	origTarget := stewardRunTarget
	origShell := stewardRunShell
	t.Cleanup(func() {
		stewardRunTarget = origTarget
		stewardRunShell = origShell
	})
	stewardRunTarget = "os:linux"
	stewardRunShell = "bash"

	runErr := runRunCommand(stewardRunCommandCmd, []string{"echo hello"})
	require.Error(t, runErr, "steward run-command must fail when no bundle credential is available")
	assert.True(t,
		strings.Contains(runErr.Error(), "bundle") && strings.Contains(runErr.Error(), "CFGMS_ADMIN_BUNDLE"),
		"error must explicitly name the required credential: %q", runErr.Error())
}

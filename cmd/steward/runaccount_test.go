// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestAccountFromUnixEUID_NonRootReportsInsufficientRights(t *testing.T) {
	acct := accountFromUnixEUID(1000, "svc-steward")
	assert.False(t, acct.Default)

	reg := client.NewHealthReasonRegistry()
	reportRunAccount(reg, acct, logging.NewCapturingLogger())

	reasons := reg.List()
	require.Len(t, reasons, 1)
	assert.Equal(t, "run_account", reasons[0].Component)
	assert.Equal(t, "account.insufficient_rights", reasons[0].Code)
	assert.Contains(t, reasons[0].Message, "svc-steward lacks: ")
	assert.Contains(t, reasons[0].Message, "root privileges")
}

func TestAccountFromUnixEUID_RootReportsNothing(t *testing.T) {
	acct := accountFromUnixEUID(0, "root")
	assert.True(t, acct.Default)

	reg := client.NewHealthReasonRegistry()
	// A stale reason from an earlier non-default start is cleared.
	reg.Set(runAccountComponent, runAccountInsufficientRightsCode, "stale")
	reportRunAccount(reg, acct, logging.NewCapturingLogger())
	assert.Empty(t, reg.List(), "the default account must produce no reason")
}

func TestRunAccountReason_SanitizesAccountName(t *testing.T) {
	acct := accountFromUnixEUID(1000, "evil\nINFO forged entry")
	_, msg, ok := acct.reason()
	require.True(t, ok)
	assert.NotContains(t, msg, "\n")
}

func TestProbeRunAccount_MatchesProcessEUID(t *testing.T) {
	acct := probeRunAccount([]string{filepath.Join(t.TempDir(), "absent")})
	_, _, hasReason := acct.reason()
	if runtime.GOOS == "windows" {
		assert.Equal(t, !acct.Default, hasReason)
		return
	}
	assert.Equal(t, os.Geteuid() != 0, hasReason, "a reason appears exactly for a non-root euid")
}

// TestApplyConfiguration_PermissionDenied_ReportsFailedNotCompliant drives the
// real file module against a target the account cannot write and checks the
// config status report says failed.
func TestApplyConfiguration_PermissionDenied_ReportsFailedNotCompliant(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not deny writes on Windows; ACL-based denial is covered by the data directory tests")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX permission checks, so no write can be denied to it; the non-root CI runner exercises this")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "managed.txt")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o400))
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	executor, err := execution.NewExecutor(&execution.ExecutorConfig{
		TenantID:  "test-tenant",
		Logger:    logging.ForModule("runaccount_test"),
		DriftMode: stewardconfig.DriftModeApply,
	})
	require.NoError(t, err)

	cfg := `{"steward":{"id":"s","mode":"controller"},"resources":[{"name":"managed","module":"file","config":{"path":"` +
		filepath.ToSlash(target) + `","content":"new","permissions":384,"allowed_base_path":"` +
		filepath.ToSlash(dir) + `"}}]}`
	report, err := executor.ApplyConfiguration(context.Background(), []byte(cfg), "v-denied")
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "ERROR", report.Status)
	assert.Equal(t, "ERROR", report.Modules["file"].Status)
	require.Len(t, report.ApplyOutcomes, 1)
	assert.Equal(t, "failed", report.ApplyOutcomes[0].Status)
	assert.NotEmpty(t, report.ApplyOutcomes[0].Error)
	got, _ := os.ReadFile(target)
	assert.Equal(t, "old", string(got))
}

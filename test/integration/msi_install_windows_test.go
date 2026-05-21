// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build windows

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc/mgr"
)

// TestMSIInstallWindowsService verifies that build-msi.ps1 produces a valid MSI
// and that after silent installation the cfgms-steward binary is placed at
// C:\Program Files\CFGMS\cfgms-steward.exe and the CFGMSSteward Windows service
// is registered in the Service Control Manager.
//
// This test requires a Windows runner with PowerShell Core (pwsh), the .NET SDK,
// and Administrator privileges. It is skipped in short mode.
func TestMSIInstallWindowsService(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a Windows runner with the WiX toolset")
	}

	repoRoot := findMSITestRepoRoot(t)

	buildScript := filepath.Join(repoRoot, "build", "windows", "build-msi.ps1")
	require.FileExists(t, buildScript, "build-msi.ps1 must exist in build/windows/")

	msiPath := filepath.Join(repoRoot, "bin", "cfgms-steward-windows-amd64.msi")

	// Step 1: build the MSI.
	t.Log("Building MSI with build-msi.ps1...")
	buildCmd := exec.Command("pwsh",
		"-NonInteractive",
		"-File", buildScript,
		"-Version", "0.0.0-test",
		"-Arch", "amd64",
	)
	buildCmd.Dir = repoRoot
	out, err := buildCmd.CombinedOutput()
	t.Logf("build-msi.ps1 output:\n%s", string(out))
	require.NoError(t, err, "build-msi.ps1 must succeed")
	require.FileExists(t, msiPath, "build-msi.ps1 must produce bin/cfgms-steward-windows-amd64.msi")

	t.Cleanup(func() {
		// Uninstall silently; ignore errors (the custom action may have failed).
		_ = exec.Command("msiexec", "/qn", "/x", msiPath).Run()
		// Remove any leftover binary.
		_ = os.Remove(`C:\Program Files\CFGMS\cfgms-steward.exe`)
	})

	// Step 2: install silently.
	// tok_test123 passes the token format validator (see service/token.go).
	// The service start will fail because no controller is running, but the service
	// registration (WriteServiceConfig in SCM) happens before Start() is called.
	// msiexec exit code may be non-zero if the custom action fails on service start;
	// we verify the observable side effects rather than the exit code.
	t.Log("Running msiexec /qn /i ...")
	msiCmd := exec.Command("msiexec",
		"/qn",
		"/i", msiPath,
		"REGTOKEN=tok_test123",
		"CA_FINGERPRINT=",
	)
	msiOut, msiErr := msiCmd.CombinedOutput()
	t.Logf("msiexec output:\n%s", string(msiOut))
	// Not requiring NoError: the custom action calls Start() which contacts the
	// controller; without a running controller Start() returns an error and msiexec
	// may roll back. We verify what was written before Start() was called.

	// Step 3: verify the binary was placed at the install path.
	// copyBinary() runs before Start(), so the binary is present even on rollback
	// only if the MSI did not roll back before RemoveFiles. If the MSI rolled back
	// the binary may not be present; log and report the outcome clearly.
	const installPath = `C:\Program Files\CFGMS\cfgms-steward.exe`
	_, statErr := os.Stat(installPath)
	if statErr != nil {
		if msiErr != nil {
			t.Logf("msiexec failed and binary not present — MSI rolled back: %v", msiErr)
		}
		t.Fatalf("cfgms-steward.exe not found at %s after msiexec: %v", installPath, statErr)
	}
	t.Logf("Binary confirmed at %s", installPath)

	// Step 4: verify service registration in the SCM.
	scm, err := mgr.Connect()
	require.NoError(t, err, "must be able to connect to Windows SCM — test requires Administrator privileges")
	defer scm.Disconnect()

	svc, err := scm.OpenService("CFGMSSteward")
	if err != nil {
		// The custom action may have failed on Start() and the MSI rolled back the
		// service registration. Log the state and report the failure.
		t.Logf("CFGMSSteward service not registered in SCM: %v", err)
		t.Logf("This typically means msiexec rolled back due to cfgms-steward install failing to start the service without a running controller.")
		t.Fail()
		return
	}
	defer svc.Close()

	cfg, err := svc.Config()
	require.NoError(t, err, "must be able to read service config")

	assert.Equal(t, "CFGMS Steward", cfg.DisplayName, "service display name must match")
	t.Logf("Windows service CFGMSSteward registered (StartType=%d)", cfg.StartType)
}

// TestMSIBuildProducesFile verifies that build-msi.ps1 produces an MSI file.
// This is a lighter check that does not run msiexec and does not require Administrator.
func TestMSIBuildProducesFile(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a Windows runner with the WiX toolset")
	}

	repoRoot := findMSITestRepoRoot(t)

	buildScript := filepath.Join(repoRoot, "build", "windows", "build-msi.ps1")
	require.FileExists(t, buildScript)

	msiPath := filepath.Join(repoRoot, "bin", "cfgms-steward-windows-amd64.msi")

	buildCmd := exec.Command("pwsh",
		"-NonInteractive",
		"-File", buildScript,
		"-Version", "0.0.0-test",
		"-Arch", "amd64",
	)
	buildCmd.Dir = repoRoot
	out, err := buildCmd.CombinedOutput()
	t.Logf("build-msi.ps1 output:\n%s", string(out))
	require.NoError(t, err, "build-msi.ps1 must succeed")
	require.FileExists(t, msiPath, "MSI must be produced")

	fi, err := os.Stat(msiPath)
	require.NoError(t, err)
	assert.Greater(t, fi.Size(), int64(0), "MSI file must not be empty")
	t.Logf("MSI produced: %s (%d bytes)", msiPath, fi.Size())
}

// findMSITestRepoRoot walks up from the working directory until go.mod is found.
func findMSITestRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found (no go.mod in any parent directory)")
		}
		dir = parent
	}
}

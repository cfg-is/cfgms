// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// windowsHypervDetector checks whether the local Windows host has Hyper-V
// enabled by running Get-VMHost via PowerShell. Results are cached for 5
// minutes to avoid repeated PowerShell invocations on every module operation.
type windowsHypervDetector struct {
	mu           sync.Mutex
	cachedResult bool
	cacheExpiry  time.Time
}

// powershellExe resolves powershell.exe via an absolute path under %SystemRoot%
// rather than relying on %PATH%. Without this, an attacker (or misconfigured
// service account) who controls a directory earlier on PATH can plant a
// `powershell.exe` shim that exits 0 with empty output and convince the
// detector that Hyper-V is present on a host that isn't a Hyper-V host —
// trivially bypassing the security gate on the module.
//
// SystemRoot fallback: if %SystemRoot% is unset (e.g. the process started
// with a sanitised environment that dropped it) we fall back to %windir%,
// then to the hardcoded `C:\Windows`. A relative path here would defeat the
// whole defense — exec.Command would resolve it via %PATH%, reopening the
// shim bypass. The final guard returns an empty string only when literally
// nothing resolves; the caller treats psRunFn errors as "not Hyper-V" so
// that case still fails closed.
//
// WOW64 note: a 32-bit steward on 64-bit Windows hits the filesystem path
// `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` via the WOW64
// redirector. PowerShell exists there too, so the absolute-path under
// `System32` resolves correctly under both 32-bit and 64-bit stewards.
// Server Core ships PowerShell at the same path; no special case needed.
func powershellExe() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" {
		root = `C:\Windows`
	}
	p := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if !filepath.IsAbs(p) {
		// Belt and braces: if everything above somehow produced a relative
		// path, return empty rather than allowing PATH resolution.
		return ""
	}
	return p
}

// psRunFn executes the Get-VMHost powershell command and returns combined output.
// Overridden in tests to avoid invoking a real powershell.exe.
var psRunFn = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, powershellExe(), "-NonInteractive", "-Command", "Get-VMHost | ConvertTo-Json").CombinedOutput()
}

// isSoftError returns true for cmdlet-not-found and access-denied failures,
// which indicate Hyper-V is not installed or accessible. All other errors are
// propagated to the caller.
func isSoftError(output []byte) bool {
	text := strings.ToLower(string(output))
	return strings.Contains(text, "commandnotfoundexception") ||
		strings.Contains(text, "is not recognized") ||
		strings.Contains(text, "access is denied") ||
		strings.Contains(text, "access denied")
}

// IsHypervHost runs Get-VMHost. Cmdlet-not-found and access-denied failures
// are soft failures that return (false, nil). Other exec errors return (false, err).
//
// A successful exit code alone is not sufficient: a PATH-resident shim could
// exit 0 with empty output. We parse the `Get-VMHost | ConvertTo-Json` result
// and require a non-empty `Name` field — that's the host's own hostname as
// reported by Hyper-V, which a shim cannot fabricate without actually running
// Hyper-V. Empty / unparseable output returns (false, nil) — i.e. "not a
// Hyper-V host" — rather than an error, because the same conditions apply
// when the cmdlet itself returns nothing on a degraded install.
func (d *windowsHypervDetector) IsHypervHost(ctx context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if time.Now().Before(d.cacheExpiry) {
		return d.cachedResult, nil
	}

	output, err := psRunFn(ctx)
	if err != nil {
		if isSoftError(output) {
			return false, nil
		}
		return false, err
	}

	// Positive-content check: the stdout must parse as Hyper-V's VMHost JSON
	// and carry a non-empty Name field. Anything else — empty output, garbage
	// from a PATH shim, or a malformed Get-VMHost response — is treated as
	// "not a Hyper-V host," not as an exec error.
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return false, nil
	}
	var probe struct {
		Name string `json:"Name"`
	}
	if jsonErr := json.Unmarshal([]byte(trimmed), &probe); jsonErr != nil {
		return false, nil
	}
	if probe.Name == "" {
		return false, nil
	}

	d.cachedResult = true
	d.cacheExpiry = time.Now().Add(5 * time.Minute)
	return true, nil
}

func newDefaultDetector() HypervDetector {
	return &windowsHypervDetector{}
}

// NewDefaultDetector returns the platform-appropriate HypervDetector for
// production use. Called by the steward module factory.
func NewDefaultDetector() HypervDetector {
	return newDefaultDetector()
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWindowsDetector_SoftErrors verifies that cmdlet-not-found and access-denied
// outputs from powershell are treated as soft failures — returning (false, nil)
// rather than surfacing the exec error to the caller.
func TestWindowsDetector_SoftErrors(t *testing.T) {
	softOutputs := []struct {
		name   string
		output []byte
	}{
		{"CommandNotFoundException", []byte("CommandNotFoundException: Get-VMHost is not recognized")},
		{"is not recognized", []byte("The term 'Get-VMHost' is not recognized as the name of a cmdlet")},
		{"access is denied", []byte("Access is denied. You need to run the script as Administrator")},
		{"access denied", []byte("get-vmhost : access denied")},
	}

	for _, tc := range softOutputs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			d := &windowsHypervDetector{}

			restore := psRunFn
			t.Cleanup(func() { psRunFn = restore })
			psRunFn = func(_ context.Context) ([]byte, error) {
				return tc.output, errors.New("exit status 1")
			}

			ok, err := d.IsHypervHost(context.Background())
			if err != nil {
				t.Errorf("soft error %q produced non-nil err = %v, want nil", tc.name, err)
			}
			if ok {
				t.Errorf("soft error %q produced ok=true, want false", tc.name)
			}
		})
	}
}

// TestWindowsDetector_HardError verifies that unexpected powershell errors (e.g.
// a genuine exec failure unrelated to cmdlet availability) are surfaced as errors.
func TestWindowsDetector_HardError(t *testing.T) {
	d := &windowsHypervDetector{}
	hardErr := errors.New("CreateProcess: file not found")

	restore := psRunFn
	t.Cleanup(func() { psRunFn = restore })
	psRunFn = func(_ context.Context) ([]byte, error) {
		return nil, hardErr
	}

	ok, err := d.IsHypervHost(context.Background())
	if !errors.Is(err, hardErr) {
		t.Errorf("hard error = %v, want %v", err, hardErr)
	}
	if ok {
		t.Errorf("hard error produced ok=true, want false")
	}
}

// TestWindowsDetector_CachesPositiveResult verifies that a successful detection
// is cached for 5 minutes and the underlying PS command is not re-invoked.
func TestWindowsDetector_CachesPositiveResult(t *testing.T) {
	callCount := 0
	restore := psRunFn
	t.Cleanup(func() { psRunFn = restore })
	psRunFn = func(_ context.Context) ([]byte, error) {
		callCount++
		// Get-VMHost | ConvertTo-Json returns the host's own hostname in
		// the Name field — that's the canonical positive-presence signal
		// the detector requires (see Name-field check in IsHypervHost).
		return []byte(`{"Name":"testhost"}`), nil
	}

	d := &windowsHypervDetector{}
	ctx := context.Background()

	// First call — hits PS.
	ok, err := d.IsHypervHost(ctx)
	if err != nil || !ok {
		t.Fatalf("first call = (%v, %v), want (true, nil)", ok, err)
	}

	// Two more calls within the cache window — must not invoke PS again.
	for i := 0; i < 2; i++ {
		ok2, err2 := d.IsHypervHost(ctx)
		if err2 != nil || !ok2 {
			t.Errorf("cached call %d = (%v, %v), want (true, nil)", i+1, ok2, err2)
		}
	}

	if callCount != 1 {
		t.Errorf("psRunFn called %d times within cache window, want 1", callCount)
	}

	// Expire the cache and verify PS is called again.
	d.mu.Lock()
	d.cacheExpiry = time.Now().Add(-time.Second)
	d.mu.Unlock()

	ok3, err3 := d.IsHypervHost(ctx)
	if err3 != nil || !ok3 {
		t.Errorf("post-expiry call = (%v, %v), want (true, nil)", ok3, err3)
	}
	if callCount != 2 {
		t.Errorf("psRunFn called %d times after cache expiry, want 2", callCount)
	}
}

// TestWindowsDetector_RejectsEmptyOutput confirms the positive-content gate:
// a successful exit with empty stdout is treated as "not a Hyper-V host" rather
// than as a successful detection. This is the in-process complement to the
// out-of-process PATH-spoof test below — the kernel-level path resolution
// changed but the content check is what actually blocks the bypass.
func TestWindowsDetector_RejectsEmptyOutput(t *testing.T) {
	restore := psRunFn
	t.Cleanup(func() { psRunFn = restore })
	psRunFn = func(_ context.Context) ([]byte, error) {
		return []byte(""), nil
	}

	d := &windowsHypervDetector{}
	ok, err := d.IsHypervHost(context.Background())
	if err != nil {
		t.Errorf("empty output produced non-nil err = %v, want nil", err)
	}
	if ok {
		t.Errorf("empty output produced ok=true, want false (PATH-spoof defense bypassed)")
	}
}

// TestWindowsDetector_RejectsEmptyNameField confirms that a Get-VMHost
// response whose Name field is empty is treated as "not a Hyper-V host."
// This covers a degraded or partially-disabled Hyper-V install whose cmdlet
// returns a stub object — the detector should fail closed rather than
// activate the module against a host that can't actually run VMs.
func TestWindowsDetector_RejectsEmptyNameField(t *testing.T) {
	restore := psRunFn
	t.Cleanup(func() { psRunFn = restore })
	psRunFn = func(_ context.Context) ([]byte, error) {
		return []byte(`{"Name":""}`), nil
	}

	d := &windowsHypervDetector{}
	ok, err := d.IsHypervHost(context.Background())
	if err != nil {
		t.Errorf("empty Name produced non-nil err = %v, want nil", err)
	}
	if ok {
		t.Errorf("empty Name produced ok=true, want false")
	}
}

// TestWindowsDetector_RejectsNonJSONOutput covers the case where a PATH-resident
// shim prints non-JSON garbage on stdout while exiting 0. The detector must
// treat unparseable output as "not a Hyper-V host," not as a soft error to
// propagate.
func TestWindowsDetector_RejectsNonJSONOutput(t *testing.T) {
	restore := psRunFn
	t.Cleanup(func() { psRunFn = restore })
	psRunFn = func(_ context.Context) ([]byte, error) {
		return []byte("hello from a fake shell"), nil
	}

	d := &windowsHypervDetector{}
	ok, err := d.IsHypervHost(context.Background())
	if err != nil {
		t.Errorf("non-JSON output produced non-nil err = %v, want nil", err)
	}
	if ok {
		t.Errorf("non-JSON output produced ok=true, want false")
	}
}

// TestPowershellExe_ReturnsAbsolutePath is the actually-falsifiable unit test
// of the PATH-spoof defense: it asserts that `powershellExe()` returns an
// absolute path under %SystemRoot% (or the documented fallback chain), and
// that the path does not depend on PATH content. If a future refactor
// accidentally went back to a bare basename or to PATH-relative resolution,
// THIS test would fail clearly, whereas TestWindowsDetector_RejectsPathSpoofing
// can only prove the defense fired by absence of a shim sentinel.
func TestPowershellExe_ReturnsAbsolutePath(t *testing.T) {
	// Sanity: in the normal case, return an absolute path.
	p := powershellExe()
	if !filepath.IsAbs(p) {
		t.Errorf("powershellExe()=%q, want absolute path", p)
	}
	if !strings.HasSuffix(strings.ToLower(p), `\windowspowershell\v1.0\powershell.exe`) {
		t.Errorf("powershellExe()=%q, want path ending in WindowsPowerShell\\v1.0\\powershell.exe", p)
	}

	// PATH content must not influence the result. Set PATH to nothing and
	// confirm we still return the same absolute path. This is the
	// regression-pin for the spoof defense.
	t.Setenv("PATH", "")
	p2 := powershellExe()
	if p2 != p {
		t.Errorf("powershellExe() with empty PATH=%q, want same as default %q", p2, p)
	}
	if !filepath.IsAbs(p2) {
		t.Errorf("powershellExe() with empty PATH=%q, want absolute", p2)
	}

	// SystemRoot empty → falls back to %windir%.
	t.Setenv("SystemRoot", "")
	t.Setenv("windir", `D:\NotARealWindows`)
	p3 := powershellExe()
	if !filepath.IsAbs(p3) {
		t.Errorf("powershellExe() with SystemRoot='' fallback to windir=%q, want absolute", p3)
	}
	if !strings.HasPrefix(p3, `D:\NotARealWindows`) {
		t.Errorf("powershellExe() with SystemRoot='' did not honour windir fallback; got %q", p3)
	}

	// Both empty → hardcoded `C:\Windows` last-resort.
	t.Setenv("SystemRoot", "")
	t.Setenv("windir", "")
	p4 := powershellExe()
	if !filepath.IsAbs(p4) {
		t.Errorf("powershellExe() with both env empty=%q, want absolute (last-resort fallback)", p4)
	}
	if !strings.HasPrefix(p4, `C:\Windows`) {
		t.Errorf("powershellExe() last-resort fallback=%q, want path under C:\\Windows", p4)
	}
}

// TestWindowsDetector_RejectsPathSpoofing exercises the absolute-path defense
// end-to-end. We rebind psRunFn to invoke the configured powershellExe()
// against a PATH that has a "powershell.exe" shim prepended. If the detector
// were to resolve powershell.exe via PATH, the shim would win, exit 0 with
// empty stdout, and the detector would (incorrectly) return true. Because
// powershellExe() returns an absolute path under %SystemRoot%, the PATH shim
// is never consulted. The content check provides defense-in-depth: even if
// the absolute path was bypassed and the shim ran, the empty-output gate
// would catch it.
func TestWindowsDetector_RejectsPathSpoofing(t *testing.T) {
	dir := t.TempDir()
	// Sentinel marker: the shim writes this file when it runs. After the
	// detector call we assert the file does NOT exist, which is the
	// load-bearing evidence that the absolute-path defense actually fired
	// (rather than the shim running and returning an empty/false result
	// that happens to match the expected "not Hyper-V" outcome). Without
	// this sentinel, the test passes trivially on any non-Hyper-V dev
	// box even if the absolute-path resolution were broken.
	sentinel := filepath.Join(t.TempDir(), "shim-ran.marker")
	shimBat := filepath.Join(dir, "powershell.bat")
	shimBatBody := "@echo off\r\necho SHIM_RAN > \"" + sentinel + "\"\r\nexit /b 0\r\n"
	if err := os.WriteFile(shimBat, []byte(shimBatBody), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	// A trivial .exe in the same dir to cover cmd.exe's basename
	// resolution order; not executable but its presence with the right
	// name is enough to prove the shim dir wasn't honored.
	if err := os.WriteFile(filepath.Join(dir, "powershell.exe"), []byte(""), 0o755); err != nil {
		t.Fatalf("touch shim exe: %v", err)
	}

	// Prepend the shim dir so a basename-only resolution would pick it up.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Run the real psRunFn — production code path against real exec.Command.
	// The load-bearing assertion is "sentinel NOT written": if the absolute
	// path resolution works, our shim is never invoked, so the marker file
	// is never created. The boolean return is NOT asserted: on a real
	// Hyper-V host (including GitHub windows-latest runners, which ship the
	// Hyper-V module and return a valid Get-VMHost result), the detector
	// legitimately returns true via the real powershell.exe — that is the
	// defense working correctly, not failing. The falsifiable absolute-path
	// regression-pin lives in TestPowershellExe_ReturnsAbsolutePath above.
	d := &windowsHypervDetector{}
	_, err := d.IsHypervHost(context.Background())
	if err != nil {
		t.Logf("PATH-spoof test surfaced %v — acceptable as long as sentinel absent (PATH was not honored)", err)
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Errorf("sentinel %q was written — the PATH-resident shim ran. Absolute-path defense is broken.", sentinel)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"errors"
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
		return []byte(`{"ComputerName":"testhost"}`), nil
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

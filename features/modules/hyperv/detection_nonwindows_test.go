// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

import (
	"context"
	"testing"
)

// TestNonWindowsDetector_AlwaysReturnsFalse pins the production contract on
// non-Windows hosts: Hyper-V is a Windows-only feature, so the detector must
// uniformly return (false, nil). This is what makes a steward on ctrl-01 /
// stw-lin-01 cleanly decline a config with hyperv resources instead of
// crashing or attempting a Hyper-V operation (B4 epic AC).
func TestNonWindowsDetector_AlwaysReturnsFalse(t *testing.T) {
	d := nonWindowsDetector{}
	ok, err := d.IsHypervHost(context.Background())
	if err != nil {
		t.Errorf("nonWindowsDetector.IsHypervHost = err %v, want nil", err)
	}
	if ok {
		t.Errorf("nonWindowsDetector.IsHypervHost = true, want false")
	}
}

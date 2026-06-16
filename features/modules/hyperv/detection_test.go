// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/modules"
)

// noopDetector always returns (false, nil). Used in tests that need a concrete
// HypervDetector value but do not exercise detection logic.
type noopDetector struct{}

func (noopDetector) IsHypervHost(_ context.Context) (bool, error) { return false, nil }

// fakeDetector returns a configurable result and tracks how many times
// IsHypervHost has been called. Set err to simulate detector failures.
type fakeDetector struct {
	result bool
	err    error
	mu     sync.Mutex
	count  int
}

func (f *fakeDetector) IsHypervHost(_ context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	return f.result, f.err
}

// Calls returns the number of IsHypervHost invocations recorded so far.
func (f *fakeDetector) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

// TestHostDetection_UsesInjectedDetector verifies that a module constructed
// with fakeDetector{result: true} proceeds past the detection gate, while
// fakeDetector{result: false} returns ErrHostNotHyperV.
func TestHostDetection_UsesInjectedDetector(t *testing.T) {
	t.Run("true activates", func(t *testing.T) {
		m := newModuleWithDetector(nil, &fakeDetector{result: true})
		// "any-vm" has no colon — falls through to ErrNotImplemented, proving
		// the detector returned true and the gate was passed.
		_, err := m.Get(context.Background(), "any-vm")
		if !errors.Is(err, modules.ErrNotImplemented) {
			t.Errorf("Get with true detector = %v, want ErrNotImplemented", err)
		}
	})
	t.Run("false returns ErrHostNotHyperV", func(t *testing.T) {
		m := newModuleWithDetector(nil, &fakeDetector{result: false})
		_, err := m.Get(context.Background(), "any-vm")
		if !errors.Is(err, ErrHostNotHyperV) {
			t.Errorf("Get with false detector = %v, want ErrHostNotHyperV", err)
		}
	})
}

// TestCheckDetection_NilDetector_ReturnsErrHostNotHyperV verifies that a module
// constructed with no detector (nil) returns ErrHostNotHyperV on every call.
func TestCheckDetection_NilDetector_ReturnsErrHostNotHyperV(t *testing.T) {
	m := newModuleWithDetector(nil, nil)
	_, err := m.Get(context.Background(), "vm:some-vm")
	if !errors.Is(err, ErrHostNotHyperV) {
		t.Errorf("Get with nil detector = %v, want ErrHostNotHyperV", err)
	}
}

// TestCheckDetection_PropagatesDetectorError verifies that a detector error is
// surfaced directly from Get and Set without wrapping or swallowing.
func TestCheckDetection_PropagatesDetectorError(t *testing.T) {
	detErr := errors.New("detector: winrm timeout")
	fake := &fakeDetector{err: detErr}

	m := newModuleWithDetector(nil, fake)
	_, err := m.Get(context.Background(), "vm:some-vm")
	if !errors.Is(err, detErr) {
		t.Errorf("Get() detector error = %v, want %v", err, detErr)
	}

	setErr := m.Set(context.Background(), "vm:some-vm", &VMConfig{})
	if !errors.Is(setErr, detErr) {
		t.Errorf("Set() detector error = %v, want %v", setErr, detErr)
	}
}

// TestDetection_CachedFor5Min_CallsDetectorOnce verifies that the module-level
// detection cache prevents redundant calls to the injected detector within 5
// minutes. After the cache expires the detector is called exactly once more.
func TestDetection_CachedFor5Min_CallsDetectorOnce(t *testing.T) {
	fake := &fakeDetector{result: true}
	m := newModuleWithDetector(nil, fake)

	ctx := context.Background()

	// Three Get calls within a 5-minute window.
	for i := 0; i < 3; i++ {
		_, _ = m.Get(ctx, "any-vm") // ErrNotImplemented is expected and irrelevant here
	}

	if got := fake.Calls(); got != 1 {
		t.Errorf("detector calls within 5-min window = %d, want 1", got)
	}

	// Simulate cache expiry by rewinding the stored expiry timestamp.
	m.detMu.Lock()
	m.detExpiry = time.Now().Add(-time.Second)
	m.detMu.Unlock()

	_, _ = m.Get(ctx, "any-vm")

	if got := fake.Calls(); got != 2 {
		t.Errorf("detector calls after cache expiry = %d, want 2", got)
	}
}
